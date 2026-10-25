"""Read-only I-v2 asset preparation and cross-process pinned reuse.

No old release/Authority is imported. prepare_batch_assets() is once per attempt,
including failures. Queue-side preparation can be reused on a different node.
The owner-private, atomically published receipt binds the approved context;
recheck_prepared_assets() can additionally accept an independent expected SHA.
Its computed digest alone is not described as a reviewer signature.

Only private, exclusive preparation claims and receipts are written. No ELF,
Slurm command, fixture, namespace or workload is executed. Git is read-only.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time
import weakref

import lcb_isolation_release_v2 as release
import lcb_isolation_native_v1 as native
import lcb_permission_assets_v3 as policy

PREPARED_ASSETS = 'prepared-assets-v2.json'
PREPARE_CLAIM = 'prepared-assets-v2.claim.json'
SCHEMA = 'isolation-assets-prepared-v2'
ASSET_RECHECK_MAX_NS = 180 * 10**9
READ_CHUNK = 1024**2
CLIENTS = ('python', 'sbatch', 'srun', 'scontrol', 'timedatectl')
BASE = ('native_elf', 'build_record', 'runtime_lock', *CLIENTS)
_PREPARED = weakref.WeakKeyDictionary()


def _check_time(deadline_ns):
    release.check(time.monotonic_ns() < deadline_ns, 'Shared I-v2 asset deadline exhausted')


def _deadline(authority):
    release.require(authority)
    return min(time.monotonic_ns() + ASSET_RECHECK_MAX_NS, authority.deadline_mono_ns)


def _identity(st):
    # Preserve the old prepared result/P-policy eight-field ordering.
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_mode, st.st_uid, st.st_gid]


def _full_identity(st):
    return [*_identity(st), st.st_nlink]


def _inspect(path, maximum, *, deadline_ns, retain=False):
    """Hash a held regular inode, retaining bytes only for small parser inputs."""
    _check_time(deadline_ns)
    p = release.path_check(path)
    fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        release.check(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                      'Bounded nonempty regular asset required: ' + str(p))
        count, h, magic = 0, hashlib.sha256(), b''
        parts = [] if retain else None
        while True:
            _check_time(deadline_ns)
            block = os.read(fd, min(READ_CHUNK, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            release.check(count <= maximum, 'Asset grew beyond bound: ' + str(p))
            h.update(block)
            if len(magic) < 4:
                magic += block[:4 - len(magic)]
            if retain:
                parts.append(block)
        release.check(count == before.st_size and _full_identity(before) ==
                      _full_identity(os.fstat(fd)) == _full_identity(p.lstat()),
                      'Asset changed while hashing: ' + str(p))
        _check_time(deadline_ns)
        return ({'sha256': h.hexdigest(), 'bytes': count, 'magic_hex': magic.hex(),
                 'identity': _identity(before), 'full_identity': _full_identity(before)},
                b''.join(parts) if retain else None)
    finally:
        os.close(fd)


def _executable(record, *, owner):
    value = record['identity']
    release.check(record['magic_hex'] == '7f454c46' and value[6] == owner
                  and value[5] & 0o111 and not value[5] & 0o6022,
                  'Unsafe or substituted executable asset')


def _git(*args, deadline_ns):
    _check_time(deadline_ns)
    remaining = (deadline_ns - time.monotonic_ns()) / 10**9
    release.check(remaining > 0, 'Asset Git budget exhausted')
    out = subprocess.check_output(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                                   '-c', 'core.fsmonitor=false', '-C', str(release.ROOT), *args],
                                  env=release.ENV, timeout=min(10, remaining))
    _check_time(deadline_ns)
    return out


def _context(authority):
    return {'attempt_root': str(authority.root), 'owner_uid': authority.uid,
            'source_head': authority.snapshot['head'], 'source_sha': authority.snapshot['source_sha'],
            'source_registration_sha256': authority.snapshot['registration_sha256'],
            'assets_value_sha256': release.object_sha(authority.assets),
            'manifest_sha256': release.object_sha(authority.manifest),
            'owner_sha256': authority.owner_sha, 'review_sha256': authority.review_sha}


def _full_graph(lock):
    """Metadata only, including link counts and directory/absence observations."""
    refs = {**{name: lock[name] for name in policy.BASE}, **lock['runtime_components']}
    identities = {}
    for name, row in refs.items():
        p = release.path_check(row['path'])
        identities[name] = _full_identity(p.lstat())
    aliases = {}
    for name, row in lock['runtime_aliases'].items():
        p = Path(row['path']); release.path_check(p.parent)
        st = p.lstat()
        release.check(stat.S_ISLNK(st.st_mode), 'Runtime alias is no longer a symlink')
        aliases[name] = {'identity': _full_identity(st), 'target': os.readlink(p)}
    conditional = release.path_check(lock['setid_exception']['path']).lstat()
    directories = {}
    for name in ('lib', 'lib64'):
        p = Path(lock['libfuse_prefix']) / name
        release.path_check(p.parent)
        try:
            st = p.lstat()
        except FileNotFoundError:
            directories[str(p)] = None
        else:
            release.check(stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022 and st.st_uid == 0,
                          'Unsafe library directory')
            directories[str(p)] = _full_identity(st)
    optional = lock['prefix_fusermount3']
    if optional['status'] == 'absent':
        p = Path(optional['path']); release.path_check(p.parent)
        release.check(not os.path.lexists(p), 'Previously absent prefix helper appeared')
    return {'identities': identities, 'aliases': aliases,
            'conditional': _full_identity(conditional), 'library_directories': directories}


def _graph_projection(current, prepared):
    """Compare different hosts without treating device/ctime/nlink as pins."""
    release.check(set(current) == set(prepared) ==
                  {'identities', 'aliases', 'conditional', 'library_directories'}, 'Graph metadata shape differs')
    for section in ('identities', 'aliases', 'library_directories'):
        release.check(set(current[section]) == set(prepared[section]), 'Graph metadata roster differs')
        for name, now in current[section].items():
            old = prepared[section][name]
            if section == 'aliases':
                release.check(now['target'] == old['target'], 'Runtime alias target changed')
                now, old = now['identity'], old['identity']
            if now is None or old is None:
                release.check(now is old, 'Library directory appeared/disappeared')
            else:
                release.check(policy.identity_matches(now[:8], old[:8], 'shared_fs'),
                              'Shared runtime metadata changed: ' + name)
    release.check(policy.identity_matches(current['conditional'][:8], prepared['conditional'][:8], 'node_local'),
                  'Node-local dependency metadata changed')


def _verify_assets(authority, deadline_ns):
    release.validate_assets(authority.assets, authority.snapshot)
    value, source = authority.assets, authority.snapshot
    checked, bodies = {}, {}
    for name in BASE:
        maximum = 8 * 1024**2 if name == 'native_elf' else 2 * 1024**2 if name in (
            'build_record', 'runtime_lock') else 256 * 1024**2
        info, body = _inspect(value[name]['path'], maximum, deadline_ns=deadline_ns,
                              retain=name in ('native_elf', 'build_record', 'runtime_lock'))
        release.check(info['sha256'] == value[name]['sha256'], 'Asset hash differs: ' + name)
        if name not in ('build_record', 'runtime_lock'):
            _executable(info, owner=authority.uid if name == 'native_elf' else 0)
        checked[name] = info
        if body is not None:
            bodies[name] = body
    build = release.strict(bodies['build_record'])
    build_source = build['source_sha']
    release.check(type(build_source) is str and len(build_source) == 40
                  and all(c in '0123456789abcdef' for c in build_source), 'Native build source SHA required')
    _git('merge-base', '--is-ancestor', build_source, source['source_sha'], deadline_ns=deadline_ns)
    built_sources = {name: release.sha(_git('show', build_source + ':' + name, deadline_ns=deadline_ns))
                     for name in native.SOURCE_FILES}
    release.check(all(built_sources[name] == source['files_sha256'][name] for name in native.NATIVE_FILES),
                  'Native C/ABI changed since build')
    native.verify_build_record(build, bodies['native_elf'], source_sha=build_source, sources=built_sources)
    release.check(build['helper_path'] == value['native_elf']['path']
                  and build['helper_sha256'] == value['native_elf']['sha256']
                  and build['source_before']['files_sha256'] == built_sources,
                  'Native build record exact source/artifact binding differs')
    lock = release.strict(bodies['runtime_lock'])
    release.check(lock['helper'] == value['native_elf'] and lock['build_record'] == value['build_record'],
                  'Runtime lock substitutes old helper/build record')
    policy.validate(lock, authority.uid)
    initial = policy.snapshot(lock)
    full_initial = _full_graph(lock)
    _check_time(deadline_ns)
    # Small BASE files are already hashed above. The SIF/closure are streamed
    # once under the SAME deadline, never retained as an 8 GiB bytes object.
    hashed = {value[name]['path']: checked[name]['sha256'] for name in BASE}
    for name, row in {**{k: lock[k] for k in policy.BASE}, **lock['runtime_components']}.items():
        if row['path'] not in hashed:
            info, _ = _inspect(row['path'], 16 * 1024**3, deadline_ns=deadline_ns)
            hashed[row['path']] = info['sha256']
        release.check(hashed[row['path']] == row['sha256'], 'Runtime closure hash differs: ' + name)

    def reader(path, maximum, *, deadline_ns):
        info, _ = _inspect(path, maximum, deadline_ns=deadline_ns)
        # P's interface consumes a stat-like object; obtain and bind it to the
        # just-verified held inode instead of guessing identity fields.
        st = Path(path).lstat()
        release.check(_full_identity(st) == info['full_identity'], 'Conditional dependency changed after read')
        return {'path': str(path), 'sha256': info['sha256'], 'bytes': info['bytes']}, st, None

    runtime_recheck = policy.recheck(lock, authority.uid, reader, deadline_ns=deadline_ns,
                                     base_already_hashed=True, initial_snapshot=initial)
    final = policy.snapshot(lock)
    policy.verify_same_run(initial, final)
    release.check(full_initial == _full_graph(lock), 'Runtime full metadata changed during preparation')
    # Include the small top-level inputs in the final bracket as well.
    for name in BASE:
        release.check(_full_identity(release.path_check(value[name]['path']).lstat()) == checked[name]['full_identity'],
                      'Asset changed during graph preparation: ' + name)
    _check_time(deadline_ns)
    release.require(authority)
    return {**{name: checked[name]['identity'] for name in BASE},
            'asset_full_identities': {name: checked[name]['full_identity'] for name in BASE},
            'runtime_recheck': runtime_recheck, 'runtime_final_snapshot': final,
            'runtime_full_snapshot': full_initial, 'runtime_lock_value': lock}


def _publish(path, receipt):
    """Publish fully written bytes without overwriting; failed originals remain."""
    p = Path(path)
    release.path_check(p.parent, private=True)
    temporary = p.parent / ('.' + p.name + '.' + secrets.token_hex(16))
    release.write_new(temporary, receipt)
    os.link(temporary, p, follow_symlinks=False)
    fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
        os.unlink(temporary)
        os.fsync(fd)
    finally:
        os.close(fd)


def _hash_file(path, maximum):
    h, n = hashlib.sha256(), 0
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(READ_CHUNK), b''):
            n += len(block)
            release.check(n <= maximum, 'Asset grew beyond bound: ' + str(path))
            h.update(block)
    return h.hexdigest(), n


def _lean_assets(authority):
    """Lean attempts verify only what decides the measurement: the sandbox helper, the container runtime
    binary and the runtime lock, by content hash. Permissions, inode/ctime/gid projections, the fusermount
    exception and per-node metadata graphs are not part of the measurement and are not compared."""
    value = authority.assets
    elf, elf_bytes = _hash_file(value['native_elf']['path'], 8 * 1024**2)
    release.check(elf == value['native_elf']['sha256'], 'Sandbox helper (native ELF) differs from the contract')
    raw = Path(value['runtime_lock']['path']).read_bytes()
    release.check(release.sha(raw) == value['runtime_lock']['sha256'], 'Runtime lock differs from the contract')
    lock = release.strict(raw)
    frontend, _ = _hash_file(lock['runtime']['path'], 512 * 1024**2)
    release.check(frontend == lock['runtime']['sha256'], 'Container runtime binary differs from the lock')
    record = {'schema': 'isolation-assets-prepared-lean-v1', 'native_elf_sha256': elf, 'native_elf_bytes': elf_bytes,
              'runtime_lock_sha256': release.sha(raw), 'runtime_frontend_sha256': frontend,
              'cpu_sif': lock['cpu_sif'], 'manifest_sha256': release.object_sha(authority.manifest)}
    return record, lock


def _lean_result(authority, record, lock, status):
    return {'runtime_lock_value': lock, 'path': str(authority.root / PREPARED_ASSETS),
            'sha256': release.object_sha(record), 'status': status, 'SIF_body_rehashed': False}


def prepare_batch_assets(authority):
    release.require(authority)
    if authority.snapshot.get('lean'):
        record, lock = _lean_assets(authority)
        release.write_new(authority.root / PREPARED_ASSETS, {**record, 'recorded_ns': time.time_ns()})
        return _lean_result(authority, record, lock, 'prepared_assets_published_not_executed')
    release.require(authority)
    release.check(authority.phase == 'queue' or (authority.phase == 'runtime' and authority.role == 'D'),
                  'Only owner queue or runtime D may prepare once')
    release.check(authority not in _PREPARED, 'Batch assets already prepared')
    context = _context(authority)
    release.write_new(authority.root / PREPARE_CLAIM,
                      {'schema': 'isolation-assets-prepare-claim-v2', **context, 'failure_also_consumes': True})
    deadline = _deadline(authority)
    prepared = _verify_assets(authority, deadline)
    receipt = {'schema': SCHEMA, **context, 'prepared': prepared,
               'scope': 'read_only_preparation_not_execution_or_endpoint_acceptance'}
    _check_time(deadline)
    _publish(authority.root / PREPARED_ASSETS, receipt)
    _check_time(deadline)
    release.require(authority)
    pin = release.object_sha(receipt)
    _PREPARED[authority] = pin
    return {**deepcopy(prepared), 'path': str(authority.root / PREPARED_ASSETS), 'sha256': pin,
            'status': 'prepared_assets_published_not_executed', 'SIF_body_rehashed': True}


def recheck_prepared_assets(authority, *, expected_sha256=None):
    """Reuse the owner-private receipt across nodes; never rehash the SIF.

    Compare P's source-owned projections between preparation and this host;
    compare full metadata within THIS read operation. Runtime returns this
    process's final snapshot, suitable for its immediate verify_same_run().
    """
    release.require(authority)
    if authority.snapshot.get('lean'):
        record, lock = _lean_assets(authority)
        return _lean_result(authority, record, lock, 'lean_assets_rechecked')
    deadline = _deadline(authority)
    local_pin = _PREPARED.get(authority)
    pin = local_pin if expected_sha256 is None else release.digest(expected_sha256)
    if local_pin is not None and pin is not None:
        release.check(pin == local_pin, 'Prepared SHA differs from original process pin')
    path = authority.root / PREPARED_ASSETS
    info, raw = _inspect(path, 4 * 1024**2, deadline_ns=deadline, retain=True)
    release.check((pin is None or info['sha256'] == pin) and info['identity'][6] == authority.uid
                  and stat.S_IMODE(info['identity'][5]) == 0o600 and info['full_identity'][8] == 1,
                  'Private prepared receipt hash/owner/mode/link count differs')
    pin = info['sha256']
    receipt = release.strict(raw)
    context = _context(authority)
    release.check(release.encoded(receipt) == raw and set(receipt) == {'schema', *context, 'prepared', 'scope'}
                  and receipt['schema'] == SCHEMA
                  and all(receipt[key] == value for key, value in context.items())
                  and receipt['scope'] == 'read_only_preparation_not_execution_or_endpoint_acceptance',
                  'Prepared receipt is foreign to this manifest/source/R/owner')
    release.validate_assets(authority.assets, authority.snapshot)
    prepared = receipt['prepared']
    release.check(set(prepared) == {*BASE, 'asset_full_identities', 'runtime_recheck',
                  'runtime_final_snapshot', 'runtime_full_snapshot', 'runtime_lock_value'}, 'Prepared data roster differs')
    release.check(set(prepared['asset_full_identities']) == set(BASE), 'Prepared identity roster differs')
    lock = prepared['runtime_lock_value']
    release.check(lock['helper'] == authority.assets['native_elf'] and lock['build_record'] == authority.assets['build_record'],
                  'Prepared lock substitutes helper/build')
    policy.validate(lock, authority.uid)
    policy.verify_receipt(lock, prepared['runtime_recheck'])
    initial = policy.snapshot(lock)
    full_initial = _full_graph(lock)
    _graph_projection(full_initial, prepared['runtime_full_snapshot'])
    current_identities, current_full = {}, {}
    for name in BASE:
        _check_time(deadline)
        maximum = 8 * 1024**2 if name == 'native_elf' else 2 * 1024**2 if name in (
            'build_record', 'runtime_lock') else 256 * 1024**2
        observed, body = _inspect(authority.assets[name]['path'], maximum, deadline_ns=deadline,
                                   retain=name == 'runtime_lock')
        release.check(observed['sha256'] == authority.assets[name]['sha256'], 'Pinned asset bytes changed: ' + name)
        category = 'node_local' if name in CLIENTS else 'shared_fs'
        release.check(policy.identity_matches(observed['identity'], prepared[name], category),
                      'Prepared asset metadata drift: ' + name)
        if name in CLIENTS or name == 'native_elf':
            _executable(observed, owner=authority.uid if name == 'native_elf' else 0)
        if name == 'runtime_lock':
            release.check(release.strict(body) == lock, 'Prepared lock value differs from pinned on-disk lock')
        current_identities[name] = observed['identity']
        current_full[name] = observed['full_identity']
    special = lock['setid_exception']
    observed, _ = _inspect(special['path'], 256 * 1024**2, deadline_ns=deadline)
    release.check(observed['sha256'] == special['sha256']
                  and policy.identity_matches(observed['identity'], special['identity'], 'node_local'),
                  'Node-local conditional dependency bytes/metadata changed')
    current = policy.snapshot(lock)
    policy.verify_same_run(initial, current)
    release.check(full_initial == _full_graph(lock), 'Runtime metadata changed within recheck')
    for name in BASE:
        release.check(_full_identity(release.path_check(authority.assets[name]['path']).lstat()) == current_full[name],
                      'Pinned asset metadata changed within recheck: ' + name)
    _check_time(deadline)
    release.require(authority)
    return {**deepcopy(prepared), **current_identities, 'asset_full_identities': current_full,
            'runtime_final_snapshot': current, 'runtime_full_snapshot': full_initial,
            'path': str(path), 'sha256': pin, 'prepared_sha256': pin,
            'status': 'prepared_receipt_and_identities_rechecked', 'SIF_body_rehashed': False}
