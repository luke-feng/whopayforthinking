"""Independent I source/asset/review/owner gates. No authority from P or S.

Only explicit owner entry points call issue(). Importing this module does not
inspect a host, run Git, issue a permit, or execute a process.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
import weakref

ROOT = Path(__file__).resolve().parents[2]
REGISTRATION = 'experiments/calibration/isolation-source-v1.contract.json'
ASSETS = 'experiments/calibration/isolation-assets-v1.contract.json'
POLICY = 'experiments/calibration/isolation-runtime-v1.contract.json'
IMPLEMENTATION_REVIEW = 'review/fi-implementation-review-2026-10-20.md'
NATIVE = ('scripts/calibration/native/isolation_worker_v1.c',
          'scripts/calibration/native/isolation_worker_abi_v1.h')
ENTRIES = ('scripts/calibration/lcb_isolation_release_v1.py',
           'scripts/calibration/lcb_isolation_batch_v1.py',
           'scripts/calibration/lcb_isolation_control_v1.py',
           'scripts/calibration/lcb_isolation_owner_v1.py',
           'scripts/calibration/lcb_isolation_meter_v1.py',
           'scripts/calibration/lcb_isolation_meter_export_v1.py',
           'scripts/calibration/lcb_isolation_cpu_return_v1.py',
           'scripts/calibration/lcb_isolation_backend_v1.py',
           'scripts/calibration/lcb_isolation_acceptance_v1.py',
           'scripts/calibration/lcb_isolation_native_v1.py',
           'scripts/calibration/lcb_isolation_build_v1.py')
TEMPLATES = tuple('experiments/calibration/isolation-' + r + '-v1.slurm.template'
                  for r in ('worker', 'observer', 'gpu'))
GATES = ('trusted_fixture_execution_authorized', 'candidate_execution_authorized',
         'main_matrix_authorized', 'cost_sample_eligible')
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
_SEAL = object()
_ISSUED = weakref.WeakKeyDictionary()
_PREPARED = weakref.WeakKeyDictionary()
ASSET_RECHECK_MAX_NS = 180_000_000_000
PREPARED_ASSETS = 'assets-prepared.json'


def check(ok, why):
    if not ok:
        raise ValueError(why)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def object_sha(value):
    return sha(encoded(value))


def digest(value):
    check(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256 required')
    return value


def strict(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            check(k not in result, 'Duplicate JSON key')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: check(False, 'Nonfinite JSON'))


def integer(value, low=0, high=10**24):
    check(type(value) is int and low <= value <= high, 'Bounded integer required')
    return value


def token(value):
    check(type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value), 'Literal token required')
    return value


def number(value, zero=False):
    pattern = r'0|[1-9][0-9]{0,11}' if zero else r'[1-9][0-9]{0,11}'
    check(type(value) is str and re.fullmatch(pattern, value), 'Canonical numeric identity required')
    return value


def path_check(path, *, uid=None, private=False):
    p = Path(path)
    check(p.is_absolute() and str(p) == str(path) and '..' not in p.parts, 'Canonical absolute path required')
    for q in reversed((p, *p.parents)):
        st = q.lstat()
        sticky_root_directory = stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
        check(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0, os.getuid() if uid is None else uid)
              and (not st.st_mode & 0o022 or sticky_root_directory), 'Unsafe owner/path: ' + str(q))
    if private:
        check(p.stat().st_uid == (os.getuid() if uid is None else uid)
              and not p.stat().st_mode & 0o077, 'Private owner path required')
    return p


def deadline_check(deadline_ns):
    if deadline_ns is not None:
        check(time.monotonic_ns() < deadline_ns, 'Shared 180s asset recheck deadline exceeded')


def read(path, limit=4*1024**2, *, private=False, deadline_ns=None):
    deadline_check(deadline_ns)
    p = path_check(path, private=private)
    fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        check(stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= limit, 'Bounded regular file required')
        chunks, size = [], 0
        while True:
            deadline_check(deadline_ns)
            raw = os.read(fd, min(1024**2, limit + 1 - size))
            if not raw:
                break
            chunks.append(raw); size += len(raw)
            check(size <= limit, 'Input grew beyond bound')
        b = os.fstat(fd); c = p.lstat()
        check(identity(a) == identity(b) == identity(c), 'File changed while reading')
        deadline_check(deadline_ns)
        return b''.join(chunks)
    finally:
        os.close(fd)


def identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_mode, st.st_uid, st.st_gid)


def write_new(path, value):
    """A durable, exclusive claim; never overwrite even after failed execution."""
    p = Path(path); path_check(p.parent, private=True)
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); check(count > 0, 'Short durable write'); view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def publish_new(path, value):
    """Publish complete bytes atomically without overwriting an existing name.

    Claims deliberately keep write_new semantics. On a failed publish, retain
    the private temporary original; cleanup happens only after successful link.
    """
    p = Path(path); path_check(p.parent, private=True)
    temporary = p.parent/('.publish-'+p.name+'-'+secrets.token_hex(16))
    write_new(temporary, value)
    os.link(temporary, p, follow_symlinks=False)
    fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
        temporary.unlink()
        os.fsync(fd)
    finally:
        os.close(fd)


def read_published(path):
    # A successful publication has removed its temporary hard link. Waiting
    # for nlink=1 also avoids ctime changes during the final unlink bracket.
    p = Path(path)
    if p.lstat().st_nlink != 1:
        raise FileNotFoundError('Publication has not completed')
    return read(p, private=True)


def source_roster(root=ROOT):
    """Static local-import closure, plus literal runtime data/native/template files."""
    root = Path(root)
    found = set((*NATIVE, *TEMPLATES, POLICY, IMPLEMENTATION_REVIEW))
    pending = list(ENTRIES)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        tree = ast.parse(read(root/name))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            elif isinstance(node, ast.Constant) and type(node.value) is str:
                literal = node.value
                if (re.fullmatch(r'(?:experiments|data|review|scripts)/[A-Za-z0-9_./-]+\.(?:json|md|template|sh|c|h|py)', literal)
                        and literal not in (REGISTRATION, ASSETS) and (root/literal).is_file()):
                    if literal.endswith('.py'):
                        if literal not in found:
                            pending.append(literal)
                    else:
                        found.add(literal)
        for module in modules:
            if re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', module):
                child = 'scripts/calibration/' + module + '.py'
                if (root/child).is_file() and child not in found:
                    pending.append(child)
    check(len(found) <= 128, 'Source closure bound')
    return tuple(sorted(found))


def _git(root, *args):
    return subprocess.check_output(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                                    '-C', str(root), *args], env=ENV, timeout=10)


def source_snapshot(root=ROOT):
    root = path_check(root)
    raw = read(root/REGISTRATION); registry = strict(raw)
    check(encoded(registry) == raw, 'Canonical I registry required')
    if registry.get('status') not in ('registered', 'source_registered_assets_pending'):
        raise PermissionError('I source registration pending; no live operations')
    check(registry.get('schema') == 'isolation-source-v1', 'Independent I registry required')
    check(set(registry) == {'schema', 'status', 'source_sha', 'files_sha256', 'assets_sha256', *GATES}
          and all(registry[k] is False for k in GATES), 'Exact source registry schema and closed gates')
    head = _git(root, 'rev-parse', 'HEAD').decode().strip()
    origin = registry['source_sha']
    check(re.fullmatch('[0-9a-f]{40}', origin or '') and origin != head, 'Separate code A and registry B required')
    check(not _git(root, 'status', '--porcelain', '--untracked-files=all', '--ignored'), 'Clean source required')
    _git(root, 'merge-base', '--is-ancestor', origin, head)
    check(_git(root, 'show', head + ':' + REGISTRATION) == raw, 'Registry differs from B')
    names = source_roster(root)
    check(set(names) == set(registry['files_sha256']), 'Incomplete registered source closure')
    for name in names:
        body = read(root/name)
        check(sha(body) == registry['files_sha256'][name]
              and _git(root, 'show', origin + ':' + name) == _git(root, 'show', head + ':' + name) == body,
              'Registered source bytes drifted: ' + name)
    return {'head': head, 'source_sha': origin, 'registration_sha256': sha(raw),
            'files_sha256': dict(registry['files_sha256'])}, registry


def validate_assets(value, snapshot):
    """Pure format/provenance checks. Actual run still rehashes every asset."""
    if value.get('status') != 'owner_build_verified':
        raise PermissionError('New isolation ELF lacks owner GCC originals; assets pending')
    check(value.get('schema') == 'isolation-assets-v1', 'Independent new isolation assets required')
    check(value.get('mechanism_review_status') == 'accepted_for_trusted_fixture_execution'
          and type(value.get('mechanism_review_sha256')) is str, 'Isolation mechanisms incomplete/unreviewed; run closed')
    digest(value['mechanism_review_sha256'])
    for k in ('native_elf', 'build_record', 'runtime_lock', 'python', 'sbatch', 'srun', 'scontrol', 'timedatectl'):
        row = value[k]
        digest(row['sha256'])
        check(type(row['path']) is str and Path(row['path']).is_absolute(), 'Absolute asset path required')
    check(value['native_elf']['path'].endswith('/isolation-worker.elf')
          and 'permission-helper' not in value['native_elf']['path'], 'P helper cannot substitute for isolation worker')
    check(value['native_sources_sha256'] == {n: snapshot['files_sha256'][n] for n in NATIVE}, 'New native source binding')


def recheck_assets(value, snapshot):
    deadline_ns = time.monotonic_ns()+ASSET_RECHECK_MAX_NS
    validate_assets(value, snapshot)
    result = {}
    for name in ('native_elf', 'build_record', 'runtime_lock', 'python', 'sbatch', 'srun', 'scontrol', 'timedatectl'):
        row = value[name]
        raw = read(row['path'], 256*1024**2, deadline_ns=deadline_ns)
        check(sha(raw) == row['sha256'], 'Asset bytes changed: ' + name)
        st = Path(row['path']).stat()
        if name not in ('build_record', 'runtime_lock'):
            check(raw[:4] == b'\x7fELF' and st.st_mode & 0o111 and not st.st_mode & 0o6022, 'Unsafe executable asset')
        result[name] = identity(st)
    build = strict(read(value['build_record']['path'], deadline_ns=deadline_ns))
    import lcb_isolation_native_v1 as codec
    build_source = build['source_sha']
    check(type(build_source) is str and re.fullmatch('[0-9a-f]{40}', build_source), 'Native build source SHA')
    _git(ROOT, 'merge-base', '--is-ancestor', build_source, snapshot['source_sha'])
    for name in NATIVE:
        check(sha(_git(ROOT, 'show', build_source+':'+name)) == snapshot['files_sha256'][name], 'Native sources changed since build')
    codec.verify_build_record(build, read(value['native_elf']['path'], 8*1024**2, deadline_ns=deadline_ns),
                             source_sha=build_source,
                             sources={n: snapshot['files_sha256'][n] for n in codec.SOURCE_FILES})
    # Runtime installation graph follows the independently accepted P asset
    # policy; its helper/build references MUST be replaced with the new I ELF.
    import lcb_permission_assets_v3 as policy
    lock = strict(read(value['runtime_lock']['path'], deadline_ns=deadline_ns))
    check(lock['helper'] == value['native_elf'] and lock['build_record'] == value['build_record'], 'I runtime lock has old helper')
    policy.validate(lock, os.getuid())
    # Bracket the whole graph BEFORE its first streaming body hash. Moving the
    # initial snapshot after SIF hashing would miss a change between those reads.
    initial = policy.snapshot(lock)
    # Fully hash the SIF and runtime closure once, retain operation-local stats.
    for name, row in {**{k: lock[k] for k in policy.BASE}, **lock['runtime_components']}.items():
        raw_sha = stream_sha(row['path'], 16*1024**3, deadline_ns=deadline_ns)
        check(raw_sha == row['sha256'], 'Runtime closure bytes changed: ' + name)
    def reader(path, maximum, *, deadline_ns):
        check(time.monotonic_ns() < deadline_ns, 'Asset recheck deadline')
        info = Path(path).stat(); raw = read(path, maximum, deadline_ns=deadline_ns)
        return {'sha256': sha(raw)}, info, None
    result['runtime_recheck'] = policy.recheck(lock, os.getuid(), reader, deadline_ns=deadline_ns,
                   base_already_hashed=True, initial_snapshot=initial)
    result['runtime_final_snapshot'] = policy.snapshot(lock)
    deadline_check(deadline_ns)
    result['runtime_lock_value'] = lock
    return result


def prepare_batch_assets(authority):
    """One full 180s validation per finite batch, never per submission slot."""
    require(authority)
    check(authority not in _PREPARED, 'Batch assets already prepared; no automatic rehash/retry')
    prepared = recheck_assets(authority.assets, authority.snapshot)
    receipt = {'schema': 'isolation-assets-prepared-v1', 'owner_uid': authority.uid,
               'source_registration_sha256': authority.snapshot['registration_sha256'],
               'source_head': authority.snapshot['head'], 'assets_value_sha256': object_sha(authority.assets),
               'manifest_sha256': object_sha(authority.manifest), 'owner_sha256': authority.owner_sha,
               'review_sha256': authority.review_sha, 'prepared': prepared,
               'scope': 'batch_preparation_not_run_or_authority'}
    publish_new(authority.root/PREPARED_ASSETS, receipt)
    _PREPARED[authority] = object_sha(receipt)
    return {'path': str(authority.root/PREPARED_ASSETS), 'sha256': _PREPARED[authority]}


def recheck_prepared_assets(authority):
    """Check independent in-process receipt pin and all identities; no SIF read.

    This is a same-parent-process submission check. Each job role independently
    rehashes the complete graph once under the normal 180s run validation.
    """
    require(authority)
    check(authority in _PREPARED, 'Independent batch prepare receipt required before submit')
    raw = read_published(authority.root/PREPARED_ASSETS)
    check(sha(raw) == _PREPARED[authority], 'Prepared receipt bytes drifted')
    receipt = strict(raw)
    check(encoded(receipt) == raw and set(receipt) == {'schema', 'owner_uid', 'source_registration_sha256',
          'source_head', 'assets_value_sha256', 'manifest_sha256', 'owner_sha256', 'review_sha256',
          'prepared', 'scope'} and receipt['schema'] == 'isolation-assets-prepared-v1'
          and receipt['owner_uid'] == authority.uid
          and receipt['source_registration_sha256'] == authority.snapshot['registration_sha256']
          and receipt['source_head'] == authority.snapshot['head']
          and receipt['assets_value_sha256'] == object_sha(authority.assets)
          and receipt['manifest_sha256'] == object_sha(authority.manifest)
          and receipt['owner_sha256'] == authority.owner_sha and receipt['review_sha256'] == authority.review_sha,
          'Prepared receipt is foreign to this source/manifest/approval')
    validate_assets(authority.assets, authority.snapshot)
    prepared = receipt['prepared']
    for name in ('native_elf', 'build_record', 'runtime_lock', 'python', 'sbatch', 'srun', 'scontrol', 'timedatectl'):
        p = path_check(authority.assets[name]['path'])
        check(list(identity(p.lstat())) == prepared[name], 'Prepared asset identity drifted: ' + name)
    import lcb_permission_assets_v3 as policy
    lock = prepared['runtime_lock_value']
    check(lock['helper'] == authority.assets['native_elf'] and lock['build_record'] == authority.assets['build_record'],
          'Prepared runtime lock is not the new I helper')
    policy.validate(lock, authority.uid)
    policy.verify_same_run(prepared['runtime_final_snapshot'], policy.snapshot(lock))
    return {'schema': receipt['schema'], 'prepared_sha256': _PREPARED[authority],
            'status': 'prepared_receipt_and_identities_rechecked', 'SIF_body_rehashed': False}


def stream_sha(path, maximum, *, deadline_ns=None):
    deadline_check(deadline_ns)
    p = path_check(path); fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd); check(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'Bounded streaming asset')
        h = hashlib.sha256(); size = 0
        while True:
            deadline_check(deadline_ns)
            part = os.read(fd, 1024**2)
            if not part:
                break
            size += len(part); check(size <= maximum, 'Asset grew'); h.update(part)
        check(identity(before) == identity(os.fstat(fd)) == identity(p.lstat()), 'Asset changed during hash')
        deadline_check(deadline_ns)
        return h.hexdigest()
    finally:
        os.close(fd)


def approval_check(owner_raw, review_raw, manifest_raw, *, owner_sha, review_sha, snapshot, assets_sha, now_ns):
    """Independent expected digests are arguments, not inferred from the bundle."""
    check(sha(owner_raw) == digest(owner_sha) and sha(review_raw) == digest(review_sha), 'Independent owner/R digest mismatch')
    owner, review, manifest = strict(owner_raw), strict(review_raw), strict(manifest_raw)
    check(encoded(owner) == owner_raw and encoded(review) == review_raw and encoded(manifest) == manifest_raw,
          'Canonical owner/R/manifest bytes required')
    check(set(review) == {'schema', 'purpose', 'decision', 'source_sha', 'registration_sha256',
                         'assets_sha256', 'manifest_sha256', 'candidate_execution_authorized', 'main_matrix_authorized'},
          'Exact R schema keys')
    check(set(owner) == {'schema', 'purpose', 'owner_approved', 'owner_uid', 'review_sha256', 'source_head',
                        'registration_sha256', 'assets_sha256', 'manifest_sha256', 'slots_sha256', 'nonce',
                        'not_before_ns', 'expires_ns', 'candidate_execution_authorized', 'main_matrix_authorized'},
          'Exact owner schema keys')
    check(owner['owner_approved'] is True and all(v[k] is False for v in (owner, review, manifest)
          for k in ('candidate_execution_authorized', 'main_matrix_authorized')), 'Explicit owner approval; candidate/main closed')
    from lcb_isolation_batch_v1 import validate_manifest
    validate_manifest(manifest)
    check(review.get('schema') == 'isolation-reviewed-release-v1'
          and review.get('purpose') == 'trusted_isolation_fixed_v1'
          and review.get('decision') == 'approved' and review['source_sha'] == snapshot['source_sha']
          and review['registration_sha256'] == snapshot['registration_sha256']
          and review['assets_sha256'] == assets_sha and review['manifest_sha256'] == sha(manifest_raw), 'R scope/source/lock mismatch')
    check(owner.get('schema') == 'isolation-owner-approval-v1'
          and owner.get('purpose') == 'trusted_isolation_fixed_v1' and owner['owner_uid'] == os.getuid() > 0
          and owner['review_sha256'] == review_sha and owner['source_head'] == snapshot['head']
          and owner['registration_sha256'] == snapshot['registration_sha256']
          and owner['assets_sha256'] == assets_sha and owner['manifest_sha256'] == sha(manifest_raw)
          and owner['slots_sha256'] == object_sha(manifest['slots']) and owner['nonce'] == manifest['nonce']
          and owner['not_before_ns'] == manifest['not_before_ns']
          and owner['expires_ns'] == manifest['expires_ns'], 'Owner exact manifest/slots/window mismatch')
    integer(owner['not_before_ns'], 1); integer(owner['expires_ns'], 1)
    check(owner['not_before_ns'] <= now_ns < owner['expires_ns'], 'Owner queue/run window expired')
    return owner, review


class Authority:
    def __init__(self, seal, root, snapshot, assets, manifest, owner, owner_sha, review_sha):
        check(seal is _SEAL, 'Independent issuer only')
        self.root = root; self.snapshot = deepcopy(snapshot); self.assets = deepcopy(assets)
        self.manifest = deepcopy(manifest); self.owner = deepcopy(owner)
        self.owner_sha = owner_sha; self.review_sha = review_sha
        self.pid, self.uid = os.getpid(), os.getuid()
        _ISSUED[self] = self.fingerprint()

    def fingerprint(self):
        return object_sha({'root': str(self.root), 'snapshot': self.snapshot, 'assets': self.assets,
                           'manifest': self.manifest, 'owner': self.owner, 'owner_sha': self.owner_sha,
                           'review_sha': self.review_sha, 'pid': self.pid, 'uid': self.uid})


def require(authority):
    if (type(authority) is not Authority or authority not in _ISSUED
            or authority.fingerprint() != _ISSUED[authority]
            or (authority.pid, authority.uid) != (os.getpid(), os.getuid())
            or not authority.owner['not_before_ns'] <= time.time_ns() < authority.owner['expires_ns']):
        raise PermissionError('Live independent I authority required')


def issue(root, *, owner_sha, review_sha):
    root = path_check(root, private=True)
    snapshot, registry = source_snapshot()
    assets_raw = read(ROOT/ASSETS); assets = strict(assets_raw)
    check(registry['assets_sha256'] == sha(assets_raw), 'Unregistered I assets')
    validate_assets(assets, snapshot)  # Pending fails BEFORE any subprocess/runtime.
    manifest_raw = read(root/'manifest.json', private=True)
    from lcb_isolation_batch_v1 import validate_manifest
    manifest = validate_manifest(strict(manifest_raw))
    check(str(root) == manifest['attempt_root'] and ROOT not in root.parents,
          'Approved immutable attempt root outside source required')
    owner, review = approval_check(read(root/'owner-approval.json', private=True),
        read(root/'reviewed-release.json', private=True), manifest_raw,
        owner_sha=owner_sha, review_sha=review_sha, snapshot=snapshot, assets_sha=sha(assets_raw), now_ns=time.time_ns())
    check(manifest['source_head'] == snapshot['head'] and manifest['assets_sha256'] == sha(assets_raw), 'Manifest source/assets')
    return Authority(_SEAL, root, snapshot, assets, manifest, owner, owner_sha, review_sha)


def consume_slot(authority, slot_id, phase):
    require(authority); token(slot_id); check(phase in ('submission', 'execution'), 'Slot phase')
    slots = {s['slot_id']: s for s in authority.manifest['slots']}
    check(slot_id in slots, 'Undeclared slot')
    value = {'schema': 'isolation-slot-consumed-v1', 'slot_id': slot_id, 'phase': phase,
             'manifest_sha256': object_sha(authority.manifest), 'owner_sha256': authority.owner_sha,
             'review_sha256': authority.review_sha, 'consumed_wall_ns': time.time_ns(),
             'failure_also_consumes': True}
    write_new(authority.root/(phase+'-'+slot_id+'.consumed.json'), value)
    return deepcopy(slots[slot_id])
