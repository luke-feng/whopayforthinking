"""Independent I-v2 queue/runtime capability and provenance policy.

Import does not issue capabilities or launch anything. This module contains no
Slurm client, cancellation, signal, compiler, or ELF execution implementation.
Old I-v1 assets may be read; I-v1 authorities, registrations and R are rejected.
"""
from copy import deepcopy
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import weakref

ROOT = Path(__file__).resolve().parents[2]
REGISTRATION = 'experiments/calibration/isolation-source-v2.contract.json'
ASSETS = 'experiments/calibration/isolation-assets-v2.contract.json'
ENDPOINT_ACCEPTANCE = 'experiments/calibration/isolation-endpoint-site-v2.acceptance.json'
MODELS = 'experiments/calibration/inference-models-v1.json'
RULING = 'review/i-minimal-async-design-v1-ruling-2026-10-20.md'
REVISION_RULING = 'review/i-async-first-package-ruling-2026-10-20.md'
RULING_SHA256 = '59ae91f51f69468aca37c40a6758c516f68b2372444da8a18050ca1f39b8325d'
NATIVE = ('scripts/calibration/native/isolation_worker_v1.c',
          'scripts/calibration/native/isolation_worker_abi_v1.h')
GATES = ('trusted_fixture_execution_authorized', 'candidate_execution_authorized',
         'main_matrix_authorized', 'cost_sample_eligible')
ASYNC_FIELDS = ('submit_by_ns', 'start_by_ns', 'max_run_s', 'absolute_end_by_ns')
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_OPTIONAL_LOCKS': '0'}
_SEAL = object()
_ISSUED = weakref.WeakKeyDictionary()


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


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            check(key not in value, 'Duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: check(False, 'Nonfinite JSON'))


def digest(value):
    check(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256 required')
    return value


def integer(value, low=0, high=10**24):
    check(type(value) is int and low <= value <= high, 'Bounded integer required')
    return value


def token(value):
    check(type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value), 'Literal token required')
    return value


def number(value, zero=False):
    check(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,11}' if zero else r'[1-9][0-9]{0,11}', value),
          'Canonical numeric identity required')
    return value


def path_check(path, *, uid=None, private=False):
    p = Path(path)
    check(p.is_absolute() and str(p) == str(path) and '..' not in p.parts
          and not any(c in str(p) for c in ('\0', '\n', '\r')), 'Canonical absolute path required')
    owner = os.getuid() if uid is None else uid
    # No ancestor-chain ownership/symlink walk: it constrained where the owner may keep files, not what is measured.
    if private:
        st = p.lstat()
        check(st.st_uid == owner and not st.st_mode & 0o077, 'Private owner path required')
    return p


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_mode, st.st_uid, st.st_gid, st.st_nlink)


def read(path, limit=4 * 1024**2, *, private=False, deadline_ns=None):
    """Bounded held-fd read; deadline_ns, when given, is monotonic."""
    integer(limit, 0, 16 * 1024**3)
    p = path_check(path, private=private)
    fd = os.open(p, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        check(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'Bounded regular input required')
        parts, size = [], 0
        while True:
            check(deadline_ns is None or time.monotonic_ns() < deadline_ns, 'Read deadline exhausted')
            part = os.read(fd, min(1024**2, limit + 1 - size))
            if not part:
                break
            parts.append(part); size += len(part)
            check(size <= limit, 'Input grew beyond bound')
        after = os.fstat(fd)
        check(size == before.st_size == after.st_size and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
              'Input changed during read')
        check(deadline_ns is None or time.monotonic_ns() < deadline_ns, 'Read deadline exhausted')
        return b''.join(parts)
    finally:
        os.close(fd)


def write_new(path, value):
    """Durable exclusive claim. Failed/partial claims remain consumed."""
    p = Path(path)
    check(p.name not in ('', '.', '..') and str(p) == str(path), 'Literal output path required')
    path_check(p.parent, private=True)
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view); check(n > 0, 'Short durable write'); view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _git(root, *args, timeout_s=10):
    return subprocess.check_output(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                                    '-c', 'core.fsmonitor=false', '-C', str(root), *args],
                                   env=ENV, timeout=timeout_s)


def source_roster(root=ROOT):
    """Close over current I-v2 entries, their local imports and literal inputs."""
    root = Path(root)
    found = set((*NATIVE, RULING))
    pending = {'scripts/calibration/lcb_isolation_release_v2.py',
               'scripts/calibration/lcb_isolation_batch_v2.py'}
    pending.update(str(p.relative_to(root)) for p in (root / 'scripts/calibration').glob('lcb_isolation_*_v2.py'))
    found.update(str(p.relative_to(root)) for p in (root / 'experiments/calibration').glob('isolation-*v2*')
                 if str(p.relative_to(root)) not in (REGISTRATION, ASSETS, ENDPOINT_ACCEPTANCE) and p.is_file())
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        tree = ast.parse(read(root / name))
        for node in ast.walk(tree):
            modules = ([a.name for a in node.names] if isinstance(node, ast.Import) else
                       [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for module in modules:
                if re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', module):
                    child = 'scripts/calibration/' + module + '.py'
                    if (root / child).is_file() and child not in found:
                        pending.add(child)
            if isinstance(node, ast.Constant) and type(node.value) is str:
                value = node.value
                if (value not in (REGISTRATION, ASSETS, ENDPOINT_ACCEPTANCE)
                        and re.fullmatch(r'(?:scripts|experiments|review|data)/[A-Za-z0-9_./-]+\.(?:py|json|md|template|c|h)', value)
                        and (root / value).is_file()):
                    if value.endswith('.py') and value not in found:
                        pending.add(value)
                    elif not value.endswith('.py'):
                        found.add(value)
    check(len(found) <= 192, 'I-v2 source closure too large')
    return tuple(sorted(found))


def source_snapshot(root=ROOT, *, git_status_timeout_s=10):
    # Keep the old keyword for callers. Reproducibility is determined by the
    # registered file bytes below, not unrelated files or a slow git status.
    root = path_check(root)
    raw = read(root / REGISTRATION); registry = strict(raw)
    check(type(registry) is dict and set(registry) == {'schema', 'status', 'source_sha', 'files_sha256',
          'assets_sha256', 'endpoint_site_acceptance_sha256', *GATES}, 'Independent I-v2 registry required')
    check(registry['schema'] == 'isolation-source-v2'
          and registry['status'] in ('registered', 'source_registered_assets_pending')
          and all(registry[k] is False for k in GATES), 'I-v2 source status/gates differ')
    check(encoded(registry) == raw, 'Canonical I-v2 registry required')
    digest(registry['assets_sha256'])
    if registry['endpoint_site_acceptance_sha256'] is not None:
        digest(registry['endpoint_site_acceptance_sha256'])
    head = _git(root, 'rev-parse', 'HEAD').decode().strip()
    origin = registry['source_sha']
    check(re.fullmatch('[0-9a-f]{40}', origin or '') and re.fullmatch('[0-9a-f]{40}', head)
          and origin != head, 'Separate I-v2 source A and registration B required')
    try:
        _git(root, 'merge-base', '--is-ancestor', origin, head)
    except subprocess.CalledProcessError as exc:
        raise ValueError('I-v2 source A is not a verified ancestor of B') from exc
    check(_git(root, 'show', head + ':' + REGISTRATION) == raw, 'Registry differs from B')
    names = source_roster(root)
    check(type(registry['files_sha256']) is dict and set(registry['files_sha256']) == set(names),
          'Exact I-v2 source closure required')
    for name in names:
        body = read(root / name)
        check(sha(body) == digest(registry['files_sha256'][name])
              and _git(root, 'show', origin + ':' + name) == body == _git(root, 'show', head + ':' + name),
              'I-v2 registered source differs: ' + name)
    check(sha(read(root / RULING)) == RULING_SHA256, 'I-v2 design ruling differs')
    return {'head': head, 'source_sha': origin, 'registration_status': registry['status'],
            'registration_sha256': sha(raw), 'assets_sha256': registry['assets_sha256'],
            'endpoint_site_acceptance_sha256': registry['endpoint_site_acceptance_sha256'],
            'files_sha256': dict(registry['files_sha256'])}, registry


def validate_assets(value, snapshot):
    """Read-compatible v1 asset contract; this never reuses v1 authority."""
    check(value.get('schema') in ('isolation-assets-v1','isolation-assets-v2') and value.get('status') == 'owner_build_verified'
          and value.get('mechanism_review_status') == 'accepted_for_trusted_fixture_execution',
          'Verified I native assets required')
    digest(value['mechanism_review_sha256'])
    check(all(value.get(k) is False for k in GATES), 'Asset contract execution gates must remain false')
    check(value['native_sources_sha256'] == {n: snapshot['files_sha256'][n] for n in NATIVE},
          'Unchanged native C/ABI binding required')
    for name in ('native_elf', 'build_record', 'runtime_lock', 'python', 'sbatch', 'srun', 'scontrol', 'timedatectl'):
        row = value[name]
        check(type(row) is dict and set(row) == {'path', 'sha256'} and type(row['path']) is str
              and Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts, 'Literal asset reference required')
        digest(row['sha256'])
    check(value['native_elf']['path'].endswith('/isolation-worker.elf')
          and 'permission-helper' not in value['native_elf']['path'], 'No P helper substitution')
    if value['schema']=='isolation-assets-v2':
        from lcb_ngpu_v3 import validate_inference_assets
        validate_inference_assets(value['inference'])


def endpoint_acceptance_check(value, snapshot):
    check(type(value) is dict and value.get('schema') == 'isolation-endpoint-site-acceptance-v2'
          and value.get('status') == 'accepted', 'I-v2 endpoint site facts not accepted')
    for key in ('recorder_sha256', 'evidence_sha256', 'review_sha256'):
        digest(value.get(key))
    path = value.get('recorder_path')
    check(type(path) is str and path.startswith('scripts/calibration/') and path.endswith('.py')
          and snapshot['files_sha256'].get(path) == value['recorder_sha256'], 'Accepted recorder source differs')
    check(all(value.get(k, False) is False for k in GATES), 'Site facts cannot grant execution')


def approval_check(owner_raw, review_raw, manifest_raw, *, owner_sha, review_sha, snapshot, assets_sha):
    from lcb_isolation_batch_v2 import validate_manifest, PURPOSE, GPU_PURPOSE, is_gpu
    check(sha(owner_raw) == digest(owner_sha) and sha(review_raw) == digest(review_sha), 'Independent I-v2 owner/R hashes differ')
    owner, review, manifest = strict(owner_raw), strict(review_raw), validate_manifest(strict(manifest_raw))
    check(encoded(owner) == owner_raw and encoded(review) == review_raw and encoded(manifest) == manifest_raw,
          'Canonical I-v2 approval bytes required')
    shared = {'schema', 'purpose', 'source_sha', 'registration_sha256', 'assets_sha256',
              'manifest_sha256', 'endpoint_site_acceptance_sha256', 'candidate_execution_authorized',
              'main_matrix_authorized', 'scancel_authorized'}
    gpu=is_gpu(manifest);purpose=GPU_PURPOSE if gpu else PURPOSE
    check(set(review) == shared | {'decision', *ASYNC_FIELDS} and review['schema'] ==
          ('isolation-reviewed-release-v3' if gpu else 'isolation-reviewed-release-v2')
          and review['purpose'] == purpose and review['decision'] == 'approved', 'Current R required')
    owner_keys = {'schema', 'purpose', 'owner_approved', 'owner_uid', 'review_sha256', 'source_head',
                  'registration_sha256', 'assets_sha256', 'manifest_sha256', 'roles_sha256', 'nonce',
                  'endpoint_site_acceptance_sha256', 'submit_by_ns', 'start_by_ns', 'max_run_s',
                  'absolute_end_by_ns', 'candidate_execution_authorized', 'main_matrix_authorized', 'scancel_authorized'}
    check(set(owner) == owner_keys and owner['schema'] ==
          ('isolation-owner-approval-v3' if gpu else 'isolation-owner-approval-v2')
          and owner['purpose'] == purpose and owner['owner_approved'] is True, 'Current owner approval required')
    for doc in (review, owner):
        check(doc['candidate_execution_authorized'] is manifest['candidate_execution_authorized']
              and (gpu or doc['candidate_execution_authorized'] is False)
              and all(doc[k] is False for k in ('main_matrix_authorized', 'scancel_authorized')),
              'No candidate/main/cancellation approval')
        check(doc['registration_sha256'] == snapshot['registration_sha256']
              and doc['assets_sha256'] == assets_sha and doc['manifest_sha256'] == sha(manifest_raw)
              and doc['endpoint_site_acceptance_sha256'] == snapshot['endpoint_site_acceptance_sha256'],
              'I-v2 approval source/assets/site/manifest mismatch')
        check(all(type(doc[k]) is int and doc[k] == manifest[k] for k in ASYNC_FIELDS),
              'I-v2 R/owner asynchronous bounds differ from manifest')
    check(review['source_sha'] == snapshot['source_sha'] and owner['source_head'] == snapshot['head']
          and manifest['source_head'] == snapshot['head'] and manifest['assets_sha256'] == assets_sha
          and manifest['endpoint_site_acceptance_sha256'] == snapshot['endpoint_site_acceptance_sha256'],
          'I-v2 approval registration/manifest binding differs')
    check(owner['owner_uid'] == manifest['owner_uid'] == os.getuid() > 0
          and type(owner['owner_uid']) is int
          and owner['review_sha256'] == review_sha and owner['nonce'] == manifest['nonce']
          and owner['roles_sha256'] == object_sha(manifest['roles'])
          and all(type(owner[k]) is int and owner[k] == manifest[k]
                  for k in ('submit_by_ns', 'start_by_ns', 'max_run_s', 'absolute_end_by_ns')),
          'I-v2 owner identity/roles/queue/run bounds differ')
    return owner, review, manifest


class Authority:
    """A process-bound, mutation-evident capability; never construct from JSON."""
    __slots__ = ('root', 'manifest', 'snapshot', 'assets', 'owner', 'owner_sha', 'review_sha',
                 'phase', 'role', 'pid', 'uid', 'run_end_ns', 'deadline_mono_ns', 'runtime_receipt', '__weakref__')

    def __init__(self, seal, *, root, manifest, snapshot, assets, owner, owner_sha, review_sha,
                 phase, role, deadline_wall_ns, now_ns, runtime_receipt=None):
        check(seal is _SEAL, 'Independent I-v2 issuer only')
        self.root = Path(root)
        self.manifest, self.snapshot, self.assets, self.owner = map(deepcopy, (manifest, snapshot, assets, owner))
        self.owner_sha, self.review_sha = owner_sha, review_sha
        self.phase, self.role = phase, role
        self.pid, self.uid = os.getpid(), os.getuid()
        self.run_end_ns = deadline_wall_ns
        self.deadline_mono_ns = time.monotonic_ns() + max(0, deadline_wall_ns - now_ns)
        self.runtime_receipt = deepcopy(runtime_receipt)
        _ISSUED[self] = self.fingerprint()

    def fingerprint(self):
        return object_sha({key: str(getattr(self, key)) if key == 'root' else getattr(self, key)
                           for key in self.__slots__ if key != '__weakref__'})


def require(authority, *, phase=None, role=None):
    try:
        valid = (type(authority) is Authority and authority in _ISSUED
                 and authority.fingerprint() == _ISSUED[authority]
                 and authority.pid == os.getpid() and authority.uid == os.getuid()
                 and authority.phase in ('queue', 'runtime')
                 and (phase is None or phase == authority.phase)
                 and (role is None or role == authority.role)
                 and time.time_ns() < authority.run_end_ns
                 and time.monotonic_ns() < authority.deadline_mono_ns)
    except (TypeError, ValueError, AttributeError, KeyError):
        valid = False
    if not valid:
        raise PermissionError('Live independent phase/role-bound I-v2 authority required')
    return authority


def require_candidate(authority):
    """Existing issuer gate; R/owner/manifest were jointly checked at issue."""
    require(authority,phase='runtime')
    check(authority.manifest.get('candidate_execution_authorized') is True
          and authority.owner.get('candidate_execution_authorized') is True,
          'Candidate execution requires manifest, R and owner approval')
    return authority


LEAN_MARKER = 'lean-mode.json'
NS_PER_S = 10**9


def lean_inference(assets, cells):
    """Inference assets of one lean GPU allocation.

    The contract's SIF, candidate runner and nvidia-smi are shared by every model; the weights are the ones the
    model table names for the cells' model. One allocation serves one model (its weights are read once and bound
    into the manifest digest). The Coder weights stay the contract's own entry, so earlier manifests keep their digest.
    Other models are named by their owner asset lock: the lock file's sha256 is pinned in the table and its
    file hashes become the weight inventory, which prepare re-verifies against the bytes on disk.
    """
    from lcb_isolation_batch_v2 import panel_cell
    panel = [panel_cell(cell) for cell in cells]
    models = {row['model_id'] for row in panel}
    check(len(models) == 1, 'All cells of one allocation must use one model')
    model = next(iter(models))
    table = strict(read(ROOT / MODELS))
    check(table.get('schema') == 'ngpu-inference-models-v1' and type(table.get('models')) is dict,
          'Model weights table schema')
    entry = table['models'].get(model)
    check(entry is not None, 'No registered weights for model ' + model)
    inference = deepcopy(assets['inference'])
    if entry == 'contract':
        return inference
    check(type(entry) is dict and set(entry) == {'dir', 'lock_path', 'lock_sha256'}
          and Path(entry['dir']).is_absolute() and Path(entry['lock_path']).is_absolute(), 'Model weights table entry')
    digest(entry['lock_sha256'])
    raw = read(Path(entry['lock_path']))
    check(sha(raw) == entry['lock_sha256'], 'Weight lock differs from the table: ' + model)
    lock = strict(raw)
    check(lock.get('schema') == 'inference-assets-lock-v1' and lock.get('model_id') == model
          and all(lock.get('model_revision') == row['revision'] for row in panel)
          and type(lock.get('model_files_sha256')) is dict and lock['model_files_sha256'],
          'Weight lock is for another model or revision')
    inference['model_weights'] = {'dir': entry['dir'], 'manifest_path': entry['lock_path'],
                                  'manifest_sha256': entry['lock_sha256'], 'files': dict(lock['model_files_sha256'])}
    return inference


def _lean_request(root):
    """Lean attempt: the manifest is the approval.

    Kept (they decide WHICH experiment is measured): the manifest's own validation, the asset contract it names,
    and the inference-assets digest (model, image, runner, weights). Dropped: registry/closure pinning, endpoint
    acceptance file, reviewed-release and owner-approval JSON, receipt windows. The scope switches are the
    manifest's: candidate execution only if the manifest says so, main matrix / retry / cancel always off.
    """
    from lcb_isolation_batch_v2 import attempt_path, validate_manifest, is_gpu
    root = path_check(attempt_path(str(root)))
    manifest_raw = read(root / 'manifest.json')
    manifest = validate_manifest(strict(manifest_raw))
    check(is_gpu(manifest), 'Lean attempts are for GPU manifests')
    check(str(root) == manifest['attempt_root'], 'Attempt root binding differs')
    check(manifest['owner_uid'] == os.getuid(), 'Lean attempt belongs to another user')
    marker = strict(read(root / LEAN_MARKER))
    check(marker.get('manifest_sha256') == object_sha(manifest), 'The manifest changed after prepare')
    assets_raw = read(ROOT / ASSETS); assets = strict(assets_raw)
    check(sha(assets_raw) == manifest['assets_sha256'], 'Asset contract differs from the manifest')
    if is_gpu(manifest):
        check(assets.get('schema') == 'isolation-assets-v2', 'GPU assets v2 required')
        assets['inference'] = lean_inference(assets, manifest['cells'])
        check(object_sha(assets['inference']) == manifest['inference_assets_sha256'], 'Inference assets digest differs')
    digest_ = sha(manifest_raw)
    snapshot = {'head': manifest['source_head'], 'source_sha': manifest['source_head'],
                'registration_sha256': digest_, 'files_sha256': {}, 'lean': True,
                'endpoint_site_acceptance_sha256': manifest['endpoint_site_acceptance_sha256']}
    owner = {'owner_uid': manifest['owner_uid'], 'lean': True,
             'candidate_execution_authorized': manifest['candidate_execution_authorized']}
    return {'root': root, 'snapshot': snapshot, 'assets': assets, 'owner': owner, 'review': {'lean': True},
            'manifest': manifest, 'owner_sha': digest_, 'review_sha': digest_}


def is_lean(root):
    return (Path(root) / LEAN_MARKER).exists()


def inspect_request(root, owner_sha, review_sha):
    """Validate immutable inputs for read-only bootstrap; return no capability."""
    from lcb_isolation_batch_v2 import attempt_path
    if is_lean(root):
        return _lean_request(root)
    owner_sha, review_sha = digest(owner_sha), digest(review_sha)
    root = path_check(attempt_path(str(root)), private=True)
    check(ROOT != root and ROOT not in root.parents and root not in ROOT.parents,
          'Attempt root must be outside source')
    snapshot, registry = source_snapshot()
    check(registry['status'] == 'registered' and registry['endpoint_site_acceptance_sha256'] is not None,
          'Actual I-v2 issue requires registered source and accepted site facts')
    assets_raw = read(ROOT / ASSETS); assets = strict(assets_raw)
    check(sha(assets_raw) == registry['assets_sha256'], 'I assets digest differs')
    validate_assets(assets, snapshot)
    if manifest_is_gpu := (strict(read(root/'manifest.json',private=True)).get('schema')=='isolation-batch-manifest-v3'):
        check(assets.get('schema')=='isolation-assets-v2','GPU assets v2 required')
        check(object_sha(assets['inference'])==strict(read(root/'manifest.json',private=True))['inference_assets_sha256'],
              'Inference assets digest differs')
    site_raw = read(ROOT / ENDPOINT_ACCEPTANCE)
    check(sha(site_raw) == registry['endpoint_site_acceptance_sha256'], 'Endpoint site acceptance digest differs')
    endpoint_acceptance_check(strict(site_raw), snapshot)
    owner, review, manifest = approval_check(
        read(root / 'owner-approval.json', private=True), read(root / 'reviewed-release.json', private=True),
        read(root / 'manifest.json', private=True), owner_sha=owner_sha, review_sha=review_sha,
        snapshot=snapshot, assets_sha=sha(assets_raw))
    check(str(root) == manifest['attempt_root'], 'Attempt root binding differs')
    return {'root': root, 'snapshot': snapshot, 'assets': assets, 'owner': owner,
            'review': review, 'manifest': manifest, 'owner_sha': owner_sha, 'review_sha': review_sha}


def issue(root, owner_sha256=None, review_sha256=None, *, phase='queue', role=None,
          runtime_receipt=None, now_ns=None, owner_sha=None, review_sha=None):
    """Issue queue capability or one runtime role; never submit/wait/execute."""
    from lcb_isolation_batch_v2 import (validate_runtime_receipt, run_end_ns,
                                        bootstrap_deadline_ns, role_ids)
    check(owner_sha256 is None or owner_sha is None or owner_sha256 == owner_sha, 'Conflicting owner hashes')
    check(review_sha256 is None or review_sha is None or review_sha256 == review_sha, 'Conflicting R hashes')
    request = inspect_request(root, owner_sha256 if owner_sha256 is not None else owner_sha,
                              review_sha256 if review_sha256 is not None else review_sha)
    root, snapshot, assets, owner, manifest, owner_sha, review_sha = (
        request[k] for k in ('root', 'snapshot', 'assets', 'owner', 'manifest', 'owner_sha', 'review_sha'))
    now = time.time_ns() if now_ns is None else integer(now_ns, 1)
    if snapshot.get('lean'):
        if phase == 'queue':
            check(role is None and runtime_receipt is None, 'Queue capability takes no role')
            end = now + 6 * 3600 * NS_PER_S
        else:
            check(phase == 'runtime' and role in role_ids(manifest), 'One explicit runtime role required')
            runtime_receipt = validate_runtime_receipt(manifest, runtime_receipt)
            end = run_end_ns(manifest, runtime_receipt['actual_start_ns'])
            check(now < end, 'Runtime capability expired')
        return Authority(_SEAL, root=root, manifest=manifest, snapshot=snapshot, assets=assets, owner=owner,
                         owner_sha=owner_sha, review_sha=review_sha, phase=phase, role=role,
                         deadline_wall_ns=end, now_ns=now, runtime_receipt=runtime_receipt)
    if phase == 'queue':
        check(role is None and runtime_receipt is None and now < manifest['submit_by_ns'], 'Queue capability expired or role supplied')
        end = manifest['submit_by_ns']
    else:
        check(phase == 'runtime' and role in role_ids(manifest), 'One explicit runtime role required')
        runtime_receipt = validate_runtime_receipt(manifest, runtime_receipt)
        try:
            submission_raw = read(root / 'submission.json', private=True)
        except FileNotFoundError as exc:
            raise ValueError('Required I-v2 owner submission receipt is missing') from exc
        submission = strict(submission_raw)
        check(type(submission) is dict and set(submission) == {
                  'schema', 'status', 'job_id', 'manifest_sha256', 'nonce',
                  'owner_sha256', 'review_sha256', 'submitted_ns'}
              and encoded(submission) == submission_raw
              and submission.get('schema') == 'isolation-submission-v2' and submission.get('status') == 'submitted_once'
              and submission.get('job_id') == runtime_receipt['job_id']
              and submission.get('manifest_sha256') == object_sha(manifest)
              and submission.get('nonce') == manifest['nonce'] and submission.get('owner_sha256') == owner_sha
              and submission.get('review_sha256') == review_sha, 'Owner submission receipt differs')
        # Historical field name: this is the sbatch acknowledgement time,
        # not the RPC's start. A fast allocation may start before this ack.
        integer(submission.get('submitted_ns'), 1, min(manifest['submit_by_ns'], now))
        start = runtime_receipt['actual_start_ns']
        check(now >= start, 'Runtime before allocation start')
        deadline = bootstrap_deadline_ns(manifest, start)
        # The 120s limit concerns receipt arrival, not all later role starts.
        # Validate any published proof, including before that limit. Its
        # submission digest binds the checked nonce without adding wire fields.
        try:
            proof_raw = read(root / 'bootstrap-receipt.json', private=True)
        except FileNotFoundError as exc:
            if now >= deadline:
                raise ValueError('Fixed bootstrap receipt window exhausted without original proof') from exc
            proof_raw = None
        if proof_raw is not None:
            proof = strict(proof_raw)
            check(type(proof) is dict and set(proof) == {'schema', 'job_id', 'actual_start_ns',
                  'manifest_sha256', 'owner_sha256', 'review_sha256', 'submission_sha256', 'observed_wall_ns'}
                  and encoded(proof) == proof_raw
                  and proof['schema'] == 'isolation-bootstrap-receipt-v2'
                  and proof['job_id'] == runtime_receipt['job_id']
                  and type(proof['actual_start_ns']) is int and proof['actual_start_ns'] == start
                  and proof['manifest_sha256'] == object_sha(manifest)
                  and proof['owner_sha256'] == owner_sha and proof['review_sha256'] == review_sha
                  and proof['submission_sha256'] == object_sha(submission)
                  and type(proof['observed_wall_ns']) is int
                  and start <= proof['observed_wall_ns'] < deadline
                  and submission['submitted_ns'] <= proof['observed_wall_ns'] <= now,
                  'Bootstrap receipt content/binding/time differs')
        end = run_end_ns(manifest, start)
        check(now < end, 'Runtime capability expired')
    return Authority(_SEAL, root=root, manifest=manifest, snapshot=snapshot, assets=assets, owner=owner,
                     owner_sha=owner_sha, review_sha=review_sha, phase=phase, role=role,
                     deadline_wall_ns=end, now_ns=now, runtime_receipt=runtime_receipt)


def consume_submission(authority):
    require(authority, phase='queue')
    value = {'schema': 'isolation-submission-consumed-v2', 'manifest_sha256': object_sha(authority.manifest),
             'owner_sha256': authority.owner_sha, 'review_sha256': authority.review_sha,
             'nonce': authority.manifest['nonce'], 'consumed_ns': time.time_ns(), 'failure_also_consumes': True}
    write_new(authority.root / 'submission.consumed.json', value)
    return value


def consume_role(authority, role_id=None, *, cell_index=None):
    from lcb_isolation_batch_v2 import role_for, cell_root
    require(authority, phase='runtime')
    rid = authority.role if role_id is None else role_id
    require(authority, phase='runtime', role=rid)
    check(rid == authority.role, 'Runtime role cannot delegate another role')
    row = role_for(authority.manifest, rid)
    write_new(cell_root(authority.root,authority.manifest,cell_index) / ('role-' + rid + '.consumed.json'), {
        'schema': 'isolation-role-consumed-v2', 'role_id': rid, 'nonce': row['nonce'],
        'job_id': authority.runtime_receipt['job_id'], 'manifest_sha256': object_sha(authority.manifest),
        'owner_sha256': authority.owner_sha, 'review_sha256': authority.review_sha,
        'consumed_ns': time.time_ns(), 'failure_also_consumes': True, 'scancel_authorized': False})
    return row


def consume_execution(authority, role_id):
    """Only D dispatches each fixed native E once; E never runs Python issuer."""
    from lcb_isolation_batch_v2 import role_for
    require(authority, phase='runtime', role='D')
    check(role_id in ('E1', 'E2'), 'D native dispatch is limited to E1/E2')
    row = role_for(authority.manifest, role_id)
    write_new(authority.root / ('role-' + role_id + '.consumed.json'), {
        'schema':'isolation-role-consumed-v2', 'role_id':role_id, 'nonce':row['nonce'],
        'job_id':authority.runtime_receipt['job_id'], 'manifest_sha256':object_sha(authority.manifest),
        'owner_sha256':authority.owner_sha, 'review_sha256':authority.review_sha,
        'consumed_ns':time.time_ns(), 'dispatched_by':'D', 'failure_also_consumes':True,
        'scancel_authorized':False})
    return row
