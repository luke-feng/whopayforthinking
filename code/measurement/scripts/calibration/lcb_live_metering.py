"""Registered read-only CPU capture; no subprocesses, signals or job submission."""
from dataclasses import asdict
import hashlib
import json
import os
import stat
import time

import lcb_supervision_release_v3 as release
import lcb_supervision_site_v3 as site
import lcb_worker_metering_v1 as meter
import lcb_worker_metering_v2 as endpoint

MAX_READ_NS = 5_000_000
POST_RETIREMENT_MAX_NS = 20_000_000
MAX_SNAPSHOTS = 96
PHASES = ('setup', 'service', 'standby', 'cleanup')


class EndpointUnavailable(Exception):
    """Observed retirement race/incomplete evidence, never an authority error."""


def _post_check(ok, message):
    if not ok:
        raise EndpointUnavailable(message)


def _post_stat(info, path, kind):
    _post_check(stat.S_ISDIR(info.st_mode) if kind == 'directory' else stat.S_ISREG(info.st_mode),
                'retirement resource type changed')
    return {'path': path, 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'kind': kind}


def _empty_user_tree(tree, binding):
    """Use existing retained baseline fds; never reopen a retired directory."""
    names = ['user', 'user/task_0']
    if 'user/task_special' in tree.fds:
        names.append('user/task_special')
    result = {'directories': {}, 'children': {}, 'procs': {}}
    for name in names:
        fd = tree.fds[name]
        path = tree.identities[name]['path']
        parent, _, leaf = name.rpartition('/')
        held = _post_stat(os.fstat(fd), path, 'directory')
        named = _post_stat(os.stat(leaf, dir_fd=tree.fds[parent], follow_symlinks=False), path, 'directory')
        _post_check(held == named == binding['directory_binding'][name], 'retired directory identity changed')
        children = []
        for leaf in os.listdir(fd):
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            _post_check(not stat.S_ISLNK(info.st_mode), 'link in retired user subtree')
            if stat.S_ISDIR(info.st_mode):
                children.append(leaf)
        children.sort()
        wanted = ['task_0'] + (['task_special'] if len(names) == 3 else []) if name == 'user' else []
        _post_check(children == wanted, 'unexpected retired user subtree')
        pfd = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        try:
            ppath = path+'/cgroup.procs'
            before = _post_stat(os.fstat(pfd), ppath, 'regular')
            raw = b''
            while True:
                part = os.read(pfd, min(8192, site.MAX_BYTES+1-len(raw)))
                if not part:
                    break
                raw += part
                _post_check(len(raw) <= site.MAX_BYTES, 'oversized retirement membership')
            after = _post_stat(os.fstat(pfd), ppath, 'regular')
            named = _post_stat(os.stat('cgroup.procs', dir_fd=fd, follow_symlinks=False), ppath, 'regular')
            _post_check(before == after == named == binding['membership_binding'][name], 'retired membership identity changed')
            text = raw.decode('ascii')
            _post_check(not text.split(), 'retired user subtree is not empty')
        finally:
            os.close(pfd)
        result['directories'][name] = held
        result['children'][name] = children
        result['procs'][name] = {**before, 'raw': text, 'pids': []}
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def enabled(snapshot):
    return snapshot.get('schema') == 'supervision-source-snapshot-v5'


class Capture:
    def __init__(self, authority, role, context, anchor, pair_raw, journal, *, reader_factory=meter.ReadOnlyCpuDomain, deadline_ns=None):
        release.require_live(authority)
        site.check(enabled(authority.snapshot), 'Metering requires the new registered source set')
        site.check(role in ('worker', 'observer'), 'Fixed metering role required')
        self.authority, self.role, self.context = authority, role, context
        self.anchor, self.journal, self.reader_factory = anchor, journal, reader_factory
        self.pair = release.strict(pair_raw)
        self.pair_sha = hashlib.sha256(pair_raw).hexdigest()
        self.wid, self.oid = anchor['worker_job_id'], anchor['observer_job_id']
        self.primary = self.wid if role == 'worker' else self.oid
        self.allowed = [self.wid] if role == 'worker' else [self.oid, self.wid]
        site.pair_record_check(self.pair, self.wid, self.oid, context['node'], context['boot_id'],
            context['uid'], authority.approval['attempt_nonce'], authority.approval_sha)
        site.check(anchor['nonce'] == authority.approval['attempt_nonce'] and
                   anchor['approval_sha256'] == authority.approval_sha and
                   context['uid'] == authority.approval['owner_uid'] and
                   context['cgroup'].startswith('/system.slice/slurmstepd.scope/job_'+self.primary+'/'),
                   'Metering caller/attempt differs')
        self.readers, self.unavailable, self.counts = {}, set(), {}
        self.last_samples = {}
        self.execution_lease = self.execution_baseline = None
        self.post_attempted = False
        self.phase, self.sealed_jobs, self.closed = 'setup', set(), False
        self.deadline_ns=deadline_ns
        self.journal.append('metering_binding', {
            'schema': 'live-metering-binding-v1', 'role': role, 'node': context['node'],
            'boot_id': context['boot_id'], 'nonce': anchor['nonce'],
            'approval_sha256': authority.approval_sha,
            'source_registration_sha256': authority.snapshot['registration_sha256'],
            'primary_job_id': self.primary, 'allowed_jobs': self.allowed,
            'pair_admission_sha256': self.pair_sha})
        try:
            for jid in self.allowed:
                self.add(jid, 'batch')
                self.add(jid, 'extern')
        except BaseException:
            self.close()
            raise

    def add(self, job_id, step_id, *, baseline=None, lease=None):
        release.require_live(self.authority)
        site.check(not self.closed and job_id in self.allowed and job_id not in self.sealed_jobs,
                   'Metering outside owned live subjects')
        site.check(step_id in ('batch', 'extern') or baseline is not None and lease is not None
                   and job_id == self.wid and step_id == lease['step_id'], 'Unbound metering step')
        subject = 'worker' if job_id == self.wid else 'observer'
        hard = self.pair[subject]['hard_resources']
        envelope = {'job_cgroup': hard['scope_identity']['path'],
                    'cpu_ids': hard['logical_cpu_ids'], 'source_sha256': self.pair_sha}
        for kind, leaf in (('workload', 'user'), ('control_plane', 'slurm')):
            self._guard()
            key = (job_id, step_id, kind)
            site.check(key not in self.readers and key not in self.unavailable, 'No reader reopen or duplicate epoch')
            path = f'{endpoint.CGROOT}/job_{job_id}/step_{step_id}/{leaf}'
            reader = None
            try:
                reader = self.reader_factory(path)
                identity = asdict(reader.identity)
                site.check(identity['path'] == path and identity['context']['node'] == self.context['node']
                           and identity['context']['boot_id'] == self.context['boot_id'], 'Reader host/epoch differs')
                if baseline is not None:
                    d = baseline['directory_binding'][leaf]
                    site.check((identity['device'], identity['inode']) == (d['device'], d['inode']),
                               'Reader differs from typed baseline directory')
                evidence = {'schema': 'live-metering-origin-v1', 'pair_admission': self.pair,
                    'pair_admission_sha256': self.pair_sha, 'typed_baseline': baseline, 'lease': lease,
                    'job_id': job_id, 'step_id': step_id, 'kind': kind,
                    'resource_envelope': envelope, 'directory_identity': identity}
                self.journal.append('metering_origin', {'job_id': job_id, 'step_id': step_id, 'kind': kind,
                    'path': path, 'resource_envelope': envelope, 'origin_evidence_sha256': digest(evidence),
                    'origin_evidence': evidence})
                self.readers[key] = reader
                self.counts[key] = 0
                reader = None
            except (OSError, ValueError) as exc:
                self.unavailable.add(key)
                self.journal.append('metering_unavailable', {'job_id': job_id, 'step_id': step_id, 'kind': kind,
                    'path': path, 'error': type(exc).__name__+': '+str(exc)})
            finally:
                if reader is not None:
                    reader.close()

    def execution(self, lease, baseline):
        site.check(lease['job_id'] == self.wid and lease['node'] == self.context['node'], 'Foreign execution meter')
        site.baseline_certificate_check(baseline, lease, baseline['baseline']['controller'],
            self.authority.snapshot['runtime_bindings']['runtime']['native_sha256'])
        self.execution_lease, self.execution_baseline = lease, baseline
        self.add(self.wid, lease['step_id'], baseline=baseline, lease=lease)

    def sample(self, event, *, case_id=None, only_jobs=None):
        release.require_live(self.authority)
        site.check(not self.closed and type(event) is str and event, 'Closed/unnamed capture')
        subjects = self.allowed if only_jobs is None else only_jobs
        site.check(set(subjects) <= set(self.allowed), 'Foreign capture subject')
        for key, reader in self.readers.items():
            jid, sid, kind = key
            if jid not in subjects or jid in self.sealed_jobs:
                continue
            deadline=self._guard()
            site.check(self.counts[key] < MAX_SNAPSHOTS, 'Bounded sample roster exceeded')
            snapshot, bracket = endpoint.captured_snapshot(reader)
            elapsed = snapshot.finished_ns - snapshot.started_ns
            row = {'job_id': jid, 'step_id': sid, 'kind': kind,
                'phase': self.phase, 'event': event, 'case_id': case_id, 'snapshot': asdict(snapshot),
                'wall_bracket': bracket, 'elapsed_ns': elapsed, 'applied_deadline_ns':deadline,
                'within_read_budget': elapsed <= MAX_READ_NS and snapshot.finished_ns<=deadline}
            self.journal.append('metering_sample', row)
            self.last_samples[key] = row
            self.counts[key] += 1

    def post_retirement(self, session, peer, baseline):
        """One read after the existing C pidfd exits. Observation loss is M-only."""
        deadline = self._guard()  # Permission/deadline errors must propagate.
        site.check(self.role == 'worker' and self.phase == 'cleanup' and not self.closed
                   and self.wid not in self.sealed_jobs and not self.post_attempted,
                   'Post-retirement capture outside the single open normal retirement')
        site.check(self.execution_lease == session.lease and self.execution_baseline is not None
                   and isinstance(peer, site.ProcessHandle)
                   and site.process_identity(peer.identity) == baseline.controller
                   == self.execution_baseline['baseline']['controller'], 'Foreign retirement controller/baseline')
        self.post_attempted = True
        key = self.wid, session.lease['step_id'], 'workload'
        row = {'schema': 'm-post-retirement-v1', 'job_id': key[0], 'step_id': key[1], 'kind': key[2],
               'phase': 'cleanup', 'event': 'post_retirement', 'status': 'unidentified', 'error': None,
               'controller_identity': site.process_identity(peer.identity), 'applied_deadline_ns': deadline,
               'begin_ns': time.monotonic_ns(), 'begin_wall_ns': time.time_ns()}
        try:
            state = peer.state()  # Kernel/identity errors here are not missing observations.
            row['controller_state'] = state
            _post_check(state['exited'] is True, 'controller pidfd has not exited')
            _post_check(key in self.readers and key in self.last_samples, 'missing retained workload reader')
            reader = self.readers[key]
            last = self.last_samples[key]
            site.check(last['event'] == 'last_pre_retirement', 'Wrong retirement phase origin')
            site.check(self.counts[key] < MAX_SNAPSHOTS, 'Bounded sample roster exceeded')
            row['last_pre_retirement_snapshot_id'] = last['snapshot']['snapshot_id']
            row['origin_identity'] = asdict(reader.identity)
            self._guard()
            row['before'] = _empty_user_tree(baseline.tree, self.execution_baseline)
            snapshot, bracket = endpoint.captured_snapshot(reader)
            row['snapshot'], row['wall_bracket'] = asdict(snapshot), bracket
            row['after'] = _empty_user_tree(baseline.tree, self.execution_baseline)
            row['controller_state_after'] = peer.state()
            self._guard()
            _post_check(row['controller_state_after']['exited'] is True, 'retirement pidfd state changed')
            _post_check(snapshot.identity == reader.identity and row['before'] == row['after'], 'retirement identity/tree changed')
            if snapshot.error and snapshot.error.startswith('PermissionError:'):
                raise PermissionError(snapshot.error)
            _post_check(snapshot.usage_usec is not None and snapshot.populated_before is False
                        and snapshot.populated_after is False, 'retirement counter/population unavailable')
            _post_check(last['snapshot']['usage_usec'] is not None
                        and snapshot.usage_usec >= last['snapshot']['usage_usec'], 'retirement counter decreased')
            self.counts[key] += 1
            row['status'] = 'captured'
        except PermissionError:
            raise
        except (EndpointUnavailable, OSError, UnicodeError) as exc:
            row['error'] = type(exc).__name__+': '+str(exc)
        finally:
            row['end_wall_ns'] = time.time_ns()
            row['end_ns'] = time.monotonic_ns()
        if row['end_ns'] > deadline or row['end_ns']-row['begin_ns'] > POST_RETIREMENT_MAX_NS:
            row['status'], row['error'] = 'unidentified', 'retirement read budget exceeded'
        self.journal.append('metering_post_retirement', row)
        return row

    def bound(self, deadline_ns):
        release.require_live(self.authority)
        site.check(type(deadline_ns) is int and deadline_ns>0, 'Absolute metering deadline required')
        self.deadline_ns=deadline_ns

    def _guard(self):
        release.require_live(self.authority)
        budget=release._BUDGET.get()
        if budget is not None:
            budget.timeout(1)
        else:
            site.check(self.deadline_ns is not None, 'Metering needs a bounded phase')
        if self.deadline_ns is not None:
            site.check(time.monotonic_ns()<self.deadline_ns, 'Metering phase deadline expired')
        return min(x for x in (self.deadline_ns,budget.end if budget is not None else None) if x is not None)

    def boundary(self, event, next_phase, *, case_id=None):
        allowed={'setup':('service','cleanup'),'service':('standby','cleanup'),
                 'standby':('service','cleanup'),'cleanup':('cleanup',)}
        site.check(next_phase in allowed[self.phase],
                   'Invalid/reversed phase boundary')
        self.sample(event, case_id=case_id)
        self.phase = next_phase

    def seal_job(self, job_id, reason):
        site.check(job_id in self.allowed and job_id not in self.sealed_jobs, 'Duplicate/foreign seal')
        self.sealed_jobs.add(job_id)
        self.journal.append('metering_subject_sealed', {'job_id': job_id, 'reason': reason,
            'phase': self.phase, 'observed_ns': time.monotonic_ns()})

    def close(self):
        if self.closed:
            return
        self.closed = True
        error=None
        for reader in self.readers.values():
            try:reader.close()
            except BaseException as exc:error=error or exc
        try:
            self.journal.append('metering_sealed', {'role': self.role, 'reason': 'role_finally',
                'sealed_jobs': sorted(self.sealed_jobs), 'phase': self.phase})
        finally:
            if error is not None:raise error
