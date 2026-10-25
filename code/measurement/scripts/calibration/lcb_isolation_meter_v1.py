"""I-owned real read-only CPU capture: per-case limits, E retirement, job join.

Uses the shared read-only M primitives, never the S release authority. No cgroup
writes, polling thread, sacct fallback for E, or full-physical-CPU assertion.
"""
from copy import deepcopy
from dataclasses import asdict
import time

import lcb_isolation_release_v1 as release
import lcb_supervision_site_v3 as site
import lcb_worker_metering_v1 as m1
import lcb_worker_metering_v2 as m2
import lcb_live_metering as shared_live

CASE_MAX = 96
FIXED_RESERVE = 32
JOB_MAX = FIXED_RESERVE + 3*CASE_MAX + 1


class Capture:
    def __init__(self, authority, job_id, journal, *, cross_evidence=False, clock_qualified=False, live_join=None):
        release.require(authority); release.number(job_id)
        release.check(shared_live.MAX_READ_NS == 5_000_000
                      and shared_live.POST_RETIREMENT_MAX_NS == m2.POST_RETIREMENT_MAX_NS == 20_000_000,
                      'I requires registered shared 5ms ordinary / 20ms E policy')
        self.authority, self.job_id, self.journal = authority, job_id, journal
        self.cross_evidence = cross_evidence; self.readers = {}; self.counts = {}
        self.clock_qualified = clock_qualified is True
        self.case_counts = {}; self.rows = []; self.marks = {}; self.retired = False
        self.tree = self.step = None; self.baseline = None; self.e_key = None
        self.context = site.LinuxHost().context()
        self.live_join = deepcopy(live_join)
        if live_join is not None:
            release.check(live_join['job_id'] == job_id and live_join['node'] == self.context['node']
                          and live_join['boot_id'] == self.context['boot_id'], 'M live job origin differs')
        self.add(job_id, 'batch'); self.add(job_id, 'extern')

    def add(self, job_id, step_id):
        release.require(self.authority); release.number(job_id)
        release.check(step_id in ('batch', 'extern') or release.number(step_id, zero=True), 'Known step')
        for kind, leaf in (('workload', 'user'), ('control_plane', 'slurm')):
            key = (job_id, step_id, kind)
            release.check(key not in self.readers, 'No duplicate metering epoch')
            path = site.CGBASE+'/job_'+job_id+'/step_'+step_id+'/'+leaf
            try:
                reader = m1.ReadOnlyCpuDomain(path)
                release.check(reader.identity.context.node == self.context['node']
                              and reader.identity.context.boot_id == self.context['boot_id'], 'Meter node/boot mismatch')
                self.readers[key] = reader; self.counts[key] = 0
                self.journal.append('isolation_meter_origin', {'job_id': job_id, 'step_id': step_id,
                    'kind': kind, 'identity': asdict(reader.identity), 'cross_evidence_only': self.cross_evidence or job_id != self.job_id,
                    'source_registration_sha256': self.authority.snapshot['registration_sha256'],
                    'owner_sha256': self.authority.owner_sha,
                    'manifest_sha256': release.object_sha(self.authority.manifest),
                    'reader_job_id': self.job_id, 'live_join': self.live_join,
                    'birth_provenance': 'bound_live_allocation_requires_offline_M_review'})
            except PermissionError:
                raise
            except (OSError, ValueError) as exc:
                self.journal.append('isolation_meter_unidentified', {'path': path, 'error': str(exc)})

    def execution(self, step_id):
        release.check(self.e_key is None, 'One E only')
        release.number(step_id, zero=True)
        self.step = site.GroupHandle(site.CGBASE+'/job_'+self.job_id+'/step_'+step_id)
        self.tree = site.StepTree(self.step); self.baseline = self.tree.snapshot()
        self.add(self.job_id, step_id); self.e_key = (self.job_id, step_id, 'workload')
        self.journal.append('isolation_E_baseline', self.baseline)
        self.sample('execution_setup')

    def sample(self, event, *, case_id=None):
        release.require(self.authority); release.check(not self.retired, 'Sealed I capture')
        current = {}
        for key, reader in self.readers.items():
            release.check(self.counts[key] < JOB_MAX, 'Fixed I job sample roster bound')
            if case_id is not None:
                ckey = case_id, key
                count = self.case_counts.get(ckey, 0)
                release.check(count < CASE_MAX, 'Each case each domain <=96')
                self.case_counts[ckey] = count+1
            else:
                fixed = self.case_counts.get(('fixed', key), 0)
                release.check(fixed < FIXED_RESERVE, 'Fixed lifecycle reserve exhausted')
                self.case_counts['fixed', key] = fixed+1
            snap, bracket = m2.captured_snapshot(reader)
            if snap.error and snap.error.startswith('PermissionError:'):
                raise PermissionError(snap.error)
            row = {'job_id': key[0], 'step_id': key[1], 'kind': key[2], 'event': event,
                   'case_id': case_id, 'snapshot': asdict(snap), 'wall_bracket': bracket,
                   'within_read_budget': snap.finished_ns-snap.started_ns <= shared_live.MAX_READ_NS,
                   'clock_qualified': self.clock_qualified,
                   'cross_evidence_only': self.cross_evidence or key[0] != self.job_id}
            self.journal.append('isolation_meter_sample', row); self.rows.append(row)
            self.counts[key] += 1; current[key] = row
        self.marks[case_id, event] = current
        return current

    def _empty(self):
        snap = self.tree.snapshot()
        user_names = {'user', 'user/task_0'} | ({'user/task_special'} if 'user/task_special' in snap['procs'] else set())
        release.check(snap['directories'] == self.baseline['directories'], 'Retirement directory identity changed')
        for name in user_names:
            release.check(not snap['procs'][name]['pids'], 'Workload leaf not empty')
            release.check(snap['procs'][name]['device'] == self.baseline['procs'][name]['device']
                          and snap['procs'][name]['inode'] == self.baseline['procs'][name]['inode'], 'Membership file identity changed')
            expected = sorted(n.split('/')[-1] for n in user_names if n.startswith(name+'/'))
            release.check(snap['children'][name] == expected, 'Unexpected workload subtree')
        return {k: {name: snap[k][name] for name in user_names}
                for k in ('directories', 'children', 'procs')}

    def post_retirement(self, peer, deadline_ns):
        release.require(self.authority)
        release.check(not self.retired and self.e_key is not None, 'Once-only bound E endpoint')
        self.retired = True
        row = {'status': 'unidentified_post_retirement', 'begin_ns': time.monotonic_ns(),
               'begin_wall_ns': time.time_ns(), 'applied_deadline_ns': deadline_ns,
               'job_id': self.job_id, 'step_id': self.e_key[1], 'endpoint_budget_ns': shared_live.POST_RETIREMENT_MAX_NS,
               'C_identity': dict(peer.identity), 'snapshot': None, 'full_physical_cpu_us': None,
               'controller_state': None, 'controller_state_after': None,
               'last_pre_retirement_snapshot_id': None, 'origin_identity': None}
        try:
            state = peer.state()
            row['controller_state'] = state
            release.check(state['exited'] is True and state['registered_process_reaped'] is True, 'C exit/reap unavailable')
            before = self._empty()
            reader = self.readers[self.e_key]; snap, bracket = m2.captured_snapshot(reader)
            if snap.error and snap.error.startswith('PermissionError:'):
                raise PermissionError(snap.error)
            after = self._empty()
            state_after = peer.state(); row['controller_state_after'] = state_after
            release.check(before == after and state_after['registered_process_reaped'] is True
                          and snap.usage_usec is not None and snap.populated_before is False
                          and snap.populated_after is False, 'Retirement empty/identity/count unavailable')
            last = self.marks[None, 'last_pre_retirement'][self.e_key]['snapshot']
            row['last_pre_retirement_snapshot_id'] = last['snapshot_id']
            row['origin_identity'] = last['identity']
            release.check(last['usage_usec'] is not None and snap.usage_usec >= last['usage_usec'], 'E endpoint rollback')
            row.update(status='captured', snapshot=asdict(snap), wall_bracket=bracket,
                       before=before, after=after, retirement_tail_cpu_us=snap.usage_usec-last['usage_usec'])
        except PermissionError:
            raise
        except (OSError, ValueError, KeyError, UnicodeError) as exc:
            row['reason'] = type(exc).__name__+': '+str(exc)
        row['end_ns'] = time.monotonic_ns()
        row['end_wall_ns'] = time.time_ns()
        if row['end_ns'] > deadline_ns or row['end_ns']-row['begin_ns'] > shared_live.POST_RETIREMENT_MAX_NS:
            row.update(status='unidentified_post_retirement', reason='20ms endpoint/deadline overrun')
        if not self.clock_qualified:
            row.update(status='unidentified_clock_bound', reason='W/O clock qualification absent or failed')
        self.journal.append('isolation_post_retirement', row)
        return row

    def close(self):
        for reader in self.readers.values():
            reader.close()
        self.readers = {}
        if self.tree is not None:
            self.tree.close(); self.tree = None
        if self.step is not None:
            self.step.close(); self.step = None

    def seal_subject(self, job_id):
        """End O's cross-read epoch before the worker's domains are removed."""
        release.require(self.authority)
        release.check(job_id != self.job_id, 'Cannot seal own cost before own cleanup')
        keys = [key for key in self.readers if key[0] == job_id]
        release.check(keys, 'No open cross-read subject')
        for key in keys:
            self.readers.pop(key).close()
        self.journal.append('isolation_cross_subject_sealed', {'job_id':job_id,
            'reader_job_id':self.job_id,'last_samples_retained':True})


def case_increment(before, after, *, cpu_count=1):
    release.integer(cpu_count, 1, 1)
    release.check(before['identity'] == after['identity'], 'Case CPU domain identity changed')
    for snap in (before, after):
        if snap['usage_usec'] is None:
            return {'status': 'unidentified', 'case_cpu_us': None}
    delta = after['usage_usec']-before['usage_usec']
    release.check(delta >= 0, 'Case CPU counter rollback')
    # Enclose the counter-read windows; never borrow the whole job's duration.
    upper = (after['finished_ns']-before['started_ns']+999)//1000
    release.check(delta <= upper, 'Case CPU exceeds its own single-CPU window')
    return {'status': 'observed_window_not_lifetime', 'case_cpu_us': delta}


def job_conservation(prefix, cases, standby, cleanup, retirement, endpoint):
    terms = [prefix, *cases, *standby, cleanup, retirement, endpoint]
    if any(x is None for x in terms):
        return {'status': 'unidentified', 'E_workload_cpu_us': None, 'full_physical_cpu_us': None}
    for value in terms:
        release.integer(value)
    release.check(prefix+sum(cases)+sum(standby)+cleanup+retirement == endpoint, 'Job lifetime conservation')
    return {'status': 'E_point_pending_origin_and_M_review', 'E_workload_cpu_us': endpoint,
            'control_plane_tail_included': False, 'full_physical_cpu_us': None}


def analyze_m2(base_raw, base_receipt, cpu_raw, cpu_receipt, jobs, series, **independent_hashes):
    """Actual shared M2 analyzer, retaining its exact raw/receipt/series checks.

    The independent acquisition/export manifest is required; I never fabricates
    accounting rows, an E endpoint, or a complete physical cost from case sums.
    """
    return m2.analyze(base_raw, base_receipt, cpu_raw, cpu_receipt, jobs, series, **independent_hashes)
