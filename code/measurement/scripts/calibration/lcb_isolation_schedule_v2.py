"""Pure I-v2 allocation/step plans and dispatch bookkeeping.

This module does not call Slurm or create a process. A plan is not a permit.
The live owner/broker verifies the allocation and role joins (seven for CPU,
eight for N/GPU). The existing I-v1 owner is not a caller.
"""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import PurePosixPath

import lcb_isolation_batch_v2 as batch
import lcb_isolation_release_v2 as release

NS = 10**9
MIB = 1024**2
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
INITIAL_ROLES = ('W1', 'O1', 'W2', 'O2')
EXECUTION_ROLES = ('E1', 'E2')


def literal(path):
    release.check(type(path) is str and path.startswith('/')
                  and str(PurePosixPath(path)) == path
                  and '..' not in PurePosixPath(path).parts
                  and not any(c in path for c in ('\0', '\n', '\r', ':', ',')),
                  'Canonical literal path required')
    return path


def walltime(seconds):
    release.integer(seconds, 1, 48*3600)
    # Slurm rounds a seconds-bearing --time upward to whole minutes. Request
    # only whole minutes below the signed remaining window instead.
    seconds = seconds // 60 * 60
    release.check(seconds >= 60, 'At least one whole Slurm minute must remain')
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f'{hours:02d}:{minutes:02d}:{seconds:02d}'


def deadline_utc(nanoseconds):
    """Round toward an earlier deadline, never extend signed authority."""
    release.integer(nanoseconds, 1)
    return datetime.fromtimestamp(nanoseconds // NS, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')


def allocation_plan(manifest, *, template, source, owner_sha256, review_sha256):
    m = batch.validate_manifest(manifest)
    for path in (template, source):
        literal(path)
    for value in (owner_sha256, review_sha256):
        release.digest(value)
    root = m['attempt_root']
    gpu=batch.is_gpu(m)
    a=m['allocation']
    return {
        'schema': 'isolation-allocation-plan-v2',
        'env': dict(ENV),
        'argv': ['--parsable', '--clusters=cluster', '--partition='+a['partition'], '--qos='+a['qos'],
                 '--constraint='+m['constraint'], '--nodes=1', '--ntasks='+('1' if gpu else str(a['cpus'])), '--cpus-per-task='+(str(a['cpus']) if gpu else '1'),
                 '--mem='+str(a['memory_bytes']//MIB)+'M', *(['--gpus=1'] if gpu else ['--gres=none']), '--no-requeue', '--export=NIL',
                 '--time=' + walltime(m['max_run_s']),
                 '--deadline=' + deadline_utc(m['absolute_end_by_ns']),
                 '--job-name=www27-I2-' + m['nonce'][:12],
                 '--comment=www27-I2:' + m['nonce'],
                 '--output=' + root + '/allocation.stdout',
                 '--error=' + root + '/allocation.stderr',
                 template, source, root, owner_sha256, review_sha256],
        'manifest_sha256': release.object_sha(m),
        'submission_returns_after_receipt': True,
        'poll_until_running': False,
        'resource_reserved_by_plan': False,
        'execution_authorized': False,
    }


def step_plan(manifest, role_id, *, job_id, epilog_wrapper, payload_argv,
              actual_start_ns, now_ns, export_values=None, cell_index=None):
    """Build one resource-bounded srun plan from an already fixed role argv.

    payload_argv is supplied by the live broker's registered role factory;
    accepting it here does not authorize it. No plan is executed in this module.
    """
    m = batch.validate_manifest(manifest)
    role = batch.role_for(m, role_id)
    output_root=str(batch.cell_root(m['attempt_root'],m,cell_index))
    release.number(job_id)
    literal(epilog_wrapper)
    release.check(epilog_wrapper == m['attempt_root'] + '/task-epilog',
                  'Use the fixed per-attempt epilog wrapper')
    release.check(type(payload_argv) is list and payload_argv
                  and all(type(v) is str and v and '\0' not in v for v in payload_argv),
                  'Literal role argv required')
    literal(payload_argv[0])
    end = batch.run_end_ns(m, actual_start_ns)
    release.integer(now_ns, actual_start_ns, end - 1)
    # walltime() also rounds down to the scheduler's whole-minute resolution.
    remaining_s = (end - now_ns) // NS
    release.check(remaining_s >= 60, 'No full Slurm minute remains for a role step')
    export_values = {} if export_values is None else export_values
    required = {'WWW27_EPILOG_CONFIG', 'WWW27_EPILOG_CONFIG_SHA256'}
    pins = {'WWW27_I_FRONTEND_' + name for name in
            ('INODE', 'MAJOR', 'MINOR', 'BYTES', 'MTIME', 'CTIME', 'GID', 'MODE')} | {
            'WWW27_I_STARTER_' + name for name in ('INODE', 'MAJOR', 'MINOR')}
    release.check(type(export_values) is dict and set(export_values) <= required | pins,
                  'Only explicit epilog and frontend pins may be exported')
    release.check(not export_values or required <= set(export_values), 'Complete epilog export required')
    for key, value in export_values.items():
        release.check(type(value) is str and value and not any(c in value for c in ',\n\r\0'),
                      'Literal export value required')
    # NONE cannot be combined with explicit variables in Slurm 25.05.4.
    exported = '--export=' + (','.join(k + '=' + export_values[k] for k in sorted(export_values)) or 'NONE')
    return {
        'schema': 'isolation-role-plan-v2', 'role_id': role_id,
        'role_nonce': role['nonce'], 'job_id': job_id,
        'argv': ['--jobid=' + job_id, '--exact', '--nodes=1', '--ntasks=1', exported,
                 '--cpus-per-task='+str(role['cpus']), '--mem='+str(role['memory_bytes']//MIB)+'M',
                 '--gres='+('gpu:1' if role_id=='G' else 'none'),
                 '--time=' + walltime(min(remaining_s, m['max_run_s'])),
                 '--task-epilog=' + epilog_wrapper,
                 '--output=' + output_root + '/' + role_id + '.stdout',
                 '--error=' + output_root + '/' + role_id + '.stderr',
                 *payload_argv],
        'run_end_ns': end, 'execution_authorized': False,
    }


def receipt_gate(manifest, receipt, *, actual_job_id, actual_start_ns, now_ns,
                 owner_sha256, review_sha256):
    """One fixed startup window; None means wait, not a renewed window."""
    m = batch.validate_manifest(manifest)
    release.number(actual_job_id)
    deadline = batch.bootstrap_deadline_ns(m, actual_start_ns)
    release.integer(now_ns, actual_start_ns)
    release.check(now_ns < deadline, 'Fixed 120s receipt window exhausted')
    if receipt is None:
        return {'status': 'wait_original_window', 'deadline_ns': deadline,
                'roles_may_start': False}
    expected = {'schema', 'status', 'job_id', 'manifest_sha256', 'nonce',
                'owner_sha256', 'review_sha256', 'submitted_ns'}
    release.check(type(receipt) is dict and set(receipt) == expected
                  and receipt['schema'] == 'isolation-submission-v2'
                  and receipt['status'] == 'submitted_once'
                  and receipt['job_id'] == actual_job_id
                  and receipt['manifest_sha256'] == release.object_sha(m)
                  and receipt['nonce'] == m['nonce']
                  and receipt['owner_sha256'] == release.digest(owner_sha256)
                  and receipt['review_sha256'] == release.digest(review_sha256),
                  'Submission receipt does not bind this allocation')
    release.integer(receipt['submitted_ns'], 1, m['submit_by_ns'])
    # The scheduler may start the job before the submit client returns its
    # acknowledgement. Exact job/nonce/source bindings above identify the
    # allocation; acknowledgement time is not used as a start lower bound.
    release.check(receipt['submitted_ns'] <= now_ns, 'Submission acknowledgement is in the future')
    return {'status': 'receipt_bound_pending_live_admission', 'deadline_ns': deadline,
            'roles_may_start': False}


class DispatchLedger:
    """Monotone local bookkeeping for D; no signals or cancellation verbs.

    A nonzero child result permanently closes dispatch. The only remaining
    operation is to record waits up to the original run end. The live owner
    must keep waiting even after a failure rather than exit via shell set -e.
    """
    def __init__(self, manifest, *, actual_start_ns):
        self.manifest = batch.validate_manifest(manifest)
        self.run_end_ns = batch.run_end_ns(self.manifest, actual_start_ns)
        self.launched = {}
        self.waited = {}
        self.stopped = False
        self.failure = None
        self.joins = None

    def launch(self, role_id, child_pid, *, now_ns):
        release.check(role_id in INITIAL_ROLES + EXECUTION_ROLES, 'D launches only six sibling roles')
        release.integer(child_pid, 1)
        release.integer(now_ns, 1, self.run_end_ns - 1)
        release.check(not self.stopped and role_id not in self.launched
                      and child_pid not in self.launched.values(), 'Dispatch stopped or child already claimed')
        if role_id in EXECUTION_ROLES:
            release.check(all(r in self.launched for r in INITIAL_ROLES), 'W/O launch precedes E')
        self.launched[role_id] = child_pid

    def admit(self, joins, *, runtime_receipt):
        release.check(not self.stopped and self.joins is None
                      and set(self.launched) == set(INITIAL_ROLES + EXECUTION_ROLES),
                      'All six sibling steps must be launched before once-only admission')
        actual = batch.validate_runtime_receipt(self.manifest, runtime_receipt)
        release.check(batch.run_end_ns(self.manifest, actual['actual_start_ns']) == self.run_end_ns,
                      'Live receipt start differs from dispatcher origin')
        self.joins = batch.validate_joins(self.manifest, joins, runtime_receipt=actual)
        return deepcopy(self.joins)

    def stop(self, reason):
        release.check(type(reason) is str and reason, 'Failure reason required')
        self.stopped = True
        if self.failure is None:
            self.failure = reason

    def wait_result(self, role_id, child_pid, returncode, *, wait_ns):
        release.check(self.launched.get(role_id) == child_pid and role_id not in self.waited,
                      'Wait must refer to one owned child exactly once')
        release.integer(wait_ns, 1)
        release.check(type(returncode) is int and -128 <= returncode <= 255, 'Child status required')
        self.waited[role_id] = {'pid': child_pid, 'returncode': returncode,
                               'wait_completed': True, 'wait_ns': wait_ns}
        if wait_ns >= self.run_end_ns:
            # Retain the real late reap; never turn an expired attempt into a
            # normal completion simply because all processes eventually end.
            self.stop('wait_after_run_end:' + role_id)
        if returncode != 0:
            self.stop('nonzero_child:' + role_id)

    def summary(self, *, now_ns):
        release.integer(now_ns, 1)
        pending = sorted(set(self.launched) - set(self.waited))
        complete = len(self.launched) == 6 and not pending and not self.stopped and self.joins is not None
        return {'schema': 'isolation-dispatch-ledger-v2',
                'status': ('all_owned_steps_waited_pending_review' if complete else
                           'bounded_wait_expired_unidentified' if pending and now_ns >= self.run_end_ns else
                           'failed_all_owned_steps_waited' if self.stopped and not pending else
                           'stopped_waiting_owned_steps' if self.stopped else
                           'bounded_dispatch_expired_unidentified' if now_ns >= self.run_end_ns else
                           'dispatch_in_progress'),
                'pending_roles': pending, 'waits': deepcopy(self.waited),
                'failure': self.failure, 'run_end_ns': self.run_end_ns,
                'cancel_authority': False, 'scientific_cost_accepted': False,
                'candidate_execution_authorized': False, 'main_matrix_authorized': False}
