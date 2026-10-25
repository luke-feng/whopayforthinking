"""Single-submit asynchronous I allocation with D-owned sibling steps.

All live entries need registration, endpoint acceptance, R and owner approval.
The optional v3 manifest dispatches one N/GPU cell through lcb_ngpu_v3;
the CPU fixture path is retained. No Slurm cancellation verb is added.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_release_v2 as release
import lcb_isolation_batch_v2 as batch
import lcb_isolation_schedule_v2 as schedule
import lcb_isolation_runtime_v2 as runtime
import lcb_isolation_assets_v2 as assets
import lcb_isolation_control_v2 as control
import lcb_isolation_meter_v2 as meter
import lcb_isolation_native_v1 as native
import lcb_task_epilog_v1 as epilog
import lcb_supervision_site_v3 as site
from lcb_worker_metering_v2 import SACCT_SHA256

TEMPLATE = 'experiments/calibration/isolation-allocation-v2.slurm.template'
GATES = dict.fromkeys(release.GATES, False)
FAILURE_CLOSEOUT_NS = 10 * 10**9


class ObservationUnavailable(runtime.InfrastructureError):
    """A bounded RPC failed; source/permission identity errors remain fatal."""


class Client:
    """Pinned short-lived clients only; never a role launcher or canceller."""
    def __init__(self, source_assets, journal, authority=None):
        self.assets, self.journal, self.authority = source_assets, journal, authority

    def command(self, name, arguments, timeout_s=60, *, environment=None):
        if self.authority is not None:
            release.require(self.authority)
        release.check(name in ('sbatch', 'scontrol', 'timedatectl', 'sacct'), 'No cancellation/arbitrary client')
        command_env=dict(schedule.ENV if environment is None else environment)
        release.check(command_env==schedule.ENV and command_env['TZ']=='UTC','Fixed UTC client environment required')
        item = self.assets[name]
        raw = release.read(item['path'], 32*1024**2)
        client_matches_lock = release.sha(raw) == item['sha256']  # recorded in the journal below, not a gate
        argv = [item['path'], *arguments]
        started = time.monotonic_ns()
        started_wall = time.time_ns()
        out, err, code = b'', b'', None
        proc = None
        buffers = [bytearray(), bytearray()]
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=command_env, close_fds=True)
            deadline = time.monotonic()+timeout_s
            poll = select.poll()
            fds = {proc.stdout.fileno():0, proc.stderr.fileno():1}
            for fd in fds:
                os.set_blocking(fd, False); poll.register(fd, select.POLLIN | select.POLLHUP)
            while fds:
                if time.monotonic() >= deadline:
                    raise ObservationUnavailable('Pinned client timed out; no retry')
                for fd, _ in poll.poll(20):
                    if fd not in fds:
                        continue
                    index = fds[fd]
                    part = os.read(fd, 65536)
                    if not part:
                        poll.unregister(fd); del fds[fd]
                    else:
                        buffers[index].extend(part)
                        release.check(len(buffers[index]) <= 1024**2, 'Client output exceeded bound')
            code = proc.wait(timeout=max(.001, deadline-time.monotonic()))
            if code != 0:
                raise ObservationUnavailable('Pinned client returned nonzero')
            return bytes(buffers[0]).decode('utf-8', 'strict')
        finally:
            # This can kill only this Popen's short RPC client. D's srun children
            # never enter this class; there is no job/step cancellation target.
            cleanup_error=None;reaped=proc is None
            try:
                if proc is not None:
                    if proc.poll() is None:
                        proc.kill()
                    code = proc.wait(timeout=1);reaped=True
            except BaseException as exc:
                cleanup_error=type(exc).__name__+': '+str(exc)
            finally:
                if proc is not None:
                    for stream in (proc.stdout,proc.stderr):
                        try:stream.close()
                        except OSError:pass
                out, err = map(bytes, buffers)
                self.journal.append('client', {'argv':argv, 'binary_sha256':item['sha256'], 'matches_lock':client_matches_lock,
                    'environment':command_env,
                    'returncode':code, 'stdout':out.decode('utf-8','replace'), 'stderr':err.decode('utf-8','replace'),
                    'stdout_hex':out.hex(),'stderr_hex':err.hex(),'cleanup_error':cleanup_error,'wait_completed':reaped,
                    'begin_ns':started, 'end_ns':time.monotonic_ns(), 'no_retry':True})
                self.journal.append('client_wall_bracket', {'started_wall_ns':started_wall,
                                                           'finished_wall_ns':time.time_ns()})
            if cleanup_error is not None:
                raise ObservationUnavailable('RPC cleanup/reap unverified: '+cleanup_error)


def prepare(root, request, lean=False):
    """Copy a finite request. No approval, permit, asset execution or Slurm."""
    value = batch.validate_manifest(release.strict(release.read(request)))
    root = Path(root)
    release.check(str(root) == value['attempt_root'] and root != release.ROOT
                  and release.ROOT not in root.parents, 'Exact separate attempt root required')
    os.mkdir(root, 0o700)
    release.write_new(root/'manifest.json', value)
    if lean:
        release.write_new(root/release.LEAN_MARKER, {'schema':'lean-attempt-v1','manifest_sha256':release.object_sha(value),
            'note':'The manifest is the approval: no registry, reviewed-release or owner-approval files.'})
    for directory in ('configs','endpoints'):
        os.mkdir(root/directory, 0o700)
    if batch.is_gpu(value):
        os.mkdir(root/'cells',0o700)
        for index in range(len(value['cells'])):
            cell=batch.cell_root(root,value,index);os.mkdir(cell,0o700)
            for directory in ('configs','endpoints'):os.mkdir(cell/directory,0o700)
    for worker in batch.WORKERS:
        release.write_new(root/('key-'+worker), os.urandom(32))
    wrapper = epilog.wrapper_bytes(release.ROOT/'scripts/calibration/lcb_task_epilog_v1.py')
    release.write_new(root/'task-epilog', wrapper); os.chmod(root/'task-epilog', 0o700)
    return {'status':'prepared_lean' if lean else 'prepared_not_approved',
            'manifest_sha256':release.object_sha(value), 'lean':lean, **GATES}


def submit(authority, journal):
    release.require(authority, phase='queue')
    release.consume_submission(authority)  # Unknown sbatch outcome remains consumed.
    prepared = assets.prepare_batch_assets(authority)
    if batch.is_gpu(authority.manifest):
        from lcb_ngpu_v3 import prepare_inference
        prepare_inference(authority,prepared)
    journal.append('assets_prepared', prepared)
    template='experiments/calibration/isolation-allocation-gpu-v2.slurm.template' if batch.is_gpu(authority.manifest) else TEMPLATE
    plan = schedule.allocation_plan(authority.manifest, template=str(release.ROOT/template),
        source=str(release.ROOT), owner_sha256=authority.owner_sha, review_sha256=authority.review_sha)
    release.check(plan['env']==schedule.ENV and plan['env'].get('TZ')=='UTC', 'Submission must use the planned UTC environment')
    if not authority.snapshot.get('lean'):
        release.check(release.sha(release.read(release.ROOT/template)) == authority.snapshot['files_sha256'][template],
                      'Allocation template is not registered')
    runtime.publish(authority.root/'submission-intent.json', plan)
    raw = Client(authority.assets, journal, authority).command('sbatch', plan['argv'], timeout_s=120,
                                                             environment=plan['env'])
    match = re.fullmatch(r'([1-9][0-9]*)(?:;cluster)?\n?', raw)
    release.check(match, 'Unknown sbatch outcome: retain claim and never resubmit')
    receipt = batch.submission_receipt(authority, match[1])
    runtime.publish(authority.root/'submission.json', receipt)
    # Return now. No login-side squeue/scontrol polling or node selection.
    return {**receipt, 'status':'allocation_submitted_not_accepted', **GATES,
            'candidate_execution_authorized':authority.manifest.get('candidate_execution_authorized') is True}


def bootstrap(root, owner_sha, review_sha, journal):
    request = release.inspect_request(root, owner_sha, review_sha)
    manifest = request['manifest']
    job_id = release.number(os.environ.get('SLURM_JOB_ID', ''))
    release.check(os.environ.get('SLURM_STEP_ID', 'batch') == 'batch', 'Bootstrap belongs to batch step')
    context = runtime.local_context()
    try:
        group = runtime.resource_group(site.CGBASE+'/job_'+job_id,
            on_read=lambda reading: runtime.publish(Path(root)/'allocation-resource-observation.json',reading))
        raw = Client(request['assets'], journal).command('scontrol', ['--clusters=cluster','--oneliner','show','job',job_id])
        actual = runtime.allocation_facts(raw, manifest, job_id, context=context, cpu_model=runtime.local_model(),
            cpu_ids=group['cpu_ids'], memory_bytes=group['memory_max_bytes'])
    except BaseException as exc:
        runtime.publish(Path(root)/'bootstrap-failure.json',{'stage':'allocation_observation',
            'error':type(exc).__name__+': '+str(exc),'traceback':traceback.format_exc()})
        raise
    runtime.publish(Path(root)/'allocation-resource-summary.json',{
        'requested_cpus':manifest['allocation']['cpus'],'allocated_cpus':actual['cpus'],
        'extra_allocated_cpus':actual['cpus']-manifest['allocation']['cpus'],
        'cpu_ids':group['cpu_ids'],'memory_max_bytes':group['memory_max_bytes']})
    deadline = batch.bootstrap_deadline_ns(manifest, actual['actual_start_ns'])
    receipt = None
    lean = bool(request.get('snapshot',{}).get('lean'))
    while not lean:
        now = time.time_ns()
        if now >= deadline:
            break
        try:
            receipt = release.strict(runtime.read_published(Path(root)/'submission.json'))
        except FileNotFoundError:
            pass
        now = time.time_ns()
        try:
            gate = schedule.receipt_gate(manifest, receipt, actual_job_id=job_id,
                actual_start_ns=actual['actual_start_ns'], now_ns=now,
                owner_sha256=owner_sha, review_sha256=review_sha)
        except ValueError as exc:
            raise runtime.InfrastructureError('Submission receipt does not match the allocation/window') from exc
        if receipt is not None:
            break
        time.sleep(min(.02, max(0, (gate['deadline_ns']-time.time_ns())/10**9)))
    if receipt is None and not lean:
        raise runtime.InfrastructureError('No owner submission receipt in original 120s window')
    if not lean:
        runtime.publish(Path(root)/'bootstrap-receipt.json', {'schema':'isolation-bootstrap-receipt-v2',
            'job_id':job_id, 'actual_start_ns':actual['actual_start_ns'],
            'manifest_sha256':release.object_sha(manifest), 'owner_sha256':owner_sha,
            'review_sha256':review_sha, 'submission_sha256':release.object_sha(receipt),
            'observed_wall_ns':now})
    runtime.publish(Path(root)/'allocation.json', actual)
    runtime.publish(Path(root)/'allocation-resources.json', group)
    runtime.publish(Path(root)/'allocation-clock.json', {'monotonic_ns':time.monotonic_ns(),
        'wall_ns':time.time_ns(), 'protocol_clock_error_ns':10**9})
    authority = release.issue(root, owner_sha, review_sha, phase='runtime', role='D', runtime_receipt=actual)
    assets.recheck_prepared_assets(authority)
    manager = StepManager(authority, journal)
    try:
        manager.start('D', runtime.role_argv(authority, 'D'))
        manager.wait_all()
        pending=sorted(set(manager.children)-set(manager.records))
        successful=not manager.stopped and not pending and set(manager.records)=={'D'} and manager.records['D']['returncode']==0
        result={'status':'bootstrap_waited_pending_review' if successful else 'bootstrap_failed_unidentified',
                'children':manager.records,'pending':pending,**GATES}
        runtime.publish(Path(root)/'bootstrap-outcome.json',result)
        if not successful:
            raise runtime.InfrastructureError('Dispatcher failed or remains unwaited; see bootstrap-outcome.json')
        return result
    finally:
        if len(manager.records) != len(manager.children):
            manager.wait_all()
        manager.close()


def native_environment(authority, prepared):
    import lcb_permission_assets_v3 as policy
    lock = prepared['runtime_lock_value']
    policy.verify_same_run(prepared['runtime_final_snapshot'], policy.snapshot(lock))
    front, starter = Path(lock['runtime']['path']).stat(), Path(lock['runtime_components']['starter']['path']).stat()
    pins = native.frontend_env({'inode':front.st_ino, 'dev_major':os.major(front.st_dev),
        'dev_minor':os.minor(front.st_dev), 'bytes':front.st_size, 'mtime_ns':front.st_mtime_ns,
        'ctime_ns':front.st_ctime_ns, 'gid':front.st_gid, 'mode':front.st_mode},
        {'inode':starter.st_ino, 'dev_major':os.major(starter.st_dev), 'dev_minor':os.minor(starter.st_dev)})
    return {**release.ENV, **pins, '_runtime_lock':lock}


def clock_qualification(authority, journal):
    rows = []
    client = Client(authority.assets,journal,authority)
    for args in (['--no-ask-password','--no-pager','show','--property=NTPSynchronized','--property=TimeUSec'],
                 ['--no-ask-password','--no-pager','timesync-status']):
        try:
            rows.append(client.command('timedatectl',args,timeout_s=5))
        except (ObservationUnavailable,subprocess.TimeoutExpired) as exc:
            journal.append('clock_observation_unavailable',{'error':str(exc),'retry':False})
            rows.append('')
    match = re.search(r'^\s*Offset:\s*([+-]?[0-9.]+)\s*(us|µs|μs|ms|s)\s*$',rows[1],re.MULTILINE)
    qualified = 'NTPSynchronized=yes' in rows[0].splitlines() and match is not None
    if qualified:
        try:
            qualified = abs(Decimal(match[1]))*{'us':1000,'µs':1000,'μs':1000,'ms':10**6,'s':10**9}[match[2]] <= 100_000_000
        except InvalidOperation:
            qualified = False
    result = {'qualified':qualified, 'protocol_clock_error_ns':10**9,
              'first_raw':rows[0], 'second_raw':rows[1]}
    journal.append('clock_qualification',result)
    return result


def native_argv(authority, execution_role, prepared):
    slot = batch.role_for(authority.manifest, execution_role)
    release.check(slot['kind'] == 'execution', 'Native program only belongs to E')
    lock = prepared['runtime_lock_value']
    return native.controller_argv({'helper_path':authority.assets['native_elf']['path'],
        'helper_sha256':authority.assets['native_elf']['sha256'], 'runtime_path':lock['runtime']['path'],
        'runtime_sha256':lock['runtime']['sha256'], 'sif_path':lock['cpu_sif']['path'],
        'sif_sha256':lock['cpu_sif']['sha256'], 'nonce':slot['nonce'], 'private_nproc':32},
        authority.root/('native-'+slot['worker_id']), authority.root/('c-'+slot['worker_id']+'.sock'))


class StepManager:
    """Own exactly the launched srun PIDs; never signal or cancel them."""
    def __init__(self, authority, journal, *, cell_index=None):
        release.require(authority, phase='runtime', role='D')
        self.authority, self.journal = authority, journal
        self.cell_index=cell_index
        self.root=batch.cell_root(authority.root,authority.manifest,cell_index)
        self.children, self.records, self.streams = {}, {}, []
        self.stopped = False
        self.failure = None
        self.failure_deadline_ns = None

    def diagnostic(self, kind, value, path=None):
        """Best effort evidence must never replace the original exception."""
        def stderr(message):
            try:print(message,file=sys.stderr,flush=True)
            except Exception:pass
        if path is not None:
            try:runtime.publish(path,value)
            except FileExistsError:pass  # Preserve the first original.
            except Exception as exc:
                stderr(f'{kind}: evidence publication failed: {exc}')
        try:self.journal.append(kind,value)
        except Exception as exc:
            stderr(f'{kind}: journal failed: {exc}')
        stderr(release.encoded({'kind':kind,'data':value}).decode())

    def fail(self, exc, stage):
        self.stopped = True
        if self.failure is not None:return
        self.failure_deadline_ns=min(self.authority.deadline_mono_ns,time.monotonic_ns()+FAILURE_CLOSEOUT_NS)
        self.failure={'status':getattr(exc,'status','protocol_or_fixture_failure'),
            'stage':stage,'error_type':type(exc).__name__,'error':str(exc),
            'traceback':''.join(traceback.format_exception(type(exc),exc,exc.__traceback__)),
            'pending':sorted(set(self.children)-set(self.records)),
            'wall_ns':time.time_ns(),'cell_index':self.cell_index,
            'automatic_retry':False,'cancellation_invoked':False}
        # Publish the cause before waking peers or waiting for any child.
        self.diagnostic('dispatcher_failure',self.failure,self.root/'D-failure.json')
        self.diagnostic('dispatcher_stop_notification',self.failure,self.root/'batch.stop.json')  # per cell; later cells continue

    def failure_closeout(self):
        try:self.wait_all(deadline_ns=self.failure_deadline_ns)
        except Exception as exc:
            self.diagnostic('dispatcher_closeout_error',{'error_type':type(exc).__name__,'error':str(exc)})
        pending=sorted(set(self.children)-set(self.records))
        result={'status':'pending_children_unidentified' if pending else 'owned_launchers_waited_after_failure',
            'pending':pending,'waits':deepcopy(self.records),'deadline_mono_ns':self.failure_deadline_ns,
            'all_launchers_waited':not pending,'role_cleanup_verified':False,
            'automatic_retry':False,'cancellation_invoked':False}
        self.diagnostic('dispatcher_failure_closeout',result,self.root/'D-failure-closeout.json')
        return result

    def poll(self):
        for role, proc in self.children.items():
            if role in self.records or proc.poll() is None:
                continue
            code = proc.wait()
            record = {'role_id':role, 'pid':proc.pid, 'returncode':code, 'wait_completed':True,
                      'wait_ns':time.time_ns(), 'wait_mono_ns':time.monotonic_ns()}
            self.records[role] = record
            runtime.publish(self.root/(role+'.wait.json'), record)
            self.journal.append('owned_srun_wait', record)
            if code != 0 or record['wait_ns'] >= self.authority.run_end_ns:
                self.stopped = True
        if (self.root/'batch.stop.json').exists():
            self.stopped = True
        return deepcopy(self.records)

    def start(self, role, argv, *, pins=None):
        self.poll()
        release.require(self.authority, phase='runtime', role='D')
        release.check(not self.stopped and role not in self.children, 'No new dispatch after failure/duplicate role')
        config = runtime.epilog_config(self.authority, role, self.cell_index)
        config_path = self.root/'configs'/(role+'.json')
        release.write_new(config_path, epilog.encoded(config))
        export_values = {epilog.CONFIG_ENV:str(config_path), epilog.HASH_ENV:release.sha(epilog.encoded(config))}
        if pins:
            export_values.update(pins)
        env = {**release.ENV, **{k:os.environ[k] for k in
               ('SLURM_JOB_ID', 'SLURM_CLUSTER_NAME', 'SLURM_CONF') if k in os.environ}, **export_values}
        plan = schedule.step_plan(self.authority.manifest, role, job_id=self.authority.runtime_receipt['job_id'],
            epilog_wrapper=str(self.authority.root/'task-epilog'), payload_argv=argv,
            actual_start_ns=self.authority.runtime_receipt['actual_start_ns'], now_ns=time.time_ns(),
            export_values=export_values,cell_index=self.cell_index)
        # The wrapper/config are private fixed bytes; srun exports only this
        # generated environment, not ambient owner shell variables.
        wrapper = epilog.wrapper_bytes(release.ROOT/'scripts/calibration/lcb_task_epilog_v1.py')
        release.check(release.read(self.authority.root/'task-epilog') == wrapper, 'Epilog wrapper changed')
        runtime.publish(self.root/(role+'.launch.json'), {'plan':plan, 'config_sha256':env[epilog.HASH_ENV]})
        binary = self.authority.assets['srun']
        srun_matches_lock = release.sha(release.read(binary['path'],32*1024**2)) == binary['sha256']  # recorded below, not a gate
        out = open(self.root/(role+'.srun.stdout'), 'xb')
        err = open(self.root/(role+'.srun.stderr'), 'xb')
        self.streams.extend((out,err))
        proc = subprocess.Popen([binary['path'], *plan['argv']], env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err, close_fds=True)
        self.children[role] = proc
        self.journal.append('owned_srun_started', {'role_id':role,'pid':proc.pid,'plan':plan,'srun_matches_lock':srun_matches_lock})

    def wait_all(self, *, deadline_ns=None, stop_on_failure=False):
        until=self.authority.deadline_mono_ns if deadline_ns is None else min(deadline_ns,self.authority.deadline_mono_ns)
        while time.monotonic_ns() < until:
            self.poll()
            if stop_on_failure and self.stopped:
                raise runtime.InfrastructureError('A child or peer stopped; no further normal wait')
            if len(self.records) == len(self.children):
                return
            time.sleep(.02)
        self.stopped = True
        self.journal.append('bounded_wait_expired', {'pending':sorted(set(self.children)-set(self.records))})
        if stop_on_failure:raise runtime.InfrastructureError('Owned child wait reached runtime bound')

    def close(self):
        for stream in self.streams:
            try:stream.close()
            except Exception as exc:
                if self.failure is None:raise
                self.diagnostic('dispatcher_close_error',{'error':str(exc)})


class WorkerBroker:
    """W publishes only a fixed E request; D is the sole srun parent."""
    def __init__(self, authority):
        self.authority = authority

    def request_execution(self, slot, root, socket_path, argv, pins, deadline_ns):
        expected = 'E'+self.authority.role[1]
        release.require(self.authority, phase='runtime', role='W'+expected[1])
        release.check(slot == batch.role_for(self.authority.manifest,expected), 'W cannot request another E')
        runtime.publish(self.authority.root/(expected+'.request.json'), {'role_id':expected,
            'manifest_sha256':release.object_sha(self.authority.manifest), 'nonce':slot['nonce'],
            'argv':argv, 'pins':pins, 'output_root':str(root), 'socket':str(socket_path)})

    def bind_execution(self, slot, identity, step_id, deadline_ns):
        release.require(self.authority, phase='runtime')
        runtime.publish(self.authority.root/(slot['role_id']+'.proposal.json'), {'identity':identity,'step_id':step_id})
        bound = runtime.wait_object(self.authority.root/(slot['role_id']+'.bound.json'), deadline_ns,
                                    authority=self.authority)
        release.check(bound['process']['pid'] == identity['pid'] and bound['join']['step_id'] == step_id,
                      'D execution bind differs')
        return bound

    def wait_execution(self, slot, deadline_ns):
        record = runtime.wait_object(self.authority.root/(slot['role_id']+'.wait.json'), deadline_ns,
                                    authority=self.authority, stop=False)
        release.check(record['role_id'] == slot['role_id'] and record['wait_completed'] is True,
                      'D wait record differs')
        return record['returncode']


def dispatcher(authority, journal, own):
    prepared = assets.recheck_prepared_assets(authority)
    manager = StepManager(authority, journal)
    capture = meter.Capture(authority, own['subject'], journal,
                            endpoint_config_sha256=runtime.endpoint_config_digest(authority,'D'))
    records = {'D':own}
    capture.sample('dispatcher_setup')
    stage='launch_control_roles'
    try:
        for role in schedule.INITIAL_ROLES:
            stage='launch_'+role
            manager.start(role, runtime.role_argv(authority, role))
        while len(records) < 5:
            manager.poll()
            release.check(not manager.stopped, 'Control role failed before binding')
            for role in schedule.INITIAL_ROLES:
                path = authority.root/(role+'.started.json')
                if role not in records and path.exists():
                    stage='read_started_'+role
                    proposal = release.strict(runtime.read_published(path))
                    stage='observe_'+role
                    journal.append('control_role_bind_begin',{'role_id':role})
                    observed = runtime.observe_role(authority,role,proposal['join']['pid'],runtime.role_argv(authority,role))
                    stage='compare_'+role
                    release.check(observed['join'] == proposal['join'] and observed['subject'] == proposal['subject'],
                                  'Control role publication differs from kernel')
                    records[role] = observed
                    journal.append('control_role_bound',{'role_id':role})
            time.sleep(min(.02, control.remaining(authority.deadline_mono_ns)))
        stage='publish_control_joins'
        runtime.publish(authority.root/'control-joins.json', records)
        capture.sample('control_roles_joined')
        launched = set()
        while len(records) < 7:
            stage='execution_admission'
            manager.poll()
            release.check(not manager.stopped, 'Role failed before complete seven-role admission')
            for role in schedule.EXECUTION_ROLES:
                request_path = authority.root/(role+'.request.json')
                if role not in launched and request_path.exists():
                    stage='request_'+role
                    request = release.strict(runtime.read_published(request_path))
                    env = native_environment(authority, prepared)
                    pins = {k:v for k,v in env.items() if k.startswith('WWW27_I_')}
                    expected = {'role_id':role, 'manifest_sha256':release.object_sha(authority.manifest),
                        'nonce':batch.role_for(authority.manifest,role)['nonce'],
                        'argv':native_argv(authority,role,prepared), 'pins':pins,
                        'output_root':str(authority.root/('native-'+batch.role_for(authority.manifest,role)['worker_id'])),
                        'socket':str(authority.root/('c-'+batch.role_for(authority.manifest,role)['worker_id']+'.sock'))}
                    release.check(request == expected, 'E request must equal independently recomputed fixed native argv/pins')
                    release.consume_execution(authority,role)
                    manager.start(role, expected['argv'], pins=pins)
                    launched.add(role)
                proposal_path = authority.root/(role+'.proposal.json')
                if role in launched and role not in records and proposal_path.exists():
                    stage='observe_'+role
                    proposal = release.strict(runtime.read_published(proposal_path))
                    observed = runtime.observe_role(authority,role,proposal['identity']['pid'],
                        native_argv(authority,role,prepared), expected_step=proposal['step_id'])
                    release.check(site.process_identity(observed['process']) == site.process_identity(proposal['identity']),
                                  'C identity differs from socket peer')
                    records[role] = observed
                    runtime.publish(authority.root/(role+'.bound.json'), observed)
            time.sleep(min(.02, control.remaining(authority.deadline_mono_ns)))
        bundle = {'schema':'isolation-seven-joins-v2', 'joins':[records[r]['join'] for r in batch.ROLE_IDS],
                  'subjects':{r:records[r]['subject'] for r in batch.ROLE_IDS},
                  'manifest_sha256':release.object_sha(authority.manifest)}
        runtime.bundle_check(authority,bundle)
        runtime.publish(authority.root/'7-joins.json',bundle)
        capture.sample('all_roles_admitted')
        stage='wait_children'
        manager.wait_all(stop_on_failure=True)
        capture.sample('dispatcher_closeout')
        successful = len(manager.records) == 6 and not manager.stopped
        return {'status':'all_owned_steps_waited_pending_review' if successful else 'dispatch_failed_unidentified',
                'waits':manager.records, 'pending':sorted(set(manager.children)-set(manager.records)), **GATES}
    except BaseException as exc:
        manager.fail(exc,stage)
        manager.failure_closeout()
        raise
    finally:
        if manager.failure is None:
            try:runtime.publish(authority.root/'D.meter.json',capture.export_record())
            finally:
                capture.close();manager.close()
        else:
            for action in (lambda:runtime.publish(authority.root/'D.meter.json',capture.export_record()),capture.close,manager.close):
                try:action()
                except Exception as exc:manager.diagnostic('dispatcher_finalization_error',{'error':str(exc)})


def run_role(authority, role_id, journal, *, cell_index=None):
    release.require(authority, phase='runtime', role=role_id)
    gpu=batch.is_gpu(authority.manifest)
    if not gpu:release.check(cell_index is None,'CPU role cannot select a GPU cell')
    if gpu and role_id!='D':release.check(cell_index is not None,'GPU worker requires a cell index')
    output_root=batch.cell_root(authority.root,authority.manifest,cell_index)
    release.check(role_id in (batch.GPU_ROLE_IDS if gpu else ('D','W1','O1','W2','O2')), 'E is the fixed native ELF, not a Python role')
    assets.recheck_prepared_assets(authority)
    if cell_index is None:release.consume_role(authority)
    else:release.consume_role(authority,cell_index=cell_index)
    own = runtime.observe_role(authority,role_id,os.getpid(),runtime.role_argv(authority,role_id,cell_index))
    qualification = clock_qualification(authority,journal)
    runtime.publish(output_root/(role_id+'.clock.json'),qualification)
    if role_id == 'D':
        runtime.publish(authority.root/'clock-qualification.json',qualification)
    runtime.publish(output_root/(role_id+'.started.json'),own)
    if gpu:
        from lcb_ngpu_v3 import run_role as run_gpu
        return run_gpu(authority,own,journal,cell_index=cell_index)
    if role_id == 'D':
        return dispatcher(authority,journal,own)
    import lcb_isolation_roles_v2 as roles
    return roles.run(authority, own, journal)


def collect_return(root, output, owner_sha, review_sha):
    """Post-terminal read-only accounting. No live issuer or old R is consumed."""
    import lcb_isolation_return_v2 as returned
    request = release.inspect_request(root,owner_sha,review_sha)
    if batch.is_gpu(request['manifest']):
        from lcb_ngpu_v3 import collect_gpu
        return collect_gpu(root,output,request)
    actual = release.strict(runtime.read_published(Path(root)/'allocation.json'))
    batch.validate_runtime_receipt(request['manifest'],actual)
    output=Path(output)
    release.check(output!=Path(root) and Path(root) not in output.parents and
                  output!=release.ROOT and release.ROOT not in output.parents,
                  'Return output must be outside source and original attempt')
    release.path_check(output.parent,private=True);os.mkdir(output,0o700)
    events=[]
    class Journal:
        def append(self,kind,data):
            events.append((kind,deepcopy(data)))
    binary='/usr/bin/sacct'
    client=Client({'sacct':{'path':binary,'sha256':SACCT_SHA256}},Journal())
    raw={};receipts={}
    try:
        for label,fields in (('base',returned.BASE_FIELDS),('cpu',returned.CPU_FIELDS)):
            args=['--clusters=cluster','--duplicates','--parsable2','--jobs='+actual['job_id'],'--format='+fields]
            begin=len(events);begin_wall=time.time_ns();error=None
            try:
                client.command('sacct',args,timeout_s=120)
            except BaseException as exc:
                error=type(exc).__name__+': '+str(exc)
                raise
            finally:
                segment=events[begin:]
                data=next((v for k,v in segment if k=='client'),{})
                bracket=next((v for k,v in segment if k=='client_wall_bracket'),
                             {'started_wall_ns':begin_wall,'finished_wall_ns':time.time_ns()})
                body=bytes.fromhex(data.get('stdout_hex',''));stderr=bytes.fromhex(data.get('stderr_hex',''))
                raw[label]=body
                receipts[label]={'argv':[binary,*args],'environment':returned.ENV,'returncode':data.get('returncode'),
                    'stderr':stderr.decode('utf-8','replace'),'stdout_sha256':release.sha(body),**bracket,
                    'binary_sha256':SACCT_SHA256,'error':error,'no_retry':True,
                    'wait_completed':data.get('wait_completed') is True,'cleanup_error':data.get('cleanup_error')}
                release.write_new(output/(label+'.txt'),body)
                release.write_new(output/(label+'.stderr.bin'),stderr)
                release.write_new(output/(label+'.receipt.json'),receipts[label])
    finally:
        release.write_new(output/'client-originals.json',events)
    base_rows=returned.accounting.table(raw['base'],returned.BASE_FIELDS)
    if any(row['State']!='COMPLETED' or row['ExitCode']!='0:0' for row in base_rows.values()):
        receipt={'schema':returned.RECEIPT_SCHEMA,'source_snapshot':request['snapshot'],**receipts}
        failed=returned.collect_failure(root,raw['base'],raw['cpu'],receipt)
        receipt['files_sha256']=failed['summary']['files_sha256']
        release.write_new(output/'collector-receipt.json',receipt)
        for name,body in failed['raw'].items():
            path=output/'originals'/name
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            release.write_new(path,body)
        release.write_new(output/'failure-inventory.json',failed['summary'])
        return {'status':'readonly_failed_originals_collected_not_accepted','output':str(output),**GATES}
    inventory=returned.collect(root)
    receipt={'schema':returned.RECEIPT_SCHEMA,'source_snapshot':request['snapshot'],
             'files_sha256':inventory['sha256'],**receipts}
    release.write_new(output/'collector-receipt.json',receipt)
    result=returned.assemble(root,raw['base'],raw['cpu'],receipt)
    release.write_new(output/'conditional-analysis.json',result)
    return {'status':'readonly_return_assembled_pending_review','output':str(output),**GATES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare','submit','bootstrap','role','collect'))
    parser.add_argument('--root',required=True); parser.add_argument('--request')
    parser.add_argument('--owner-sha256'); parser.add_argument('--review-sha256')
    parser.add_argument('--role-id'); parser.add_argument('--execute',action='store_true')
    parser.add_argument('--cell-index',type=int)
    parser.add_argument('--output')
    parser.add_argument('--lean',action='store_true',
                        help='prepare only: the manifest is the approval (no registry, R or owner-approval files)')
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == 'prepare':
        release.check(args.request and not args.execute and not args.owner_sha256 and not args.review_sha256,
                      'Prepare never grants or executes')
        print(release.encoded(prepare(args.root,args.request,lean=args.lean)).decode(),end=''); return
    if release.is_lean(args.root):
        # Lean attempts carry no separate owner/R digests; both default to the manifest's own digest.
        placeholder = release.sha(release.read(Path(args.root)/'manifest.json'))
        args.owner_sha256 = args.owner_sha256 or placeholder
        args.review_sha256 = args.review_sha256 or placeholder
    if args.operation == 'collect':
        release.check(not args.execute and args.output and args.owner_sha256 and args.review_sha256,
                      'Read-only collect requires output and original hashes, not --execute')
        print(release.encoded(collect_return(args.root,args.output,args.owner_sha256,args.review_sha256)).decode(),end='');return
    release.check(args.execute and args.owner_sha256 and args.review_sha256,
                  'Explicit execute and independent new owner/R digests required')
    root = release.path_check(args.root, private=True)
    output_root=batch.cell_root(root,release.strict(release.read(root/'manifest.json',private=True)),args.cell_index) if args.cell_index is not None else root
    journal = control.Journal(output_root, 'owner-'+args.operation+'-'+(args.role_id or 'allocation')+'.jsonl')
    authority = None
    try:
        if args.operation == 'bootstrap':
            result = bootstrap(root,args.owner_sha256,args.review_sha256,journal)
        else:
            actual = None if args.operation == 'submit' else release.strict(runtime.read_published(root/'allocation.json'))
            authority = release.issue(root,args.owner_sha256,args.review_sha256,
                phase='queue' if args.operation == 'submit' else 'runtime',
                role=None if args.operation == 'submit' else args.role_id,runtime_receipt=actual)
            journal.append('source_authorization',{'snapshot':authority.snapshot,
                'owner_sha256':authority.owner_sha,'review_sha256':authority.review_sha,
                'phase':authority.phase,'role':authority.role})
            result = submit(authority,journal) if args.operation == 'submit' else run_role(authority,args.role_id,journal,cell_index=args.cell_index)
            if not authority.snapshot.get('lean'):
                current,_=release.source_snapshot()
                release.check(current==authority.snapshot,'Source changed during run')
                journal.append('source_after',current)
        journal.append('result',result)
        runtime.publish(output_root/(args.operation+'-'+(args.role_id or 'allocation')+'.result.json'),result)
        if args.operation == 'role' and args.role_id == 'D':
            runtime.publish(root/'dispatch-result.json',result)
        print(release.encoded(result).decode(),end='')
        if result.get('status')=='dispatch_failed_unidentified':
            raise runtime.InfrastructureError('One or more sibling steps failed or outlived the runtime bound')
    except BaseException as exc:
        record = {'status':getattr(exc,'status','protocol_or_fixture_failure'),
                  'error':type(exc).__name__+': '+str(exc), 'wall_ns':time.time_ns(), **GATES}
        journal.append('failure',record)
        if authority is not None:
            result_path=output_root/(args.operation+'-'+(args.role_id or 'allocation')+'.result.json')
            paths=[result_path]
            if args.operation=='role' and args.role_id=='D':
                paths.append(root/'dispatch-result.json')
            if args.operation != 'submit':  # a failed submit must not leave a flag that later blocks D
                paths.append(output_root/'batch.stop.json')  # per cell for GPU roles; the attempt root otherwise
            for path in paths:
                try:runtime.publish(path,record)
                except FileExistsError:pass
                except Exception as publication_error:
                    try:
                        print('Failure publication unavailable: '+str(path)+': '+
                              type(publication_error).__name__+': '+str(publication_error),
                              file=sys.stderr,flush=True)
                    except Exception:pass
        raise
    finally:
        journal.close()


if __name__ == '__main__':
    main()
