"""Independent I owner submit/W/O/GPU entries. Every live path needs I R+owner.

No live command is run on import or by tests. The checked-in registry and new
ELF assets are pending, so submit/worker/observer/gpu fail before dispatch.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import select
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_release_v1 as release
import lcb_isolation_batch_v1 as batch
import lcb_isolation_control_v1 as control
import lcb_isolation_meter_v1 as meter
import lcb_isolation_backend_v1 as backend
import lcb_isolation_native_v1 as native
import lcb_supervision_site_v3 as site

GPU_PROBE = """import json, torch
assert torch.cuda.is_available() and torch.cuda.device_count() == 1, 'One visible CUDA device required'
p = torch.cuda.get_device_properties(0)
u = str(p.uuid)
print(json.dumps({'gpu_uuid': u if u.startswith('GPU-') else 'GPU-' + u,
                  'gpu_name': p.name, 'gpu_memory_bytes': p.total_memory,
                  'visible_device_count': torch.cuda.device_count()}))
"""
GPU_UUID = r'GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'


class ObservationUnavailable(Exception):
    """A bounded command observation failed; never an identity/permission error."""


class Client:
    """Bounded fixed Slurm client verbs with original argv/rc/stdout/stderr."""
    def __init__(self, authority, journal):
        release.require(authority); self.authority, self.journal = authority, journal

    def command(self, name, arguments, *, timeout_s=10, maximum=1024**2):
        release.require(self.authority)
        release.check(name in ('sbatch', 'scontrol', 'timedatectl'), 'No arbitrary live command')
        asset = self.authority.assets[name]
        raw = release.read(asset['path'], 32*1024**2)
        release.check(release.sha(raw) == asset['sha256'] and Path(asset['path']).stat().st_uid == 0, 'Pinned root executable')
        argv = [asset['path'], *arguments]; out = err = b''; proc = None
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=release.ENV, close_fds=True)
            deadline = time.monotonic()+timeout_s
            buffers = [bytearray(), bytearray()]
            selector = select.poll()
            streams = {proc.stdout.fileno(): 0, proc.stderr.fileno(): 1}
            for fd in streams:
                os.set_blocking(fd, False); selector.register(fd, select.POLLIN | select.POLLHUP)
            while streams:
                if time.monotonic() >= deadline:
                    raise ObservationUnavailable('Fixed client command timeout')
                for fd, _ in selector.poll(20):
                    chunk = os.read(fd, min(65536, maximum+1-len(buffers[streams[fd]])))
                    if not chunk:
                        selector.unregister(fd); del streams[fd]; continue
                    buffers[streams[fd]].extend(chunk)
                    release.check(len(buffers[streams[fd]]) <= maximum, 'Client output bound')
            out, err = map(bytes, buffers)
            code = proc.wait(timeout=max(.001, deadline-time.monotonic()))
            if code != 0 or err:
                raise ObservationUnavailable('Client observation failed; no retry/resubmission')
            release.check(release.sha(release.read(asset['path'], 32*1024**2)) == asset['sha256'], 'Client changed')
            return out.decode('utf-8', 'strict')
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()  # Only this exact short-lived CLI child, never a Slurm target.
                proc.wait(timeout=1)
                proc.stdout.close(); proc.stderr.close()
            self.journal.append('client', {'argv': argv, 'environment': release.ENV,
                'returncode': None if proc is None else proc.returncode,
                'stdout': out.decode('utf-8', 'replace'), 'stderr': err.decode('utf-8', 'replace'),
                'binary_sha256': asset['sha256'], 'no_retry': True})

    def job(self, job_id):
        release.number(job_id)
        return self.command('scontrol', ['--clusters=cluster', '--oneliner', 'show', 'job', job_id])


def role_argv(authority, role, slot_id):
    return [authority.assets['python']['path'], '-I', '-B', str(release.ROOT/'scripts/calibration/lcb_isolation_owner_v1.py'),
            role, '--root', str(authority.root), '--owner-sha256', authority.owner_sha,
            '--review-sha256', authority.review_sha, '--slot', slot_id, '--execute']


def submission_argv(authority, slot, *, node=None):
    release.require(authority)
    name, comment = batch.labels(authority.manifest, slot)
    template = release.ROOT/('experiments/calibration/isolation-'+slot['role']+'-v1.slurm.template')
    release.check(release.sha(release.read(template)) == authority.snapshot['files_sha256'][str(template.relative_to(release.ROOT))], 'Template differs from registered source')
    seconds = slot['walltime_s']; hours, residue = divmod(seconds, 3600); minutes, seconds = divmod(residue, 60)
    argv = ['--clusters=cluster', '--parsable', '--nodes=1', '--ntasks=1', '--no-requeue',
            '--partition='+slot['partitions'], '--qos='+slot['qos'], '--job-name='+name, '--comment='+comment,
            '--cpus-per-task='+str(slot['cpus']), '--mem='+str(slot['memory_bytes']//1024**2)+'M',
            '--time='+f'{hours:02d}:{minutes:02d}:{seconds:02d}', '--export=NONE',
            '--output='+str(authority.root/(slot['slot_id']+'.slurm.stdout')),
            '--error='+str(authority.root/(slot['slot_id']+'.slurm.stderr'))]
    if node is not None:
        release.token(node); argv.append('--nodelist='+node)
    if slot['role'] == 'gpu':
        argv.append('--gres=gpu:1')
    else:
        argv.append('--gres=none')
    # Template has a fixed interpreter/script path derived only from this
    # reviewed source. It cannot accept an arbitrary program or shell fragment.
    return [*argv, str(template), str(release.ROOT), str(authority.root), authority.owner_sha,
            authority.review_sha, slot['slot_id']]


def submit_one(authority, client, slot, *, node=None):
    release.consume_slot(authority, slot['slot_id'], 'submission')  # before every possible failing step
    result = {'slot_id': slot['slot_id'], 'job_id': None, 'status': 'failed_or_unidentified_no_retry'}
    try:
        release.check(not (authority.root/'batch.stop').exists(), 'Prior unexpected failure permanently stops dispatch')
        current, _ = release.source_snapshot()
        release.check(current == authority.snapshot, 'Source changed after authority issue')
        prepared = release.recheck_prepared_assets(authority)
        client.journal.append('submission_asset_identity_check', prepared)
        release.check(time.time_ns()+slot['walltime_s']*10**9 < authority.owner['expires_ns'], 'Insufficient approved run time after queue')
        raw = client.command('sbatch', submission_argv(authority, slot, node=node), timeout_s=15)
        match = re.fullmatch(r'([1-9][0-9]*)(?:;cluster)?\n?', raw)
        release.check(match, 'Unidentified submission outcome; do not resubmit')
        result.update(job_id=match[1], status='submitted_once')
        return result
    finally:
        release.publish_new(authority.root/('submission-'+slot['slot_id']+'.json'), result)


def wait_running(authority, client, slot, submitted):
    # The exact owner wall window covers queue time. A pending job does not get
    # a fresh relative TTL at each poll; no repeated sbatch occurs here.
    deadline = authority.owner['expires_ns']-slot['walltime_s']*10**9
    while time.time_ns() < deadline:
        release.require(authority)
        raw = client.job(submitted['job_id'])
        state = re.search(r'(?:^|\s)JobState=([^\s]+)', raw)
        release.check(state is not None, 'Unidentified queue state')
        if state[1] == 'RUNNING':
            actual = batch.parse_job(raw, submitted['job_id'])
            return batch.live_join(authority.manifest, slot, actual, job_id=submitted['job_id'])
        release.check(state[1] in ('PENDING', 'CONFIGURING'), 'Unexpected queued/terminal job; stop dispatch')
        time.sleep(min(authority.manifest['queue_poll_s'], max(.001, (deadline-time.time_ns())/10**9)))
    raise PermissionError('Owner queue window exhausted; slot remains consumed')


def submit_batch(authority, journal):
    release.require(authority); client = Client(authority, journal)
    release.write_new(authority.root/'batch-dispatch.consumed.json', {'manifest_sha256': release.object_sha(authority.manifest),
                       'owner_sha256': authority.owner_sha, 'wall_ns': time.time_ns()})
    journal.append('batch_assets_prepared', release.prepare_batch_assets(authority))
    for worker in batch.WORKERS:
        release.write_new(authority.root/('key-'+worker), secrets.token_bytes(32))
    observers = {}
    for worker in batch.WORKERS:
        s = batch.peer_slot(authority.manifest, worker, 'observer')
        observers[worker] = submit_one(authority, client, s, node=authority.manifest['cpu_node'])
    for worker in batch.WORKERS:
        s = batch.peer_slot(authority.manifest, worker, 'observer')
        joined = wait_running(authority, client, s, observers[worker])
        w = batch.peer_slot(authority.manifest, worker, 'worker')
        submit_one(authority, client, w, node=joined['node'])
    for slot in authority.manifest['slots']:
        if slot['role'] == 'gpu':
            submit_one(authority, client, slot)
    return {'status': 'finite_slots_submitted_once_not_accepted', **dict.fromkeys(release.GATES, False)}


def wait_object(path, deadline_ns):
    while time.monotonic_ns() < deadline_ns:
        try:
            return release.strict(release.read_published(path))
        except FileNotFoundError:
            time.sleep(control.remaining(deadline_ns, .02))
    raise control.InfrastructureError('Published-record deadline exceeded; no automatic retry')


def bind_role(authority, slot, client):
    claimed = release.consume_slot(authority, slot['slot_id'], 'execution')
    release.check(claimed == slot, 'Execution slot changed')
    job_id = release.number(os.environ.get('SLURM_JOB_ID', ''))
    published = wait_object(authority.root/('submission-'+slot['slot_id']+'.json'),
                            control.wait_deadline(authority, 'bind_wait_s'))
    release.check(published['status'] == 'submitted_once' and published['job_id'] == job_id, 'Unbound or duplicate live allocation')
    host = site.LinuxHost(); ctx = host.context()
    actual = batch.parse_job(client.job(job_id), job_id)
    join = batch.live_join(authority.manifest, slot, actual, job_id=job_id, local_context=ctx)
    if slot['role'] in ('worker', 'observer'):
        group = host.group(site.CGBASE+'/job_'+job_id)
        try:
            hard = group.resources()
            release.check(len(hard['logical_cpu_ids']) == 1 and hard['memory_max_bytes'] == 1073741824, 'Hard one-CPU/1GiB CPU judge domain')
            join['hard_resources'] = hard
        finally:
            group.close()
        model = [line.split(':', 1)[1].strip() for line in release.read('/proc/cpuinfo', 4*1024**2).decode().splitlines()
                 if line.startswith('model name')]
        release.check(model and set(model) == {authority.manifest['cpu_model']}, 'Exact CPU model admission')
    client.journal.append('isolation_job_binding', {'join': join, 'context': ctx})
    return join, ctx


def clock_qualification(client, journal):
    rows = []
    for argv in (['--no-ask-password', '--no-pager', 'show', '--property=NTPSynchronized', '--property=TimeUSec'],
                 ['--no-ask-password', '--no-pager', 'timesync-status']):
        try:
            # 4s observation + the exact child cleanup <=1s = existing 5s bound.
            rows.append(client.command('timedatectl', argv, timeout_s=4))
        except (ObservationUnavailable, subprocess.TimeoutExpired, TimeoutError) as exc:
            journal.append('clock_query_unavailable', {'argv': argv, 'error': type(exc).__name__+': '+str(exc),
                                                       'qualified': False, 'retry': False})
            rows.append('')
        # PermissionError and source/client identity ValueError propagate.
    first, second = rows
    offset = re.search(r'^\s*Offset:\s*([+-]?[0-9.]+)\s*(us|µs|μs|ms|s)\s*$', second, re.MULTILINE)
    qualified = 'NTPSynchronized=yes' in first.splitlines() and offset is not None
    if qualified:
        nanoseconds = abs(float(offset[1]))*{'us': 1000, 'µs': 1000, 'μs': 1000, 'ms': 10**6, 's': 10**9}[offset[2]]
        qualified = nanoseconds <= 100_000_000
    journal.append('clock_qualification', {'qualified': qualified, 'protocol_clock_error_ns': 10**9,
                                         'first_raw': first, 'second_raw': second})
    return qualified


def _native_env(authority, asset_check):
    import lcb_permission_assets_v3 as runtime_policy
    lock = asset_check['runtime_lock_value']; front = Path(lock['runtime']['path']).stat()
    runtime_policy.verify_same_run(asset_check['runtime_final_snapshot'], runtime_policy.snapshot(lock))
    starter = Path(lock['runtime_components']['starter']['path']).stat()
    pin = {'inode': front.st_ino, 'dev_major': os.major(front.st_dev), 'dev_minor': os.minor(front.st_dev),
           'bytes': front.st_size, 'mtime_ns': front.st_mtime_ns, 'ctime_ns': front.st_ctime_ns,
           'gid': front.st_gid, 'mode': front.st_mode}
    starter_pin = {'inode': starter.st_ino, 'dev_major': os.major(starter.st_dev), 'dev_minor': os.minor(starter.st_dev)}
    return {**release.ENV, **{k: v for k, v in os.environ.items() if k.startswith('SLURM_')},
            **native.frontend_env(pin, starter_pin), '_runtime_lock': lock}


def worker(authority, slot, journal):
    release.require(authority); client = Client(authority, journal)
    join, ctx = bind_role(authority, slot, client)
    assets = release.recheck_assets(authority.assets, authority.snapshot)
    key = control.key_bytes(authority.root/('key-'+slot['worker_id']))
    obs = batch.peer_slot(authority.manifest, slot['worker_id'], 'observer')
    ready_deadline = control.wait_deadline(authority, 'ready_wait_s', live_join=join)
    observer_packet = control.authenticate(wait_object(authority.root/('bound-'+obs['slot_id']+'.json'), ready_deadline), key)
    observer = observer_packet['join']
    pair = batch.join_pair(join, observer)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    witness = capture = channel = None
    try:
        sock.settimeout(control.remaining(ready_deadline)); sock.connect(str(authority.root/('o-'+slot['worker_id']+'.sock')))
        sock.setblocking(False)
        witness = control.ReadyConnection(sock, authority, observer['job_id'], pair['lease_sha256'], key, obs['slot_id'])
        qualified = clock_qualification(client, journal)
        witness.request('bootstrap', {'pair': pair, 'clock_qualified': qualified}, ready_deadline)
        release.publish_new(authority.root/('pre-native-'+slot['worker_id']+'.json'), control.seal(pair, key))
        all_pairs = []
        for wid in batch.WORKERS:
            all_pairs.append(control.authenticate(wait_object(authority.root/('pre-native-'+wid+'.json'), ready_deadline),
                                                 control.key_bytes(authority.root/('key-'+wid))))
        journal.append('pre_native_barrier', batch.pre_native_barrier(all_pairs))
        capture = meter.Capture(authority, join['job_id'], journal, live_join=join,
                                clock_qualified=qualified and observer_packet['clock_qualified'] is True)
        capture.sample('job_setup')
        channel = control.NativeChannel(authority, slot, journal, _native_env(authority, assets), live_join=join)
        capture.execution(channel.step_id)
        baseline = {pid: site.process(pid) for pid in capture.step.pids()}
        witness.request('native_ready', {'C': channel.identity, 'step_id': channel.step_id}, channel.deadline_ns)
        ready = {'batch_id': authority.manifest['batch_id'], 'worker_id': slot['worker_id'],
                 'C': channel.identity, 'node': ctx['node'], 'boot_id': ctx['boot_id'],
                 'observed_ns': time.monotonic_ns(), 'manifest_sha256': release.object_sha(authority.manifest)}
        release.publish_new(authority.root/('native-ready-'+slot['worker_id']+'.json'), control.seal(ready, key))
        barrier = control.wait_deadline(authority, 'barrier_wait_s', live_join=join,
                                        hard_deadline_ns=channel.deadline_ns)
        peers = []
        for wid in batch.WORKERS:
            other = control.authenticate(wait_object(authority.root/('native-ready-'+wid+'.json'), barrier),
                                          control.key_bytes(authority.root/('key-'+wid)))
            release.check(other['batch_id'] == authority.manifest['batch_id'] and other['node'] == ctx['node']
                          and other['boot_id'] == ctx['boot_id'] and other['manifest_sha256'] == release.object_sha(authority.manifest), 'Two-worker common host/boot barrier')
            peers.append(other)
        journal.append('two_worker_ready', peers)
        channel.authenticate()  # C's 120s service lifetime begins only now.
        adapter = backend.FixedFixtureAdapter(authority, channel)
        for case_id in batch.CASES:
            request = backend.fixture_request(authority, slot['worker_id'], case_id)
            capture.sample('case_begin', case_id=case_id)
            armed = adapter.prepare(request, channel.deadline_ns)
            witness.request('case_armed', armed, channel.case_deadline)
            capture.sample('case_armed', case_id=case_id)
            receipt = adapter.finish(request, channel.case_deadline)
            release.check(set(capture.step.pids()) == set(baseline)
                          and all(all(site.process(pid)[k] == value[k] for k in ('pid', 'start_ticks', 'uid', 'cgroup'))
                                  for pid, value in baseline.items()), 'Unexpected persistent E member or replaced baseline')
            capture.sample('case_closed', case_id=case_id)
            witness.request('case_closed', receipt, channel.deadline_ns)
            journal.append('case_receipt', receipt)
        capture.sample('last_pre_retirement')
        stopped = channel.stop(channel.deadline_ns)
        endpoint = capture.post_retirement(channel.peer, channel.deadline_ns)
        journal.append('native_stop_complete', stopped)
        witness.request('retired', {'C': stopped['C'], 'endpoint_status': endpoint['status']}, channel.deadline_ns)
        verified = channel.wait_launcher(channel.deadline_ns)
        first_prepare = [r['ns'] for r in channel.rows if r['actor'] == 'controller' and r['event'] == 'prepare']
        last_finish = [r['ns'] for r in channel.rows if r['actor'] == 'controller' and r['event'] == 'case_finish']
        service_window = {'node': ctx['node'], 'boot_id': ctx['boot_id'], 'time_namespace': ctx['time_namespace'],
                          'first_prepare_ns': min(first_prepare), 'last_finish_ns': max(last_finish),
                          'worker_id': slot['worker_id'], 'trace_sha256': verified['trace_sha256']}
        release.publish_new(authority.root/('service-window-'+slot['worker_id']+'.json'), control.seal(service_window, key))
        journal.append('native_srun_wait_return', {'ns': time.monotonic_ns(), 'trace': verified})
        witness.request('finished', {'cases': list(batch.CASES)}, time.monotonic_ns()+5*10**9)
        return {'status': 'trusted_I_records_collected_pending_acceptance', 'M_endpoint': endpoint['status'],
                **dict.fromkeys(release.GATES, False)}
    finally:
        if channel is not None:
            channel.close()
        if capture is not None:
            capture.close()
        if witness is not None:
            witness.close()
        else:
            sock.close()


def observer(authority, slot, journal):
    client = Client(authority, journal); join, ctx = bind_role(authority, slot, client)
    release.recheck_assets(authority.assets, authority.snapshot)
    qualified = clock_qualification(client, journal)
    key = control.key_bytes(authority.root/('key-'+slot['worker_id']))
    listener = control._listen(authority.root/('o-'+slot['worker_id']+'.sock'))
    witness = capture = None; tracked = {}; cgroup = None
    try:
        release.publish_new(authority.root/('bound-'+slot['slot_id']+'.json'), control.seal({'join': join, 'clock_qualified': qualified}, key))
        queue_deadline = control.wait_deadline(authority, 'observer_wait_running_s', live_join=join)
        w = batch.peer_slot(authority.manifest, slot['worker_id'], 'worker')
        sub = wait_object(authority.root/('submission-'+w['slot_id']+'.json'), queue_deadline)
        while True:
            control.remaining(queue_deadline)
            raw = client.job(sub['job_id'])
            state = re.search(r'(?:^|\s)JobState=([^\s]+)', raw)
            release.check(state is not None and state[1] in ('PENDING', 'CONFIGURING', 'RUNNING'), 'Unexpected W queue state')
            if state[1] == 'RUNNING':
                break
            time.sleep(control.remaining(queue_deadline, .1))
        worker_job = batch.parse_job(raw, sub['job_id'])
        worker_join = batch.live_join(authority.manifest, w, worker_job, job_id=sub['job_id'])
        worker_join['boot_id'] = ctx['boot_id']
        worker_join['time_namespace'] = ctx['time_namespace']
        # W independently supplies its hard-resource join inside authenticated
        # bootstrap. Both sides then freeze exactly those complete bytes.
        capture = meter.Capture(authority, join['job_id'], journal, live_join=join,
                                clock_qualified=qualified)
        capture.sample('job_setup')
        capture.add(sub['job_id'], 'batch')
        capture.add(sub['job_id'], 'extern')
        conn = control._accept(listener, control.wait_deadline(authority, 'ready_wait_s', live_join=join))
        # Bootstrap lease derives from stable identities only; W hard resources
        # are separately cross-read below, rather than guessed into its join.
        worker_group = site.GroupHandle(site.CGBASE+'/job_'+sub['job_id'])
        try:
            worker_join['hard_resources'] = worker_group.resources()
        finally:
            worker_group.close()
        pair = batch.join_pair(worker_join, join)
        witness = control.ReadyConnection(conn, authority, sub['job_id'], pair['lease_sha256'], key, w['slot_id'])
        deadline = control.role_deadline(authority, join)
        phase, expected_case = 'bootstrap', 0
        while True:
            message = witness.receive(deadline); event = message['event']; wrapper = message['data']; data = wrapper['value']
            journal.append('authenticated_worker_event', {'event': event, 'data': data})
            if event == 'bootstrap':
                release.check(phase == 'bootstrap' and data['pair'] == pair, 'Exact independently joined pair')
                journal.append('pair_clock_qualification', {'qualified': qualified and data['clock_qualified'] is True})
                capture.clock_qualified = qualified and data['clock_qualified'] is True
                phase = 'native_ready'
            elif event == 'native_ready':
                release.check(phase == 'native_ready', 'Duplicate C registration')
                release.number(data['step_id'], zero=True)
                tracked['C'] = site.ProcessHandle(data['C']['pid'], join['uid'], site.CGBASE+'/job_'+sub['job_id']+'/step_'+data['step_id'])
                release.check(tracked['C'].identity == data['C'] and site.LinuxHost().executable_info(data['C']['pid'])['sha256'] == authority.assets['native_elf']['sha256'], 'Observer actual C identity')
                cgroup = site.GroupHandle(site.CGBASE+'/job_'+sub['job_id']+'/step_'+data['step_id'])
                capture.add(sub['job_id'], data['step_id']); phase = 'case_armed'
            elif event == 'case_armed':
                release.check(phase == 'case_armed' and expected_case < 3 and data['case_id'] == batch.CASES[expected_case], 'Independent case order')
                for role, identity in data['roles'].items():
                    tracked[role] = site.ProcessHandle(identity['pid'], join['uid'], cgroup.identity['path'])
                    release.check(tracked[role].identity == identity, 'Observer actual I/J role identity')
                capture.sample('case_armed', case_id=data['case_id']); phase = 'case_closed'
            elif event == 'case_closed':
                release.check(phase == 'case_closed' and data['case_id'] == batch.CASES[expected_case]
                              and not tracked['C'].state()['exited'], 'C must persist through case closeout')
                for role in ('created', 'judge_fd'):
                    release.check(tracked[role].state()['registered_process_reaped'] is True, 'Observer I/J reap incomplete')
                    tracked.pop(role).close()
                capture.sample('case_closed', case_id=data['case_id']); expected_case += 1
                phase = 'case_armed' if expected_case < 3 else 'retired'
            elif event == 'retired':
                release.check(phase == 'retired' and tracked['C'].state()['registered_process_reaped'] is True, 'Independent retired C proof')
                capture.seal_subject(sub['job_id'])
                phase = 'finished'
            elif event == 'finished':
                release.check(phase == 'finished' and data['cases'] == list(batch.CASES), 'All cases before final observer completion')
                capture.sample('observer_cleanup')
            else:
                raise ValueError('Unreviewed ready/control event')
            witness.send('ack', {'event': event, 'challenge': wrapper['challenge']})
            if event == 'finished':
                return {'status': 'external_I_observations_pending_acceptance', **dict.fromkeys(release.GATES, False)}
    finally:
        for handle in tracked.values():
            handle.close()
        if cgroup is not None:
            cgroup.close()
        if capture is not None:
            capture.close()
        if witness is not None:
            witness.close()
        listener.close()


def gpu_identity_from_L(raw, allocation_id, hardware, cuda, expected_name):
    release.check(re.fullmatch(r'0|[1-9][0-9]*', allocation_id or '')
                  or re.fullmatch(GPU_UUID, allocation_id or ''), 'One canonical Slurm integer or complete UUID')
    lines = raw.strip().splitlines(); release.check(lines and not any('MIG' in x for x in lines), 'No MIG/empty enumeration')
    rows = []
    for line in lines:
        match = re.fullmatch(r'GPU [0-9]+: (.+) \(UUID: ('+GPU_UUID+r')\)', line)
        release.check(match, 'Exact nvidia-smi -L identity rows required')
        rows.append({'model': match[1], 'uuid': match[2]})
    release.check(len(rows) == 1, 'Complete unfiltered enumeration must expose exactly one GPU; no index selection')
    release.check(cuda.get('visible_device_count') == 1 and type(cuda.get('visible_device_count')) is int
                  and cuda.get('gpu_uuid') == rows[0]['uuid'] and cuda.get('gpu_name') == rows[0]['model'] == expected_name
                  and type(cuda.get('gpu_memory_bytes')) is int and cuda['gpu_memory_bytes'] >= 75*1024**3,
                  'Single CUDA device UUID/model/80GB envelope must equal full -L enumeration')
    if allocation_id.startswith('GPU-'):
        release.check(allocation_id == rows[0]['uuid'], 'Complete Slurm UUID must exactly match CUDA/NVML')
    model = rows[0]['model']
    release.check(('H100' in model and '80GB' in model) if hardware == 'H100-primary'
                  else ('A100' in model and '80GB' in model), 'Exact hardware family/80GB admission; no H200/L4 substitution')
    return {**rows[0], 'method': 'singleton_full_L_and_CUDA_identity', 'slurm_gpu_id_recorded_only': allocation_id}


def _gpu_command(argv, env, journal, label, timeout_s=30):
    # Only callers below construct these two fixed, source-bound argv vectors.
    done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=timeout_s, check=False)
    journal.append(label, {'argv': argv, 'returncode': done.returncode,
        'stdout': done.stdout.decode('utf-8', 'replace'), 'stderr': done.stderr.decode('utf-8', 'replace')})
    release.check(done.returncode == 0 and not done.stderr and len(done.stdout) <= 65536, 'GPU identity probe failed')
    return done.stdout.decode('utf-8', 'strict')


def gpu(authority, slot, journal):
    # Separate trusted identity job only; this is never native main generation.
    client = Client(authority, journal); join, ctx = bind_role(authority, slot, client)
    checked = release.recheck_assets(authority.assets, authority.snapshot)
    executable = authority.assets.get('nvidia_smi')
    release.check(executable is not None, 'GPU client/environment admission pending')
    release.check(release.stream_sha(executable['path'], 32*1024**2) == executable['sha256'], 'GPU client source changed')
    argv = [executable['path'], '-L']
    env = {**release.ENV, **{k: v for k, v in os.environ.items() if k.startswith(('SLURM_', 'CUDA_'))}}
    raw = _gpu_command(argv, env, journal, 'nvidia_smi_L', timeout_s=5)
    visible = os.environ.get('CUDA_VISIBLE_DEVICES', '')
    release.check(re.fullmatch(r'0|[1-9][0-9]*', visible) or re.fullmatch(GPU_UUID, visible), 'Preserve exactly one scheduler CUDA selector')
    lock = checked['runtime_lock_value']
    probe = [lock['runtime']['path'], 'exec', '--nv', '--cleanenv', '--no-eval', '--env', 'CUDA_VISIBLE_DEVICES='+visible]
    order = os.environ.get('CUDA_DEVICE_ORDER')
    if order is not None:
        release.check(order in ('PCI_BUS_ID', 'FASTEST_FIRST'), 'Known unchanged CUDA device order')
        probe += ['--env', 'CUDA_DEVICE_ORDER='+order]
    probe += [lock['cpu_sif']['path'], 'python3', '-I', '-B', '-c', GPU_PROBE]
    cuda = release.strict(_gpu_command(probe, env, journal, 'CUDA_identity_probe'))
    allocated = os.environ.get('SLURM_STEP_GPUS') or os.environ.get('SLURM_JOB_GPUS', '')
    identity = gpu_identity_from_L(raw, allocated, slot['hardware'], cuda, slot['expected_gpu_name'])
    release.check(release.stream_sha(executable['path'], 32*1024**2) == executable['sha256'], 'GPU client changed after probes')
    return {'status': 'GPU_identity_only_pending_environment_admission', 'job': join, 'identity': identity,
            'inference_calls': 0, **dict.fromkeys(release.GATES, False)}


def prepare_manifest(root, request_path):
    """Pure preparation: no Git, asset validation, R, owner approval, or permit."""
    value = batch.validate_manifest(release.strict(release.read(request_path)))
    root = Path(root)
    release.check(str(root) == value['attempt_root'] and release.ROOT not in root.parents, 'Manifest exact root outside source')
    if not root.exists():
        release.path_check(root.parent, private=True); os.mkdir(root, 0o700)
    release.path_check(root, private=True)
    release.write_new(root/'manifest.json', value)
    return {'status': 'manifest_prepared_not_approved', 'manifest_sha256': release.object_sha(value),
            'slots': len(value['slots']), **dict.fromkeys(release.GATES, False)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'submit', 'worker', 'observer', 'gpu'))
    parser.add_argument('--root', required=True); parser.add_argument('--owner-sha256')
    parser.add_argument('--review-sha256'); parser.add_argument('--slot'); parser.add_argument('--request')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.operation == 'prepare':
        if not args.request or args.execute or args.owner_sha256 or args.review_sha256:
            parser.error('Pure prepare requires --request and no execution/approval arguments')
        print(release.encoded(prepare_manifest(args.root, args.request)).decode(), end='')
        return
    if not args.owner_sha256 or not args.review_sha256:
        parser.error('Independent owner/R SHA256 arguments required')
    if not args.execute:
        parser.error('Explicit --execute plus independent I R/owner required; pending assets remain closed')
    try:
        authority = release.issue(args.root, owner_sha=args.owner_sha256, review_sha=args.review_sha256)
    except PermissionError as exc:
        parser.exit(78, str(exc)+'\n')
    journal = control.Journal(authority.root, 'owner-'+args.operation+'-'+(args.slot or 'batch')+'.jsonl')
    try:
        if args.operation == 'submit':
            result = submit_batch(authority, journal)
        else:
            slot = batch.slot_for(authority, args.slot)
            release.check(slot['role'] == args.operation, 'Exact role/slot match')
            result = {'worker': worker, 'observer': observer, 'gpu': gpu}[args.operation](authority, slot, journal)
        journal.append('result', result)
        print(release.encoded(result).decode(), end='')
    except BaseException as exc:
        journal.append('failure_no_retry', {'status': getattr(exc, 'status', 'protocol_or_fixture_failure'), 'type': type(exc).__name__, 'error': str(exc)})
        try:
            release.write_new(authority.root/'batch.stop', {'status': getattr(exc, 'status', 'protocol_or_fixture_failure'), 'type': type(exc).__name__, 'error': str(exc),
                              'owner_sha256': authority.owner_sha, 'permanent_for_this_attempt': True})
        except FileExistsError:
            pass
        raise
    finally:
        journal.close()


if __name__ == '__main__':
    main()
