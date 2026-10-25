"""W/O normal trusted-fixture lifecycle inside separate sibling steps.

W controls only its native protocol socket. D owns E's srun process and wait.
O observes W/E through independent pidfds and read-only cgroup handles.
"""
from types import SimpleNamespace
import os
import socket
import time

import lcb_isolation_release_v2 as release
import lcb_isolation_batch_v2 as batch
import lcb_isolation_runtime_v2 as runtime
import lcb_isolation_control_v2 as control
import lcb_isolation_backend_v2 as backend
import lcb_isolation_meter_v2 as meter
import lcb_supervision_site_v3 as site


def baseline(authority, record, controller, journal):
    step = site.GroupHandle(site.CGBASE+'/job_'+record['join']['job_id']+'/step_'+record['join']['step_id'])
    session = SimpleNamespace(host=site.LinuxHost(), step=step,
        lease={'schema':'isolation-step-baseline-v2', 'uid':authority.uid,
               'manifest_sha256':release.object_sha(authority.manifest),
               'step_cgroup':dict(step.identity), 'role_id':record['join']['role_id'],
               'nonce':record['join']['nonce']})
    try:
        return step, site.StepBaseline(session,controller,authority.assets['native_elf']['sha256'],journal)
    except BaseException:
        step.close(); raise


def pair(authority, own):
    records = runtime.wait_object(authority.root/'control-joins.json', authority.deadline_mono_ns,
                                  authority=authority)
    index = authority.role[1]
    w, o = records['W'+index], records['O'+index]
    release.check(records[authority.role]['join'] == own['join'], 'D changed own role binding')
    lease = release.object_sha({'manifest':release.object_sha(authority.manifest),
                               'worker':w['join'], 'observer':o['join']})
    return records, w, o, lease


def check_peer(connection, record):
    release.check(site.process_identity(connection.peer.identity) == site.process_identity(record['process']),
                  'Socket peer differs from D-verified live process')


def active_baseline(authority, baseline, armed, prepared, journal):
    """I's ARMED tree includes the runtime/factory, unlike S's tiny fixture.

    All observed user processes must be C descendants running pinned runtime
    components. The private I/J limits remain native checks, not a whole-step
    process count. Idle/closeout still use the unchanged strict S M+C checker.
    """
    release.require(authority,phase='runtime')
    host=baseline.session.host
    before=baseline.tree.snapshot()
    fixed=baseline.binding['baseline']
    c=fixed['controller'];m=fixed['management']
    release.check(set(armed['outer'])=={'factory','runtime'} and
                  all(type(v) is int and v>0 for v in armed['outer'].values()),'Native outer PID binding required')
    peer=armed['outer_evidence']
    release.check(peer['event']=='peer' and peer['actor']=='controller' and
                  peer['text']=='factory-exe-cgroup-pidfd' and
                  peer['case_index']==batch.CASES.index(armed['case_id'])+1 and
                  peer['values'][1]==armed['outer']['factory'] and
                  peer['values'][4]==armed['outer']['runtime'] and peer['values'][5]==peer['values'][1],
                  'Outer PID differs from current native PEER evidence')
    release.check(all(not baseline.handles[p['pid']].state()['exited'] for p in (c,m)),
                  'Persistent baseline process exited')
    required={c['pid'],m['pid'],armed['outer']['factory'],
              armed['roles']['created']['pid'],armed['roles']['judge_fd']['pid']}
    release.check(len(required)==5 and required <= set(before['full_step_pids']) and len(before['full_step_pids'])<=64,
                  'Missing declared I factory/init/judge or excessive trusted runtime tree')
    release.check(before['directories']==baseline.binding['directory_binding'] and
                  before['children']==baseline.initial['after']['children'] and
                  not before['procs']['']['pids'] and not before['procs']['user']['pids'] and
                  before['procs']['slurm']['pids']==[m['pid']] and
                  not before['procs'].get('user/task_special',{'pids':[]})['pids'],
                  'Active E directory layout or protected management leaf differs')
    lock=prepared['runtime_lock_value']
    hashes={authority.assets['native_elf']['sha256'],lock['runtime']['sha256']}
    hashes.update(row['sha256'] for row in lock['runtime_components'].values() if row['kind']=='executable')
    handles=[];observed=[]
    try:
        for pid in before['full_step_pids']:
            ident=host.process(pid)
            h=host.track(pid,ident['uid'],baseline.session.step.identity['path']);handles.append(h)
            if pid==m['pid']:
                release.check(site.process_identity(ident)==m,'Management baseline changed')
            else:
                release.check(ident['uid']==authority.uid and
                    ident['cgroup']==c['cgroup'] and host.executable_info(pid)['sha256'] in hashes,
                    'Unpinned executable or foreign process in active E')
                cursor=pid;ancestors=set()
                while cursor!=c['pid']:
                    release.check(cursor>1 and cursor not in ancestors and len(ancestors)<64,
                                  'Active E process is not C descendant')
                    ancestors.add(cursor)
                    tail=runtime.read_proc('/proc/'+str(cursor)+'/stat').decode().rsplit(')',1)[1].split()
                    cursor=int(tail[1])
                release.check(not h.state()['exited'],'Active E process exited during observation')
            observed.append(site.process_identity(ident))
        by_pid={v['pid']:v for v in observed}
        for declared in (c,m,*armed['roles'].values()):
            release.check(by_pid[declared['pid']]==site.process_identity(declared),'Declared actor identity differs from live process')
        runtime_pid=armed['outer']['runtime']
        if runtime_pid in by_pid:
            runtime_observation={'pid':runtime_pid,'status':'observed_active','identity':by_pid[runtime_pid]}
        else:
            try:host.process(runtime_pid)
            except FileNotFoundError:
                runtime_observation={'pid':runtime_pid,'status':'not_present_at_armed','reaped':None,
                                     'binding':'native_PEER_evidence_only_not_exit_proof'}
            else:raise ValueError('Runtime PID exists outside the observed E tree')
        after=baseline.tree.snapshot()
        release.check(before==after and all(site.process_identity(host.process(v['pid']))==v for v in observed),
                      'Active E tree changed during observation')
        journal.append('isolation_active_baseline_v2',{'before':before,'after':after,
            'processes':observed,'required_pids':sorted(required),'outer':armed['outer'],
            'outer_evidence':peer,'runtime_observation':runtime_observation,
            'baseline_binding':baseline.binding,'scope':'pinned_C_descendant_tree_not_private_nproc_claim'})
    finally:
        for h in handles:h.close()


def run(authority, own, journal):
    release.require(authority, phase='runtime', role=own['join']['role_id'])
    return worker(authority,own,journal) if authority.role.startswith('W') else observer(authority,own,journal)


def worker(authority, own, journal):
    import lcb_isolation_owner_v2 as owner
    key = control.key_bytes(authority.root/('key-'+own['join']['worker_id']))
    _, w, o, lease = pair(authority,own)
    ready = runtime.wait_object(authority.root/(o['join']['role_id']+'.listening.json'),
                               authority.deadline_mono_ns, authority=authority)
    address = str(authority.root/('o-'+own['join']['worker_id']+'.sock'))
    release.check(ready == {'role_id':o['join']['role_id'], 'nonce':o['join']['nonce'], 'socket':address},
                  'Observer listener binding differs')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    witness = channel = capture = ecapture = tree = group = None
    try:
        sock.settimeout(control.remaining(authority.deadline_mono_ns)); sock.connect(address); sock.setblocking(False)
        witness = control.ReadyConnection(sock,authority,w['join']['job_id'],lease,key,
                                          o['join']['role_id'],o['join']['step_id'])
        check_peer(witness,o)
        capture = meter.Capture(authority,own['subject'],journal,
            endpoint_config_sha256=runtime.endpoint_config_digest(authority,authority.role))
        capture.sample('worker_setup')
        witness.request('bootstrap', {'lease':lease}, authority.deadline_mono_ns)
        prepared = owner.assets.recheck_prepared_assets(authority)
        eslot = batch.role_for(authority.manifest,'E'+authority.role[1])
        channel = control.NativeChannel(authority,eslot,journal,owner.native_environment(authority,prepared),
                                         broker=owner.WorkerBroker(authority),live_join=own['join'],defer_hello=True)
        all_roles = runtime.bundle_check(authority, runtime.wait_object(authority.root/'7-joins.json',
            channel.deadline_ns, authority=authority))
        e = runtime.wait_object(authority.root/(eslot['role_id']+'.bound.json'),channel.deadline_ns,authority=authority)
        release.check(all_roles['subjects'][eslot['role_id']] == e['subject'], 'Execution subject differs')
        ecapture = meter.Capture(authority,e['subject'],journal,
            endpoint_config_sha256=runtime.endpoint_config_digest(authority,eslot['role_id']))
        ecapture.sample('execution_setup')
        group, tree = baseline(authority,e,channel.identity,journal)
        channel.receive_hello()
        witness.request('native_ready', {'controller':channel.identity,'execution':e,'lease':lease}, channel.deadline_ns)
        # Every role and resource has now been joined by D before C receives auth.
        channel.authenticate()
        adapter = backend.FixedFixtureAdapter(authority,channel)
        for case_id in batch.CASES:
            request = backend.fixture_request(authority,eslot['worker_id'],case_id)
            witness.request('case_begin', {'case_id':case_id},channel.deadline_ns)
            capture.sample('case_begin',case_id=case_id); ecapture.sample('case_begin',case_id=case_id)
            armed = adapter.prepare(request,channel.deadline_ns)
            active_baseline(authority,tree,armed,prepared,journal)
            witness.request('case_armed',armed,channel.case_deadline)
            receipt = adapter.finish(request,channel.case_deadline)
            tree.sample('closeout')
            capture.sample('case_closed',case_id=case_id); ecapture.sample('case_closed',case_id=case_id)
            witness.request('case_closed',receipt,channel.deadline_ns)
            journal.append('case_receipt',receipt)
        capture.sample('last_pre_retirement'); ecapture.sample('last_pre_retirement')
        stopped = channel.stop(channel.deadline_ns)
        journal.append('native_stop_complete',stopped)
        witness.request('retired',{'controller':stopped['C']},channel.deadline_ns)
        verified = channel.wait_launcher(authority.deadline_mono_ns)
        journal.append('native_srun_wait_observed',verified)
        witness.request('finished',{'cases':list(batch.CASES)},authority.deadline_mono_ns)
        capture.sample('worker_cleanup')
        return {'status':'trusted_fixture_loop_complete_pending_review',**owner.GATES}
    finally:
        for cap, name in ((ecapture,'E'+authority.role[1]),(capture,authority.role)):
            if cap is not None:
                runtime.publish(authority.root/(name+'.meter.json'),cap.export_record()); cap.close()
        if tree is not None: tree.close()
        if group is not None: group.close()
        if channel is not None: channel.close()
        if witness is not None: witness.close()
        else: sock.close()


def observer(authority, own, journal):
    import lcb_isolation_owner_v2 as owner
    key = control.key_bytes(authority.root/('key-'+own['join']['worker_id']))
    address = authority.root/('o-'+own['join']['worker_id']+'.sock')
    listener = control._listen(address)
    runtime.publish(authority.root/(authority.role+'.listening.json'),
        {'role_id':authority.role,'nonce':own['join']['nonce'],'socket':str(address)})
    witness = capture = tree = group = None
    tracked = {}
    try:
        _, w, o, lease = pair(authority,own)
        capture = meter.Capture(authority,own['subject'],journal,
            endpoint_config_sha256=runtime.endpoint_config_digest(authority,authority.role))
        capture.add_cross(w['subject']); capture.sample('observer_setup')
        tracked['W'] = site.ProcessHandle(w['process']['pid'],authority.uid,
            site.CGBASE+'/job_'+w['join']['job_id']+'/step_'+w['join']['step_id'])
        conn = control._accept(listener,authority.deadline_mono_ns)
        witness = control.ReadyConnection(conn,authority,w['join']['job_id'],lease,key,
                                          w['join']['role_id'],w['join']['step_id'])
        check_peer(witness,w)
        # Hashing/rechecking assets precedes bootstrap ACK and the E request.
        prepared = owner.assets.recheck_prepared_assets(authority)
        phase, current = 'bootstrap', 0
        while True:
            message = witness.receive(authority.deadline_mono_ns)
            event, wrapper = message['event'], message['data']; value = wrapper['value']
            journal.append('authenticated_worker_event',{'event':event,'value':value})
            if event == 'bootstrap':
                release.check(phase == 'bootstrap' and value == {'lease':lease}, 'Bootstrap phase/lease differs')
                phase = 'native_ready'
            elif event == 'native_ready':
                release.check(phase == 'native_ready' and value['lease'] == lease,'Native registration order')
                bundle = runtime.bundle_check(authority,runtime.wait_object(authority.root/'7-joins.json',
                    authority.deadline_mono_ns,authority=authority))
                e = value['execution']
                release.check(e['subject'] == bundle['subjects']['E'+authority.role[1]], 'Foreign E subject')
                checked = runtime.observe_role(authority,e['join']['role_id'],value['controller']['pid'],
                    owner.native_argv(authority,e['join']['role_id'],prepared),
                    expected_step=e['join']['step_id'])
                release.check(checked['join'] == e['join'], 'Observer native identity differs')
                group, tree = baseline(authority,e,value['controller'],journal)
                tracked['C'] = site.ProcessHandle(value['controller']['pid'],authority.uid,group.identity['path'])
                capture.add_cross(e['subject']); phase = 'case_begin'
            elif event == 'case_begin':
                release.check(phase == 'case_begin' and current < 3 and value == {'case_id':batch.CASES[current]},
                              'Case begin order differs')
                capture.sample('case_begin',case_id=batch.CASES[current]); phase = 'case_armed'
            elif event == 'case_armed':
                release.check(phase == 'case_armed' and value['case_id'] == batch.CASES[current], 'Case armed order differs')
                for name, identity in value['roles'].items():
                    handle = site.ProcessHandle(identity['pid'],authority.uid,group.identity['path'])
                    release.check(site.process_identity(handle.identity) == site.process_identity(identity), 'I/J identity differs')
                    tracked[name] = handle
                active_baseline(authority,tree,value,prepared,journal)
                phase = 'case_closed'
            elif event == 'case_closed':
                release.check(phase == 'case_closed' and value['case_id'] == batch.CASES[current]
                              and not tracked['C'].state()['exited'], 'Case close order/controller differs')
                for name in ('created','judge_fd'):
                    release.check(tracked[name].state()['registered_process_reaped'], 'Case member not reaped')
                    tracked.pop(name).close()
                tree.sample('closeout')
                capture.sample('case_closed',case_id=batch.CASES[current]); current += 1
                phase = 'case_begin' if current < 3 else 'retired'
            elif event == 'retired':
                release.check(phase == 'retired' and tracked['C'].state()['registered_process_reaped'], 'C retirement unverified')
                capture.retire_cross('E'+authority.role[1])
                journal.append('native_retirement',tree.retirement()); phase = 'finished'
            elif event == 'finished':
                release.check(phase == 'finished' and value == {'cases':list(batch.CASES)}, 'Incomplete final case list')
                while not all(v['registered_process_reaped'] for v in (
                    tree.retirement()['management_state'],tree.retirement()['controller_state'])):
                    time.sleep(control.remaining(authority.deadline_mono_ns,.005))
                journal.append('native_retirement',tree.retirement())
                # E may already be removed; stop cross sampling after retirement.
                capture.sample('observer_cleanup')
            else:
                raise ValueError('Unreviewed W/O event')
            witness.send('ack',{'event':event,'challenge':wrapper['challenge']})
            if event == 'finished':
                return {'status':'observer_complete_pending_review',**dict.fromkeys(release.GATES,False)}
    except runtime.CooperativeStop:
        # This runs between synchronous snapshots. Finish one bounded cross
        # observation before the existing finally block seals the series.
        if capture is not None:
            try:
                capture.sample('observer_cooperative_stop')
            except (OSError, ValueError) as exc:
                journal.append('observer_shutdown_observation_unavailable',
                               {'error':type(exc).__name__+': '+str(exc)})
        raise
    finally:
        if capture is not None:
            runtime.publish(authority.root/(authority.role+'.meter.json'),capture.export_record()); capture.close()
        for handle in tracked.values(): handle.close()
        if tree is not None: tree.close()
        if group is not None: group.close()
        if witness is not None: witness.close()
        listener.close()
