"""Read-only live joins and atomic IPC for the single-allocation I runtime.

No scheduler client, executable launch or signal operation is defined here.
The owner verifies the allocation before any role can use these helpers.
"""
from copy import deepcopy
import os
from pathlib import Path
import re
import secrets
import stat
import time

import lcb_isolation_batch_v2 as batch
import lcb_isolation_release_v2 as release
import lcb_isolation_meter_v2 as meter
import lcb_task_epilog_v1 as epilog
import lcb_supervision_site_v3 as site


class InfrastructureError(RuntimeError):
    status = 'infrastructure_failure'


class CooperativeStop(InfrastructureError):
    """A sibling requested bounded shutdown, not a signal or a verdict."""


def read_proc(path, limit=16384):
    """Bound kernel pseudo-files by bytes, not their normally zero st_size."""
    release.check(type(path) is str and re.fullmatch(r'/proc/[1-9][0-9]*/(?:cmdline|stat|status|cgroup)',path),
                  'Literal numeric proc field required')
    release.integer(limit,1,1024**2)
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        release.check(stat.S_ISREG(before.st_mode),'Regular kernel field required')
        chunks=[];size=0
        while True:
            part=os.read(fd,min(65536,limit+1-size))
            if not part:break
            chunks.append(part);size+=len(part)
            release.check(size<=limit,'Kernel field exceeds bound')
        after=os.fstat(fd);named=os.stat(path,follow_symlinks=False)
        release.check((before.st_dev,before.st_ino,before.st_mode,before.st_uid)==
                      (after.st_dev,after.st_ino,after.st_mode,after.st_uid)==
                      (named.st_dev,named.st_ino,named.st_mode,named.st_uid),'Kernel field identity changed')
        return b''.join(chunks)
    finally:os.close(fd)


def _rename_claimed(parent, temporary, name):
    """Caller owns the persistent exclusive claim for this publication name.

    All I IPC publishers use that claim. An existing target from an older
    publisher is also refused. This is writer coordination, not protection
    against a different same-UID program deliberately replacing our files.
    """
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(name)
    os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)


def publish(path, value):
    """Expose complete immutable IPC bytes, with no post-publication inode change.

    link(temp, name) followed by unlink(temp) changes nlink/ctime after a
    reader can open name. One durable O_EXCL claim per target serializes our
    publishers; a normal atomic rename then exposes the finished inode. No
    optional rename flags or post-publication inode changes are needed.
    Claims and failed temp files remain consumed. The strict reader and the
    accepted task-epilog recorder are unchanged.
    """
    raw = value if isinstance(value, bytes) else release.encoded(value)
    path = epilog.literal_path(str(path))
    epilog.private_directory(path.parent)
    parent = epilog.open_directory(path.parent)
    temporary = '.' + path.name + '.' + secrets.token_hex(12) + '.partial'
    try:
        claim = os.open('.' + path.name + '.publish-claim',
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=parent)
        try:
            os.fsync(claim)
        finally:
            os.close(claim)
        os.fsync(parent)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                release.check(count > 0, 'Short IPC publication write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _rename_claimed(parent, temporary, path.name)
        os.fsync(parent)
    finally:
        os.close(parent)


def read_published(path, limit=1024**3):
    # Published journal objects grow with the cell: the samples of a k=8 thinking cell are tens of MB, a main cell far more.
    return release.read(path, limit, private=True)


def wait_object(path, deadline_ns, *, authority=None, stop=True):
    while time.monotonic_ns() < deadline_ns:
        if authority is not None:
            release.require(authority, phase='runtime')
            if stop and (Path(path).parent/'batch.stop.json').exists():
                raise CooperativeStop('Peer stopped this attempt; no new dispatch')
        try:
            raw = read_published(path)
            value = release.strict(raw)
            release.check(release.encoded(value) == raw, 'Noncanonical IPC object')
            return value
        except FileNotFoundError:
            time.sleep(min(.02, max(0, (deadline_ns-time.monotonic_ns())/10**9)))
    raise InfrastructureError('Original IPC deadline exhausted; no retry')


def role_argv(authority, role_id, cell_index=None):
    batch.role_for(authority.manifest, role_id)
    argv = [authority.assets['python']['path'], '-I', '-B',
            str(release.ROOT/'scripts/calibration/lcb_isolation_owner_v2.py'), 'role',
            '--root', str(authority.root), '--owner-sha256', authority.owner_sha,
            '--review-sha256', authority.review_sha, '--role-id', role_id, '--execute']
    if cell_index is not None:
        batch.cell_root(authority.root,authority.manifest,cell_index)
        argv.extend(['--cell-index',str(cell_index)])
    return argv


def fields(raw):
    lines = raw.strip().splitlines()
    release.check(len(lines) == 1, 'One scheduler record required')
    return site.fields(lines[0])


def allocation_facts(raw, manifest, job_id, *, context, cpu_model, cpu_ids, memory_bytes):
    """Cross-bind Slurm metadata and actual local hard resources, not requests."""
    m = batch.validate_manifest(manifest)
    actual_cpus=batch.allocation_cpu_count(m,len(meter.cpus(cpu_ids)))
    release.number(job_id)
    f = fields(raw)
    uid = re.fullmatch(r'[^\s()]+\(([0-9]+)\)', f.get('UserId', ''))
    release.check(f.get('JobId') == job_id and uid and int(uid[1]) == m['owner_uid'],
                  'Allocation ID/owner differs')
    release.check(not any(k in f for k in ('ArrayJobId', 'ArrayTaskId', 'HetJobId', 'HetJobOffset')),
                  'No arrays or heterogeneous allocation')
    release.check(f.get('JobState') == 'RUNNING' and f.get('Requeue') == f.get('Restarts') == '0'
                  and f.get('BatchFlag') == '1' and f.get('SecsPreSuspend') == '0'
                  and f.get('SuspendTime') in ('None', 'Unknown'), 'Unrequeued running batch required')
    gpu=batch.is_gpu(m)
    if not gpu and not (f.get('NodeList') == f.get('BatchHost') == context['node']
            and context['node'] in m['node_pool'] and cpu_model == m['cpu_model']):
        raise InfrastructureError('Allocation node/model differs from approved pool')
    # GPU pilot: node, model, partition, QOS and Slurm's own CPU count are recorded in the receipt, not matched.
    release.check(f.get('NumNodes') == '1', 'One allocated node required')
    if not gpu:
        release.check(f.get('NumCPUs') == str(actual_cpus)
                      and f.get('Partition') in m['allocation']['partition'].split(',')
                      and f.get('QOS') == m['allocation']['qos'], 'Allocation metadata resources differ')
        release.check(f.get('JobName') == 'www27-I2-'+m['nonce'][:12]
                      and f.get('Comment') == 'www27-I2:'+m['nonce'], 'Allocation nonce labels differ')
    tres = {}
    for item in f.get('AllocTRES', '').split(','):
        parts = item.split('=')
        release.check(len(parts) == 2 and parts[0] not in tres, 'Duplicate allocation TRES')
        tres[parts[0]] = parts[1]
    ram = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)([KMGT]?)', tres.get('mem', ''))
    ram_bytes = int(float(ram[1])*{'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}[ram[2]]) if ram else 0
    if gpu:
        release.check({'cpu','mem','node'}<=set(tres) and int(tres['cpu']) >= m['allocation']['cpus']
                      and ram_bytes >= m['allocation']['memory_bytes'] and int(tres.get('gres/gpu','0')) >= 1,
                      'Allocation has too few CPUs, memory or GPUs (cpu='+tres.get('cpu','?')+' mem='+tres.get('mem','?')+')')
    else:
        allowed={'cpu','mem','node','billing'}
        release.check(set(tres)<=allowed and {'cpu','mem','node'}<=set(tres)
                      and tres.get('cpu') == str(actual_cpus) and tres.get('node') == '1' and ram
                      and ram_bytes == m['allocation']['memory_bytes'], 'Actual allocation TRES differs')
    release.check(site.duration(f.get('TimeLimit')) <= m['max_run_s']
                  and site.duration(f.get('TimeLimit')) >= 60, 'Allocation time limit outside approval')
    release.check((memory_bytes is None or memory_bytes >= m['allocation']['memory_bytes']) if gpu
                  else memory_bytes == m['allocation']['memory_bytes'], 'Actual allocation cpuset/memory differs')
    result = {'schema': 'isolation-allocation-runtime-v2', 'job_id': job_id,
              'manifest_sha256': release.object_sha(m), 'nonce': m['nonce'], 'source_head': m['source_head'],
              'actual_start_ns': site.epoch_ns(f.get('StartTime')), 'node': context['node'],
              'boot_id': context['boot_id'], 'cpu_model': cpu_model,
              'cpus': actual_cpus, 'memory_bytes': m['allocation']['memory_bytes'], 'gpus': m['allocation']['gpus']}
    # GPU: a late start is only a queue-time fact; an allocation that is already running is never aborted for it.
    if not gpu and result['actual_start_ns'] > m['start_by_ns']:
        raise InfrastructureError('Allocation started after start_by_ns')
    return batch.validate_runtime_receipt(m, result)


def resource_group(path, *, on_read=None):
    group = site.GroupHandle(path)
    try:
        group.verify()
        cpu_raw = site.read_fd(group.fd, 'cpuset.cpus.effective')
        mem_raw = site.read_fd(group.fd, 'memory.max')
        if on_read is not None:
            on_read({'identity':deepcopy(group.identity),'cpuset_raw':cpu_raw,'memory_max_raw':mem_raw})
        cpu_ids = meter.parse_cpus(cpu_raw)
        memory = None if mem_raw.strip() == 'max' else int(mem_raw.strip())
        group.verify()
        return {'identity': deepcopy(group.identity), 'cpu_ids': cpu_ids,
                'memory_max_bytes': memory, 'cpuset_raw': cpu_raw, 'memory_max_raw': mem_raw}
    finally:
        group.close()


def observed_cgroup_identity(path, uid):
    """Read the process leaf itself; do not substitute its user ancestor."""
    fd=epilog.open_directory(path)
    try:
        held=os.fstat(fd);named=os.stat(path,follow_symlinks=False)
        release.check(stat.S_ISDIR(held.st_mode) and held.st_uid in (0,uid) and not held.st_mode&0o022
                      and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino),
                      'Process cgroup leaf changed or has unsafe ownership')
        return {'path':path,'device':held.st_dev,'inode':held.st_ino}
    finally:os.close(fd)


def local_context():
    value = site.LinuxHost().context()
    value['node'] = value['node'].split('.')[0]
    return value


def local_model():
    # Bound both each pseudo-file read and the total; decode after reassembly.
    limit = 4*1024**2
    chunks, size = [], 0
    with open('/proc/cpuinfo', 'rb') as source:
        while True:
            part = source.read(min(65536, limit+1-size))
            if not part:
                break
            size += len(part)
            release.check(size <= limit, 'cpuinfo size bound')
            chunks.append(part)
    raw = b''.join(chunks).decode('utf-8')
    models = [line.split(':', 1)[1].strip() for line in raw.splitlines() if line.startswith('model name')]
    release.check(models and len(set(models)) == 1, 'One observed CPU model required')
    return models[0]


def observe_role(authority, role_id, pid, expected_argv, *, expected_step=None):
    """Retain a pidfd while checking role process, executable and both leaves."""
    release.require(authority, phase='runtime')
    slot = batch.role_for(authority.manifest, role_id)
    actual = authority.runtime_receipt
    if role_id=='G' and batch.is_gpu(authority.manifest):
        return observe_inference(authority,pid)
    host = site.LinuxHost()
    ctx = local_context()
    release.check(ctx['node'] == actual['node'] and ctx['boot_id'] == actual['boot_id'], 'Foreign host/boot')
    handle = host.track(pid, authority.uid, site.CGBASE+'/job_'+actual['job_id'])
    try:
        process = host.process(pid)
        match = re.fullmatch(re.escape('/system.slice/slurmstepd.scope/job_'+actual['job_id'])+
                             r'/step_([0-9]+)/user/task_0', process['cgroup'])
        release.check(match and (expected_step is None or match[1] == expected_step), 'Wrong numeric role step')
        step = match[1]
        raw=read_proc('/proc/'+str(pid)+'/cmdline',16384)
        release.check(len(raw) <= 16384 and raw.endswith(b'\0')
                      and raw[:-1].decode().split('\0') == expected_argv, 'Actual role argv differs')
        exe = host.executable_info(pid)
        expected_hash = authority.assets['native_elf' if slot['kind'] == 'execution' and not batch.is_gpu(authority.manifest) else 'python']['sha256']
        release.check(not handle.state()['exited'], 'Role exited before it was observed')
        exe_matches_lock = exe['sha256'] == expected_hash  # recorded with the observation, not a gate
        base = site.CGBASE+'/job_'+actual['job_id']+'/step_'+step
        domains = {leaf: resource_group(base+'/'+leaf) for leaf in ('user', 'slurm')}
        user = domains['user']
        leaf = observed_cgroup_identity('/sys/fs/cgroup'+process['cgroup'],authority.uid)
        join = batch.live_join(authority.manifest, role_id, actual, step_id=step,
            pid=pid, pid_start_ticks=process['start_ticks'], uid=process['uid'], cgroup_path=process['cgroup'],
            cgroup_device=leaf['device'], cgroup_inode=leaf['inode'], user_cgroup=user['identity'],
            node=ctx['node'], boot_id=ctx['boot_id'],
            cpu_ids=user['cpu_ids'], memory_max_bytes=user['memory_max_bytes'], role_nonce=slot['nonce'])
        subject = meter.binding({'job_id':actual['job_id'], 'step_id':step, 'role_id':role_id,
            'kind':slot['kind'], 'nonce':slot['nonce'], 'node':actual['node'], 'boot_id':actual['boot_id'],
            'uid':authority.uid, 'domains': {k: {n:v for n,v in d.items() if n in
                ('identity', 'cpu_ids', 'memory_max_bytes')} for k,d in domains.items()}})
        release.check(site.process_identity(host.process(pid)) == site.process_identity(process)
                      and not handle.state()['exited'], 'Role changed while joined')
        return {'join':join, 'subject':subject, 'process':process, 'context':ctx,
                'executable':{'sha256':exe['sha256'],'matches_lock':exe_matches_lock}}
    finally:
        handle.close()


def observe_inference(authority,pid):
    """G contributes a job/step/cgroup reading, not another executable identity gate."""
    actual=authority.runtime_receipt;process=site.LinuxHost().process(pid)
    match=re.fullmatch(re.escape('/system.slice/slurmstepd.scope/job_'+actual['job_id'])+
                       r'/step_([0-9]+)/user/task_0',process['cgroup'])
    release.check(match is not None,'Inference process outside the allocation step')
    step=match[1];base=site.CGBASE+'/job_'+actual['job_id']+'/step_'+step
    domains={leaf:resource_group(base+'/'+leaf) for leaf in ('user','slurm')}
    leaf=os.stat('/sys/fs/cgroup'+process['cgroup'])
    slot=batch.role_for(authority.manifest,'G')
    join=batch.live_join(authority.manifest,'G',actual,step_id=step,pid=pid,pid_start_ticks=process['start_ticks'],
        uid=authority.uid,node=actual['node'],boot_id=actual['boot_id'],cgroup_path=process['cgroup'],
        cgroup_device=leaf.st_dev,cgroup_inode=leaf.st_ino,user_cgroup=domains['user']['identity'],
        cpu_ids=domains['user']['cpu_ids'],memory_max_bytes=domains['user']['memory_max_bytes'],role_nonce=slot['nonce'])
    subject=meter.binding({k:join[k] for k in meter.CONTEXT}|{
        'domains':{k:{n:v for n,v in d.items() if n in ('identity','cpu_ids','memory_max_bytes')} for k,d in domains.items()}})
    return {'join':join,'subject':subject,'process':process,'context':local_context()}


def verify_inference_join(authority,value):
    join=value['join'];actual=authority.runtime_receipt
    release.check(join['job_id']==actual['job_id'],'Inference job differs')
    path=site.CGBASE+'/job_'+actual['job_id']+'/step_'+join['step_id']+'/user'
    seen=resource_group(path)
    release.check(seen['identity']==join['user_cgroup'],'Inference cgroup inode differs')
    return value


def bundle_check(authority, value):
    release.require(authority, phase='runtime')
    release.check(set(value) == {'schema','joins','subjects','manifest_sha256'}
                  and value['schema'] == ('isolation-eight-joins-v3' if batch.is_gpu(authority.manifest) else 'isolation-seven-joins-v2')
                  and value['manifest_sha256'] == release.object_sha(authority.manifest), 'Seven-role bundle differs')
    joins = batch.validate_joins(authority.manifest, value['joins'], runtime_receipt=authority.runtime_receipt)
    release.check(set(value['subjects']) == set(batch.role_ids(authority.manifest)), 'Subject roster incomplete')
    for j in joins:
        subject = meter.binding(value['subjects'][j['role_id']])
        release.check(all(subject[k] == j[k] for k in ('job_id','step_id','role_id','kind','nonce','node','boot_id','uid'))
                      and subject['domains']['user']['identity'] == j['user_cgroup']
                      and subject['domains']['user']['cpu_ids'] == j['cpu_ids'], 'Subject/join mismatch')
    return deepcopy(value)


def epilog_config(authority, role_id, cell_index=None):
    release.require(authority, phase='runtime', role='D')
    slot = batch.role_for(authority.manifest, role_id)
    return epilog.validate_config({'schema':epilog.CONFIG_SCHEMA, 'role_id':role_id, 'nonce':slot['nonce'],
        'owner_uid':authority.uid, 'job_id':authority.runtime_receipt['job_id'],
        'node':authority.runtime_receipt['node'], 'boot_id':authority.runtime_receipt['boot_id'],
        'record_path':str(batch.cell_root(authority.root,authority.manifest,cell_index)/'endpoints'/(role_id+'.json'))})


def endpoint_config_digest(authority, role_id, cell_index=None):
    """Bind the allocation-specific configuration to the signed role nonce."""
    release.require(authority,phase='runtime')
    allowed={authority.role}
    if authority.role.startswith('W'):
        allowed.add('E'+authority.role[1])
    release.check(role_id in allowed,'Endpoint config outside the collector role')
    row=batch.role_for(authority.manifest,role_id)
    root=batch.cell_root(authority.root,authority.manifest,cell_index)
    raw=release.read(root/'configs'/(role_id+'.json'),private=True)
    value=epilog.validate_config(epilog.strict(raw))
    expected={'schema':epilog.CONFIG_SCHEMA,'role_id':role_id,'nonce':row['nonce'],'owner_uid':authority.uid,
              'job_id':authority.runtime_receipt['job_id'],'node':authority.runtime_receipt['node'],
              'boot_id':authority.runtime_receipt['boot_id'],
              'record_path':str(root/'endpoints'/(role_id+'.json'))}
    release.check(value==expected and raw==epilog.encoded(expected),'Endpoint config differs from signed role/allocation')
    return release.sha(raw)
