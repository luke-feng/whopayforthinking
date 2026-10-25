"""Closed live-site adapter: fixed read-only queries and retained kernel objects.

No job submission/cancellation/namespace operations. open_live is release-closed.
The classes implement the data path; tests inject a virtual host and scheduler.
"""
from datetime import datetime, timezone
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import socket
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_supervisor_v3 as core

NS=1_000_000_000
CGROOT='/sys/fs/cgroup'
CGBASE=CGROOT+'/system.slice/slurmstepd.scope'
MAX_BYTES=262144
MAX_GROUPS=256
MAX_PIDS=4096
GATES=('trusted_probe_authorized','candidate_execution_authorized','main_matrix_authorized','site_recovery_verified')


def check(ok,message):
    if not ok:raise ValueError(message)


def numeric_id(value,step=False):
    pattern=r'0|[1-9][0-9]{0,8}' if step else r'[1-9][0-9]{0,9}'
    check(isinstance(value,str) and re.fullmatch(pattern,value),'One explicit numeric ID required')
    return value


def fields(line):
    check(isinstance(line,str) and len(line)<=MAX_BYTES and '\n' not in line,'One bounded record required')
    matches=list(re.finditer(r'(?:^|\s)([A-Za-z][A-Za-z0-9_/:]*)=',line))
    check(matches and matches[0].start()==0,'Malformed Slurm record')
    result={}
    for i,m in enumerate(matches):
        key=m[1];check(key not in result,'Duplicate scheduler field: '+key)
        end=matches[i+1].start() if i+1<len(matches) else len(line)
        result[key]=line[m.end():end].strip()
    return result


def duration(value):
    m=re.fullmatch(r'(?:(\d{1,4})-)?(\d{1,3}):([0-5]\d):([0-5]\d)',value or '')
    check(m is not None,'Finite explicit Slurm duration required')
    return int(m[1] or 0)*86400+int(m[2])*3600+int(m[3])*60+int(m[4])


def epoch_ns(value):
    check(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',value or ''),'Explicit UTC date required')
    return int(datetime.strptime(value,'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp())*NS


def parse_job(text,job_id,cluster,expected_limit_s=1200):
    lines=text.strip().splitlines();check(len(lines)==1,'Expected exactly one job record')
    f=fields(lines[0]);check(f.get('JobId')==numeric_id(job_id),'Job ID differs')
    for key in ('ArrayJobId','ArrayTaskId','HetJobId','HetJobOffset'):
        check(key not in f,'Array/heterogeneous jobs not supported')
    uid=re.fullmatch(r'[^\s()]+\(([0-9]+)\)',f.get('UserId',''))
    check(uid is not None and int(uid[1])>0,'Explicit nonroot job UID required')
    check(f.get('Requeue')=='0' and f.get('Restarts')=='0' and f.get('BatchFlag')=='1','Dedicated unrequeued batch job required')
    check(f.get('SuspendTime') in ('None','Unknown') and f.get('SecsPreSuspend')=='0','Suspended/resumed worker refused')
    node=f.get('NodeList','');check(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',node) and f.get('BatchHost')==node,'One exact node required')
    check(f.get('NumCPUs')=='1' and f.get('NumNodes')=='1','One CPU/node allocation required')
    tres={}
    for pair in f.get('AllocTRES','').split(','):
        parts=pair.split('=');check(len(parts)==2 and parts[0] not in tres,'Invalid/duplicate allocation TRES')
        tres[parts[0]]=parts[1]
    check(set(tres) in ({'cpu','mem','node'},{'cpu','mem','node','billing'}) and
          tres['cpu']==tres['node']=='1','GPU/extra/unidentified resources refused')
    mem=re.fullmatch(r'(\d+)([KMG]?)',tres['mem']);check(mem is not None,'Explicit allocated memory required')
    ram=int(mem[1])*{'':1,'K':1024,'M':1024**2,'G':1024**3}[mem[2]]
    check(ram==1073741824,'Frozen 1 GiB allocation required')
    if 'billing' in tres:check(re.fullmatch(r'\d+(?:\.\d+)?',tres['billing']) is not None,'Invalid billing TRES')
    for key in ('SubmitTime','StartTime','EndTime'):epoch_ns(f.get(key))
    limit=duration(f.get('TimeLimit'));runtime=duration(f.get('RunTime'))
    check(type(expected_limit_s) is int and expected_limit_s in (1200,2700) and limit==expected_limit_s and
          f.get('JobState') in ('RUNNING','COMPLETING',*core.TERMINAL),'Unexpected job state/limit')
    return {'cluster':cluster,'job_id':job_id,'uid':int(uid[1]),'node':node,
            'submit_time':f['SubmitTime'],'start_time':f['StartTime'],'end_time':f['EndTime'],
            'job_name':f.get('JobName'),'job_comment':f.get('Comment'),'partition':f.get('Partition'),'state':f['JobState'],
            'requeue':False,'restarts':0,'time_limit_s':limit,'runtime_s':runtime,
            'allocation':{'logical_cpus':1,'ram_bytes':ram,'gpu_count':0,'nodes':1}}


def parse_steps(text,job_id,node,uid):
    result={}
    for line in text.strip().splitlines():
        f=fields(line);identifier=f.get('StepId','')
        check(identifier.startswith(job_id+'.'),'Foreign step')
        sid=identifier[len(job_id)+1:]
        check(sid in ('batch','extern') or re.fullmatch(r'0|[1-9][0-9]{0,8}',sid),'Invalid step ID')
        check(sid not in result and f.get('NodeList')==node and f.get('Nodes')=='1' and f.get('UserId')==str(uid),
              'Step identity differs')
        check(f.get('State') in ('RUNNING','COMPLETING',*core.TERMINAL),'Unknown step state')
        result[sid]={'step_id':sid,'job_id':job_id,'node':node,'state':f['State']}
    return result


def stable_job(job):
    return {k:job[k] for k in ('cluster','job_id','uid','node','submit_time','start_time',
                             'job_name','job_comment','partition','requeue','restarts','time_limit_s','allocation')}


class RemainingClock:
    """Conservative non-extending monotonic deadline, not TimeLimit-as-remaining."""
    def __init__(self):self.deadline_ns=None;self.identity=None;self.last_mono=None;self.last_wall=None;self.scheduled_end=None
    def update(self,job,begin,end):
        bmono,bwall=begin;mono,wall=end
        check(0<bmono<=mono and mono-bmono<=5*NS,'Slow/backward observation')
        check(abs((wall-bwall)-(mono-bmono))<=250_000_000,'Wall/monotonic discontinuity')
        check(self.last_mono is None or bmono>=self.last_mono,'Observation clock regressed')
        if self.last_mono is not None:
            check(abs((bwall-self.last_wall)-(bmono-self.last_mono))<=250_000_000,'Clock discontinuity between observations')
        identity=stable_job(job)
        check(self.identity is None or identity==self.identity,'Job lifetime/identity changed')
        self.identity=identity;self.last_mono=mono;self.last_wall=wall
        if self.scheduled_end is None:self.scheduled_end=job['end_time']
        if job['state'] in core.TERMINAL:
            check(epoch_ns(job['start_time'])<=epoch_ns(job['end_time'])<=wall+NS,'Invalid terminal end time')
            return 0  # Terminal EndTime is ACTUAL, not the scheduled deadline.
        check(job['end_time']==self.scheduled_end,'Scheduled deadline changed')
        # RunTime has integer-second precision. Charge one extra second plus
        # the entire query interval; the local wall clock can only shorten it.
        runtime_left=(job['time_limit_s']-job['runtime_s']-1)*NS-(mono-bmono)
        wall_left=epoch_ns(job['end_time'])-wall-NS
        proposed=mono+min(runtime_left,wall_left)
        self.deadline_ns=proposed if self.deadline_ns is None else min(self.deadline_ns,proposed)
        return max(0,(self.deadline_ns-mono)//NS)


class OwnedJobReader:
    """Bracketed own O/W job reads; no implicit TimeLimit-as-remaining."""
    def __init__(self,scheduler,host,job_id,role,nonce,uid,node):
        numeric_id(job_id);check(role in ('worker','observer'),'Explicit O/W role required')
        check(re.fullmatch('[0-9a-f]{32}',nonce or '') and type(uid) is int and uid>0,'Owner nonce/UID required')
        self.scheduler=scheduler;self.host=host;self.job_id=job_id;self.role=role;self.nonce=nonce;self.uid=uid;self.node=node
        self.clock=RemainingClock();self.records=[]
    def _job(self):
        begin=self.host.stamp();limit=2700 if self.role=='observer' else 1200
        a=parse_job(self.scheduler.query('job',self.job_id),self.job_id,'cluster',limit)
        b=parse_job(self.scheduler.query('job',self.job_id),self.job_id,'cluster',limit)
        check(stable_job(a)==stable_job(b) and a['state']==b['state'] and a['end_time']==b['end_time'],'Job changed during role read')
        name=('www27-o-' if self.role=='observer' else 'www27-v3-')+self.nonce[:12]
        check(b['uid']==self.uid and b['node']==self.node and b['job_name']==name and
              b['job_comment']=='www27-attempt:'+self.nonce and b['partition']=='standard' and b['state']=='RUNNING','O/W identity/not-running mismatch')
        return begin,b
    def _remaining(self,begin,job,minimum_remaining_s):
        remaining=self.clock.update(job,begin,self.host.stamp())
        check(type(minimum_remaining_s) is int and remaining>=minimum_remaining_s,'Observer/worker remaining time insufficient')
        return {**job,'time_remaining_s':remaining,'observed_ns':self.clock.last_mono}
    def metadata(self,minimum_remaining_s=0):
        """Remote scheduler evidence only; never opens the caller's cgroup tree."""
        begin,job=self._job()
        out={**self._remaining(begin,job,minimum_remaining_s),
             'verification_scope':'scheduler_metadata_only','hard_resources':None}
        self.records.append(out);return out
    def observe(self,minimum_remaining_s=0):
        begin,b=self._job()
        check(self.host.context()['node']==self.node,'Local resource observation requires the allocated node')
        resource=self.host.group(CGBASE+'/job_'+self.job_id)
        try:
            hard=resource.resources()
            check(hard['scope_identity']==resource.identity and len(hard['logical_cpu_ids'])==1 and
                  type(hard['memory_max_bytes']) is int and 0<hard['memory_max_bytes']<=1073741824,
                  'O/W hard resource enforcement differs')
        finally:resource.close()
        out={**self._remaining(begin,b,minimum_remaining_s),'hard_resources':hard}
        self.records.append(out);return out


class PinnedScontrol:
    """Only fixed own-job reads; no generic command or environment override."""
    def __init__(self,binary,sha256,cluster,*,approved_nodes=()):
        check(binary=='/usr/bin/scontrol' and re.fullmatch(r'[0-9a-f]{64}',sha256 or ''),'Pinned site client required')
        check(cluster=='cluster','Frozen cluster required')
        import lcb_supervision_release_v3 as release
        if approved_nodes:release.nodes_check(list(approved_nodes))
        self.approved_nodes=tuple(approved_nodes)
        self.binary=binary;self.digest=sha256;self.cluster=cluster;self.records=[]
    def _identity(self):
        p=Path(self.binary);check(not p.is_symlink() and p.is_file(),'Regular pinned client required')
        a=p.stat();check(a.st_uid==0 and not a.st_mode&0o022 and a.st_size<8*1024**2,'Unsafe client permissions/size')
        digest=hashlib.sha256(p.read_bytes()).hexdigest();b=p.stat()
        check((a.st_ino,a.st_dev,a.st_size,a.st_mtime_ns)==(b.st_ino,b.st_dev,b.st_size,b.st_mtime_ns) and digest==self.digest,'Client drift')
        return (a.st_dev,a.st_ino,digest)
    def query(self,kind,job_id,*,allow_missing=False):
        check(kind in ('job','step','node','partition'),'Only fixed metadata reads permitted')
        if kind in ('job','step'):numeric_id(job_id)
        elif kind=='node':check(job_id in self.approved_nodes,'Node outside owner approval')
        else:check(job_id=='standard','Only the fixed partition may be queried')
        check(not allow_missing or kind=='job','Missing-state handling is only for jobs')
        import lcb_supervision_release_v3 as release
        before=self._identity()
        maximum=release.timeout(2)
        argv=[self.binary,'--clusters='+self.cluster,'--oneliner','show',kind,job_id]
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}
        start=time.monotonic()
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              env=env,close_fds=True)
        buffers={};selector=selectors.DefaultSelector();ok=False;missing=False
        try:
            for key,stream in (('stdout',proc.stdout),('stderr',proc.stderr)):
                buffers[key]=bytearray();os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,key)
            while selector.get_map():
                check(time.monotonic()-start<maximum,'Metadata query timed out')
                for item,_ in selector.select(.02):
                    chunk=os.read(item.fd,min(8192,MAX_BYTES-len(buffers[item.data])+1))
                    if not chunk:selector.unregister(item.fileobj);continue
                    buffers[item.data].extend(chunk);check(len(buffers[item.data])<=MAX_BYTES,'Metadata output limit')
            code=proc.wait(timeout=max(.001,maximum-(time.monotonic()-start)))
            missing=(allow_missing and kind=='job' and code==1 and not buffers['stdout'] and
                     bytes(buffers['stderr']).strip() in (b'slurm_load_jobs error: Invalid job id specified',
                                                        b'Invalid job id specified'))
            check(missing or code==0 and not buffers['stderr'],'Metadata CLI error; no empty-state inference')
            check(self._identity()==before,'Client changed during query');ok=True
            return None if missing else bytes(buffers['stdout']).decode('utf-8',errors='strict')
        finally:
            selector.close()
            if proc.poll() is None:proc.kill()  # This exact metadata child only.
            reaped=False
            try:proc.wait(timeout=1);reaped=True
            finally:
                for stream in (proc.stdout,proc.stderr):stream.close()
                self.records.append({'argv':argv,'ok':ok and reaped,'returncode':proc.returncode,'metadata_child_reaped':reaped,
                                     'missing_job_record':missing,'stdout':bytes(buffers.get('stdout',b'')).decode('utf-8',errors='replace'),
                                     'stderr':bytes(buffers.get('stderr',b'')).decode('utf-8',errors='replace'),
                                     'streams':{k:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in buffers.items()}})


def node_snapshot(text,node,approved_nodes):
    """Parse allocation counters, never OS FreeMem or CPU load."""
    check(node in approved_nodes,'Unapproved node')
    lines=text.strip().splitlines();check(len(lines)==1,'One node record required')
    f=fields(lines[0]);check(f.get('NodeName')==node,'Node identity differs')
    check(f.get('Gres')=='(null)' and f.get('ThreadsPerCore')=='1','CPU-only single-thread cores required')
    keys=('CPUTot','CPUEfctv','CPUAlloc','RealMemory','AllocMem')
    check(all(re.fullmatch(r'0|[1-9][0-9]{0,12}',f.get(k,'')) for k in keys),
          'Explicit integral allocation counters required')
    n={k:int(f[k]) for k in keys}
    check(0<=n['CPUAlloc']<=n['CPUEfctv']<=n['CPUTot'] and n['CPUEfctv']>0 and
          0<=n['AllocMem']<=n['RealMemory'] and n['RealMemory']>0,'Inconsistent node allocation')
    check('standard' in f.get('Partitions','').split(','),'Node not in fixed partition')
    check(re.fullmatch(r'[A-Z_]+(?:\+[A-Z_]+)*',f.get('State','')),'Unknown node state syntax')
    return {'node':node,'state':f['State'],'threads_per_core':1,'gpu_count':0,**n}


def partition_snapshot(text):
    lines=text.strip().splitlines();check(len(lines)==1,'One partition record required')
    f=fields(lines[0])
    check(f.get('PartitionName')=='standard' and f.get('State')=='UP' and
          f.get('OverSubscribe')=='NO','Partition identity/state/sharing differs')
    return {'partition':'standard','state':'UP','oversubscribe':'NO'}


def resource_snapshot(client,host,node,approved_nodes):
    before=host.stamp()
    nr=client.query('node',node);pr=client.query('partition','standard')
    after=host.stamp()
    check(0<=after[0]-before[0]<=5*NS and
          abs((after[1]-before[1])-(after[0]-before[0]))<=250_000_000,'Snapshot clock/window')
    return {'node':node_snapshot(nr,node,approved_nodes),'partition':partition_snapshot(pr),
            'begin_ns':before[0],'end_ns':after[0],'begin_wall_ns':before[1],'end_wall_ns':after[1],
            'node_raw':nr,'partition_raw':pr,
            'node_sha256':hashlib.sha256(nr.encode()).hexdigest(),
            'partition_sha256':hashlib.sha256(pr.encode()).hexdigest()}


def screen_resource_pair(old,new,phase,now_ns):
    check(phase in ('initial','post_observer'),'Unknown screening phase')
    check(type(now_ns) is int and 0<=now_ns-new['begin_ns']<=5*NS and
          0<=now_ns-old['begin_ns']<=10*NS and
          new['begin_ns']-old['end_ns']>=NS,'Stale or unseparated snapshots')
    check(old['partition']==new['partition'],'Partition changed between snapshots')
    stable=('node','CPUTot','CPUEfctv','RealMemory','threads_per_core','gpu_count')
    check(all(old['node'][k]==new['node'][k] for k in stable),'Node topology changed')
    need=2 if phase=='initial' else 1
    for snap in (old,new):
        n=snap['node'];check(n['state'] in (('IDLE','MIXED') if phase=='initial' else ('MIXED',)),'Ineligible node state')
        if phase=='initial' and n['state']=='IDLE':check(n['CPUAlloc']==n['AllocMem']==0,'Contradictory IDLE allocation')
        check(n['CPUEfctv']-n['CPUAlloc']>=need and n['RealMemory']-n['AllocMem']>=1024*need,
              'Insufficient paired allocation headroom')
    return {'schema':'scheduler-pair-resource-screen-v1','phase':phase,'node':new['node']['node'],
            'snapshots':[old,new],'checked_ns':now_ns,'resource_reserved':False}


def resource_evidence_check(snap,approved_nodes):
    check(snap['node']==node_snapshot(snap['node_raw'],snap['node']['node'],approved_nodes) and
          snap['partition']==partition_snapshot(snap['partition_raw']) and
          snap['node_sha256']==hashlib.sha256(snap['node_raw'].encode()).hexdigest() and
          snap['partition_sha256']==hashlib.sha256(snap['partition_raw'].encode()).hexdigest(),
          'Resource snapshot raw/parsed evidence differs')
    check(0<=snap['end_ns']-snap['begin_ns']<=5*NS and
          abs((snap['end_wall_ns']-snap['begin_wall_ns'])-(snap['end_ns']-snap['begin_ns']))<=250_000_000,
          'Resource snapshot time evidence differs')
    return snap


def queue_record(text,job_id,role,uid,nonce,node,deadline_utc):
    """Read-only queue states; never feed this result into a live lease."""
    lines=text.strip().splitlines();check(len(lines)==1,'One queued job required')
    f=fields(lines[0]);check(f.get('JobId')==numeric_id(job_id),'Queued job ID differs')
    check(not any(k in f for k in ('ArrayJobId','ArrayTaskId','HetJobId','HetJobOffset')),'Only ordinary queued jobs')
    check(role in ('worker','observer'),'Fixed queue role')
    user=re.fullmatch(r'[^\s()]+\(([0-9]+)\)',f.get('UserId',''))
    name=('www27-o-' if role=='observer' else 'www27-v3-')+nonce[:12]
    check(user is not None and int(user[1])==uid and f.get('JobName')==name and
          f.get('Comment')=='www27-attempt:'+nonce and f.get('Partition')=='standard' and
          f.get('BatchFlag')=='1' and f.get('Requeue')=='0' and f.get('Restarts')=='0',
          'Queued identity differs')
    check(f.get('TimeLimit')==('00:45:00' if role=='observer' else '00:20:00') and
          f.get('Deadline')==deadline_utc,'Queue deadline/time limit differs')
    state=f.get('JobState');check(state in ('PENDING','CONFIGURING','RUNNING',*core.TERMINAL),'Unknown queue state')
    if state=='RUNNING':
        check(f.get('NodeList')==f.get('BatchHost')==node,'Running queue node differs')
    elif state in ('PENDING','CONFIGURING'):
        check('NodeList' in f and f['NodeList'] in ('','(null)',node),'Queued/terminal node differs')
    else:check(f.get('NodeList') in ('(null)',node),'Queued/terminal node differs')
    check(f.get('ReqNodeList')==node,'Requested node differs')
    # ReqTRES is the relevant allocation request before a job has resources.
    tres={}
    for pair in f.get('ReqTRES','').split(','):
        k,sep,v=pair.partition('=');check(sep and k not in tres,'Malformed queue request');tres[k]=v
    check(set(tres) in ({'cpu','mem','node'},{'cpu','mem','node','billing'}) and
          tres['cpu']==tres['node']=='1' and tres['mem'] in ('1G','1024M','1048576K','1073741824'),
          'Queued resource request differs')
    epoch_ns(f.get('SubmitTime'))
    return {'job_id':job_id,'role':role,'node':node,'state':state,'reason':f.get('Reason') or 'unknown',
            'expected_start':f.get('StartTime','Unknown'),'submit_time':f['SubmitTime'],
            'deadline_utc':deadline_utc,'verification_scope':'queue_metadata_only',
            'raw':text,'sha256':hashlib.sha256(text.encode()).hexdigest()}


def pair_admission(client,host,worker_id,observer_id,nonce,uid,node,observer_boot_id,approval_sha):
    """Bracket live scheduler and retained cgroups; does not issue authority."""
    numeric_id(worker_id);numeric_id(observer_id);check(worker_id!=observer_id,'Separate O/W jobs required')
    before=host.stamp();ctx=host.context()
    check(ctx['node']==node and ctx['uid']==uid and ctx['boot_id']==observer_boot_id,'Pair host/boot differs')
    check((CGROOT+ctx['cgroup']).startswith(CGBASE+'/job_'+worker_id+'/'),'Pair caller outside W job')
    def job(identifier,role):
        row=parse_job(client.query('job',identifier),identifier,'cluster',1200 if role=='worker' else 2700)
        name=('www27-v3-' if role=='worker' else 'www27-o-')+nonce[:12]
        check(row['uid']==uid and row['node']==node and row['state']=='RUNNING' and
              row['job_name']==name and row['job_comment']=='www27-attempt:'+nonce and
              row['partition']=='standard','Pair live identity differs')
        return row
    wa=job(worker_id,'worker');oa=job(observer_id,'observer');handles=[]
    try:
        for identifier in (worker_id,observer_id):handles.append(host.group(CGBASE+'/job_'+identifier))
        ids=[h.identity for h in handles]
        check(ids[0]['path']!=ids[1]['path'] and
              not any(ids[i]['path'].startswith(ids[1-i]['path']+'/') for i in (0,1)) and
              (ids[0]['device'],ids[0]['inode'])!=(ids[1]['device'],ids[1]['inode']),'Pair domains alias/nest')
        hard=[h.resources() for h in handles]
        for h,identity in zip(hard,ids):
            check(h['scope_identity']==identity and h['memory_max_bytes']==1073741824 and
                  len(h['logical_cpu_ids'])==1,'Pair hard resources differ')
        check(not set(hard[0]['logical_cpu_ids'])&set(hard[1]['logical_cpu_ids']),'Pair CPU sets overlap')
        wb=job(worker_id,'worker');ob=job(observer_id,'observer')
        check(stable_job(wa)==stable_job(wb) and stable_job(oa)==stable_job(ob) and
              wa['end_time']==wb['end_time'] and oa['end_time']==ob['end_time'],'Pair changed while observed')
        for h in handles:h.verify()
        end_context=host.context();end=host.stamp()
        keys=('node','boot_id','uid','pid_namespace','cgroup_namespace','time_namespace','proc_identity')
        check(all(ctx[k]==end_context[k] for k in keys),'Pair local context changed')
        wc=RemainingClock();oc=RemainingClock()
        wl=wc.update(wb,before,end);ol=oc.update(ob,before,end);check(ol>=1740,'Pair observer remaining')
        return {'schema':'scheduler-pair-admission-v1','node':node,'boot_id':ctx['boot_id'],
                'nonce':nonce,'approval_sha256':approval_sha,'begin_ns':before[0],'end_ns':end[0],
                'begin_wall_ns':before[1],'end_wall_ns':end[1],
                'worker':{**wb,'time_remaining_s':wl,'hard_resources':hard[0]},
                'observer':{**ob,'time_remaining_s':ol,'hard_resources':hard[1]},
                'resource_reserved':False,'execution_authorized_by_this_record':False}
    finally:
        for h in reversed(handles):h.close()


def pair_record_check(value,worker_id,observer_id,node,boot_id,uid,nonce,approval_sha):
    """Archived consistency only, never substitutes for a fresh kernel read."""
    check(value['schema']=='scheduler-pair-admission-v1' and value['node']==node and
          value['boot_id']==boot_id and value['nonce']==nonce and value['approval_sha256']==approval_sha and
          value['resource_reserved'] is False and value['execution_authorized_by_this_record'] is False,
          'Pair record binding differs')
    check(type(value['begin_ns']) is int and type(value['end_ns']) is int and
          0<value['begin_ns']<=value['end_ns']<=value['begin_ns']+5*NS,'Pair observation interval')
    check(type(value['begin_wall_ns']) is int and type(value['end_wall_ns']) is int and
          abs((value['end_wall_ns']-value['begin_wall_ns'])-(value['end_ns']-value['begin_ns']))<=250_000_000,
          'Pair clock interval differs')
    rows=[value['worker'],value['observer']]
    for row,identifier,role in zip(rows,(worker_id,observer_id),('worker','observer')):
        name=('www27-v3-' if role=='worker' else 'www27-o-')+nonce[:12]
        check(row['job_id']==numeric_id(identifier) and row['state']=='RUNNING' and row['uid']==uid and
              row['node']==node and row['job_name']==name and row['job_comment']=='www27-attempt:'+nonce and
              row['cluster']=='cluster' and row['partition']=='standard' and row['requeue'] is False and
              row['restarts']==0,'Archived pair identity differs')
        hard=row['hard_resources'];identity=hard['scope_identity']
        check(identity['path']==CGBASE+'/job_'+identifier and hard['memory_max_bytes']==1073741824 and
              len(hard['logical_cpu_ids'])==1 and type(hard['logical_cpu_ids'][0]) is int and
              hard['logical_cpu_ids'][0]>=0,'Archived pair resources differ')
        check(epoch_ns(row['start_time'])<=value['end_wall_ns']<epoch_ns(row['end_time']),
              'Pair observation outside running interval')
    wi,oi=(r['hard_resources']['scope_identity'] for r in rows)
    check(worker_id!=observer_id and (wi['device'],wi['inode'])!=(oi['device'],oi['inode']) and
          not set(rows[0]['hard_resources']['logical_cpu_ids'])&set(rows[1]['hard_resources']['logical_cpu_ids']),
          'Archived pair resource alias')
    check(rows[1]['time_remaining_s']>=1740,'Archived pair observer remaining')
    return value


def read_fd(fd,name,limit=65536):
    check(re.fullmatch(r'[A-Za-z0-9_.-]+',name),'Single relative kernel file required')
    child=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
    try:
        raw=os.read(child,limit+1);check(len(raw)<=limit,'Kernel file too large')
        return raw.decode('ascii')
    finally:os.close(child)


def kernel_pairs(text):
    out={}
    for line in text.splitlines():
        pair=line.split();check(len(pair)==2 and pair[0] not in out and pair[1].isdigit(),'Invalid kernel counters')
        out[pair[0]]=int(pair[1])
    return out


class GroupHandle:
    def __init__(self,path):
        check(path.startswith(CGBASE+'/job_') and str(Path(path))==path and '..' not in Path(path).parts,'Invalid resource path')
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            for part in Path(path).parts[1:]:
                new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=new
            meta=os.fstat(fd)
            check(meta.st_uid==0 and not meta.st_mode&0o022,'Delegated/writable resource domain refused')
            check(read_fd(fd,'cgroup.type').strip()=='domain','Unified domain required')
            self.fd=fd;self.identity={'path':path,'device':meta.st_dev,'inode':meta.st_ino};fd=None
        finally:
            if fd is not None:os.close(fd)
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
    def verify(self):
        check(self.fd is not None,'Closed resource handle')
        held=os.fstat(self.fd);current=os.stat(self.identity['path'],follow_symlinks=False)
        check((held.st_dev,held.st_ino)==(current.st_dev,current.st_ino)==(self.identity['device'],self.identity['inode']),
              'Resource vanished/replaced; not proof of release')
    def path_state(self):
        """ENOENT is a separate observation, never an empty-domain assertion."""
        check(self.fd is not None,'Closed resource handle')
        held=os.fstat(self.fd)
        check((held.st_dev,held.st_ino)==(self.identity['device'],self.identity['inode']),'Retained resource identity changed')
        try:current=os.stat(self.identity['path'],follow_symlinks=False)
        except FileNotFoundError:return 'removed'
        check((current.st_dev,current.st_ino)==(held.st_dev,held.st_ino) and stat.S_ISDIR(current.st_mode),'Resource path replaced')
        return 'present'
    def empty(self):
        self.verify();before=kernel_pairs(read_fd(self.fd,'cgroup.events'))
        check('populated' in before and before['populated'] in (0,1),'Missing populated counter')
        empty=before['populated']==0 and not self.pids()
        self.verify();after=kernel_pairs(read_fd(self.fd,'cgroup.events'))
        return empty and after.get('populated')==0
    def step_domains(self):
        self.verify();steps=set()
        for name in os.listdir(self.fd):
            if not name.startswith('step_'):continue
            meta=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            check(stat.S_ISDIR(meta.st_mode),'Non-directory step entry')
            sid=name[5:]
            check(sid in ('batch','extern') or re.fullmatch(r'0|[1-9][0-9]{0,8}',sid),'Unknown local step domain')
            steps.add(sid)
        self.verify();return steps
    def pids(self):
        result=set();visited=0
        def walk(fd):
            nonlocal visited
            visited+=1;check(visited<=MAX_GROUPS,'Resource tree too large')
            for value in read_fd(fd,'cgroup.procs').split():
                check(value.isdigit() and int(value)>0,'Invalid cgroup PID');result.add(int(value))
                check(len(result)<=MAX_PIDS,'Too many tasks to identify')
            for name in os.listdir(fd):
                st=os.stat(name,dir_fd=fd,follow_symlinks=False)
                check(not stat.S_ISLNK(st.st_mode),'Symlink in resource tree')
                if stat.S_ISDIR(st.st_mode):
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
                    try:walk(child)
                    finally:os.close(child)
        self.verify();walk(self.fd);self.verify();return sorted(result)
    def resources(self):
        self.verify();cpu=read_fd(self.fd,'cpuset.cpus.effective').strip()
        check(re.fullmatch(r'\d+',cpu) is not None,'One actual logical CPU required')
        memory=read_fd(self.fd,'memory.max').strip();swap=read_fd(self.fd,'memory.swap.max').strip()
        check(memory.isdigit() and 0<int(memory)<=1073741824,'Actual hard RAM bound required')
        check(swap=='max' or swap.isdigit(),'Unknown swap bound')
        self.verify()
        return {'logical_cpu_ids':[int(cpu)],'memory_max_bytes':int(memory),
                'swap_max_bytes':None if swap=='max' else int(swap),'scope_identity':dict(self.identity)}


def process(pid):
    check(type(pid) is int and pid>0,'Positive PID required')
    root=Path('/proc')/str(pid)
    def snapshot():
        text=(root/'stat').read_text();head,tail=text.rsplit(')',1);parts=tail.split()
        check(int(head.split('(',1)[0])==pid and len(parts)>=20,'Malformed proc stat')
        return parts[0],int(parts[19])
    first=snapshot();uid=root.stat().st_uid
    rows=(root/'cgroup').read_text().splitlines()
    check(len(rows)==1 and rows[0].startswith('0::/'),'Unified host cgroup view required')
    last=snapshot();check(first[1]==last[1],'PID changed during read')
    return {'pid':pid,'start_ticks':last[1],'uid':uid,'cgroup':rows[0][3:],'state':last[0]}


BASELINE_SCHEMA='scheduler-step-dual-baseline-v1'
BASELINE_DIRS=('', 'slurm', 'user', 'user/task_0')
BASELINE_SPECIAL='user/task_special'
BASELINE_CAPS=('CapInh','CapPrm','CapEff','CapAmb')


def process_identity(value):
    result={k:value[k] for k in ('pid','start_ticks','uid','cgroup')}
    check(all(type(result[k]) is int and result[k]>0 for k in ('pid','start_ticks')) and
          type(result['uid']) is int and result['uid']>=0 and isinstance(result['cgroup'],str),
          'Invalid typed process identity')
    return result


def baseline_capabilities(text):
    check(isinstance(text,str) and len(text)<=MAX_BYTES,'Bounded self capability record required')
    values={}
    for line in text.splitlines():
        key,sep,value=line.partition(':')
        if key in BASELINE_CAPS:
            check(sep and key not in values and re.fullmatch('[0-9a-fA-F]{1,16}',value.strip()),
                  'Malformed/duplicate capability field')
            values[key]=int(value.strip(),16)
    check(set(values)==set(BASELINE_CAPS) and all(v==0 for v in values.values()),
          'Privileged reader cannot establish the management boundary')
    return {'raw':text,'values':values}


def _baseline_stat(st,path,kind):
    check((stat.S_ISDIR(st.st_mode) if kind=='directory' else stat.S_ISREG(st.st_mode)),
          'Unexpected baseline resource type')
    return {'path':path,'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,
            'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'kind':kind}


class StepTree:
    """Retain four required fds and an optional special leaf; never filter step PIDs."""
    def __init__(self,step):
        self.step=step;self.fds={};self.identities={}
        try:
            step.verify();self.fds['']=os.dup(step.fd)
            for name,parent,leaf in (('slurm','','slurm'),('user','','user'),('user/task_0','user','task_0')):
                self.fds[name]=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                                       dir_fd=self.fds[parent])
            try:
                self.fds[BASELINE_SPECIAL]=os.open('task_special',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                                                 dir_fd=self.fds['user'])
            except FileNotFoundError:
                pass  # Only absence is optional; permissions, links and I/O errors fail closed.
            for name,fd in self.fds.items():
                path=step.identity['path']+('/'+name if name else '')
                self.identities[name]=_baseline_stat(os.fstat(fd),path,'directory')
            self.verify()
        except BaseException:self.close();raise
    def close(self):
        for fd in reversed(list(self.fds.values())):os.close(fd)
        self.fds={}
    def verify(self):
        self.step.verify();check(set(self.fds) in (set(BASELINE_DIRS),set(BASELINE_DIRS)|{BASELINE_SPECIAL}),
                                 'Closed/incomplete step tree')
        for name,fd in self.fds.items():
            held=_baseline_stat(os.fstat(fd),self.identities[name]['path'],'directory')
            if name:
                parent,_,leaf=name.rpartition('/')
                live=_baseline_stat(os.stat(leaf,dir_fd=self.fds[parent],follow_symlinks=False),held['path'],'directory')
            else:live=_baseline_stat(os.fstat(self.step.fd),held['path'],'directory')
            check(held==live==self.identities[name],'Baseline directory changed/replaced')
    def snapshot(self):
        self.verify();children={};procs={}
        for name,fd in self.fds.items():
            children[name]=[]
            for leaf in os.listdir(fd):
                st=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
                check(not stat.S_ISLNK(st.st_mode),'Link in baseline step tree')
                if stat.S_ISDIR(st.st_mode):children[name].append(leaf)
            children[name].sort()
            pfd=os.open('cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
            try:
                path=self.identities[name]['path']+'/cgroup.procs'
                before=_baseline_stat(os.fstat(pfd),path,'regular');raw=b''
                while True:
                    chunk=os.read(pfd,min(8192,MAX_BYTES+1-len(raw)))
                    if not chunk:break
                    raw+=chunk;check(len(raw)<=MAX_BYTES,'Oversized baseline cgroup.procs')
                after=_baseline_stat(os.fstat(pfd),path,'regular')
                current=_baseline_stat(os.stat('cgroup.procs',dir_fd=fd,follow_symlinks=False),path,'regular')
                check(before==after==current,'Baseline membership file replaced')
                tokens=raw.decode('ascii').split()
                check(all(re.fullmatch('[1-9][0-9]*',p) for p in tokens) and len(tokens)==len(set(tokens)),
                      'Invalid/duplicate baseline PID')
                procs[name]={**before,'raw':raw.decode('ascii'),'pids':sorted(map(int,tokens))}
            finally:os.close(pfd)
        full=self.step.pids();self.verify()
        return {'directories':dict(self.identities),'children':children,'procs':procs,'full_step_pids':full}


def baseline_binding(cert):
    """Only stable identities, not reader-local timestamps, fd numbers or raw PID ordering."""
    return deepcopy({k:cert[k] for k in ('schema','lease_sha256','baseline','directory_binding','membership_binding')})


def baseline_certificate_check(cert,lease,controller,exe_sha,*,previous=None):
    check(type(cert) is dict and set(cert)=={'schema','lease_sha256','phase','begin_ns','end_ns','before','after',
        'processes','capabilities','controller_executable','management_executable','baseline','directory_binding',
        'membership_binding','roles'},'Typed baseline certificate keys differ')
    check(cert['schema']==BASELINE_SCHEMA and cert['lease_sha256']==core.canonical(lease) and
          cert['phase'] in ('idle','registered','closeout') and type(cert['begin_ns']) is int and
          type(cert['end_ns']) is int and 0<cert['begin_ns']<=cert['end_ns']<=cert['begin_ns']+5*NS,
          'Typed baseline lease/phase/time differs')
    check(baseline_capabilities(cert['capabilities']['raw'])==cert['capabilities'],'Capability evidence differs')
    root=lease['step_cgroup']['path'];uid=lease['uid']
    def layout(value):
        names=BASELINE_DIRS+(BASELINE_SPECIAL,) if BASELINE_SPECIAL in value.get('directories',{}) else BASELINE_DIRS
        check(set(value)=={'directories','children','procs','full_step_pids'} and
              set(value['directories'])==set(value['procs'])==set(names),'Incomplete baseline tree')
        children={'':['slurm','user'],'slurm':[],'user':['task_0'],'user/task_0':[]}
        if BASELINE_SPECIAL in names:
            children['user'].append('task_special');children[BASELINE_SPECIAL]=[]
        check(value['children']==children,
              'Unknown baseline subtree')
        identities=[];members=[]
        for name in names:
            d=value['directories'][name];p=value['procs'][name];path=root+('/'+name if name else '')
            for record,expected,kind in ((d,path,'directory'),(p,path+'/cgroup.procs','regular')):
                keys={'path','device','inode','uid','gid','mode','kind'}|({'raw','pids'} if kind=='regular' else set())
                check(set(record)==keys and record['path']==expected and record['kind']==kind and
                      all(type(record[k]) is int and record[k]>0 for k in ('device','inode')) and
                      type(record['uid']) is int and record['uid'] in (0,uid) and
                      type(record['gid']) is int and record['gid']>=0 and type(record['mode']) is int and
                      0<=record['mode']<=0o7777 and not record['mode']&0o022,'Unsafe baseline resource metadata')
                if name in ('','slurm',BASELINE_SPECIAL) or (BASELINE_SPECIAL in names and name=='user'):
                    check(record['uid']==0,'Management ancestry/membership must be root-owned')
                identities.append((record['device'],record['inode']))
            check(isinstance(p['raw'],str) and len(p['raw'])<=MAX_BYTES and
                  all(re.fullmatch('[1-9][0-9]*',x) for x in p['raw'].split()) and
                  p['pids']==sorted(map(int,p['raw'].split())) and len(set(p['pids']))==len(p['pids']),
                  'Membership raw/parsed record differs')
            if name==BASELINE_SPECIAL:
                check(not p['pids'],'Special baseline leaf must remain empty')
            members+=p['pids']
        check(len(set(identities))==2*len(names) and len({x[0] for x in identities})==1,'Aliased/cross-mount baseline resources')
        check(value['directories']['']['device']==lease['step_cgroup']['device'] and
              value['directories']['']['inode']==lease['step_cgroup']['inode'],'Different step root')
        check(not value['procs']['']['pids'] and not value['procs']['user']['pids'] and
              len(value['procs']['slurm']['pids'])==1 and len(set(members))==len(members) and
              value['full_step_pids']==sorted(members),'Unknown/missing full-step process')
        return ({n:dict(value['directories'][n]) for n in names},
                {n:{k:v for k,v in value['procs'][n].items() if k not in ('raw','pids')} for n in names})
    db,mb=layout(cert['before']);da,ma=layout(cert['after'])
    check(db==da==cert['directory_binding'] and mb==ma==cert['membership_binding'] and
          all(cert['before']['procs'][n]['pids']==cert['after']['procs'][n]['pids'] for n in db),
          'Step membership or identity changed during certificate')
    records=cert['processes'];check(type(records) is list and len(records)<=4,'Unexpected baseline process count')
    ids=[process_identity(p['identity']) for p in records]
    check(len({p['pid'] for p in ids})==len(ids) and sorted(p['pid'] for p in ids)==cert['after']['full_step_pids'],
          'Process identities do not cover full step')
    for p in records:
        check(set(p)=={'identity','state'} and p['state']=={'exited':False,'registered_process_reaped':False},
              'Baseline/case process already exited')
    manager=[p for p in ids if CGROOT+p['cgroup']==root+'/slurm' and p['uid']==0]
    users=[p for p in ids if CGROOT+p['cgroup']==root+'/user/task_0' and p['uid']==uid]
    check(len(manager)==1 and len(manager)+len(users)==len(ids),'Unclassified process or wrong management identity')
    check([p['pid'] for p in manager]==cert['after']['procs']['slurm']['pids'] and
          sorted(p['pid'] for p in users)==cert['after']['procs']['user/task_0']['pids'],
          'Process identity and membership leaf disagree')
    c=process_identity(controller)
    check(c in users and cert['baseline']=={'management':manager[0],'controller':c},'Controller or management binding differs')
    check(set(cert['controller_executable'])=={'status','path','sha256'} and
          cert['controller_executable']['status']=='observed' and isinstance(cert['controller_executable']['path'],str) and
          cert['controller_executable']['sha256']==exe_sha,
          'Native controller executable differs')
    mexe=cert['management_executable']
    check(mexe.get('status') in ('observed','unobserved') and
          (set(mexe)=={'status','reason'} and mexe.get('reason')=='permission_denied' if mexe['status']=='unobserved' else
           set(mexe)=={'status','path','sha256'} and isinstance(mexe.get('path'),str) and
           re.fullmatch('[0-9a-f]{64}',mexe.get('sha256','')) is not None),'Invalid management executable observation')
    if cert['phase']=='registered':
        check(set(cert['roles'])=={'init','runner'},'Both registered case roles required')
        roles=[process_identity(p) for p in cert['roles'].values()]
        check(len({p['pid'] for p in roles})==2 and c not in roles and manager[0] not in roles and
              all(p in users for p in roles) and
              sorted(p['pid'] for p in users)==sorted(p['pid'] for p in [c,*roles]),'Unknown/aliased registered case role')
    else:check(cert['roles']=={} and users==[c],'Idle/closeout user subtree must contain only C')
    if previous is not None:check(baseline_binding(cert)==previous,'Frozen baseline replaced/moved')
    return cert


class StepBaseline:
    """Held M/C identities and whole-step checks; never owns a signal/cancel path."""
    def __init__(self,session,controller,exe_sha,journal):
        self.session=session;self.controller=process_identity(controller);self.exe_sha=exe_sha
        self.journal=journal;self.tree=None;self.handles={};self.binding=None;self.last=None
        try:
            self.tree=session.host.step_tree(session.step)
            self.initial=self.sample('idle')
            self.binding=baseline_binding(self.initial)
        except BaseException as exc:
            if self.tree is None:
                journal.append('typed_baseline_rejected',{'error':type(exc).__name__+': '+str(exc),'observation':{'tree_open_failed':True}})
            self.close();raise
    def sample(self,phase,roles=None):
        temporary={};raw={'phase':phase}
        try:
            begin=self.session.host.stamp()[0]
            before=self.tree.snapshot();raw['before']=before
            check(len(before['full_step_pids'])<=4,'Too many processes for fixed normal fixture')
            processes=[]
            for pid in before['full_step_pids']:
                current=self.session.host.process(pid)
                handle=self.handles.get(pid)
                if handle is None:
                    handle=self.session.host.track(pid,current['uid'],self.session.step.identity['path']);temporary[pid]=handle
                check(process_identity(handle.identity)==process_identity(current),'Baseline PID changed')
                processes.append({'identity':process_identity(current),'state':handle.state()})
            raw['processes']=processes
            managers=[p['identity'] for p in processes if p['identity']['uid']==0 and
                      CGROOT+p['identity']['cgroup']==self.session.step.identity['path']+'/slurm']
            check(len(managers)==1,'One management process in the protected leaf required')
            caps=self.session.host.baseline_capabilities()
            cexe=self.session.host.executable_info(self.controller['pid'])
            mexe=self.session.host.executable_info(managers[0]['pid'],optional=True)
            after=self.tree.snapshot();raw['after']=after
            for p in processes:
                pid=p['identity']['pid'];handle=self.handles.get(pid) or temporary[pid]
                check(process_identity(self.session.host.process(pid))==p['identity'] and
                      handle.state()==p['state'],'Baseline process changed during observation')
            cert={'schema':BASELINE_SCHEMA,'lease_sha256':core.canonical(self.session.lease),'phase':phase,
                  'begin_ns':begin,'end_ns':self.session.host.stamp()[0],'before':before,'after':after,
                  'processes':processes,'capabilities':caps,'controller_executable':cexe,'management_executable':mexe,
                  'baseline':{'management':managers[0],'controller':self.controller},
                  'directory_binding':after['directories'],
                  'membership_binding':{n:{k:v for k,v in after['procs'][n].items() if k not in ('raw','pids')} for n in after['directories']},
                  'roles':{k:process_identity(v) for k,v in (roles or {}).items()}}
            raw=cert
            baseline_certificate_check(cert,self.session.lease,self.controller,self.exe_sha,previous=self.binding)
            if self.binding is None:
                for pid,handle in temporary.items():self.handles[pid]=handle
                temporary={}
            self.last=cert;self.journal.append('typed_step_baseline',cert);return cert
        except (OSError,ValueError,RuntimeError) as exc:
            self.journal.append('typed_baseline_rejected',{'error':type(exc).__name__+': '+str(exc),'observation':raw})
            raise
        finally:
            for handle in temporary.values():handle.close()
    def retirement(self):
        m=self.binding['baseline']['management'];c=self.controller
        return {'schema':'scheduler-management-retirement-v1','baseline_binding':deepcopy(self.binding),
                'management':m,'controller':c,'management_state':self.handles[m['pid']].state(),
                'controller_state':self.handles[c['pid']].state()}
    def close(self):
        for handle in self.handles.values():handle.close()
        self.handles={}
        if self.tree is not None:self.tree.close();self.tree=None


def pidfd_task(fd):
    with (Path('/proc/self/fdinfo')/str(fd)).open('r') as stream:raw=stream.read(4097)
    check(len(raw)<=4096,'Bounded pidfd metadata required')
    values=[line.split(':',1)[1].strip() for line in raw.splitlines() if line.startswith('Pid:')]
    check(len(values)==1 and re.fullmatch(r'-1|[1-9][0-9]*',values[0]),'Pidfd not in the bound proc view')
    return int(values[0])


class ProcessHandle:
    def __init__(self,pid,uid,domain):
        a=process(pid)
        check(a['uid']==uid and (CGROOT+a['cgroup']).startswith(domain.rstrip('/')+'/'),'Process outside owned domain')
        fd=os.pidfd_open(pid)
        try:
            b=process(pid);check(all(a[k]==b[k] for k in ('pid','start_ticks','uid','cgroup')),'PID identity changed')
            self.identity=a;self.fd=fd;fd=None
        finally:
            if fd is not None:os.close(fd)
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
    def state(self):
        check(self.fd is not None,'Closed pidfd');poll=select.poll();poll.register(self.fd,select.POLLIN)
        flags=poll.poll(0);check(not any(v&(select.POLLNVAL|select.POLLERR) for _,v in flags),'pidfd error')
        exited=any(v&select.POLLIN for _,v in flags)
        task=pidfd_task(self.fd)
        if task==-1:
            check(exited,'Detached pidfd without exit readiness')
            return {'exited':True,'registered_process_reaped':True}
        check(task==self.identity['pid'],'Pidfd/proc namespace mismatch')
        try:
            now=process(self.identity['pid'])
            check(all(now[k]==self.identity[k] for k in ('pid','start_ticks','uid','cgroup')),'PID identity reused/moved')
        except FileNotFoundError:
            return {'exited':exited,'registered_process_reaped':exited and pidfd_task(self.fd)==-1}
        # Linux 6.8 poll signals thread-group exit, not wait/reap. A zombie
        # remains attached to its pidfd. fdinfo Pid=-1 requires !pid_has_task;
        # pathname absence alone never substitutes for this kernel observation.
        return {'exited':exited,'registered_process_reaped':False}


def proc_pid_view_check(status,mountinfo,pid):
    """Check self-visible PID numbering, not membership in the initial PID namespace.

    A remounted proc filesystem inside a PID namespace can also have one NSpid
    level. Shared namespace/proc identities and Slurm domains remain separately
    bound by SiteSession and KernelPeer. No other user's namespace link is read.
    """
    check(type(pid) is int and pid>0 and isinstance(status,str) and isinstance(mountinfo,str)
          and len(status)<=MAX_BYTES and len(mountinfo)<=MAX_BYTES,'Bounded self proc records required')
    values={}
    for line in status.splitlines():
        key,sep,value=line.partition(':')
        if key in ('Pid','Tgid','NSpid'):
            check(sep and key not in values,'Duplicate/malformed self PID field')
            values[key]=value.split()
    expected=[str(pid)]
    check(set(values)=={'Pid','Tgid','NSpid'} and all(values[k]==expected for k in values),
          'One-level self proc PID numbering required')
    selected={key:[] for key in ('/proc',CGROOT)}
    for line in mountinfo.splitlines():
        left,sep,right=line.partition(' - ');fields=left.split();tail=right.split()
        check(sep and len(fields)>=6 and len(tail)>=3,'Malformed self mountinfo')
        if fields[4] in selected:selected[fields[4]].append((fields[3],tail[0],tail[2]))
    check(len(selected['/proc'])==1 and selected['/proc'][0][:2]==('/','proc'),
          'One root-mounted proc filesystem required')
    options=selected['/proc'][0][2]
    check(not any(option.startswith(('hidepid=','subset=')) for option in options.split(',')),
          'Restricted proc super options refused')
    check(len(selected[CGROOT])==1 and selected[CGROOT][0][:2]==('/','cgroup2'),'Unhidden cgroup2 mount required')
    return options


class LinuxHost:
    def stamp(self):return time.monotonic_ns(),time.time_ns()
    def context(self):
        options=proc_pid_view_check(Path('/proc/self/status').read_text(),Path('/proc/self/mountinfo').read_text(),os.getpid())
        value=process(os.getpid());value.update(node=socket.gethostname(),boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        value.update(pid_namespace=os.readlink('/proc/self/ns/pid'),mount_namespace=os.readlink('/proc/self/ns/mnt'),
                     cgroup_namespace=os.readlink('/proc/self/ns/cgroup'),time_namespace=os.readlink('/proc/self/ns/time'),
                     proc_identity=[Path('/proc').stat().st_dev,Path('/proc').stat().st_ino],proc_mount_super_options=options)
        check(value['uid']==os.getuid()==os.geteuid()>0 and re.fullmatch(r'[0-9a-f-]{36}',value['boot_id']),
              'Nonroot stable host required')
        return value
    def group(self,path):return GroupHandle(path)
    def track(self,pid,uid,domain):return ProcessHandle(pid,uid,domain)
    def process(self,pid):return process(pid)
    def step_tree(self,step):return StepTree(step)
    def baseline_capabilities(self):return baseline_capabilities(Path('/proc/self/status').read_text())
    def executable_info(self,pid,optional=False):
        try:
            path=Path('/proc')/str(pid)/'exe'
            target=os.readlink(path)
            with path.open('rb') as stream:
                before=os.fstat(stream.fileno());raw=stream.read(64*1024**2+1);after=os.fstat(stream.fileno())
            check(0<len(raw)<=64*1024**2 and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
                  (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'Executable changed during baseline read')
            return {'status':'observed','path':target,'sha256':hashlib.sha256(raw).hexdigest()}
        except PermissionError:
            if not optional:raise
            return {'status':'unobserved','reason':'permission_denied'}


class SiteSession:
    """A live-object lease is never loaded from user-written JSON."""
    def __init__(self,draft,job_id,step_id,host,scheduler,*,external=False):
        core.timing(draft);numeric_id(job_id);numeric_id(step_id,True)
        self.draft=draft;self.job_id=job_id;self.step_id=step_id;self.host=host;self.scheduler=scheduler
        self.external=external;self.context=host.context();self.clock=RemainingClock();self.lease=None;self.groups=[]
        check(self.context['uid']==draft['owner_uid'],'Observer owner mismatch')
        root=CGBASE+'/job_'+job_id
        in_job=(CGROOT+self.context['cgroup']).startswith(root+'/')
        check((not in_job) if external else (CGROOT+self.context['cgroup']).startswith(root+'/step_batch/'),
              'W must be inside batch; external observer must be outside target job')
        try:
            self.job=host.group(root);self.groups.append(self.job)
            self.step=host.group(root+'/step_'+step_id);self.groups.append(self.step)
            snapshot=self.observe()
            job=snapshot['job']
            check(job['state']=='RUNNING' and snapshot['step'] is not None and snapshot['step']['state']=='RUNNING',
                  'Lease must bind while target job AND step are running')
            self.lease={k:job[k] for k in ('cluster','job_id','uid','node','submit_time','job_name','job_comment')}
            self.lease.update(step_id=step_id,node_boot_id=self.context['boot_id'],attempt_nonce=draft['attempt_nonce'],
                              source_sha=draft['source']['head'],job_cgroup=self.job.identity,step_cgroup=self.step.identity,dedicated_cpu_worker=True)
            core.lease_check(draft,self.lease)
        except BaseException:
            self.close();raise
    def close(self):
        for group in reversed(self.groups):group.close()
        self.groups=[]
    def observe(self):
        begin=self.host.stamp();ctx=self.host.context()
        check(all(ctx[k]==self.context[k] for k in ('pid','start_ticks','uid','cgroup','node','boot_id',
                  'pid_namespace','mount_namespace','cgroup_namespace','time_namespace','proc_identity',
                  'proc_mount_super_options')),'Observer moved/rebooted/reused')
        a=parse_job(self.scheduler.query('job',self.job_id),self.job_id,'cluster')
        check(a['uid']==ctx['uid'] and a['node']==ctx['node'] and a['job_name']==self.draft['expected_job_name'] and
              a['job_comment']==self.draft['expected_job_comment'],'Job is not this exact attempt')
        steps=parse_steps(self.scheduler.query('step',self.job_id),self.job_id,ctx['node'],ctx['uid'])
        check(set(steps)<={'batch','extern',self.step_id},'Shared worker steps refused')
        b=parse_job(self.scheduler.query('job',self.job_id),self.job_id,'cluster')
        check(stable_job(a)==stable_job(b) and a['state']==b['state'] and a['end_time']==b['end_time'],
              'Scheduler state changed during observation')
        hard=self.job.resources()
        check(hard['scope_identity']==self.job.identity and isinstance(hard['logical_cpu_ids'],list) and
              len(hard['logical_cpu_ids'])==1 and type(hard['logical_cpu_ids'][0]) is int and hard['logical_cpu_ids'][0]>=0 and
              type(hard['memory_max_bytes']) is int and 0<hard['memory_max_bytes']<=1073741824 and
              (hard['swap_max_bytes'] is None or type(hard['swap_max_bytes']) is int and hard['swap_max_bytes']>=0),
              'Actual resource fields incomplete or outside limits')
        local_steps=self.job.step_domains()
        check(local_steps<={'batch','extern',self.step_id},'Unreported/shared local step domain')
        if self.step_id in steps:self.step.verify()
        # Controller step listings may omit special steps. Check the retained
        # local job directory independently; omission is NOT empty extern proof.
        extern=[]
        if 'extern' in steps or 'extern' in local_steps:
            handle=self.host.group(self.job.identity['path']+'/step_extern')
            try:extern=[p for p in handle.pids() if self.host.process(p)['uid']==ctx['uid']]
            finally:handle.close()
        check(not extern,'Unrelated extern user workload')
        check(self.job.step_domains()==local_steps,'Local step tree changed during observation')
        after_ctx=self.host.context()
        check(all(after_ctx[k]==ctx[k] for k in ctx if k!='state'),'Observer changed during bracketed read')
        end=self.host.stamp();remaining=self.clock.update(b,begin,end)
        b.update(cgroup=dict(self.job.identity),time_remaining_s=remaining)
        step=steps.get(self.step_id)
        if step is not None:step={**step,'cgroup':dict(self.step.identity)}
        obs={'observed_ns':end[0],'node_boot_id':ctx['boot_id'],'observer_job_id':self.job_id if not self.external else None,
             'observer_step':'batch' if not self.external else 'external','observer_uid':ctx['uid'],
             'job':b,'step_ids':list(steps),'hard_resources':hard,'extern_user_tasks':extern,'step':step}
        if self.lease is not None and not self.external and b['state'] in ('RUNNING','COMPLETING'):
            core.observation_check(self.draft,self.lease,obs,end[0],'job')
        self.last_observation=core.readonly.strict(json.dumps(obs,allow_nan=False))
        return obs
    def evidence(self):
        return {'lease':self.lease,'deadline_monotonic_ns':self.clock.deadline_ns,
                'observer_identity':self.context,'evidence_scope':'live_handles_not_serializable_authority',
                **dict.fromkeys(GATES,False)}


def open_live(*args,**kwargs):
    raise PermissionError('Site runtime/client/native release not registered; no host or Slurm access started')


if __name__=='__main__':
    raise SystemExit('No executable entry: live site/observer release remains closed')
