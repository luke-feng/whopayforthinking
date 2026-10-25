"""M v2 offline accounting: workload points and separate control-plane tails.

No process/Slurm/namespace operation. Accepted scope is not execution authority.
Input hashes must come from the separately frozen evidence manifest, not be
recomputed as expected values from an untrusted return bundle.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re

import lcb_worker_metering_v1 as live

SCHEMA = 'worker-metering-v2'
RULING_SHA256 = '8e377319d4bc84ff994b8f83e0a0804bcacad6c375ebf0b66112d548ea6746b5'
CLOCK_POLICY_SHA256 = 'f1a5df593c917b06961fd0b06a6a0c19fda3217ccd0f3eb0f28e691321772d93'
RETIREMENT_RULING_SHA256 = '19176dff989da5a0a01dd80e3e7b8150cfc8aa66cf94d600ba1058d4e782bb69'
PROTOCOL_CLOCK_ERROR_NS = 1_000_000_000
SACCT_SHA256 = 'd99269fd68502a51ca89b229f0125ff8b2b3d349ee3d950c6769fdd09da8a456'
BASE_FIELDS = 'JobIDRaw,JobName,Cluster,UID,NodeList,Submit,Start,End,State,ExitCode,AllocTRES'
CPU_FIELDS = 'JobIDRaw,State,ElapsedRaw,CPUTimeRAW,TotalCPU,UserCPU,SystemCPU,TRESUsageInTot'
ENV = {'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}
CGROOT = '/sys/fs/cgroup/system.slice/slurmstepd.scope'
LIVE_PHASES = ('setup','service','standby','cleanup')
NS = 10**9
POST_RETIREMENT_MAX_NS = 20_000_000


def check(condition, message):
    if not condition: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()


def strict(raw):
    def pairs(items):
        out={}
        for k,v in items:
            check(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:check(False,'nonfinite JSON'))


def duration_us(raw):
    if raw == '': return None
    check(type(raw) is str,'CPU duration must be raw text')
    m=re.fullmatch(r'(?:(\d+)-)?(\d+):(\d{2})(?::(\d{2}))?(?:\.(\d{1,6}))?',raw)
    check(m is not None,'invalid CPU duration')
    if m[4] is None:
        check(not m[1] and int(m[3])<60,'invalid minute duration')
        seconds=int(m[2])*60+int(m[3])
    else:
        check(int(m[3])<60 and int(m[4])<60,'invalid second duration')
        seconds=(int(m[1] or 0)*24+int(m[2]))*3600+int(m[3])*60+int(m[4])
    return seconds*10**6+int((m[5] or '').ljust(6,'0') or '0')


def duration_quantum_us(raw):
    """Declared Slurm millisecond truncation, or finer explicit precision."""
    fraction=raw.partition('.')[2]
    return 10**(6-len(fraction)) if fraction else 1000


def displayed_additivity(total, user, system, raw):
    # Intersect half-open truncation intervals; displayed values need not add.
    tq,uq,sq=(duration_quantum_us(raw[k]) for k in ('TotalCPU','UserCPU','SystemCPU'))
    return total<user+system+uq+sq and user+system<total+tq


def epoch_ns(raw):
    check(type(raw) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',raw),
          'exact UTC second-resolution accounting time required')
    return int(datetime.fromisoformat(raw).replace(tzinfo=timezone.utc).timestamp())*NS


def table(raw, fields):
    check(type(raw) is bytes and 0<len(raw)<=2*1024**2,'bounded accounting original required')
    reader=csv.DictReader(io.StringIO(raw.decode('utf-8')),delimiter='|')
    check(reader.fieldnames==fields.split(','),'accounting field contract differs')
    rows={}
    for row in reader:
        check(None not in row and all(v is not None for v in row.values()),'accounting row width differs')
        key=row['JobIDRaw'];check(key not in rows,'duplicate accounting row');rows[key]=row
    return rows


def receipt(raw, receipt_raw, fields, job_ids, expected_sha, expected_receipt_sha):
    check(type(expected_sha) is str and re.fullmatch('[0-9a-f]{64}',expected_sha)
          and sha(raw)==expected_sha,'independent accounting hash differs')
    check(type(expected_receipt_sha) is str and re.fullmatch('[0-9a-f]{64}',expected_receipt_sha)
          and type(receipt_raw) is bytes and sha(receipt_raw)==expected_receipt_sha,'independent receipt hash differs')
    record=strict(receipt_raw)
    argv=record['argv']
    # Two existing raw receipt shapes; no arbitrary normalization or extra flags.
    if 'environment' in record:
        check(fields==BASE_FIELDS,'CPU accounting requires detailed collector receipt')
        check(set(record)=={'argv','environment','binary_sha256','returncode','stderr','stdout_sha256'},'base receipt schema')
        env,binary,output,error=record['environment'],record['binary_sha256'],record['stdout_sha256'],record['stderr']
    else:
        check(record.get('name')=='sacct' and record.get('status')=='captured'
              and record.get('child_reaped') is True and record.get('streams_complete') is True,
              'collector CPU receipt is not complete')
        before=record['binary_before']
        check(before==record['binary_after'] and before['before']==before['after']==record['pinned_fd_after']
              and record.get('binary_stable') is True and before['status']=='read','CPU receipt binary drift')
        info=before['before']
        check(info['uid']==0 and info['file_type']==32768 and not info['mode']&0o6022
              and info['mode']&0o111 and before['magic_hex']=='7f454c46'
              and record['client_trust']['accepted'] is True
              and re.fullmatch(r'/proc/self/fd/[0-9]+',record['execution_path']), 'CPU client trust differs')
        env,binary,output,error=record['env'],before['sha256'],record['stdout']['sha256'],record['error']
    check(env==ENV and binary==SACCT_SHA256 and output==expected_sha and type(record['returncode']) is int and record['returncode']==0
          and error in ('',None),'accounting client/environment/result differs')
    prefix=['/usr/bin/sacct','--clusters=cluster']
    if fields==BASE_FIELDS:prefix+=['--duplicates']
    check(type(argv) is list and len(argv)==len(prefix)+3 and argv[:len(prefix)]==prefix
          and argv[-3]=='--parsable2' and argv[-1]=='--format='+fields
          and argv[-2].startswith('--jobs='),'fixed sacct argv differs')
    requested=argv[-2][7:].split(',')
    check(len(requested)==len(set(requested)) and set(requested)==set(job_ids),'accounting jobs differ')


def accounting(base_raw, base_receipt, cpu_raw, cpu_receipt, jobs, *, base_sha, cpu_sha, base_receipt_sha, cpu_receipt_sha):
    check(type(jobs) is list and jobs,'frozen job inventory required')
    specs={}
    for job in jobs:
        check(set(job)=={'job_id','job_name','uid','cluster','node','submit_time','step_ids','purpose'},'job inventory schema')
        j=job['job_id'];check(type(j) is str and re.fullmatch('[1-9][0-9]*',j) and j not in specs,'job identity')
        check(type(job['job_name']) is str and job['job_name'] and type(job['uid']) is int and job['uid']>0 and job['cluster']=='cluster'
              and type(job['node']) is str and job['node'] and job['purpose'] in ('online','offline_audit'), 'job scope')
        steps=job['step_ids'];check(type(steps) is list and {'batch','extern'}<=set(steps) and len(steps)==len(set(steps))
          and all(type(s) is str and re.fullmatch(r'batch|extern|0|[1-9][0-9]*',s) for s in steps),'explicit step roster')
        epoch_ns(job['submit_time']);specs[j]=job
    receipt(base_raw,base_receipt,BASE_FIELDS,specs,base_sha,base_receipt_sha)
    receipt(cpu_raw,cpu_receipt,CPU_FIELDS,specs,cpu_sha,cpu_receipt_sha)
    base,cpu=table(base_raw,BASE_FIELDS),table(cpu_raw,CPU_FIELDS)
    wanted=set(specs)|{j+'.'+s for j,v in specs.items() for s in v['step_ids']}
    check(set(base)==wanted and set(cpu)<=wanted,'missing base or foreign accounting row')
    result={}
    for j,spec in specs.items():
        parent=base[j];check(parent['UID']==str(spec['uid']) and parent['Submit']==spec['submit_time']
                             and parent['JobName']==spec['job_name'],'parent owner/submit/name differs')
        for identifier in [j]+[j+'.'+s for s in spec['step_ids']]:
            b=base[identifier];start,end=epoch_ns(b['Start']),epoch_ns(b['End']);submitted=epoch_ns(b['Submit'])
            check(b['Cluster']==spec['cluster'] and b['NodeList']==spec['node']
                  and b['UID'] in (str(spec['uid']),'' if identifier!=j else str(spec['uid'])),'step owner/node/cluster differs')
            check(epoch_ns(parent['Submit'])<=submitted<=start<=end<=epoch_ns(parent['End']),'step timestamp binding')
            tres={}
            for token in b['AllocTRES'].split(','):
                pair=token.split('=');check(len(pair)==2 and pair[0] not in tres,'duplicate/invalid allocation');tres[pair[0]]=pair[1]
            check(tres.get('cpu')=='1' and tres.get('node')=='1' and tres.get('mem') in ('1G','1024M','1048576K','1073741824')
                  and set(tres)<={'cpu','node','mem','billing'},'one CPU/1GiB allocation required')
            c=cpu.get(identifier);problems=[];total=None
            if c is None:problems.append('missing_cpu_row')
            else:
                check(c['State']==b['State'],'CPU/base state mismatch')
                try:
                    total,user,system=(duration_us(c[k]) for k in ('TotalCPU','UserCPU','SystemCPU'))
                except ValueError:
                    problems.append('malformed_cpu_field');total=None
                else:
                    if None in (total,user,system):problems.append('missing_cpu_field')
                    elif not displayed_additivity(total,user,system,c):problems.append('displayed_CPU_additivity_mismatch')
            if b['State']!='COMPLETED' or b['ExitCode']!='0:0':problems.append('non_normal_terminal_state')
            result[identifier]={'base':b,'cpu':c,'reported_total_cpu_us':total,'problems':problems,
                                'end_wall_upper_ns':end+NS,'spec':spec}
    return result


def captured_snapshot(reader):
    """Read-only primitive for future wiring; no process or cgroup is created."""
    import time
    a=time.time_ns();snapshot=reader.snapshot();b=time.time_ns()
    return snapshot,{'snapshot_id':snapshot.snapshot_id,'started_wall_ns':a,'finished_wall_ns':b}


def shared_CPU_windows_fit(intervals):
    """Necessary one-CPU demand bound, with conservative read-time envelopes.

    Each measured delta must fit between its earliest first read and latest
    final read. Check all contained demands, not each domain in isolation.
    One microsecond per delta covers integer-counter truncation. This is not
    a proof of source provenance or of the unobserved within-window schedule.
    """
    by_end=sorted(intervals,key=lambda item:item[1])
    for begin in sorted({a for a,_,_ in intervals}):
        demand=0;count=0
        for a,end,cpu in by_end:
            if a>=begin:demand+=cpu;count+=1
            if end>=begin and demand>(end-begin+999)//1000+count:return False
    return True


def post_retirement_report(value, identifier, identity, last, uid):
    """Pure certificate consistency. Acquisition is bound by S in the exporter."""
    from dataclasses import asdict
    keys={'schema','job_id','step_id','kind','phase','event','status','error','controller_identity',
          'controller_state','controller_state_after','applied_deadline_ns','begin_ns','end_ns',
          'begin_wall_ns','end_wall_ns','last_pre_retirement_snapshot_id','origin_identity',
          'before','after','snapshot','wall_bracket'}
    check(type(value) is dict and set(value)==keys and value['schema']=='m-post-retirement-v1',
          'missing_or_malformed_post_retirement')
    job,step=identifier.split('.',1)
    check(step not in ('batch','extern') and
          (value['job_id'],value['step_id'],value['kind'],value['phase'],value['event'])==
          (job,step,'workload','cleanup','post_retirement'), 'post_retirement_scope')
    check(value['status']=='captured' and value['error'] is None, 'post_retirement_unidentified')
    check(value['origin_identity']==asdict(identity) and
          value['last_pre_retirement_snapshot_id']==last.snapshot_id, 'post_retirement_origin')
    for key in ('begin_ns','end_ns','begin_wall_ns','end_wall_ns','applied_deadline_ns'):
        check(type(value[key]) is int and value[key]>0, 'post_retirement_timestamp')
    check(last.finished_ns<=value['begin_ns']<=value['end_ns']<=value['applied_deadline_ns']
          and value['end_ns']-value['begin_ns']<=POST_RETIREMENT_MAX_NS
          and value['begin_wall_ns']<=value['end_wall_ns'], 'post_retirement_budget_or_order')
    controller=value['controller_identity']
    check(type(controller) is dict and set(controller)=={'pid','uid','start_ticks','cgroup'}
          and all(type(controller[k]) is int and controller[k]>0 for k in ('pid','start_ticks'))
          and type(controller['uid']) is int and controller['uid']==uid
          and controller['cgroup']==identity.path.removeprefix('/sys/fs/cgroup')+'/task_0',
          'post_retirement_controller')
    for key in ('controller_state','controller_state_after'):
        state=value[key]
        check(type(state) is dict and set(state)=={'exited','registered_process_reaped'}
              and state['exited'] is True and type(state['registered_process_reaped']) is bool,
              'post_retirement_pidfd_not_exited')
    before,after=value['before'],value['after']
    check(type(before) is dict and before==after and set(before)=={'directories','children','procs'},
          'post_retirement_tree_changed')
    names={'user','user/task_0'}
    if 'user/task_special' in before['directories']:names.add('user/task_special')
    check(set(before['directories'])==set(before['procs'])==set(before['children'])==names,
          'post_retirement_tree_roster')
    physical=set()
    for name in sorted(names):
        path=identity.path+name[4:]
        expected_children=(['task_0','task_special'] if len(names)==3 else ['task_0']) if name=='user' else []
        check(before['children'][name]==expected_children,'post_retirement_unexpected_subtree')
        for kind,meta in (('directory',before['directories'][name]),('regular',before['procs'][name])):
            fields={'path','device','inode','uid','gid','mode','kind'}|({'raw','pids'} if kind=='regular' else set())
            check(set(meta)==fields and meta['path']==path+('/cgroup.procs' if kind=='regular' else '')
                  and meta['kind']==kind and type(meta['device']) is int and meta['device']==identity.device
                  and type(meta['inode']) is int and meta['inode']>0
                  and type(meta['uid']) is int and meta['uid'] in (0,uid)
                  and type(meta['gid']) is int and meta['gid']>=0
                  and type(meta['mode']) is int and 0<=meta['mode']<=0o7777 and not meta['mode']&0o022,
                  'post_retirement_resource_identity')
            check((meta['device'],meta['inode']) not in physical,'post_retirement_aliased_leaf')
            physical.add((meta['device'],meta['inode']))
            if name=='user/task_special' or name=='user' and 'user/task_special' in names:
                check(meta['uid']==0,'post_retirement_protected_ancestor')
            if kind=='regular':
                check(type(meta['raw']) is str and len(meta['raw'])<=65536 and not meta['raw'].split()
                      and meta['pids']==[], 'post_retirement_nonempty_leaf')
    check(before['directories']['user']['inode']==identity.inode, 'post_retirement_root_inode')
    raw=dict(value['snapshot']);ident=dict(raw['identity']);ident['context']=live.CollectorContext(**ident['context'])
    raw['identity']=live.DomainIdentity(**ident);snapshot=live.Snapshot(**raw)
    check(snapshot.identity==identity and snapshot.snapshot_id!=last.snapshot_id
          and value['begin_ns']<=snapshot.started_ns<=snapshot.finished_ns<=value['end_ns']
          and snapshot.usage_usec is not None and last.usage_usec is not None
          and snapshot.usage_usec>=last.usage_usec and snapshot.populated_before is False
          and snapshot.populated_after is False, 'post_retirement_counter_or_population')
    wall=value['wall_bracket']
    check(type(wall) is dict and set(wall)=={'snapshot_id','started_wall_ns','finished_wall_ns'}
          and wall['snapshot_id']==snapshot.snapshot_id
          and type(wall['started_wall_ns']) is int and type(wall['finished_wall_ns']) is int
          and value['begin_wall_ns']<=wall['started_wall_ns']<=wall['finished_wall_ns']<=value['end_wall_ns'],
          'post_retirement_wall_bracket')
    tail=snapshot.usage_usec-last.usage_usec
    check(tail<=(snapshot.finished_ns-last.started_ns+999)//1000+1,
          'post_retirement_tail_exceeds_one_CPU')
    return {'snapshot':snapshot,'wall':wall,'point_cpu_us':snapshot.usage_usec,'tail_cpu_us':tail}


def series_report(value, identifier, kind, record, expected_digest):
    check(sha(encoded(value))==expected_digest,'independent series hash differs')
    fields={'schema','step_id','kind','uid','ledger','wall_brackets','clock_error_ns','origin_evidence_sha256','resource_envelope'}
    check(set(value) in (fields,fields|{'post_retirement'})
          and value['schema']=='m2-cpu-series-v1' and value['step_id']==identifier and value['kind']==kind
          and value['uid']==record['spec']['uid'],'series schema/scope')
    if 'post_retirement' in value:
        check(kind=='workload' and identifier.rsplit('.',1)[1] not in ('batch','extern'),
              'retirement endpoint on non-execution workload')
    check(type(value['origin_evidence_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['origin_evidence_sha256']),
          'bound domain-birth evidence reference required')
    ledger=live.import_ledger(value['ledger']);identity=ledger.snapshots[0].identity
    job,step=identifier.split('.',1);suffix='user' if kind=='workload' else 'slurm'
    resource=value['resource_envelope']
    check(set(resource)=={'job_cgroup','cpu_ids','source_sha256'} and resource['job_cgroup']==f'{CGROOT}/job_{job}'
          and type(resource['cpu_ids']) is list and len(resource['cpu_ids'])==1
          and type(resource['cpu_ids'][0]) is int and resource['cpu_ids'][0]>=0
          and type(resource['source_sha256']) is str and re.fullmatch('[0-9a-f]{64}',resource['source_sha256']),
          'bound actual one-CPU envelope required; allocation alone is not proof')
    check(identity.path==f'{CGROOT}/job_{job}/step_{step}/{suffix}' and identity.context.node==record['spec']['node']
          and ledger.purpose==record['spec']['purpose'],'wrong cost domain; step root/leaf substitution refused')
    check(ledger.origin is None and ledger.final is None and ledger.envelope is None,
          'v1 boundary callbacks/envelopes cannot certify v2')
    check(all(w.phase in LIVE_PHASES for w in ledger.windows),'live tail reserved for accounting residual')
    report=live._domain_report(ledger,None)  # structural, monotone, exhaustive windows; no v1 lifetime promotion
    check(ledger.windows[0].phase=='setup' and ledger.windows[-1].phase=='cleanup','setup/cleanup boundaries required')
    stamps=value['wall_brackets'];check(type(stamps) is list and len(stamps)==len(ledger.snapshots),'wall stamp coverage')
    error=value['clock_error_ns'];check(error is None or type(error) is int and error>=0,'clock uncertainty must be explicit')
    offset_lo,offset_hi=None,None;prior=None
    for stamp,snapshot in zip(stamps,ledger.snapshots):
        check(set(stamp)=={'snapshot_id','started_wall_ns','finished_wall_ns'} and stamp['snapshot_id']==snapshot.snapshot_id,'wall stamp identity')
        a,b=stamp['started_wall_ns'],stamp['finished_wall_ns']
        check(type(a) is int and type(b) is int and a<=b and (prior is None or a>=prior),'wall clock reversed/overlapped')
        prior=b
        if error is not None:
            lo=a-snapshot.finished_ns-error;hi=b-snapshot.started_ns+error
            offset_lo=lo if offset_lo is None else max(offset_lo,lo)
            offset_hi=hi if offset_hi is None else min(offset_hi,hi)
    if error is not None:
        check(offset_lo<=offset_hi,'wall/monotonic clock binding inconsistent')
        check(stamps[0]['started_wall_ns']+error>=epoch_ns(record['base']['Start'])
              and stamps[-1]['finished_wall_ns']-error<record['end_wall_upper_ns'],'series outside step lifetime')
    first,last=ledger.snapshots[0],ledger.snapshots[-1]
    complete=report['window_cpu_usec'] is not None and first.usage_usec is not None and last.usage_usec is not None
    phases={p:report['phase_cpu_usec'][p] for p in LIVE_PHASES}
    if complete:phases['setup']+=first.usage_usec  # trusted fresh-domain cumulative prefix, explicitly recorded
    capacity_problems=[]
    if error is not None:
        # Counters are integer microseconds; permit one microsecond of rounding.
        for previous,current in zip(ledger.snapshots,ledger.snapshots[1:]):
            if previous.usage_usec is not None and current.usage_usec is not None:
                if current.usage_usec-previous.usage_usec>(current.finished_ns-previous.started_ns+999)//1000+1:
                    capacity_problems.append('live_counter_exceeds_one_CPU_window');break
        prefix_capacity=(stamps[0]['finished_wall_ns']+error-epoch_ns(record['base']['Start'])+999)//1000+1
        if first.usage_usec is not None and first.usage_usec>prefix_capacity:
            capacity_problems.append('prefix_exceeds_one_CPU_lifetime')
    return {'ledger':ledger,'identity':identity,'windows':report['windows'],'phases':phases,'complete':complete,
            'prefix_cpu_us':first.usage_usec,'last_cpu_us':last.usage_usec,'clock_error_ns':error,
            'resource_envelope':resource,'capacity_problems':capacity_problems,
            'birth_mono_lower_ns':None if error is None else epoch_ns(record['base']['Start'])-offset_hi,
            'terminal_mono_upper_ns':None if error is None else record['end_wall_upper_ns']-offset_lo,
            'observed_until_mono_ns':last.finished_ns,'last_read_started_mono_ns':last.started_ns}


def analyze(base_raw,base_receipt,cpu_raw,cpu_receipt,jobs,series,*,base_sha,cpu_sha,base_receipt_sha,cpu_receipt_sha,series_hashes):
    rows=accounting(base_raw,base_receipt,cpu_raw,cpu_receipt,jobs,base_sha=base_sha,cpu_sha=cpu_sha,
                    base_receipt_sha=base_receipt_sha,cpu_receipt_sha=cpu_receipt_sha)
    expected={j['job_id']+'.'+s for j in jobs for s in j['step_ids']}
    check(set(series)<=expected and set(series_hashes)==set(series),'foreign series/digest roster')
    reports={};physical=set();kinds=set();job_contexts={};job_resources={};job_intervals={}
    for identifier in sorted(expected):
        record=rows[identifier];problems=list(record['problems']);point=None
        parent=rows[identifier.split('.',1)[0]]
        if parent['base']['State']!='COMPLETED' or parent['base']['ExitCode']!='0:0':
            problems.append('parent_non_normal_terminal_state')
        item={'step_id':identifier,'purpose':record['spec']['purpose'],'accounting':record['cpu'],
              'workload_lifetime_cpu_us':None,'control_plane_observed_cpu_us':None,
              'display_quantum_residual_us':None,'platform_underreport_us':None,
              'control_plane_tail':{'lower_cpu_us':0,'upper_cpu_us':None,'included_in_point':False},
              'point_cpu_us':None,'status':'unidentified','problems':problems}
        supplied=series.get(identifier)
        if supplied is None:problems.append('missing_live_domain_series');reports[identifier]=item;continue
        check(set(supplied)==set(series_hashes[identifier])=={'workload','control_plane'},'two disjoint domain series required')
        parsed={}
        for kind in ('workload','control_plane'):
            value=series_report(supplied[kind],identifier,kind,record,series_hashes[identifier][kind])
            identity=value['identity'];key=(identity.context.node,identity.context.boot_id,identity.device,identity.inode)
            check(key not in physical,'duplicate physical domain in cost sum');physical.add(key)
            kinds.add(identity.context.source);parsed[kind]=value
        w,c=parsed['workload'],parsed['control_plane']
        check(w['identity'].context==c['identity'].context,'workload/control node/boot/mount differs')
        check(w['resource_envelope']==c['resource_envelope'],'workload/control hard resource binding differs')
        job_id=identifier.split('.',1)[0];context=w['identity'].context
        check(job_id not in job_contexts or job_contexts[job_id]==context,'same job node/boot/mount differs across steps')
        job_contexts[job_id]=context
        check(job_id not in job_resources or job_resources[job_id]==w['resource_envelope'],
              'same job hard resource envelope differs across steps')
        job_resources[job_id]=w['resource_envelope']
        for kind,value in parsed.items():
            if value['clock_error_ns'] is None:problems.append('unidentified_'+kind+'_clock_bound')
            problems.extend(value['capacity_problems'])
            if value['clock_error_ns'] is not None and value['prefix_cpu_us'] is not None:
                job_intervals.setdefault(job_id,[]).append((value['birth_mono_lower_ns'],
                    value['ledger'].snapshots[0].finished_ns,value['prefix_cpu_us']))
            for a,b in zip(value['ledger'].snapshots,value['ledger'].snapshots[1:]):
                if a.usage_usec is not None and b.usage_usec is not None:
                    job_intervals.setdefault(job_id,[]).append((a.started_ns,b.finished_ns,b.usage_usec-a.usage_usec))
        if not w['complete'] or not c['complete']:problems.append('missing_live_counter')
        execution=identifier.rsplit('.',1)[1] not in ('batch','extern')
        post=None
        lifetime=record['reported_total_cpu_us']
        if execution:
            try:
                post=post_retirement_report(supplied['workload'].get('post_retirement'),identifier,
                    w['identity'],w['ledger'].snapshots[-1],record['spec']['uid'])
                lifetime=post['point_cpu_us']
                if w['clock_error_ns'] is not None:
                    error=w['clock_error_ns'];snap=post['snapshot'];wall=post['wall']
                    lo=wall['started_wall_ns']-snap.finished_ns-error
                    hi=wall['finished_wall_ns']-snap.started_ns+error
                    for old,stamp in zip(w['ledger'].snapshots,supplied['workload']['wall_brackets']):
                        lo=max(lo,stamp['started_wall_ns']-old.finished_ns-error)
                        hi=min(hi,stamp['finished_wall_ns']-old.started_ns+error)
                    check(lo<=hi and wall['finished_wall_ns']-error<record['end_wall_upper_ns'],
                          'post_retirement_clock_binding')
                if record['reported_total_cpu_us'] is not None:
                    check(record['reported_total_cpu_us']<=lifetime+duration_quantum_us(record['cpu']['TotalCPU']),
                          'platform_CPU_exceeds_retirement_endpoint')
            except (ValueError, KeyError, TypeError) as exc:
                lifetime=None;post=None
                problems.append('unidentified_post_retirement:'+str(exc))
        if lifetime is not None and c['last_cpu_us'] is not None:
            capacity=(record['end_wall_upper_ns']-epoch_ns(record['base']['Start']))//1000
            if lifetime+c['last_cpu_us']>capacity:
                problems.append('combined_cost_exceeds_one_CPU_lifetime')
        if not problems:
            tail=lifetime-w['last_cpu_us']
            residual=0
            if tail<0:
                if not execution and -tail<=duration_quantum_us(record['cpu']['TotalCPU']):
                    # The displayed endpoint can lag the live counter by one
                    # display quantum. Keep this discrepancy separate from
                    # both point cost and the unobserved workload tail.
                    residual=-tail;tail=0
                else:problems.append('negative_workload_tail')
            if not problems:
                check(w['prefix_cpu_us']+sum(x['cpu_usec'] for x in w['windows'])+tail==lifetime+residual,
                      'workload conservation failure')
                item.update(workload_lifetime_cpu_us=lifetime,
                            workload_live_phase_cpu_us=w['phases'],workload_prefix_cpu_us=w['prefix_cpu_us'],
                            workload_tail_cpu_us=tail,workload_conservation=True,
                            display_quantum_residual_us=residual,
                            workload_endpoint_source='post_retirement_empty_subtree' if execution else 'sacct_TotalCPU',
                            platform_underreport_us=lifetime-record['reported_total_cpu_us'] if execution else None,
                            control_plane_observed_cpu_us=c['last_cpu_us'],control_plane_live_phase_cpu_us=c['phases'])
                job_intervals.setdefault(job_id,[]).append((w['last_read_started_mono_ns'],
                    post['snapshot'].finished_ns if execution else w['terminal_mono_upper_ns'],tail))
                if c['terminal_mono_upper_ns'] is None:problems.append('unidentified_control_tail_clock_bound')
                else:
                    ns=c['terminal_mono_upper_ns']-c['last_read_started_mono_ns']
                    check(ns>=0,'control read is after terminal upper bound')
                    item['control_plane_tail'].update(upper_cpu_us=(ns+999)//1000,
                        bound_method='one_CPU_times_terminal_upper_minus_last_read_lower',
                        accounting_time_resolution_ns=NS,clock_error_ns=c['clock_error_ns'])
                point=lifetime+c['last_cpu_us']
        if not problems:item.update(point_cpu_us=point,status='input_consistent_point_pending_review')
        reports[identifier]=item
    for job in jobs:
        members=[reports[job['job_id']+'.'+s] for s in job['step_ids']]
        joint_problems=[]
        if not shared_CPU_windows_fit(job_intervals.get(job['job_id'],[])):
            joint_problems.append('shared_live_windows_exceed_job_one_CPU')
        if all(m['point_cpu_us'] is not None for m in members):
            parent=rows[job['job_id']]
            limit=(parent['end_wall_upper_ns']-epoch_ns(parent['base']['Start']))//1000
            if sum(m['point_cpu_us'] for m in members)>limit:
                joint_problems.append('combined_steps_exceed_job_one_CPU_lifetime')
        if joint_problems:
            for m in members:
                m.update(point_cpu_us=None,status='unidentified');m['problems'].extend(joint_problems)
    check(len(kinds)<=1,'synthetic and collected series cannot be mixed')
    ready=all(x['point_cpu_us'] is not None for x in reports.values())
    point=sum(x['point_cpu_us'] for x in reports.values()) if ready else None
    upper=sum(x['control_plane_tail']['upper_cpu_us'] for x in reports.values()) if ready else None
    return {'schema':SCHEMA,'scope_ruling_sha256':RULING_SHA256,'retirement_ruling_sha256':RETIREMENT_RULING_SHA256,
        'status':'input_consistent_point_pending_review' if ready else 'unidentified',
        'source_kind':next(iter(kinds),'unobserved'),'steps':reports,
        'point_scope':'workload_lifetimes_plus_observed_control_plane_not_complete_physical_CPU',
        'point_cpu_us':point,'control_plane_tail':{'lower_cpu_us':0,'upper_cpu_us':upper,'included_in_point':False},
        'full_physical_cpu_us':None,'job_rows_added_to_step_sum':False,
        'online_point_cpu_us':sum(x['point_cpu_us'] for x in reports.values() if x['purpose']=='online') if ready and any(x['purpose']=='online' for x in reports.values()) else None,
        'input_hashes':{'base':base_sha,'cpu':cpu_sha,'base_receipt':base_receipt_sha,'cpu_receipt':cpu_receipt_sha,'series':series_hashes},
        'cpu_time_raw_used_as_usage':False,
        'gates':{'runtime_registered':False,'evidence_accepted':False,'cost_sample_eligible':False,
                 'candidate_execution_authorized':False,'main_matrix_authorized':False}}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--input',required=True)
    parser.add_argument('--input-sha256',required=True);args=parser.parse_args()
    raw=Path(args.input).read_bytes();check(len(raw)<=32*1024**2 and sha(raw)==args.input_sha256,'independently bound input envelope required')
    value=strict(raw);check(set(value)=={'scope_ruling_sha256','base_raw','base_receipt','cpu_raw','cpu_receipt','jobs','series','base_sha','cpu_sha','base_receipt_sha','cpu_receipt_sha','series_hashes'},'input envelope fields')
    check(value.pop('scope_ruling_sha256')==RULING_SHA256,'M v2 scope ruling differs')
    for name in ('base_raw','cpu_raw','base_receipt','cpu_receipt'):value[name]=value[name].encode()
    print(json.dumps(analyze(**value),indent=2,allow_nan=False))


if __name__=='__main__':main()
