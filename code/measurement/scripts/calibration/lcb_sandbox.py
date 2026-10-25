"""Owner-only Apptainer I/O judge. No host execution fallback, no image pulls.

Both site/reviewer authorization evidence and a fresh trusted runtime probe are
required before candidate execution. Expected answers stay in this host process.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from pilot import digest,read_json,read_rows,write_new
from lcb_sandbox_runner import verify_probe as check_probe
from lcb_delivery import eligible,POLICY as DELIVERY_POLICY
from lcb_cpu import CaseCgroup,cpu_record,total_cpu


def file_sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def approved(config,runner):
    checks=('untrusted_code_authorized','bind_override_authorized','network_none_verified',
            'pid_namespace_verified','cgroup_limits_verified','reviewer_approved','owner_approved')
    if config.get('schema')!='lcb-sandbox-approval-v1' or any(config.get(k) is not True for k in checks):
        raise ValueError('Site, reviewer and owner isolation approval is incomplete')
    if not config.get('site_approval_reference'):raise ValueError('Site decision reference required')
    if config.get('adapter_sha256')!=file_sha(__file__) or config.get('runner_sha256')!=file_sha(runner):
        raise ValueError('Approval is not for these exact adapter/runner bytes')
    for name in ('lcb_cpu.py','lcb_case_launcher.py','lcb_delivery.py'):
        if config.get('dependency_sha256',{}).get(name)!=file_sha(Path(__file__).with_name(name)):
            raise ValueError('Approval does not bind dependency '+name)
    if config.get('cpu_metering',{}).get('mode') not in ('bounds','delegated_cgroup_v2'):
        raise ValueError('Explicit CPU measurement policy required')
    image=Path(config['sif_path']).resolve(strict=True)
    if not image.is_file() or image.suffix!='.sif' or file_sha(image)!=config.get('sif_sha256'):
        raise ValueError('Unapproved image')
    return image


def command(image,runner,program,work,operation,*,cpu_id=None,managed=False):
    paths=[Path(x).resolve() for x in (image,runner,program,work)]
    if any(any(c in str(x) for c in (':',',','\n')) for x in paths):
        raise ValueError('Unsupported bind path characters')
    image,runner,program,work=paths
    if cpu_id is None:cpu_id=min(os.sched_getaffinity(0))
    limits=[] if managed else ['--pids-limit','32','--memory','1073741824','--cpus','1','--cpuset-cpus',str(cpu_id)]
    return ['apptainer','exec','--containall','--cleanenv','--no-home','--no-eval','--userns',
            '--no-mount','home,cwd,hostfs,bind-paths,/home,/scratch,/shares,/apps',
            '--net','--network','none','--drop-caps','ALL',*limits,'--workdir',str(work),'--pwd','/tmp',
            '--bind',str(program)+':/candidate/program.py:ro',
            '--bind',str(runner)+':/judge/runner.py:ro',str(image),
            'python3','-I','-B','/judge/runner.py',*operation]


def bounded_process(cmd,data,env,cwd,timeout=20,max_bytes=1048576):
    start=time.monotonic()
    child=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           env=env,cwd=cwd,start_new_session=True)
    selector=selectors.DefaultSelector();out={'stdout':bytearray(),'stderr':bytearray()};sent=0
    for stream,name in ((child.stdout,'stdout'),(child.stderr,'stderr')):
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    if data:
        os.set_blocking(child.stdin.fileno(),False);selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
    else:child.stdin.close()
    try:
        while selector.get_map():
            if time.monotonic()-start>timeout:raise TimeoutError('Container wall-time limit')
            for key,_ in selector.select(.05):
                if key.data=='stdin':
                    try:sent+=os.write(key.fd,data[sent:sent+65536])
                    except BrokenPipeError:sent=len(data)
                    if sent==len(data):selector.unregister(key.fileobj);key.fileobj.close()
                else:
                    chunk=os.read(key.fd,8192)
                    if not chunk:selector.unregister(key.fileobj);key.fileobj.close()
                    else:
                        out[key.data].extend(chunk)
                        if len(out[key.data])>max_bytes:raise ValueError('Container output limit')
        rc=child.wait(timeout=max(.1,timeout-(time.monotonic()-start)))
        if rc:raise RuntimeError('Container failed: '+out['stderr'][:4096].decode(errors='replace'))
        return json.loads(bytes(out['stdout'])),time.monotonic()-start
    finally:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.wait(timeout=5);selector.close()
        for stream in (child.stdin,child.stdout,child.stderr):
            if not stream.closed:stream.close()


def compare(actual,expected,kind):
    if kind=='whitespace_tokens_exact':return actual.split()==expected.split()
    if kind=='json_exact':
        try:
            a=json.loads(actual);e=json.loads(expected)
            # Canonical serialization distinguishes bool from integer and retains order.
            return json.dumps(a,sort_keys=True,allow_nan=False)==json.dumps(e,sort_keys=True,allow_nan=False)
        except (ValueError,TypeError):return False
    raise ValueError('Unsupported comparator')


def execution_identity(judge):
    """Identity of the already-approved execution stack, not a new permission."""
    return {'cpu_sif_sha256':judge.approval['sif_sha256'],
            'adapter_sha256':judge.approval['adapter_sha256'],
            'runner_sha256':judge.approval['runner_sha256'],
            'dependency_sha256':judge.approval.get('dependency_sha256',{})}


class Judge:
    def __init__(self,approval):
        self.runner=Path(__file__).with_name('lcb_sandbox_runner.py')
        self.image=approved(approval,self.runner)
        if not shutil.which('apptainer'):raise ValueError('Apptainer not loaded')
        self.approval=approval
        self.cpu_id=min(os.sched_getaffinity(0))
        self.host_ns={k:os.readlink('/proc/self/ns/'+k) for k in ('pid','net','mnt')}

    def environment(self):
        env=os.environ.copy()
        # This object can only exist after explicit site approval.
        for key in list(env):
            if key.startswith(('APPTAINER_','SINGULARITY_','APPTAINERENV_','SINGULARITYENV_')):env.pop(key)
        env.update(APPTAINER_BINDPATH='',APPTAINER_BIND='')
        return env

    def preflight(self):
        with tempfile.TemporaryDirectory(prefix='www27-probe-') as td:
            root=Path(td);program=root/'unused.py';program.write_text('# never executed\n')
            work=root/'work';work.mkdir()
            result,_,cpu=self.execute_case(program,work,['--probe'],b'',root,probe_only=True)
            result['cpu_measurement_probe']=cpu
            return result

    def execute_case(self,program,work,operation,data,root,probe_only=False):
        lease=CaseCgroup(self.approval['cpu_metering'],self.cpu_id)
        began=time.monotonic()
        try:
            extra=['--cpu-id',str(self.cpu_id)]
            if lease.path is not None:extra+=['--expected-cgroup-identity',json.dumps(lease.ident)]
            cmd=command(self.image,self.runner,program,work,operation+extra,cpu_id=self.cpu_id,managed=lease.path is not None)
            if lease.path is not None:
                cmd=[sys.executable,'-I','-B',str(Path(__file__).with_name('lcb_case_launcher.py')),
                     '--cgroup',str(lease.path),'--identity',json.dumps(lease.ident),'--',*cmd]
            result,wall=bounded_process(cmd,data,self.environment(),root)
            inspection=result if probe_only else result.get('isolation_probe',{})
            check_probe(inspection,self.host_ns,self.cpu_id,lease.ident if lease.path is not None else None)
            after=lease.snapshot() if lease.path is not None else None
            cpu=cpu_record(0 if probe_only else result['reaped_child_cpu_s'],time.monotonic()-began,
                           lease.before,after,single_cpu_verified=True)
            cpu['case_id']='case-'+uuid.uuid4().hex
            return result,wall,cpu
        finally:lease.cleanup()

    def case(self,code,test,contract):
        if len(code.encode())>1024*1024 or len(test['input'].encode())>16*1024*1024:
            raise ValueError('Program or case exceeds approved input limits')
        # Deliberately no task file, expected answer, project root or home mount.
        with tempfile.TemporaryDirectory(prefix='www27-case-') as td:
            root=Path(td);program=root/'program.py';program.write_text(code)
            program.chmod(0o444);work=root/'work';work.mkdir()
            operation=['--mode',contract['test_type'],'--host-namespaces',json.dumps(self.host_ns)]
            if contract['test_type']=='functional':operation+=['--entry',contract['entry_point']]
            result,wall,cpu=self.execute_case(program,work,operation,test['input'].encode(),root)
            if result.get('schema')!='lcb-case-result-v1' or result.get('status') not in ('ok','runtime_error','time_limit','output_limit'):
                raise ValueError('Untrusted or incomplete case result')
            check_probe(result.get('isolation_probe',{}),self.host_ns)
            return {'test_id':test['test_id'],'pass':result['status']=='ok' and compare(result['stdout'],test['output'],contract['comparison']),
                    'status':result['status'],'container_wall_s':wall,
                    'nominal_one_cpu_limit_times_wall_s':cpu['nominal_one_cpu_limit_times_wall_s'],
                    'full_verifier_cpu_s':cpu['verifier_cpu_seconds_measured'],
                    'cpu_accounting':cpu,
                    'reported_child_cpu_s':result.get('reaped_child_cpu_s'),
                    'raw_result':result,'isolation_probe':result['isolation_probe']}

    def fold(self,code,task,fold,short_circuit=False):
        tests={t['test_id']:t for t in task['tests']};cases=[]
        for test_id in task['folds'][fold]:
            result=self.case(code,tests[test_id],task);cases.append(result)
            if short_circuit and not result['pass']:break
        if not cases:raise ValueError('Empty fold')
        return {'pass':all(c['pass'] for c in cases),'cases':cases,
                'container_wall_s':sum(c['container_wall_s'] for c in cases),
                'cpu_accounting':total_cpu([c['cpu_accounting'] for c in cases])}


def main():
    p=argparse.ArgumentParser();p.add_argument('--prepared');p.add_argument('--samples')
    p.add_argument('--approval',required=True);p.add_argument('--output');p.add_argument('--execute',action='store_true')
    p.add_argument('--probe-only',action='store_true')
    a=p.parse_args()
    if not a.execute:
        print(json.dumps({'execute':False,'backend':'apptainer','required':'site approval plus runtime probe','no_candidate_executed':True}));return
    judge=Judge(read_json(a.approval));inspection=judge.preflight()
    if a.probe_only:
        if a.output:write_new(a.output,inspection)
        print(json.dumps(inspection));return
    if not a.prepared or not a.samples or not a.output:p.error('Evaluation requires --prepared, --samples and --output')
    if Path(a.output).exists():raise ValueError('Do not rerun evaluation into an existing output')
    prep=Path(a.prepared);manifest=read_json(prep/'manifest.json')
    if digest((prep/'tests.private.jsonl').read_bytes())!=manifest['private_tests_sha256']:raise ValueError('Test hash mismatch')
    tasks={t['task_id']:t for t in read_rows(prep/'tests.private.jsonl')}
    rows=[];seen=set()
    for sample in read_rows(a.samples):
        key=(sample['task_id'],sample['candidate_id'])
        if key in seen:raise ValueError('Duplicate sample identifier')
        seen.add(key)
        task=tasks[sample['task_id']]
        if not eligible(sample,strict=True):
            rows.append(dict(task_id=sample['task_id'],candidate_id=sample['candidate_id'],
                             status='no_executable_final',reason='length_truncated' if sample['finish_reason']=='length' else 'no_executable_final',
                             weak2=False,weak4=False,audit=False));continue
        weak4=judge.fold(sample['code'],task,'weak4')
        weak2_cases=[c for c in weak4['cases'] if c['test_id'] in task['folds']['weak2']]
        result={'weak4':weak4,'weak2':{'pass':all(c['pass'] for c in weak2_cases),'cases':weak2_cases,
                                     'container_wall_s':sum(c['container_wall_s'] for c in weak2_cases)},
                'audit':judge.fold(sample['code'],task,'audit')}
        rows.append({'task_id':sample['task_id'],'candidate_id':sample['candidate_id'],
                     'code_sha256':digest(sample['code']),'status':'evaluated',**result})
    write_new(a.output,{'schema':'lcb-io-evaluation-v2','evidence':'owner_executed_candidates',
                       'delivery_policy':DELIVERY_POLICY,
                       'execution_identity':execution_identity(judge),'samples_sha256':file_sha(a.samples),
                       'private_tests_sha256':manifest['private_tests_sha256'],
                       'evaluator_scope':'declared strict I/O comparator, not official LCB score equivalence','rows':rows})


if __name__=='__main__':main()
