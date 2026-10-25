"""Sequential same-card GPU cells and C-backed candidates, no automatic retry.

New sockets are ordinary owner-only Unix sockets, without authentication
extensions. Existing release/batch checks supply the approved execution scope.
"""
from dataclasses import asdict
from contextvars import ContextVar
from pathlib import Path
import hashlib
import json
import os
import queue
import re
import secrets
import socket
import subprocess
import threading
import time
import tempfile

import lcb_isolation_release_v2 as release
import lcb_isolation_batch_v2 as batch
import lcb_isolation_runtime_v2 as runtime
import lcb_isolation_meter_v2 as meter
import lcb_isolation_backend_v2 as adapter
from lcb_pilot_quality_v1 import CaseRequest
from lcb_output_compare import project_compare

CELL_INDEX=ContextVar('ngpu_cell_index',default=None)
VLLM_WORKER='scripts/calibration/lcb_vllm_worker.py'
CANDIDATE_RUNNER='scripts/calibration/lcb_candidate_runner.py'
SOCKET_FRAME_LIMIT=1024**3
LAUNCH_TIMEOUT_S=75      # apptainer start + the C helper's own 5/7/10 s bounds, with room for a cold shared filesystem
STDOUT_LIMIT=32*1024**2  # a property of the test data, not of the candidate; larger output is a wrong answer
STDERR_KEEP=64*1024
PROBE_TIMEOUT_S=300


def work_root(authority):
    return batch.cell_root(authority.root,authority.manifest,CELL_INDEX.get())


def active_cell(authority):
    index=CELL_INDEX.get()
    release.check(index is not None,'A cell index is required for cell work')
    return authority.manifest['cells'][index]


def file_digest(path):
    h=hashlib.sha256();size=0
    with Path(path).open('rb') as stream:
        for part in iter(lambda:stream.read(1024**2),b''):h.update(part);size+=len(part)
    return h.hexdigest(),size


HASH_CACHE='.www27-hash-cache.json'


def file_identity(path):
    st=Path(path).stat()
    return [st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_ino]


def load_hash_cache(directory):
    try:
        value=release.strict((Path(directory)/HASH_CACHE).read_bytes())
    except (OSError,ValueError):
        return {}
    return value if type(value) is dict else {}


def save_hash_cache(directory,entries):
    """Best effort: merge into whatever is stored now and replace atomically; a failure only means a later full hash."""
    try:
        merged=load_hash_cache(directory);merged.update(entries)
        path=Path(directory)/HASH_CACHE
        temporary=path.with_name(path.name+'.'+secrets.token_hex(6)+'.tmp')
        temporary.write_bytes(release.encoded(merged));os.replace(temporary,path)
    except OSError:
        pass


def verify_file(path,expected,cache,tally):
    """True when the file has the frozen sha256. It is hashed in full only if its size, mtime, ctime and inode are not
    those of a copy already verified to have this digest, so a frozen asset costs one full read, not one per submit."""
    path=str(path);before=file_identity(path);row=cache.get(path)
    if type(row) is dict and row.get('identity')==before and row.get('sha256')==expected:
        tally['stat_matches']+=1
        return True
    digest,_=file_digest(path)
    release.check(file_identity(path)==before,'File changed while it was hashed: '+path)
    tally['full_hashes']+=1
    if digest!=expected:
        return False
    cache[path]={'identity':before,'sha256':digest}
    return True


def validate_inference_assets(value):
    release.check(type(value) is dict and set(value)=={'schema','inference_sif','model_weights','nvidia_smi','candidate_runner'}
                  and value['schema']=='ngpu-inference-assets-v2','Inference asset fields')
    row=value['inference_sif']
    release.check(set(row)=={'path','sha256','bytes'} and Path(row['path']).is_absolute(),'SIF reference')
    release.digest(row['sha256']);release.integer(row['bytes'],1)
    row=value['nvidia_smi']
    release.check(set(row)=={'path','sha256'} and Path(row['path']).is_absolute(),'nvidia-smi reference')
    release.digest(row['sha256'])
    row=value['candidate_runner']
    release.check(type(row) is dict and set(row)=={'path','sha256','bytes'} and
                  row['path']==CANDIDATE_RUNNER,'Candidate runner source reference')
    release.digest(row['sha256']);release.integer(row['bytes'],1)
    weights=value['model_weights']
    release.check(set(weights)=={'dir','manifest_path','manifest_sha256','files'} and Path(weights['dir']).is_absolute()
                  and Path(weights['manifest_path']).is_absolute()
                  and type(weights['files']) is dict and weights['files'],'Weight inventory')
    release.digest(weights['manifest_sha256'])
    for name,digest in weights['files'].items():
        release.check(not Path(name).is_absolute() and '..' not in Path(name).parts,'Weight file entry')
        release.digest(digest)
    return value


def prepare_inference(authority, prepared=None):
    release.require(authority,phase='queue')
    value=validate_inference_assets(authority.assets['inference'])
    # nvidia-smi is node-local: the login host need not have a GPU driver.
    # gpu_identity verifies its locked bytes before using it on the GPU node.
    tally={'full_hashes':0,'stat_matches':0}
    for key in ('inference_sif','candidate_runner'):
        row=value[key]
        cpu_sif=prepared['runtime_lock_value']['cpu_sif'] if prepared is not None else None
        if (key=='inference_sif' and cpu_sif is not None and row['path']==cpu_sif['path']
                and prepared.get('SIF_body_rehashed') is True):
            # This same body was already fully hashed by prepare_batch_assets.
            release.check(row['sha256']==cpu_sif['sha256'] and row['bytes']==Path(row['path']).stat().st_size,
                          'Shared CPU/inference SIF reference differs')
            continue
        if key=='inference_sif':
            directory=Path(row['path']).parent;cache=load_hash_cache(directory)
            release.check(Path(row['path']).stat().st_size==row['bytes'] and verify_file(row['path'],row['sha256'],cache,tally),
                          'Asset bytes differ: '+key)
            save_hash_cache(directory,cache)
        else:  # the runner is a small repository file: always hashed
            digest,size=file_digest(release.ROOT/row['path'])
            release.check(digest==row['sha256'] and ('bytes' not in row or size==row['bytes']),'Asset bytes differ: '+key)
    if prepared is not None and prepared.get('SIF_body_rehashed') is not True:
        cpu=prepared['runtime_lock_value']['cpu_sif'];sif=value['inference_sif']
        release.check(cpu['path']==sif['path'] and cpu['sha256']==sif['sha256'],
                      'The candidate sandbox image is not the inference image whose bytes were hashed')
    weights=value['model_weights'];raw=Path(weights['manifest_path']).read_bytes()
    release.check(release.sha(raw)==weights['manifest_sha256'],'Weight checksum manifest changed')
    expected={}
    if raw.lstrip()[:1]==b'{':  # an owner asset lock (inference-assets-lock-v1): its file hashes are the inventory
        lock=release.strict(raw)
        release.check(lock.get('schema')=='inference-assets-lock-v1' and type(lock.get('model_files_sha256')) is dict,
                      'Weight lock schema')
        expected=dict(lock['model_files_sha256'])
        for cell_id in authority.manifest['cells']:
            cell=batch.panel_cell(cell_id)
            release.check((lock.get('model_id'),lock.get('model_revision'))==(cell['model_id'],cell['revision']),
                          'Weight lock is for another model revision')
    else:
        for line in raw.decode().splitlines():
            digest,name=line.split(maxsplit=1);name=name.lstrip('*')
            if Path(name).is_absolute():name=str(Path(name).relative_to(weights['dir']))
            if name.startswith('./'):name=name[2:]
            if name.startswith('model/'):name=name[6:]
            release.check(name not in expected,'Repeated weight checksum entry');expected[name]=digest
    release.check(expected==weights['files'],'Weight file manifest differs from lock')
    root=Path(weights['dir'])
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    release.check(set(value['model_weights']['files'])<=actual,'A locked weight file is missing')  # extra files are ignored
    cache=load_hash_cache(root.parent)  # next to the model directory, so it never enters the container's /model
    try:
        for name,digest in weights['files'].items():
            release.check(verify_file(root/name,digest,cache,tally),'Weight file bytes differ')
    finally:
        save_hash_cache(root.parent,cache)  # also keeps what was verified before a later file failed
    for cell_id in authority.manifest['cells']:
        config,work=read_cell_inputs(authority,cell_id)
        validate_inputs(config,work,batch.panel_cell(cell_id),main_authorized=authority.manifest['main_matrix_authorized'])
    receipt={'schema':'ngpu-prepared-v1','inference_assets_sha256':release.object_sha(value),
             'manifest_sha256':release.object_sha(authority.manifest),'files_hashed_once':True,
             'hash_verification':tally,'node_local_hashes_deferred':['nvidia_smi']}
    release.write_new(authority.root/'inference-prepared.json',receipt)
    return receipt


def loaded_inputs(authority):
    value=validate_inference_assets(authority.assets['inference'])
    receipt=release.strict(release.read(authority.root/'inference-prepared.json',private=True))
    release.check(receipt['inference_assets_sha256']==authority.manifest['inference_assets_sha256']
                  ==release.object_sha(value),'Inference preparation differs')
    cell_id=active_cell(authority)
    config,work=read_cell_inputs(authority,cell_id)
    cell=batch.panel_cell(cell_id)
    validate_inputs(config,work,cell,main_authorized=authority.manifest['main_matrix_authorized'])
    return value,config,work,cell


def read_cell_inputs(authority,cell_id):
    refs=authority.manifest['cell_inputs'][cell_id];originals={}
    for name in ('generation_config','workload'):
        raw=Path(refs[name]['path']).read_bytes()
        release.check((release.sha(raw),len(raw))==(refs[name]['sha256'],refs[name]['bytes']),
                      'Generation input bytes changed: '+name)
        originals[name]=release.strict(raw)
    return originals['generation_config'],originals['workload']


def validate_inputs(config,work,cell,*,main_authorized=False):
    release.check(config.get('expected_vllm_version')=='0.30.0','N/GPU requires the specified vLLM version')
    release.check(config['stratum_id']==cell['stratum_id'],'Generation stratum differs')
    from lcb_native_generation import validate
    validate(config)
    from lcb_seeds import validate_policy
    validate_policy(config)
    release.check(config['model_id']==cell['model_id'] and config['model_revision']==cell['revision'],
                  'Model revision differs from panel')
    release.check(type(work) is dict and set(work)=={'tasks','jobs'} and work['tasks'] and work['jobs'],'Workload inputs')
    release.check(all(config[k]==cell[k] for k in ('k','replicate_id','pool_id','concurrency')),
                  'Generation configuration differs from panel cell')
    caps=release.strict(release.read(release.ROOT/'experiments/calibration/admission-cap-path-v3.json'))
    name=cell['stratum_id'];key=(name.replace('-','_')+'_freeze') if name!='q38-nonthinking' else 'q38_thinking_freeze'
    cap=caps[key]
    import lcb_timeout_revision as timeout_revision  # only an in-scope cell with the exact owner-approved marker may differ
    timeout=timeout_revision.expected_timeout(config,cell,cap['generation_timeout_s'])
    release.check(all(config[k]==cap[k] for k in ('max_tokens','max_model_len')) and config['generation_timeout_s']==timeout
                  and type(config['generation_timeout_s']) is int and config['reasoning_effort']==(None if name=='q38-nonthinking' else cap['effort']),
                  'Generation cap differs from frozen recommendation')
    if name=='q38-nonthinking':
        release.check(config.get('paired_on_effort')==cap['effort'],'Off-mode paired cap differs')
    frozen=release.strict(release.read(release.ROOT/'data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json'))
    release.check(config.get('selection_mode','deferred') in ('deferred','online'),'Unknown selection mode')
    release.check(config.get('selection_mode','deferred')=='deferred' or config.get('weak_size')==4,'Online selection needs the frozen weak4 selector')
    release.check(config.get('subset') in ('pilot','main'),'Generation subset must be pilot or main')
    release.check(config['subset']=='pilot' or main_authorized is True,
                  'A main-cohort cell needs main_matrix_authorized in the manifest')
    expected_ids=frozen['pilot_task_ids'] if config['subset']=='pilot' else frozen['main_task_ids']
    release.check([t['task_id'] for t in work['tasks']]==expected_ids,'Frozen task roster/order differs')
    from pool_scheduler import validate_arrivals
    validate_arrivals(work['tasks'],config['arrival_offsets_s'])
    from lcb_pilot_quality_v1 import validate_tasks, PilotRun, canonical
    raw=b'\n'.join(canonical(t) for t in work['tasks'])+b'\n'
    validate_tasks(PilotRun(name,tuple(expected_ids),(),(),{'private_tests_sha256':release.sha(raw)},'measured',4),raw)
    from lcb_seeds import candidate_seed
    expected=[(t['task_id'],i,candidate_seed(config['seed'],cell['replicate_id'],t['task_id'],i),t['prompt'])
              for t in work['tasks'] for i in range(cell['k'])]
    actual=[(j['task_id'],j['candidate_id'],j['seed'],j['prompt']) for j in work['jobs']]
    if actual!=expected:
        why='expected %d jobs, found %d'%(len(expected),len(actual))
        if len(actual)==len(expected):
            index=next(i for i,(a,e) in enumerate(zip(actual,expected)) if a!=e)
            fields=[n for n,a,e in zip(('task_id','candidate_id','seed','prompt'),actual[index],expected[index]) if a!=e]
            why='job %d differs in %s'%(index,'/'.join(fields))
        raise ValueError('Candidate coverage, order, prompt or seed differs: '+why)
    return cell


def send(sock,value):
    sock.sendall(release.encoded(value))


def receive(stream):
    raw=stream.readline(SOCKET_FRAME_LIMIT+1)
    release.check(raw and len(raw)<=SOCKET_FRAME_LIMIT and raw.endswith(b'\n'),'Incomplete inference/execute response')
    return release.strict(raw)


def request(path,value,deadline):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(max(.001,(deadline-time.monotonic_ns())/10**9));client.connect(str(path))
        send(client,value)
        return receive(client.makefile('rb'))


def serve(path,handler,until,finished,*,stop_file=None):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(path));os.chmod(path,0o600);server.listen(2);server.settimeout(.2)
        while time.monotonic_ns()<until and not finished():
            if stop_file is not None and stop_file.exists():raise runtime.CooperativeStop('Sibling failed; stop this cell')
            try:client,_=server.accept()
            except socket.timeout:continue
            with client:
                client.settimeout(max(.001,(until-time.monotonic_ns())/10**9))
                value=receive(client.makefile('rb'))
                result=handler(value);send(client,result)
        if not finished():raise runtime.InfrastructureError('GPU role deadline expired')


def candidate_transport(authority,view,*,prepared=None):
    """C creates private I/J/P; host Python never evaluates candidate code."""
    import lcb_isolation_assets_v2 as assets
    checked=assets.recheck_prepared_assets(authority) if prepared is None else prepared
    lock=checked['runtime_lock_value']
    return candidate_process(view,runtime_path=lock['runtime']['path'],
        helper=authority.assets['native_elf']['path'],sif=lock['cpu_sif']['path'],
        runner=release.ROOT/CANDIDATE_RUNNER,
        diagnostic=lambda record:_logs(authority,authority.role+'-candidate-launches.jsonl',record))


def bounded_run(argv,input_bytes,env,timeout_s,out_limit,err_keep):
    """Run a child with pipes: keep at most out_limit/err_keep bytes, count the rest, kill only this child on timeout."""
    proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,close_fds=True)
    kept={'out':bytearray(),'err':bytearray()};totals={'out':0,'err':0}
    def drain(name,stream,limit):
        while True:
            chunk=stream.read1(65536)  # whatever has arrived; read() would hold bytes back while a descendant keeps the pipe open
            if not chunk:break
            totals[name]+=len(chunk)
            room=limit-len(kept[name])
            if room>0:kept[name]+=chunk[:room]
    def feed():
        try:proc.stdin.write(input_bytes)
        except (BrokenPipeError,OSError):pass
        finally:
            try:proc.stdin.close()
            except OSError:pass
    threads=[threading.Thread(target=drain,args=('out',proc.stdout,out_limit),daemon=True),
             threading.Thread(target=drain,args=('err',proc.stderr,err_keep),daemon=True),
             threading.Thread(target=feed,daemon=True)]
    for t in threads:t.start()
    timed_out=False
    try:code=proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out=True;proc.kill();code=proc.wait()
    cutoff=time.monotonic()+3
    for t in threads:t.join(timeout=max(.05,cutoff-time.monotonic()))
    return code,bytes(kept['out']),bytes(kept['err']),totals,timed_out


def candidate_process(view,*,runtime_path,helper,sif,runner,diagnostic=None):
    """Shared C-backed transport; callers choose pilot or explicit smoke scope."""
    argv=[runtime_path,'exec','--containall','--cleanenv','--no-home','--no-eval','--userns',
          '--no-mount','home,cwd,hostfs,bind-paths,/home,/scratch,/shares,/apps',
          '--net','--network','none','--drop-caps','ALL','--bind',helper+':/probe/helper:ro',
          '--bind',str(runner)+':/probe/candidate_runner.py:ro',sif,
          '/probe/helper','--candidate-init']
    start=time.monotonic_ns();started_wall=time.time_ns();problem=None;code=None
    environment={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}
    timed_out=False
    try:
        code,stdout,stderr,totals,timed_out=bounded_run(argv,release.encoded(view),environment,LAUNCH_TIMEOUT_S,
                                                        STDOUT_LIMIT,STDERR_KEEP)
    except OSError as exc:
        problem=exc;stdout=stderr=b'';totals={'out':0,'err':0}
    stdout_size,stderr_size=totals['out'],totals['err']
    record={'argv':argv,'environment':environment,'cwd':os.getcwd(),'timeout_s':LAUNCH_TIMEOUT_S,
            'started_wall_ns':started_wall,'finished_wall_ns':time.time_ns(),
            'wall_ns':time.monotonic_ns()-start,'returncode':code,'launcher_timed_out':timed_out,
            'stdout_hex':stdout[:STDERR_KEEP].hex(),'stderr_hex':stderr[:STDERR_KEEP].hex(),
            'stdout_sha256':hashlib.sha256(stdout).hexdigest(),
            'stdout_total_bytes':stdout_size,'stderr_total_bytes':stderr_size,
            'output_truncated':stdout_size>STDOUT_LIMIT,
            'capture_limit_bytes':STDOUT_LIMIT,'error':None if problem is None else type(problem).__name__+': '+str(problem)}
    failure=None
    if problem is not None:
        failure=runtime.InfrastructureError('Candidate launcher could not start: '+str(problem))
    elif code in (77,127,255) and not timed_out:  # 255 is apptainer's own FATAL, which the C helper never returns
        failure=runtime.InfrastructureError('Candidate environment/launcher unavailable (returncode='+str(code)+'): '+stderr.decode('utf-8','replace'))
    if failure is not None:failure.launch_record=record
    if diagnostic is not None:
        try:diagnostic(record)
        except Exception as exc:
            if failure is not None:
                failure.diagnostic_error=type(exc).__name__+': '+str(exc)
                raise failure from exc
            raise
    if failure is not None:
        raise failure from problem
    shown={'stdout_hex':stdout[:STDERR_KEEP].hex(),'stderr_hex':stderr[:STDERR_KEEP].hex(),
           'stdout_total_bytes':stdout_size,'stdout_sha256':record['stdout_sha256']}
    if timed_out:  # the C helper bounds itself to about 12 s, so 75 s means the launcher hung: a failed test, not a time limit
        return {'status':'runtime_error','stdout':None,'error':'launcher_timeout','returncode':code,
                'wall_ns':time.monotonic_ns()-start,'output_truncated':False,**shown}
    if stdout_size>STDOUT_LIMIT:
        return {'status':'runtime_error','stdout':None,'error':'candidate output length',
                'wall_ns':time.monotonic_ns()-start,'returncode':code,'output_truncated':True,**shown}
    # 124: C wall bound. RLIMIT_CPU has soft==hard, so the kernel sends SIGKILL (137); 152 would be SIGXCPU. All are the CPU/time limit.
    return {'status':'ok' if code==0 else 'time_limit' if code in (124,137,152) else 'runtime_error',
            'stdout':stdout.decode('utf-8','replace') if code==0 else None,
            'error':None if code==0 else 'candidate exit '+str(code),'returncode':code,
            'wall_ns':time.monotonic_ns()-start,'output_truncated':False,**shown}


class InferenceBackend:
    """Reuse collector's vLLM request/response parser, without its legacy judge."""
    def __init__(self,authority,config,assets,journal):
        from lcb_collector import Backend
        self.log=open(work_root(authority)/'vllm.stderr','xb');self.events=queue.Queue();self.call=0
        self.child=None;self.reader=None;self.closed=False
        self.stop_ack=None;self.cfg=config
        lock=release.strict(Path(authority.assets['runtime_lock']['path']).read_bytes())
        cache=work_root(authority)/'runtime-cache';cache.mkdir(mode=0o700)
        runs=work_root(authority)/'runs';runs.mkdir(mode=0o700)
        spec=authority.manifest['cell_inputs'][active_cell(authority)]['generation_config']['path']
        visible=os.environ.get('CUDA_VISIBLE_DEVICES','')
        argv=[lock['runtime']['path'],'exec','--nv','--cleanenv','--no-eval',
              '--env','CUDA_VISIBLE_DEVICES='+visible,'--env','HF_HUB_OFFLINE=1',
              '--env','TRANSFORMERS_OFFLINE=1','--env','VLLM_CACHE_ROOT=/compile-cache/vllm',
              '--env','HF_HUB_DISABLE_TELEMETRY=1','--env','VLLM_NO_USAGE_STATS=1','--env','DO_NOT_TRACK=1',
              '--env','XDG_CACHE_HOME=/compile-cache','--bind',str(cache)+':/compile-cache',
              '--bind',str(cache)+':/runtime-cache','--bind',str(runs)+':/runs',
              '--bind',spec+':/inference-spec.json:ro',
              '--bind',assets['model_weights']['dir']+':/model:ro',
              '--bind',str(release.ROOT)+':/worker:ro',
              assets['inference_sif']['path'],'python3','-B','/worker/'+VLLM_WORKER]
        try:
            self.child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,
                                        env={**release.ENV,**{k:v for k,v in os.environ.items() if k.startswith('CUDA_')}},close_fds=True)
            self._send=Backend._send.__get__(self);self.generate=Backend.generate.__get__(self)
            self.reader=threading.Thread(target=Backend._reader,args=(self,),daemon=True);self.reader.start()
            self._send(config);self.ready=self._get((authority.deadline_mono_ns-time.monotonic_ns())/10**9)
            release.check(self.ready.get('event')=='ready','Inference startup failed')
            from lcb_timing import clock_identity,verify_clock_identity
            verify_clock_identity(clock_identity(),self.ready.get('clock_identity',{}))
            from lcb_native_generation import validate_backend_evidence
            validate_backend_evidence(self.ready.get('native_generation'),config)
            if (self.ready.get('gpu_name')!=config['expected_gpu_name'] or
                    self.ready.get('engine_metrics_schema')!=config['engine_metrics_schema']):
                raise runtime.InfrastructureError('Backend GPU/metrics configuration differs')
            journal.append('inference_started',{'argv':argv,'pid':self.child.pid,'ready':self.ready})
        except BaseException:
            try:self.close(authority.deadline_mono_ns)
            except Exception as cleanup:
                journal.append('inference_start_cleanup_error',{'error':str(cleanup)})
            raise

    def _get(self,timeout):
        if timeout<=0:raise runtime.InfrastructureError('Inference deadline')
        try:value=self.events.get(timeout=timeout)
        except queue.Empty as exc:raise runtime.InfrastructureError('Inference response timeout') from exc
        if value.get('event') in ('error','eof'):raise runtime.InfrastructureError('Inference process failed: '+str(value))
        return value

    def close(self,deadline):
        if self.closed:return
        self.closed=True
        try:
            if self.child is None:return
            try:self._send({'event':'stop'});self.child.stdin.close()
            except (BrokenPipeError,OSError):pass
            try:code=self.child.wait(timeout=max(.001,min(10,(deadline-time.monotonic_ns())/10**9)))
            except subprocess.TimeoutExpired:
                self.child.terminate()
                try:self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:self.child.kill();self.child.wait(timeout=5)
                raise runtime.InfrastructureError('Inference shutdown exceeded its bound')
            release.check(code==0,'Inference shutdown failed')
        finally:
            if self.reader is not None:self.reader.join(timeout=1)
            self.log.close()


def gpu_identity(authority,assets,journal,label):
    from lcb_isolation_owner_v1 import GPU_PROBE
    row=assets['nvidia_smi'];digest,size=file_digest(row['path'])
    journal.append('nvidia_smi_asset_check',{'path':row['path'],'sha256':digest,'bytes':size,'locked_sha256':row['sha256'],
                                          'matches_lock':digest==row['sha256'],'before':label})  # recorded, not a gate
    lock=release.strict(Path(authority.assets['runtime_lock']['path']).read_bytes())
    env={**release.ENV,**{k:v for k,v in os.environ.items() if k.startswith('CUDA_')}}
    first=subprocess.run([assets['nvidia_smi']['path'],'-L'],capture_output=True,env=env,timeout=PROBE_TIMEOUT_S,check=False)
    second=subprocess.run([lock['runtime']['path'],'exec','--nv','--cleanenv','--env',
        'CUDA_VISIBLE_DEVICES='+os.environ.get('CUDA_VISIBLE_DEVICES',''),assets['inference_sif']['path'],
        'python3','-I','-B','-c',GPU_PROBE],capture_output=True,env=env,timeout=PROBE_TIMEOUT_S,check=False)
    driver=subprocess.run([assets['nvidia_smi']['path'],'--query-gpu=driver_version','--format=csv,noheader'],
                          capture_output=True,env=env,timeout=PROBE_TIMEOUT_S,check=False)
    journal.append(label,{'nvidia_stdout':first.stdout.decode(),'nvidia_stderr':first.stderr.decode(),
        'cuda_stdout':second.stdout.decode(),'cuda_stderr':second.stderr.decode(),
        'driver_stdout':driver.stdout.decode(),'driver_stderr':driver.stderr.decode(),
        'returncodes':[first.returncode,second.returncode,driver.returncode]})
    if first.returncode or second.returncode or driver.returncode:raise runtime.InfrastructureError('GPU identity probe failed')
    cuda=release.strict(second.stdout)
    try:return hardware_identity(first.stdout.decode(),cuda,authority.manifest['gpu']['family'],
                                 driver.stdout.decode().strip(),authority.runtime_receipt['node'])
    except ValueError as exc:raise runtime.InfrastructureError('GPU identity mismatch') from exc


def hardware_identity(raw,cuda,family,driver,node):
    rows=raw.strip().splitlines()
    release.check(len(rows)==1,'One visible GPU required')
    match=re.fullmatch(r'GPU [0-9]+: (.+) \(UUID: (GPU-[0-9a-fA-F-]+)\)',rows[0])
    release.check(match is not None,'Malformed GPU identity')
    model,uuid=match.groups()
    release.check(cuda.get('visible_device_count')==1 and cuda.get('gpu_uuid')==uuid and cuda.get('gpu_name')==model,
                  'GPU and CUDA identity differ')
    memory=cuda.get('gpu_memory_bytes') if type(cuda.get('gpu_memory_bytes')) is int else None
    matches=(family=='Hopper' and ('H100' in model or 'H200' in model)) or (family=='A100' and 'A100' in model)
    return {'uuid':uuid,'model':model,'memory_bytes':memory,'driver':driver.strip() or None,'node':node,
            'family_requested':family,'family_matches_stratum':matches,'memory_at_least_75GiB':None if memory is None else memory>=75*1024**3}


def ready_bundle(authority):
    value=runtime.wait_object(work_root(authority)/'8-joins.json',authority.deadline_mono_ns,authority=authority)
    return runtime.bundle_check(authority,value)


def dispatch_cell(authority,own,journal,index):
    from lcb_isolation_owner_v2 import StepManager
    manager=StepManager(authority,journal,cell_index=index);records={'D':own}
    stage='launch_cell_roles'
    try:
        for rid in ('G','E1','E2','O1','O2','W1','W2'):
            stage='launch_'+rid
            manager.start(rid,runtime.role_argv(authority,rid,index))
        start_deadline=min(authority.deadline_mono_ns,time.monotonic_ns()+600*10**9)
        while len(records)<8:
            manager.poll()
            if manager.stopped:raise runtime.InfrastructureError('GPU role failed before cell admission')
            for rid in batch.GPU_ROLE_IDS:
                path=work_root(authority)/(rid+'.started.json')
                if rid not in records and path.exists():
                    stage='read_started_'+rid
                    proposal=release.strict(runtime.read_published(path))
                    stage='observe_'+rid
                    seen=(runtime.verify_inference_join(authority,proposal) if rid=='G' else
                          runtime.observe_role(authority,rid,proposal['join']['pid'],runtime.role_argv(authority,rid,index)))
                    release.check(seen['join']==proposal['join'],'Role live resource differs')
                    records[rid]=seen
            if time.monotonic_ns()>=start_deadline:raise runtime.InfrastructureError('A role step did not start within ten minutes (resources busy or a stuck earlier step)')
            time.sleep(.02)
        bundle={'schema':'isolation-eight-joins-v3','joins':[records[r]['join'] for r in batch.GPU_ROLE_IDS],
                'subjects':{r:records[r]['subject'] for r in batch.GPU_ROLE_IDS},
                'manifest_sha256':release.object_sha(authority.manifest)}
        runtime.bundle_check(authority,bundle);runtime.publish(work_root(authority)/'8-joins.json',bundle)
        stage='wait_cell_children'
        manager.wait_all(stop_on_failure=True)
        release.check(len(manager.records)==7 and not manager.stopped,'GPU cell role failure')
        return {'status':'gpu_cell_roles_complete_pending_review','cell_id':authority.manifest['cells'][index],
                'waits':manager.records}
    except BaseException as exc:
        manager.fail(exc,stage);manager.failure_closeout();raise
    finally:manager.close()


def dispatch(authority,own,journal):
    records=[];uuid=None;failed=0
    for index,cell_id in enumerate(authority.manifest['cells']):
        token=CELL_INDEX.set(index)
        try:
            try:
                result=dispatch_cell(authority,own,journal,index)
            except Exception as exc:  # recorded by dispatch_cell as D-failure.json; later cells still run
                failed+=1
                records.append({'status':'gpu_cell_failed','cell_id':cell_id,'error':type(exc).__name__+': '+str(exc)})
                continue
            try:
                summary=release.strict(runtime.read_published(work_root(authority)/'inference-summary.json'))
                observed=summary['gpu_start']['uuid']
                result=dict(result,paired_cells_same_gpu_uuid=uuid in (None,observed))
                uuid=observed
            except Exception as exc:
                result=dict(result,summary_read_error=type(exc).__name__+': '+str(exc))
            records.append(result)
            runtime.publish(work_root(authority)/'cell-completion.json',result)
        finally:CELL_INDEX.reset(token)
    return {'status':'gpu_cells_complete_with_failures' if failed else 'gpu_cells_complete_pending_review',
            'cells':records,'gpu_uuid':uuid}


def _logs(authority,name,value):
    # The log is data only and never fed to the candidate interpreter.
    with (work_root(authority)/name).open('ab') as stream:stream.write(release.encoded(value))


def inference(authority,journal):
    begun=time.monotonic_ns()
    assets,config,work,cell=loaded_inputs(authority)
    identity=gpu_identity(authority,assets,journal,'gpu_start')
    config=dict(config,expected_gpu_name=identity['model'])
    backend=InferenceBackend(authority,config,assets,journal)
    total_in=total_out=hidden=reasoning=final_tokens=unpartitioned=0
    service=selection_mode(config)=='online'
    def finished():
        if service:return (work_root(authority)/'service-window.json').exists()  # the window ends before the audit of delivered answers
        return all((work_root(authority)/(rid+'.done.json')).exists() for rid in ('W1','W2'))
    def handle(value):
        nonlocal total_in,total_out,hidden,reasoning,final_tokens,unpartitioned
        if value.get('op')=='cpu_snapshot':return own_cpu_snapshot()
        release.check(set(value)=={'jobs'} and type(value['jobs']) is list and value['jobs'],'Inference batch request')
        check_generation_batch(value['jobs'],cell)
        _logs(authority,'inference-requests.jsonl',value)
        timeout=min(config['generation_timeout_s'],(authority.deadline_mono_ns-time.monotonic_ns())/10**9)
        rows=backend.generate(value['jobs'],timeout,lambda row:None)
        rows=ordered_samples(value['jobs'],rows)
        for row in rows:
            total_in+=row['input_tokens'];total_out+=row['output_tokens']
            parts=row.get('token_partition')
            if parts is None:
                unpartitioned+=1;row['tokens_reasoning']=None;row['tokens_final']=None
            else:
                hidden+=len(parts['reasoning_ids'])+len(parts['control_ids'])
                reasoning+=len(parts['reasoning_ids']);final_tokens+=len(parts['final_ids'])
                row['tokens_reasoning']=len(parts['reasoning_ids']);row['tokens_final']=len(parts['final_ids'])
            _logs(authority,'inference-responses.jsonl',row)
        return {'samples':rows}
    serve_error=close_error=final_error=None
    try:
        serve(work_root(authority)/'inference.sock',handle,authority.deadline_mono_ns,finished,stop_file=work_root(authority)/'batch.stop.json')
    except Exception as exc:serve_error=exc
    try:backend.close(authority.deadline_mono_ns)
    except Exception as exc:close_error=type(exc).__name__+': '+str(exc)
    ended=time.monotonic_ns();final=None
    try:final=gpu_identity(authority,assets,journal,'gpu_end')
    except Exception as exc:final_error=type(exc).__name__+': '+str(exc)
    runtime.publish(work_root(authority)/'inference-summary.json',{'tokens_in':total_in,'tokens_out':total_out,
        'hidden_reasoning_tokens':hidden,'reasoning_tokens':reasoning,'final_tokens':final_tokens,
        'unpartitioned_samples':unpartitioned,'selection_mode':'online' if service else 'deferred',
        'gpu_occupancy_ns':ended-begun,
        'service_started_mono_ns':begun,'service_finished_mono_ns':ended,
        'occupancy_scope':'role_service_wall_including_model_load_not_GPU_execution_counter',
        'gpu_start':identity,'gpu_end':final,'hardware_recorded':identity,
        'gpu_uuid_unchanged':None if final is None else final['uuid']==identity['uuid'],
        'backend_close_error':close_error,'gpu_end_probe_error':final_error,
        'serve_error':None if serve_error is None else type(serve_error).__name__+': '+str(serve_error)})
    if serve_error is not None:raise serve_error
    return {'status':'inference_complete'}


def check_generation_batch(jobs,cell):
    tasks={j['task_id'] for j in jobs}
    release.check(0<len(tasks)<=cell['concurrency'] and len(jobs)==len(tasks)*cell['k'],
                  'Requested episode batch exceeds frozen configuration')
    for task in tasks:
        release.check(sorted(j['candidate_id'] for j in jobs if j['task_id']==task)==list(range(cell['k'])),
                      'Incomplete or repeated candidates within an episode')


def ordered_samples(jobs,rows):
    keys=lambda x:(x['task_id'],x['candidate_id'],x['seed'])
    expected=[keys(j) for j in jobs];seen={keys(row):row for row in rows}
    release.check(len(seen)==len(rows)==len(expected) and set(seen)==set(expected),
                  'Missing/duplicate/foreign generation response')
    for row in rows:
        for field in ('input_tokens','output_tokens'):
            release.check(type(row.get(field)) is int and row[field]>=0,'Missing token count')
        p=row.get('token_partition')
        if p is None:continue  # unpartitioned sample (metering_error): kept, counted, hidden-token quantity not claimed for it
        release.check(type(p) is dict and all(type(p.get(k)) is list for k in ('reasoning_ids','control_ids','final_ids')),
                      'Token partition malformed')
        release.check(sum(len(p[k]) for k in ('reasoning_ids','control_ids','final_ids'))==row['output_tokens'],
                      'Token partition does not conserve output tokens')
    return [seen[key] for key in expected]


def execution(authority,journal):
    runner=validate_inference_assets(authority.assets['inference'])['candidate_runner']
    release.check(file_digest(release.ROOT/runner['path'])==(runner['sha256'],runner['bytes']),
                  'Candidate runner bytes changed before E service')
    release.require_candidate(authority)
    worker='W'+authority.role[1]
    # This E service uses one frozen runtime. Do not rehash it for every test case.
    import lcb_isolation_assets_v2 as assets
    prepared=assets.recheck_prepared_assets(authority)
    evaluator=adapter.CandidateAdapter(authority,lambda view:candidate_transport(authority,view,prepared=prepared))
    def finished():return (work_root(authority)/(worker+'.done.json')).exists()
    def handle(value):
        if value.get('op')=='cpu_snapshot':return own_cpu_snapshot()
        req=CaseRequest(**value);start=time.monotonic_ns();started_wall=time.time_ns()
        result=evaluator.evaluate(req)
        _logs(authority,authority.role+'-candidate-receipts.jsonl',
              {'request':asdict(req),'result':result,'wall_ns':time.monotonic_ns()-start,
               'started_wall_ns':started_wall,'finished_wall_ns':time.time_ns()})
        return result
    serve(work_root(authority)/(authority.role+'.sock'),handle,authority.deadline_mono_ns,finished,stop_file=work_root(authority)/'batch.stop.json')
    return {'status':'candidate_service_complete'}


def wait_socket(authority,path):
    while not path.exists():
        release.require(authority,phase='runtime')
        if (path.parent/'batch.stop.json').exists():raise runtime.InfrastructureError('Peer stopped')
        time.sleep(.02)


SERVICE_ROLES=('G','W1','E1')
KNOWN_CASE_STATUS=('ok','runtime_error','time_limit','candidate_rejected_prefilter')


def selection_mode(config):
    return config.get('selection_mode','deferred')


def own_cpu_snapshot(cgroup_file='/proc/self/cgroup',cgroup_root='/sys/fs/cgroup'):
    """Cumulative CPU of this role's step (the cgroup v2 user domain above the task leaf, the domain the epilog endpoint
    reads), taken on request so the service window can be bracketed. Never raises: an unreadable counter is reported as such."""
    try:
        line=next(l for l in Path(cgroup_file).read_text().splitlines() if l.startswith('0::'))
        domain=line[3:].rsplit('/',1)[0]
        if not re.fullmatch(r'/system\.slice/slurmstepd\.scope/job_[0-9]+/step_[0-9]+/user',domain):
            raise ValueError('Unexpected cgroup domain shape: '+domain)  # the epilog endpoint reads the step user domain
        raw=(Path(cgroup_root+domain)/'cpu.stat').read_text()
        usage=int(next(l.split()[1] for l in raw.splitlines() if l.startswith('usage_usec ')))
        return {'status':'captured','domain':domain,'usage_usec':usage,'cpu_stat':raw,
                'mono_ns':time.monotonic_ns(),'wall_ns':time.time_ns()}
    except Exception as exc:
        return {'status':'unreadable','error':type(exc).__name__+': '+str(exc),'mono_ns':time.monotonic_ns()}


def service_cpu(window,joins=None):
    """CPU (usec) of the service roles between the start and end snapshots; a role with a missing or inconsistent snapshot is
    None and so is the total (no substitute value). With the role joins (role id -> its bound user cgroup path) a snapshot
    taken in another domain than the role's own is inconsistent too."""
    by={}
    for rid in SERVICE_ROLES:
        a,b=(window['start'].get(rid) or {}),(window['end'].get(rid) or {})
        ok=(a.get('status')=='captured' and b.get('status')=='captured' and type(a.get('usage_usec')) is int
            and type(b.get('usage_usec')) is int and b['usage_usec']>=a['usage_usec'] and a.get('domain')==b.get('domain'))
        if ok and joins is not None:
            ok=joins.get(rid)=='/sys/fs/cgroup'+a['domain']
        by[rid]=b['usage_usec']-a['usage_usec'] if ok else None
    ends=[(window['end'].get(rid) or {}) for rid in SERVICE_ROLES]
    cumulative=[e.get('usage_usec') for e in ends]
    with_startup=(sum(cumulative) if all(e.get('status')=='captured' and type(v) is int for e,v in zip(ends,cumulative))
                  and (joins is None or all(joins.get(rid)=='/sys/fs/cgroup'+e.get('domain','') for rid,e in zip(SERVICE_ROLES,ends)))
                  else None)
    return {'roles':list(SERVICE_ROLES),'by_role_usec':by,
            'total_usec':None if any(v is None for v in by.values()) else sum(by.values()),
            # cumulative at the end snapshot: the service plus the cold start before it, still without the audit
            'total_with_startup_usec':with_startup,
            'excludes':'the audit after the end snapshot and the idle roles W2 E2 O1 O2; total_usec also excludes the cold start'}


def online_weak4_selection(samples,weak_ids,run_test,*,clock=time.monotonic):
    """The service selector: candidates in id order, an ineligible one is skipped, a candidate runs the weak fold test by test
    and stops at its first failing test, the first candidate that passes the whole fold is delivered, none passing is a refusal.
    run_test(sample, test_id) -> (passed, status)."""
    from lcb_delivery import eligible
    from lcb_metering import episode_meters
    release.check(len(weak_ids)>0,'The weak fold must have tests')
    started=clock();checks=[];selected=None
    for sample in sorted(samples,key=lambda s:s['candidate_id']):
        j=sample['candidate_id']
        if not eligible(sample,strict=True):
            checks.append({'candidate_id':j,'status':'no_executable_final',
                           'reason':'length_truncated' if sample.get('finish_reason')=='length' else 'no_executable_final'});continue
        cases=[];passed_all=True;rejected=False
        for tid in weak_ids:
            passed,status=run_test(sample,tid)
            cases.append({'test_id':tid,'pass':passed,'status':status})
            if status=='candidate_rejected_prefilter':rejected=True;passed_all=False;break
            if not passed:passed_all=False;break
        checks.append({'candidate_id':j,'status':'rejected_prefilter' if rejected else 'evaluated',
                       'result':{'pass':passed_all,'cases':cases}})
        if passed_all:selected=j;break
    return {'selected_id':selected,'weak_size':len(weak_ids),'online_checks':checks,'verification_wall_s':clock()-started,
            'meters':episode_meters(samples,selected),'audit_label':None,'refusal':selected is None}


def delivered_audit(sample,audit_ids,run_test):
    """Audit label of one delivered candidate: every test of the audit fold must pass; the first failure ends it (the label
    does not depend on the remaining tests). Returns (passed, tests_run)."""
    for index,tid in enumerate(audit_ids):
        passed,status=run_test(sample,tid)
        if status=='candidate_rejected_prefilter' or not passed:return False,index+1
    return True,len(audit_ids)


def service_results(episodes,audits):
    """Per-candidate rows of a service cell in the format of the deferred worker. weak4 is known only for candidates the
    selector reached; audit only for the delivered one (None elsewhere: not measured, not failed)."""
    results=[]
    for ep in episodes:
        checks={c['candidate_id']:c for c in ep['online_checks']}
        for sample in ep['samples']:
            j=sample['candidate_id'];c=checks.get(j)
            if c is None:row={'status':'not_evaluated','weak4':None,'audit':None}
            elif c['status']=='no_executable_final':row={'status':'no_deliverable','weak4':False,'audit':False}
            elif c['status']=='rejected_prefilter':row={'status':'candidate_rejected_prefilter','weak4':False,'audit':False}
            else:row={'status':'judged','weak4':c['result']['pass'],'audit':None}
            if ep['selected_id']==j:
                row['status']='delivered'
                if (sample['task_id'],j) in audits:  # absent when the audit phase failed: unmeasured, not failed
                    passed,tests=audits[(sample['task_id'],j)]
                    row.update(audit=passed,audit_tests_run=tests)
            results.append({'task_id':sample['task_id'],'candidate_id':j,**row})
    return results


def case_runner(authority,cell,task,task_digest,sock,fold,manifest_sha):
    tests={t['test_id']:t for t in task['tests']}
    def run(sample,tid):
        test=tests[tid]
        req=CaseRequest(manifest_sha,cell['stratum_id'],sample['task_id'],sample['candidate_id'],sample['seed'],
            release.object_sha(sample),hashlib.sha256(sample['code'].encode()).hexdigest(),task_digest,fold,tid,
            sample['code'],test['input'],task['test_type'],task.get('entry_point'))
        value=request(sock,asdict(req),authority.deadline_mono_ns)
        release.check(value['request_sha256']==adapter.request_digest(req),'Candidate response mapping')
        if value['status'] not in KNOWN_CASE_STATUS:
            raise runtime.InfrastructureError('Unknown candidate case status: '+str(value['status']))
        return value['status']=='ok' and project_compare(value['stdout'],test['output'],task['comparison']),value['status']
    return run


def service_worker(authority,config,work,cell):
    """Service path. W1 generates and selects online with the weak4 selector through E1; W2 only follows W1. The service
    window is bracketed by CPU snapshots of the service roles (G, W1, E1) and ends with service-window.json, which stops
    G. Only after that are the delivered candidates audited (labels for the quality estimands); audit time and CPU are
    outside the window."""
    root=work_root(authority);deadline=authority.deadline_mono_ns
    if authority.role=='W2':
        runtime.wait_object(root/'W1.done.json',deadline,authority=authority)
        runtime.publish(root/'W2.done.json',{'results':[],'selection_mode':'online'})
        return {'status':'candidate_worker_complete'}
    wait_socket(authority,root/'inference.sock');wait_socket(authority,root/'E1.sock')
    from pool_scheduler import run_cohort
    indexed={(j['task_id'],j['candidate_id']):j for j in work['jobs']}
    tasks={t['task_id']:t for t in work['tasks']};digests={}
    manifest_sha=release.object_sha(authority.manifest)
    def digest(task_id):
        if task_id not in digests:digests[task_id]=release.object_sha(tasks[task_id])  # tasks can be tens of MB
        return digests[task_id]
    def generate(jobs):
        packed=[indexed[(task['task_id'],index)] for task,index in jobs]
        response=request(root/'inference.sock',{'jobs':packed},deadline)
        return ordered_samples(packed,response['samples'])
    def select(task_row,samples):
        task=tasks[task_row['task_id']]
        run=case_runner(authority,cell,task,digest(task['task_id']),root/'E1.sock','weak4',manifest_sha)
        return online_weak4_selection(samples,task['folds']['weak4'],run)
    def snapshots(label):
        def ask(sock):
            try:return request(sock,{'op':'cpu_snapshot','label':label},deadline)
            except Exception as exc:  # a failed side channel makes that role's CPU unidentified, it never costs the cell
                return {'status':'unreadable','error':type(exc).__name__+': '+str(exc),'mono_ns':time.monotonic_ns()}
        return {'W1':own_cpu_snapshot(),'G':ask(root/'inference.sock'),'E1':ask(root/'E1.sock')}
    for task_id in tasks:digest(task_id)  # evaluation bookkeeping (hashing tasks of tens of MB) stays out of the window
    start=snapshots('service_start')
    episodes=run_cohort(work['tasks'],config['arrival_offsets_s'],pool_id=cell['pool_id'],
        concurrency=cell['concurrency'],k=cell['k'],generate=generate,select=select,
        emit=lambda event:_logs(authority,'cohort-events.jsonl',event),selection_mode='online')
    end=snapshots('service_end')
    runtime.publish(root/'service-window.json',{'schema':'service-window-v1','selection_mode':'online',
        'weak_size':len(next(iter(tasks.values()))['folds']['weak4']),'start':start,'end':end})
    rows=[sample for episode in episodes for sample in episode['samples']]
    release.check(len(rows)==len(work['jobs']),'Incomplete generation result')
    runtime.publish(root/'generation-episodes.json',{'episodes':episodes})
    runtime.publish(root/'generated-samples.json',{'samples':rows})
    audits={};audit_error=None
    try:
        for episode in episodes:
            j=episode['selected_id']
            if j is None:continue
            task=tasks[episode['task_id']];sample=next(x for x in episode['samples'] if x['candidate_id']==j)
            run=case_runner(authority,cell,task,digest(task['task_id']),root/'E1.sock','audit',manifest_sha)
            audits[(episode['task_id'],j)]=delivered_audit(sample,task['folds']['audit'],run)
    except Exception as exc:  # the window, delivery and cost are already on disk; quality of the unaudited answers stays unmeasured
        audit_error=type(exc).__name__+': '+str(exc)
    runtime.publish(root/'W1.done.json',{'results':service_results(episodes,audits),'selection_mode':'online','audit_error':audit_error})
    return {'status':'candidate_worker_complete'}


def worker(authority,journal):
    release.require_candidate(authority)
    assets,config,work,cell=loaded_inputs(authority)
    if selection_mode(config)=='online':return service_worker(authority,config,work,cell)
    sample_path=work_root(authority)/'generated-samples.json'
    if authority.role=='W1':
        wait_socket(authority,work_root(authority)/'inference.sock')
        from pool_scheduler import run_cohort
        indexed={(j['task_id'],j['candidate_id']):j for j in work['jobs']}
        def generate(jobs):
            packed=[indexed[(task['task_id'],index)] for task,index in jobs]
            response=request(work_root(authority)/'inference.sock',{'jobs':packed},authority.deadline_mono_ns)
            return ordered_samples(packed,response['samples'])
        episodes=run_cohort(work['tasks'],config['arrival_offsets_s'],pool_id=cell['pool_id'],
            concurrency=cell['concurrency'],k=cell['k'],generate=generate,select=None,
            emit=lambda event:_logs(authority,'cohort-events.jsonl',event),selection_mode='deferred')
        rows=[sample for episode in episodes for sample in episode['samples']]
        release.check(len(rows)==len(work['jobs']),'Incomplete generation result')
        runtime.publish(work_root(authority)/'generation-episodes.json',{'episodes':episodes})
        runtime.publish(sample_path,{'samples':rows})
    generated=runtime.wait_object(sample_path,authority.deadline_mono_ns,authority=authority)['samples']
    wait_socket(authority,work_root(authority)/('E'+authority.role[1]+'.sock'))
    tasks={t['task_id']:t for t in work['tasks']};results=[];task_digests={}
    for index,sample in enumerate(generated):
        if index%2!=int(authority.role[1])-1:continue
        if not sample.get('code') or sample.get('truncated'):
            results.append({'task_id':sample['task_id'],'candidate_id':sample['candidate_id'],
                            'status':'no_deliverable','weak4':False,'audit':False});continue
        task=tasks[sample['task_id']];outcome={'task_id':sample['task_id'],'candidate_id':sample['candidate_id']}
        if sample['task_id'] not in task_digests:task_digests[sample['task_id']]=release.object_sha(task)  # tasks can be tens of MB
        failed=False
        tests={t['test_id']:t for t in task['tests']}
        for fold in ('weak4','audit'):
            passes=[];rejected=False
            for tid in task['folds'][fold]:
                test=tests[tid]
                req=CaseRequest(release.object_sha(authority.manifest),cell['stratum_id'],sample['task_id'],
                    sample['candidate_id'],sample['seed'],release.object_sha(sample),
                    hashlib.sha256(sample['code'].encode()).hexdigest(),task_digests[sample['task_id']],
                    fold,tid,sample['code'],test['input'],task['test_type'],task.get('entry_point'))
                value=request(work_root(authority)/('E'+authority.role[1]+'.sock'),asdict(req),authority.deadline_mono_ns)
                release.check(value['request_sha256']==adapter.request_digest(req),'Candidate response mapping')
                if value['status']=='candidate_rejected_prefilter':rejected=True
                if value['status'] in ('runtime_error','time_limit'):failed=True
                passes.append(value['status']=='ok' and project_compare(value['stdout'],test['output'],task['comparison']))
                if rejected:break
            outcome[fold]=all(passes)
            if rejected:
                outcome.update(status='candidate_rejected_prefilter',weak4=False,audit=False)
                break
        outcome.setdefault('status','failed' if failed else 'judged');results.append(outcome)
    runtime.publish(work_root(authority)/(authority.role+'.done.json'),{'results':results})
    return {'status':'candidate_worker_complete'}


def observer(authority,journal):
    bundle=ready_bundle(authority)
    from lcb_supervision_site_v3 import LinuxHost
    host=LinuxHost();index=authority.role[1]
    joins={j['role_id']:j for j in bundle['joins']};handles=[]
    try:
        for name in ('W'+index,'E'+index):
            j=joins[name];handles.append(host.track(j['pid'],j['uid'],'/sys/fs/cgroup'+j['cgroup_path'].rsplit('/',1)[0]))
        while not (work_root(authority)/('W'+index+'.done.json')).exists():
            release.require(authority,phase='runtime')
            if any(h.state()['exited'] for h in handles):raise runtime.InfrastructureError('Observed worker exited before completion')
            time.sleep(.05)
        return {'status':'candidate_observer_complete'}
    finally:
        for h in handles:h.close()


def run_role(authority,own,journal,*,cell_index=None):
    token=CELL_INDEX.set(cell_index)
    try:return _run_role(authority,own,journal,cell_index)
    finally:CELL_INDEX.reset(token)


def _run_role(authority,own,journal,cell_index):
    release.require(authority,phase='runtime',role=authority.role)
    if authority.role!='D':ready_bundle(authority)
    capture=meter.Capture(authority,own['subject'],journal,primary_role=authority.role,
        endpoint_config_sha256=runtime.endpoint_config_digest(authority,authority.role,cell_index))
    try:
        capture.sample('setup')
        fn=dispatch if authority.role=='D' else inference if authority.role=='G' else execution if authority.role.startswith('E') else worker if authority.role.startswith('W') else observer
        result=fn(authority,own,journal) if authority.role=='D' else fn(authority,journal)
        capture.sample('cleanup')
        return {**result,'candidate_execution_authorized':authority.manifest['candidate_execution_authorized'],
                'main_matrix_authorized':authority.manifest['main_matrix_authorized']}
    finally:
        runtime.publish(work_root(authority)/(authority.role+'.meter.json'),capture.export_record());capture.close()


def cell_report(manifest,endpoints,inference_summary,case_rows,wall_ns,*,cell_index=0,partial_ok=False,service_clean=True):
    cell=batch.panel_cell(manifest['cells'][cell_index])
    complete=set(endpoints)==set(batch.GPU_ROLE_IDS)-{'D'} and all(v.get('status')=='captured' for v in endpoints.values())
    counts=all(type(inference_summary.get(k)) is int and inference_summary[k]>=0
               for k in ('tokens_in','tokens_out','hidden_reasoning_tokens'))
    h=inference_summary.get('hardware_recorded')
    hardware=type(h) is dict and all(type(h.get(k)) is str and h[k] for k in ('model','node'))
    unpartitioned=inference_summary.get('unpartitioned_samples') or 0
    return {'cell_id':cell['cell_id'],'k':cell['k'],'config_id':cell['config_id'],
        'candidate_limits':dict(manifest['candidate_limits']),
        'hardware_recorded':inference_summary.get('hardware_recorded'),
        'tokens_in':inference_summary.get('tokens_in'),'tokens_out':inference_summary.get('tokens_out'),
        # A sample whose output did not follow the template has no token partition: the hidden-token quantities are then
        # not claimed for the cell (None), while input/output totals and the CPU point stay.
        'reasoning_tokens':None if unpartitioned else inference_summary.get('reasoning_tokens'),
        'final_tokens':None if unpartitioned else inference_summary.get('final_tokens'),
        'hidden_reasoning_tokens':None if unpartitioned else inference_summary.get('hidden_reasoning_tokens'),
        'unpartitioned_samples':unpartitioned,'wall_ns':wall_ns,
        'gpu_step_user_usec':endpoints['G']['user_snapshot']['usage_usec'] if complete else None,
        'inference_service_wall_ns':inference_summary.get('gpu_occupancy_ns'),
        'user_step_total_usec':sum(v['user_snapshot']['usage_usec'] for v in endpoints.values()) if complete else None,
        'estimands':cell['estimands'],'status':(('measured_hidden_tokens_unidentified' if unpartitioned else 'measured_pending_pilot_review')
                  if complete and service_clean and counts and hardware else 'measured_service_partial' if partial_ok and counts and hardware
                  else 'unidentified'),
        'cost_sample_eligible':False,'case_results':case_rows}


def accounting_summary(base_raw,cpu_raw,actual,endpoints,*,include_shared=True,allow_other_steps=False):
    """Lifecycle coverage, without substituting sacct's zero for a role endpoint."""
    import lcb_worker_metering_v2 as display
    base=display.table(base_raw,display.BASE_FIELDS);cpu=display.table(cpu_raw,display.CPU_FIELDS)
    job=actual['job_id'];parent=base[job]
    start,end=display.epoch_ns(parent['Start']),display.epoch_ns(parent['End'])
    expected={job,job+'.batch',job+'.extern'}|{job+'.'+v['role_binding']['step_id'] for v in endpoints.values()}
    release.check((expected<=set(base) and expected<=set(cpu)) if allow_other_steps else
                  (set(base)==expected and set(cpu)==expected),'Incomplete allocation/step accounting roster')
    shared_rows={job,job+'.batch',job+'.extern'}
    for identifier,row in base.items():
        # Only this call's own role steps must have ended normally and inside the allocation. The parent/batch/extern
        # rows (which turn FAILED when ANOTHER cell failed) and other cells' steps are recorded in job-state-notes.json.
        if identifier not in expected or identifier in shared_rows:continue
        release.check(row['State']=='COMPLETED' and row['ExitCode']=='0:0'
                      and cpu[identifier]['State']==row['State'],'Role step did not end normally: '+identifier+' '+row['State'])
        lo,hi=display.epoch_ns(row['Start']),display.epoch_ns(row['End'])
        release.check(start-10**9<=lo<=hi<=end+10**9,'Step outside allocation lifetime')
    extras={name:{'user_usec':display.duration_us(cpu[job+'.'+name]['TotalCPU']),
                  'scope':'workload user subtree; excludes slurm management leaf'} for name in ('batch','extern')} if include_shared else {}
    tail=0
    for record in endpoints.values():
        release.check(record['status']=='captured','Missing endpoint')
        rid=record['role_binding'];row=base[job+'.'+rid['step_id']]
        # End is second-quantized; add its resolution plus two 1s clock errors.
        upper=display.epoch_ns(row['End'])+3*10**9
        observed=record['original']['timing']['end_wall_ns']
        release.check(upper>=observed,'Endpoint occurs after terminal envelope')
        tail+=((upper-observed+999)//1000)*len(rid['domains']['slurm']['cpu_ids'])
    gpu_ns=None
    if 'G' in endpoints:
        gid=job+'.'+endpoints['G']['role_binding']['step_id']
        gpu_ns=display.epoch_ns(base[gid]['End'])-display.epoch_ns(base[gid]['Start'])
    if not include_shared:
        starts=[display.epoch_ns(base[job+'.'+v['role_binding']['step_id']]['Start']) for v in endpoints.values()]
        ends=[display.epoch_ns(base[job+'.'+v['role_binding']['step_id']]['End']) for v in endpoints.values()]
        start,end=min(starts),max(ends)
    return {'D_user_usec':endpoints['D']['user_snapshot']['usage_usec'] if 'D' in endpoints else None,
            **extras,
            'control_plane_observed_usec':sum(v['slurm_snapshot']['usage_usec'] for v in endpoints.values()),
            'control_plane_tail':{'lower_usec':0,'upper_usec':tail,'included_in_point':False},
            'gpu_step_occupancy_ns':gpu_ns,'gpu_occupancy_resolution_ns':10**9,
            'wall_ns':end-start,'parent_included_in_cpu_sum':False}


def role_lifecycle(cellroot,rid,bundle):
    """Lifecycle endpoint of one role of a service cell; its step must have been waited and exited 0. Raises otherwise."""
    record=read_endpoint(cellroot,rid,bundle['subjects'][rid])
    release.check(record.get('status')=='captured','Endpoint not captured: '+str(record.get('status')))
    wait=release.strict(runtime.read_published(cellroot/(rid+'.wait.json')))
    release.check(wait['wait_completed'] is True and wait['returncode']==0,'Unwaited or failed role')
    return record


def service_g_error(cellroot,bundle):
    """Why G does not qualify as the end of a service window, or None. G stops the window, so an unclean G leaves no service
    measurement. Collect and the extractor use this one judgement: G's step was waited and exited 0 and, when the role bindings
    (8-joins.json) could be read, its lifecycle endpoint is captured."""
    try:
        if bundle is None:
            wait=release.strict(runtime.read_published(cellroot/'G.wait.json'))
            release.check(wait['wait_completed'] is True and wait['returncode']==0,'Unwaited or failed role')
        else:role_lifecycle(cellroot,'G',bundle)
    except (OSError,KeyError,TypeError,ValueError) as exc:
        return type(exc).__name__+': '+str(exc)
    return None


def read_service_cell(cellroot,bundle):
    """Evidence of a cell run on the service path. The measurement of the window (service-window.json, the episodes with their
    delivery times, the generated samples, the G summary) survives whatever happened after the window ended: a role that fails
    during the audit, a follower that never published its done file or an observer that stopped early are recorded as
    lifecycle failures and cost only what they carried (that role's lifecycle endpoint, the audit labels), never the window.
    G is the exception: it ends the window, so an unclean G means there is no service measurement."""
    failures={};endpoints={};clocks={}
    g_error=service_g_error(cellroot,bundle)
    if g_error is not None:raise ValueError('G is not clean: '+g_error)
    for rid in batch.GPU_ROLE_IDS:
        if rid=='D':continue
        try:endpoints[rid]=role_lifecycle(cellroot,rid,bundle)
        except (FileNotFoundError,KeyError,TypeError,ValueError) as exc:failures[rid]=type(exc).__name__+': '+str(exc)
        try:clocks[rid]=release.strict(runtime.read_published(cellroot/(rid+'.clock.json')))
        except (FileNotFoundError,ValueError):clocks[rid]=None
    info=release.strict(runtime.read_published(cellroot/'inference-summary.json'))
    window=release.strict(runtime.read_published(cellroot/'service-window.json'))
    episodes=release.strict(runtime.read_published(cellroot/'generation-episodes.json'))['episodes']
    joins={j['role_id']:j['user_cgroup']['path'] for j in bundle['joins']}
    dones={}
    for rid in ('W1','W2'):
        try:dones[rid]=release.strict(runtime.read_published(cellroot/(rid+'.done.json')))
        except (FileNotFoundError,ValueError) as exc:failures.setdefault(rid,type(exc).__name__+': '+str(exc))
    if 'W1' in dones:
        cases=list(dones['W1']['results']);audit_error=dones['W1'].get('audit_error')
    else:  # the delivery and the online weak4 decisions are on disk; the audit labels are not
        cases=service_results(episodes,{});audit_error='W1.done.json missing: the audit phase did not finish'
    unlabelled=sum(1 for row in cases if row.get('status')=='delivered' and row.get('audit') is None)
    return {'endpoints':endpoints,'clocks':clocks,'failures':failures,'info':info,'window':window,'episodes':episodes,
            'cases':cases,'audit_error':audit_error,'service':service_cpu(window,joins),
            # complete only when every role ended cleanly, the audit phase finished and every delivered candidate has its label
            'clean':not failures and not audit_error and not unlabelled}


def collect_gpu_failure(root,output,manifest,actual,originals):
    """Bounded raw inventory for a failed GPU batch; never construct cost points."""
    import lcb_isolation_return_v2 as returned
    from lcb_worker_metering_v2 import table,BASE_FIELDS,CPU_FIELDS
    base=table(originals['base'],BASE_FIELDS);cpu=table(originals['cpu'],CPU_FIELDS)
    job=actual['job_id']
    release.check(job in base and set(base)==set(cpu),'Failed GPU accounting coverage differs')
    release.check(base[job]['State'].split()[0] in returned.TERMINAL,'GPU allocation not terminal')
    for name,row in base.items():
        suffix=name.removeprefix(job+'.')
        release.check(name==job or name.startswith(job+'.') and
                      (suffix in ('batch','extern') or suffix.isdigit()),'Foreign GPU accounting job')
        release.check(row['NodeList']==actual['node'] and row['Cluster']=='cluster' and
                      row['UID'] in (str(manifest['owner_uid']), '') and
                      (name!=job or row['UID']==str(manifest['owner_uid'])) and
                      row['State'].split()[0] in returned.TERMINAL and cpu[name]['State']==row['State'],
                      'Failed GPU accounting identity/state differs')
    names=set(returned.DOCUMENTS+returned.FAILURE_NAMES)
    names.update(('allocation-resource-observation.json','allocation-resource-summary.json','bootstrap-failure.json'))
    names.update(('owner-role-D.jsonl','D.meter.json','D.clock.json','D.launch.json',
                  'role-D.result.json','configs/D.json','endpoints/D.json','cells-complete.json'))
    for index in range(len(manifest['cells'])):
        prefix=f'cells/{index:03d}/'
        names.update(prefix+n for n in ('8-joins.json','control-joins.json','inference-summary.json',
            'inference-requests.jsonl','inference-responses.jsonl','generated-samples.json','vllm.stderr',
            'nvidia-smi-start.json','nvidia-smi-end.json'))
        for rid in batch.GPU_ROLE_IDS[1:]:
            names.update(prefix+rid+suffix for suffix in ('.started.json','.bound.json','.proposal.json',
                '.request.json','.wait.json','.stderr','.stdout','.meter.json','.clock.json','.launch.json',
                '.done.json','-candidate-receipts.jsonl','-candidate-launches.jsonl'))
            names.update((prefix+'configs/'+rid+'.json',prefix+'endpoints/'+rid+'.json',
                          prefix+'owner-role-'+rid+'.jsonl',prefix+'role-'+rid+'.result.json'))
    hashes={};total=0;fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in sorted(names):
            try:body=returned._read(fd,name)
            except FileNotFoundError:hashes[name]=None;continue
            total+=len(body);release.check(total<=returned.MAX_TOTAL,'GPU failure original size bound')
            path=output/'originals'/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            release.write_new(path,body);hashes[name]=release.sha(body)
    finally:os.close(fd)
    report={'status':'failed_unidentified_originals_only','job_id':job,'files_sha256':hashes,
            'missing_originals':[n for n,h in hashes.items() if h is None],
            'cost_sample_eligible':False,'analysis':None,'main_matrix_authorized':manifest['main_matrix_authorized']}
    release.write_new(output/'failure-inventory.json',report)
    return report


def collect_gpu(root,output,request_inputs):
    from lcb_isolation_owner_v2 import Client
    from lcb_worker_metering_v2 import BASE_FIELDS,CPU_FIELDS,SACCT_SHA256
    root,output=Path(root),Path(output)
    release.check(output!=root and root not in output.parents and output!=release.ROOT and release.ROOT not in output.parents,
                  'Collector output must be outside source and attempt')
    output.mkdir(mode=0o700)
    manifest=request_inputs['manifest']
    try:actual=release.strict(runtime.read_published(root/'allocation.json'))
    except FileNotFoundError:actual=None
    if actual is None:
        submitted=release.strict(runtime.read_published(root/'submission.json'))
        release.check(submitted['manifest_sha256']==release.object_sha(manifest),'Submitted manifest differs')
        job_id=release.number(submitted['job_id'])
    else:
        batch.validate_runtime_receipt(manifest,actual)
        actual={**actual,'owner_uid':manifest['owner_uid']};job_id=actual['job_id']
    records=[]
    class Log:
        def append(self,kind,data):records.append({'kind':kind,'data':data})
    originals={}
    for kind,fields in (('base',BASE_FIELDS),('cpu',CPU_FIELDS)):
        client=Client({'sacct':{'path':'/usr/bin/sacct','sha256':SACCT_SHA256}},Log())
        try:raw=client.command('sacct',['--clusters=cluster','--duplicates','--parsable2','--jobs='+job_id,'--format='+fields],timeout_s=120)
        finally:release.write_new(output/(kind+'-client-receipts.json'),records);records=[]
        release.write_new(output/(kind+'.txt'),raw.encode())
        originals[kind]=raw.encode()
    from lcb_worker_metering_v2 import table
    if actual is None:
        parent=table(originals['base'],BASE_FIELDS)[job_id]
        release.write_new(output/'bootstrap-missing.json',{
            'reason':'allocation.json was not published; accounting and failure originals only',
            'cost_sample_eligible':False})
        return collect_gpu_failure(root,output,manifest,{'job_id':job_id,'node':parent['NodeList']},originals)
    job_state_notes=[{'job':k,'state':v['State'],'exit':v['ExitCode']}
                     for k,v in table(originals['base'],BASE_FIELDS).items()
                     if v['State']!='COMPLETED' or v['ExitCode']!='0:0']
    release.write_new(output/'job-state-notes.json',job_state_notes)  # recorded; cells are judged on their own originals
    reports=[];shared={'status':'unidentified'};batch_error=None;observed_uuid=None
    try:
        d=release.strict(runtime.read_published(root/'D.started.json'))['subject']
        point=read_endpoint(root,'D',d)
        shared=accounting_summary(originals['base'],originals['cpu'],actual,{'D':point},allow_other_steps=True)
        shared.update(status='captured',scope='D_batch_extern_once_per_allocation')
        shared.update(requested_cpu_count=manifest['allocation']['cpus'],
                      allocated_cpu_count=actual['cpus'],
                      extra_allocated_cpu_count=actual['cpus']-manifest['allocation']['cpus'])
    except (FileNotFoundError,KeyError,TypeError,ValueError) as exc:
        batch_error=type(exc).__name__+': '+str(exc)
    for index,cell_id in enumerate(manifest['cells']):
        cellroot=batch.cell_root(root,manifest,index);endpoints={};info={};cases=[];reasons=[];notes=[];accounting=None;clocks={};mode='deferred';window=None;service=None;failures={};clean=True
        try:
            online=(cellroot/'service-window.json').exists()
            if online:
                # the window is kept whatever else cannot be read; without the role bindings its CPU values are None
                mode='online'
                window=release.strict(runtime.read_published(cellroot/'service-window.json'))
                service=service_cpu(window,{})
            bundle=release.strict(runtime.read_published(cellroot/'8-joins.json'))
            if online:
                evidence=read_service_cell(cellroot,bundle)
                endpoints,clocks,info,cases=evidence['endpoints'],evidence['clocks'],evidence['info'],evidence['cases']
                failures,window,service,clean=evidence['failures'],evidence['window'],evidence['service'],evidence['clean']
                dones={'W1':{'audit_error':evidence['audit_error']}}
                uuid=info['gpu_start']['uuid']
                if observed_uuid not in (None,uuid):notes.append('cells did not run on the same GPU')
                if info.get('gpu_end') is None or info['gpu_end']['uuid']!=uuid:notes.append('GPU end record missing or differs')
                observed_uuid=uuid
            else:
                for rid in batch.GPU_ROLE_IDS:
                    if rid=='D':continue
                    endpoints[rid]=read_endpoint(cellroot,rid,bundle['subjects'][rid])
                    wait=release.strict(runtime.read_published(cellroot/(rid+'.wait.json')))
                    release.check(wait['wait_completed'] is True and wait['returncode']==0,'Unwaited or failed role')
                    try:clocks[rid]=release.strict(runtime.read_published(cellroot/(rid+'.clock.json')))
                    except (FileNotFoundError,ValueError):clocks[rid]=None  # recorded, never a gate on counter values
                info=release.strict(runtime.read_published(cellroot/'inference-summary.json'))
                uuid=info['gpu_start']['uuid']
                if observed_uuid not in (None,uuid):notes.append('cells did not run on the same GPU')
                if info.get('gpu_end') is None or info['gpu_end']['uuid']!=uuid:notes.append('GPU end record missing or differs')
                observed_uuid=uuid
                dones={rid:release.strict(runtime.read_published(cellroot/(rid+'.done.json'))) for rid in ('W1','W2')}
                for rid in ('W1','W2'):cases.extend(dones[rid]['results'])
                mode=dones['W1'].get('selection_mode','deferred')
                if mode=='online':  # a service cell always has its window file, so this is only a mislabelled cell
                    raise ValueError('Service cell without its service-window.json')
            if info.get('backend_close_error'):notes.append('G backend close: '+info['backend_close_error'])
            if dones['W1'].get('audit_error'):notes.append('audit phase: '+dones['W1']['audit_error'])
            samples=release.strict(runtime.read_published(cellroot/'generated-samples.json'))['samples']
            release.check(len(cases)==len(samples) and {(x['task_id'],x['candidate_id']) for x in cases}==
                          {(x['task_id'],x['candidate_id']) for x in samples},'Incomplete candidate result coverage')
            lines=(cellroot/'inference-responses.jsonl').read_bytes().splitlines()  # parsed one at a time: main cells are large
            release.check(len(lines)==len(samples) and all(release.strict(line)==sample for line,sample in zip(lines,samples)),
                          'Generated sample original differs')
            release.check(info['tokens_in']==sum(x['input_tokens'] for x in samples)
                          and info['tokens_out']==sum(x['output_tokens'] for x in samples)
                          and info['hidden_reasoning_tokens']==sum(len((x.get('token_partition') or {}).get('reasoning_ids',()))+
                              len((x.get('token_partition') or {}).get('control_ids',())) for x in samples)
                          and info['reasoning_tokens']==sum(len((x.get('token_partition') or {}).get('reasoning_ids',())) for x in samples)
                          and info['final_tokens']==sum(len((x.get('token_partition') or {}).get('final_ids',())) for x in samples),
                          'Token totals differ from original samples')
            accounting=accounting_summary(originals['base'],originals['cpu'],actual,endpoints,
                                          include_shared=False,allow_other_steps=True)
        except (FileNotFoundError,KeyError,TypeError,ValueError) as exc:
            reasons.append(type(exc).__name__+': '+str(exc))
        report=cell_report(manifest,endpoints,info,cases,accounting['wall_ns'] if accounting else None,cell_index=index,partial_ok=mode=='online',
                            service_clean=clean)
        report['lifecycle_failures']=failures
        report['subset']=cell_subset(manifest,cell_id)
        report['coordination_accounting']=accounting
        report['shared_cost_reference']='shared-cost.json'
        report['shared_cost_status']='captured' if shared.get('status')=='captured' else 'unidentified'
        report['clock_series_recorded']=clocks
        report['selection_mode']=mode
        report['service_window']=None if window is None else {**window,'service_cpu':service}
        report['cpu_point_usec']=None
        if accounting and report['status']!='unidentified' and not reasons:
            report['gpu_step_occupancy_ns']=accounting['gpu_step_occupancy_ns']
            report['gpu_occupancy_resolution_ns']=accounting['gpu_occupancy_resolution_ns']
            report['gpu_occupancy_scope']='allocated G step wall interval; not GPU execution time'
            if report['user_step_total_usec'] is not None:  # a lifecycle failure after the window leaves no whole-cell CPU
                report['cpu_point_usec']=report['user_step_total_usec']+accounting['control_plane_observed_usec']
        if reasons:report['status']='unidentified'
        report['unidentified_reasons']=reasons
        report['notes']=notes  # covariates and observations; they never change the status
        release.write_new(output/f'cell-{index:03d}.json',report)
        release.write_new(output/f'endpoints-{index:03d}.json',endpoints);reports.append(report)
    if shared.get('status')!='captured':shared['reason']=batch_error
    release.write_new(output/'shared-cost.json',shared)
    measured=[r['status'].startswith('measured') for r in reports]
    clean=[r['status']!='measured_service_partial' for r in reports]  # a service cell with a lifecycle failure is measured but partial
    result={'status':('measured_pending_pilot_review' if all(measured) and all(clean) and shared.get('status')=='captured'
                      else 'partial_pending_pilot_review' if any(measured) else 'unidentified'),'cells':reports,'output':str(output),'cost_sample_eligible':False,'main_matrix_authorized':manifest['main_matrix_authorized']}
    release.write_new(output/'batch.json',result)
    return result


def pinned_generation_config(manifest,cell_id):
    """The cell's generation configuration as the manifest pins it (sha256 and bytes checked, as the roles do), or None when the
    file is missing, is not the pinned one or is not a JSON object."""
    try:
        ref=manifest['cell_inputs'][cell_id]['generation_config']
        raw=Path(ref['path']).read_bytes()
        if (release.sha(raw),len(raw))!=(ref['sha256'],ref['bytes']):return None
        config=release.strict(raw)
        return config if type(config) is dict else None
    except (OSError,ValueError,KeyError,TypeError):
        return None


def cell_timeout_record(manifest,cell_id):
    """What the extract records about the per-call generation timeout of a cell: its seconds (an int) and whether the configuration
    carries the owner-approved revision marker (validate_inputs judged the marker when the cell ran). Anything that cannot be
    established is None, which the tables show as unknown, never as the frozen value."""
    config=pinned_generation_config(manifest,cell_id)
    if config is None or type(config.get('generation_timeout_s')) is not int:
        return {'seconds':None,'revised':None}
    return {'seconds':config['generation_timeout_s'],'revised':'timeout_revision' in config}


def cell_subset(manifest,cell_id):
    """'pilot' or 'main' from the cell's generation configuration, or None if that file cannot be read. A label of the report: unlike
    the timeout record it does not check the manifest's pin (a collect report is made where the file was written)."""
    try:
        config=release.strict(Path(manifest['cell_inputs'][cell_id]['generation_config']['path']).read_bytes())
        return config.get('subset') if type(config) is dict else None
    except (OSError,ValueError,KeyError):
        return None


def read_endpoint(root,rid,subject):
    config=release.read(root/'configs'/(rid+'.json'),private=True)
    try:value=release.strict(release.read(root/'endpoints'/(rid+'.json'),private=True))
    except FileNotFoundError:value=None
    return meter.adapt_task_epilog(value,subject,expected_config_sha256=release.sha(config))
