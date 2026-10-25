"""Owner-run exclusive GPU backend + sibling CPU Apptainer judge.

Default is a dry plan. --execute requires reviewed configuration, local pinned
weights/images and site approval. No SSH, provisioning, model downloads or APIs.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time

from pilot import digest,read_json,read_rows,write_new,gpu_sample
from lcb_sandbox import Judge,file_sha,execution_identity
from lcb_metering import episode_meters
from pool_scheduler import run_cohort,validate_arrivals
from lcb_timing import SCHEMAS,clock_identity,verify_clock_identity
from lcb_manifest import validate_manifest
from lcb_lifecycle import LinuxHost,CellLifecycle,PROTOCOL as RELEASE_PROTOCOL
from lcb_seeds import validate_policy,verify_appendix,POLICY as HASH_SEEDS,LEGACY as LEGACY_SEEDS
from lcb_cache_observation import observe_cache
from lcb_delivery import POLICY as DELIVERY_POLICY, eligible
from lcb_cpu import total_cpu
from lcb_resources import summarize as resource_ledger
from lcb_admission import PURPOSE as ADMISSION_PURPOSE,validate as validate_admission,validate_tokenization
import lcb_native_generation as native

PREFIX=b'WWW27_BACKEND '
SOURCE_FILES=('lcb_collector.py','lcb_vllm_worker.py','pool_scheduler.py','lcb_timing.py','lcb_metering.py',
              'lcb_manifest.py','lcb_lifecycle.py','lcb_seeds.py','lcb_cache_observation.py','lcb_delivery.py',
              'lcb_cpu.py','lcb_resources.py','lcb_sandbox.py','lcb_sandbox_runner.py','lcb_case_launcher.py',
              'lcb_admission.py','lcb_admission_report.py','lcb_feasibility.py','lcb_cap_policy.py','lcb_admission_v2.py',
              'lcb_native_generation.py','lcb_cap_policy_v3.py','lcb_admission_v3.py')


def source_hashes():
    return {name:file_sha(Path(__file__).with_name(name)) for name in SOURCE_FILES}


def require_resource_review_clear(resources):
    if resources is not None and resources.get('pause_review'):
        raise RuntimeError('Service power gaps exceed the frozen threshold; originals retained; stop subsequent cells')


def validate_config(cfg):
    if native.active(cfg):native.validate(cfg)
    elif 'generation_policy' in cfg:raise ValueError('Unknown generation policy')
    if cfg.get('schema')!='lcb-owner-run-v1':raise ValueError('Unknown run schema')
    mode=cfg.get('judge','online')
    if mode not in ('online','deferred'):raise ValueError('Unknown judge mode')
    approval=cfg.get('deferred_review',{}) if mode=='deferred' else cfg
    if approval.get('reviewer_approved') is not True or approval.get('owner_approved') is not True:
        raise ValueError('Run is not approved by reviewer and owner')
    if not approval.get('review_reference') or str(approval['review_reference']).startswith('OWNER_'):
        raise ValueError('Actual review reference required')
    review=cfg.get('lifecycle_review',{})
    if (cfg.get('lifecycle_protocol')!=RELEASE_PROTOCOL or review.get('reviewer_approved') is not True
        or review.get('owner_approved') is not True or not review.get('review_reference')
        or str(review['review_reference']).startswith('OWNER_')):
        raise ValueError('New lifecycle implementation is not approved by reviewer and owner')
    purpose=cfg.get('execution_purpose')
    if purpose=='lifecycle_acceptance':
        if (mode!='deferred' or cfg.get('subset')!='pilot' or cfg.get('pool_id')!=0
            or cfg.get('k')!=1 or cfg.get('concurrency')!=1
            or cfg.get('sampling_seed_policy') not in (LEGACY_SEEDS,HASH_SEEDS)
            or (cfg.get('sampling_seed_policy')==HASH_SEEDS and cfg.get('replicate_id')!=0)):
            raise ValueError('Lifecycle acceptance is only pool0-k1-c1 pilot, with legacy or hash replicate0 seeds')
    elif purpose==ADMISSION_PURPOSE:
        validate_admission(cfg)
    elif purpose=='scientific_collection':
        scientific=cfg.get('collection_review',{})
        if (scientific.get('reviewer_approved') is not True or scientific.get('owner_approved') is not True
            or not scientific.get('review_reference') or str(scientific['review_reference']).startswith('OWNER_')):
            raise ValueError('Scientific collection requires separate approval')
    else:raise ValueError('Explicit execution_purpose required')
    if mode=='deferred':
        if cfg.get('reviewer_approved') is not False or cfg.get('owner_approved') is not False:
            raise ValueError('Deferred permission must not authorize the online path')
        if purpose!=ADMISSION_PURPOSE and (cfg.get('subset')!='pilot' or cfg.get('k') not in (1,8) or cfg.get('concurrency') not in (1,16)
            or cfg.get('model_id')!='Qwen/Qwen2.5-Coder-7B-Instruct'
            or cfg.get('model_revision')!='c03e6d358207e414f1eca0bb1891e29f1db0e242'
            or cfg.get('reasoning_mode')!='none' or cfg.get('cache_mode')!='off'):
            raise ValueError('Deferred permission covers only the frozen Coder-7B pilot')
    if cfg.get('engine_metrics_schema') not in SCHEMAS:
        raise ValueError('Explicit reviewed engine metrics schema required')
    if not cfg.get('engine_metrics_source_reference') or str(cfg['engine_metrics_source_reference']).startswith('OWNER_'):
        raise ValueError('Pinned engine source review reference required')
    for key in ('k','concurrency','max_tokens','max_model_len','max_num_seqs'):
        if type(cfg.get(key)) is not int or cfg[key]<1:raise ValueError('Invalid '+key)
    cap_limit=24576 if purpose==ADMISSION_PURPOSE else 16384
    if cfg['k']>32 or cfg['concurrency']>64 or cfg['max_tokens']>cap_limit:
        raise ValueError('Run exceeds the reviewed protocol envelope')
    if cfg['max_model_len']<=cfg['max_tokens']:raise ValueError('Context must leave room for the prompt')
    if type(cfg.get('seed')) is not int:raise ValueError('Integer seed required')
    validate_policy(cfg)
    if type(cfg.get('system_reference',False)) is not bool:
        raise ValueError('Explicit boolean system_reference required')
    if cfg.get('system_reference',False):
        if (cfg.get('system_reference_owner_approved') is not True or purpose!='scientific_collection'
            or cfg.get('subset')!='main' or cfg['sampling_seed_policy']!=HASH_SEEDS
            or cfg.get('replicate_id')!=0 or cfg.get('pool_id')!=1 or cfg.get('concurrency')!=16 or cfg.get('k')!=8):
            raise ValueError('Optional system reference needs separate owner opt-in and main hash-replicate0 pool1-k8-c16')
    if not re.fullmatch('[0-9a-f]{64}',str(cfg.get('workload_manifest_sha256',''))):
        raise ValueError('Exact reviewed workload manifest SHA required')
    cache=cfg.get('compile_cache_dir')
    if not isinstance(cache,str) or not cache.startswith('/') or not Path(cache).name.startswith('www27-'):
        raise ValueError('Dedicated absolute www27- compile cache directory required')
    if type(cfg.get('pool_id')) is not int or cfg['pool_id'] not in (0,1):raise ValueError('Invalid pool')
    if cfg.get('weak_size') not in (2,4):raise ValueError('Pilot/main weak selector must be frozen')
    if cfg.get('subset') not in ('pilot','main'):raise ValueError('Explicit subset required')
    if cfg.get('reasoning_mode') not in ('none','think_tags') or cfg.get('cache_mode') not in ('off','on'):
        raise ValueError('Unknown generation mode')
    for key in ('expected_vllm_version','expected_gpu_name','model_id','model_revision','system_prompt'):
        if not isinstance(cfg.get(key),str) or not cfg[key] or cfg[key].startswith('OWNER_'):
            raise ValueError('Missing '+key)
    if not 0<float(cfg['temperature'])<=2 or not 0<float(cfg['top_p'])<=1:
        raise ValueError('Invalid sampling parameters')
    if not 0<float(cfg['gpu_memory_utilization'])<1:raise ValueError('Invalid GPU memory fraction')
    if not 1<=float(cfg['generation_timeout_s'])<=3600:raise ValueError('Bounded generation timeout required')


def verify_weights(root,manifest):
    root=Path(root).resolve(strict=True)
    if not root.is_dir() or not isinstance(manifest,dict) or not manifest:
        raise ValueError('Local weights and hashes required')
    all_files={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    if all_files!=set(manifest) or not any(n.endswith('.safetensors') for n in manifest):
        raise ValueError('Weight manifest must cover exactly this local snapshot')
    for name,expected in manifest.items():
        path=(root/name).resolve(strict=True)
        if root not in path.parents or not re.fullmatch('[0-9a-f]{64}',str(expected)) or file_sha(path)!=expected:
            raise ValueError('Weight snapshot/hash mismatch: '+name)
    return root


class Backend:
    def __init__(self,cfg,gpu_uuid,log):
        self.log=log;self.events=queue.Queue();self.call=0
        self.cfg=cfg;self.gpu_uuid=gpu_uuid;self.child=None;self.reader=None
        self.lifecycle=None;self.baseline=None;self.release_result=None;self.last_observe=0.
        self.stop_ack=None
        self.host=None

    def start(self):
        cfg=self.cfg;gpu_uuid=self.gpu_uuid;log=self.log
        host=LinuxHost(gpu_uuid)
        self.host=host
        self.baseline=host.gpu()
        if cfg['execution_purpose']=='lifecycle_acceptance' and self.baseline['memory_used_mib']!=4:
            raise ValueError('H100 lifecycle acceptance requires the observed 4 MiB idle baseline')
        self.lifecycle=CellLifecycle(host,self.baseline)
        image=Path(cfg['inference_sif']).resolve(strict=True)
        if not image.is_file() or file_sha(image)!=cfg['inference_sif_sha256']:
            raise ValueError('Inference image digest mismatch')
        weights=verify_weights(cfg['weights_dir'],read_json(cfg['weights_manifest']))
        code=Path(__file__).resolve().parent
        cache=Path(cfg['compile_cache_dir'])
        if not cache.is_dir() or cache.is_symlink():raise ValueError('Existing materialized compile-cache directory required')
        cache=cache.resolve(strict=True)
        if not cache.name.startswith('www27-'):raise ValueError('Dedicated compile-cache directory required')
        cache_stat=cache.stat()
        if cache_stat.st_uid!=os.getuid() or cache_stat.st_mode & 0o022:
            raise ValueError('Compile cache must be owner-owned and not group/world writable')
        for path in (image,weights,code,cache):
            if any(ch in str(path) for ch in (':',',','\n')):raise ValueError('Unsupported bind path')
        cmd=['apptainer','exec','--nv','--cleanenv','--no-eval',
             '--env','CUDA_VISIBLE_DEVICES='+gpu_uuid,'--env','HF_HUB_OFFLINE=1',
             '--env','TRANSFORMERS_OFFLINE=1','--env','HF_HUB_DISABLE_TELEMETRY=1',
             '--env','VLLM_NO_USAGE_STATS=1','--env','DO_NOT_TRACK=1',
             '--env','VLLM_CACHE_ROOT=/compile-cache/vllm','--env','XDG_CACHE_HOME=/compile-cache',
             '--bind',str(cache)+':/compile-cache','--bind',str(weights)+':/model:ro',
             '--bind',str(code)+':/worker:ro',str(image),'python3','-B','/worker/lcb_vllm_worker.py']
        self.child=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,start_new_session=True)
        self.lifecycle.attach(self.child.pid)  # Before sending config/model init.
        self.reader=threading.Thread(target=self._reader,daemon=True);self.reader.start()
        self._send(cfg)
        ready=self._get(600)
        if ready.get('event')!='ready':raise ValueError('Inference backend did not initialize')
        verify_clock_identity(clock_identity(),ready.get('clock_identity',{}))
        if ready.get('engine_metrics_schema')!=cfg['engine_metrics_schema']:
            raise ValueError('Engine metrics schema mismatch')
        if ready.get('gpu_name')!=cfg['expected_gpu_name']:
            raise ValueError('Backend GPU name differs from the frozen hardware stratum')
        if ready.get('cache_environment')!={'VLLM_CACHE_ROOT':'/compile-cache/vllm','XDG_CACHE_HOME':'/compile-cache'}:
            raise ValueError('Backend did not receive the explicit persistent cache environment')
        if native.active(cfg):native.validate_backend_evidence(ready.get('native_generation'),cfg)
        self.ready=ready

    def _reader(self):
        try:
            while True:
                line=self.child.stdout.readline(4*1024*1024+1)
                if not line:break
                if len(line)>4*1024*1024:raise ValueError('Oversized backend frame')
                if line.startswith(PREFIX):
                    event=json.loads(line[len(PREFIX):])
                    if event.get('event')=='stop_received':self.stop_ack=event
                    self.events.put(event)
                else:self.log.write(line);self.log.flush()
        except Exception as exc:self.events.put({'event':'error','error':str(exc)})
        finally:self.events.put({'event':'eof'})

    def _send(self,value):
        self.child.stdin.write(json.dumps(value).encode()+b'\n');self.child.stdin.flush()

    def _get(self,timeout):
        if timeout<=0:raise TimeoutError('Inference backend deadline')
        deadline=time.monotonic()+timeout
        while True:
            if time.monotonic()-self.last_observe>=1:
                self.lifecycle.observe();self.last_observe=time.monotonic()
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('Inference backend deadline')
            try:event=self.events.get(timeout=min(1.,remaining));break
            except queue.Empty:continue
        if event.get('event') in ('error','eof'):raise RuntimeError('Inference backend: '+str(event))
        return event

    def generate(self,jobs,timeout,on_sample):
        call_id=self.call;self.call+=1;start=time.monotonic();samples=[]
        self._send({'event':'generate','call_id':call_id,'jobs':jobs})
        while True:
            event=self._get(timeout-(time.monotonic()-start))
            if event.get('call_id')!=call_id:raise ValueError('Backend call mismatch')
            if event['event']=='done':return samples
            if event['event']!='sample':raise ValueError('Unexpected backend event')
            samples.append(event['sample']);on_sample(event['sample'])

    def tokenize_prompts(self,tasks):
        self._send({'event':'tokenize_prompts','tasks':[{'task_id':t['task_id'],'prompt':t['prompt']} for t in tasks]})
        result=self._get(120)
        if result.get('event')!='tokenized_prompts':raise ValueError('Missing complete tokenization preflight')
        if [r['task_id'] for r in result['rows']]!=[t['task_id'] for t in tasks]:
            raise ValueError('Tokenization coverage changed')
        return result

    def _stop(self):
        if self.child is None or self.child.stdin.closed:return {'pipe':'not_open'}
        result={}
        try:
            fd=self.child.stdin.fileno();os.set_blocking(fd,False)
            payload=b'{"event":"stop"}\n'
            result['stop_bytes_written']=os.write(fd,payload)
            result['stop_message_complete']=result['stop_bytes_written']==len(payload)
        except (OSError,ValueError) as exc:result['pipe_error']=type(exc).__name__+': '+str(exc)
        finally:
            try:self.child.stdin.close()
            except (OSError,ValueError) as exc:result['close_error']=type(exc).__name__+': '+str(exc)
        return result

    def close(self):
        if self.release_result is not None:return self.release_result
        if self.lifecycle is None:
            self._stop()
            result={'release_status':'timeout','engine_release_wall_ns':None,
                    'last_nvidia_smi':getattr(self.host,'last_gpu_observation',self.baseline),
                    'errors':['Preflight/ownership not established; no signals sent']}
        else:
            result=self.lifecycle.close(self._stop,lambda:self.child.poll() if self.child else None)
        if self.reader is not None:
            self.reader.join(timeout=2)
            result['reader_stopped']=not self.reader.is_alive()
            if self.reader.is_alive():
                result['release_status']='timeout';result['engine_release_wall_ns']=None
                result['errors'].append('Output reader did not reach EOF; no clean-close claim')
        if self.child is not None and (self.reader is None or not self.reader.is_alive()):
            if not self.child.stdout.closed:self.child.stdout.close()
        result['worker_stop_ack']=self.stop_ack
        result['worker_returncode']=self.child.poll() if self.child else None
        self.release_result=result
        return result


def online_selection(task,samples,private_task,judge,weak_size):
    checks=[];selected=None;start=time.monotonic()
    allowed={row['candidate_id']:eligible(row,strict=True) for row in samples}
    for row in samples:
        if not allowed[row['candidate_id']]:
            checks.append({'candidate_id':row['candidate_id'],'status':'no_executable_final',
                           'reason':'length_truncated' if row['finish_reason']=='length' else 'no_executable_final'});continue
        result=judge.fold(row['code'],private_task,'weak'+str(weak_size),short_circuit=True)
        checks.append({'candidate_id':row['candidate_id'],'status':'evaluated','result':result})
        if result['pass']:selected=row['candidate_id'];break
    return {'selected_id':selected,'weak_size':weak_size,'online_checks':checks,
            'verification_wall_s':time.monotonic()-start,'meters':episode_meters(samples,selected),
            'cpu_accounting':total_cpu([case['cpu_accounting'] for check in checks if check['status']=='evaluated'
                                      for case in check['result']['cases']]),
            'audit_label':None,'refusal':selected is None}


def collect(cfg,prepared,output,execute=False):
    print(json.dumps({'execute':execute,'pool_id':cfg.get('pool_id'),'k':cfg.get('k'),
                      'backend':'exclusive local Apptainer vLLM process','no_external_api':True}))
    if not execute:return
    validate_config(cfg)
    native.require_current_execution(cfg)
    if not os.environ.get('SLURM_JOB_ID'):raise ValueError('Owner must run in an allocated Slurm job')
    if not shutil.which('apptainer'):raise ValueError('Apptainer module required')
    prep=Path(prepared);manifest=read_json(prep/'manifest.json')
    validate_manifest(manifest)
    if file_sha(prep/'manifest.json')!=cfg['workload_manifest_sha256']:
        raise ValueError('Workload differs from the reviewed exact manifest')
    seed_map=None
    if cfg['sampling_seed_policy']==HASH_SEEDS:
        if file_sha(cfg['seed_appendix'])!=cfg['seed_appendix_sha256']:
            raise ValueError('Seed appendix digest mismatch')
        seed_map=verify_appendix(read_json(cfg['seed_appendix']),(prep/'manifest.json').read_bytes(),cfg['seed'])
    for name,key in (('prompts.jsonl','prompts_sha256'),('tests.private.jsonl','private_tests_sha256')):
        if file_sha(prep/name)!=manifest[key]:raise ValueError('Frozen preparation changed')
    prompts=read_rows(prep/'prompts.jsonl');cohort=validate_manifest(manifest,prompts)
    wanted=manifest[cfg['subset']+'_task_ids'];by_id={t['task_id']:t for t in prompts}
    def seed_for(task_id,candidate_id):
        if task_id not in wanted or type(candidate_id) is not int or not 0<=candidate_id<cfg['k']:
            raise ValueError('Unexpected candidate identity')
        return seed_map[cfg['replicate_id'],task_id,candidate_id] if seed_map is not None else cfg['seed']+wanted.index(task_id)*100000+candidate_id
    tasks=[by_id[x] for x in wanted];deferred=cfg.get('judge','online')=='deferred'
    private={} if deferred else {t['task_id']:t for t in read_rows(prep/'tests.private.jsonl')}
    offsets=cfg['arrival_offsets_s'];validate_arrivals(tasks,offsets)
    judge=None if deferred else Judge(read_json(cfg['sandbox_approval']))
    sandbox_inspection=None if deferred else judge.preflight()  # Online guard remains before GPU startup.
    devices=gpu_sample(cfg['allocated_gpu_selector'])
    if len(devices)!=1:raise ValueError('Exactly one explicitly allocated full GPU required')
    if str(cfg['allocated_gpu_selector']).startswith('MIG'):raise ValueError('MIG not supported by this protocol')
    if devices[0]['name']!=cfg['expected_gpu_name']:raise ValueError('Allocated GPU name mismatch')
    root=Path(output)
    if root.exists():raise ValueError('Never overwrite a cell')
    root.mkdir(parents=True)
    metadata={'schema':'lcb-owner-cell-v3','evidence':'measured','config':cfg,
              'delivery_policy':DELIVERY_POLICY,
              'execution_purpose':cfg['execution_purpose'],'lifecycle_protocol':RELEASE_PROTOCOL,
              'sampling_seed_policy':cfg['sampling_seed_policy'],'replicate_id':cfg.get('replicate_id'),
              'system_reference':cfg.get('system_reference',False),
              'seed_appendix_sha256':cfg.get('seed_appendix_sha256') if seed_map is not None else None,
              'frozen_cohort':cohort,'preparation_schema':manifest['schema'],
              'task_ids':wanted,'private_tests_sha256':manifest['private_tests_sha256'],
              'sandbox_preflight':sandbox_inspection,
              'sandbox_execution_identity':None if deferred else execution_identity(judge),
              'judge_mode':cfg.get('judge','online'),'candidate_execution':False if deferred else None,
              'measurement_scope':'generation_only_deferred' if deferred else 'generation_and_online_selection',
              'gpu_name':devices[0]['name'],'gpu_name_source':'nvidia-smi; also checked by torch before model load',
              'source_files_sha256':source_hashes(),
              'preparation_sha256':file_sha(prep/'manifest.json'),'gpu_devices':devices,
              'slurm_job_id':os.environ['SLURM_JOB_ID'],'driver_allocation_scope':'owner must attach full job allocation timing',
              'internal_gpu_batch_observed':False,'cache_state':'persistent compiler cache; no prompt warmup; steady state unverified',
              'delivery_latency_semantics':'unobserved_judge_deferred' if deferred else 'synchronous_batch_barrier_then_serial_verification',
              'start_wall_ns':time.time_ns(),'attempt_start_monotonic_s':time.monotonic()}
    if native.active(cfg):
        from lcb_feasibility import generation_settings
        metadata['generation_settings']=generation_settings(cfg)
    write_new(root/'run.json',metadata)
    stop=threading.Event();backend=None;state='failed';reason=None;caught=None;generation_end=None;failure_stage='backend_initialization'
    release={'release_status':'timeout','engine_release_wall_ns':None,'last_nvidia_smi':None,
             'errors':['Backend was not constructed; release not observed']}
    def monitor():
        with (root/'gpu.jsonl').open('x') as f:
            while not stop.is_set():
                before=time.monotonic_ns();row={'timestamp_ns':time.time_ns()}
                try:row['gpus']=gpu_sample(devices[0]['uuid'])
                except Exception as exc:row['error']=str(exc)
                after=time.monotonic_ns();row.update(monotonic_ns=(before+after)//2,
                    query_start_monotonic_ns=before,query_end_monotonic_ns=after)
                f.write(json.dumps(row)+'\n');f.flush();stop.wait(.2)
    telemetry=threading.Thread(target=monitor,daemon=True);telemetry.start()
    native_prompts={}
    # Keep the backend log OPEN throughout shutdown: the previous placement
    # closed it before close(), losing late engine diagnostics.
    with (root/'backend.log').open('xb') as log:
        try:
            with (root/'schedule.jsonl').open('x') as events,(root/'samples.jsonl').open('x') as raw:
                def emit(event):
                    event=dict(event,wall_ns=time.time_ns());events.write(json.dumps(event)+'\n');events.flush()
                def on_sample(row):
                    eligible(row,strict=True)
                    if native.active(cfg):
                        native.validate_sample(row,cfg)
                        if cfg['execution_purpose']==ADMISSION_PURPOSE:
                            if row['task_id'] not in native_prompts:raise ValueError('Missing native prompt preflight')
                            native.match_prompt_evidence(row,native_prompts[row['task_id']])
                    if (type(row.get('seed')) is not int or row['seed']!=seed_for(row['task_id'],row['candidate_id'])
                        or row.get('sampling_seed_policy')!=cfg['sampling_seed_policy']
                        or row.get('replicate_id')!=cfg.get('replicate_id')):
                        raise ValueError('Backend candidate seed/policy/replicate differs from dispatch')
                    raw.write(json.dumps(row)+'\n');raw.flush()
                backend=Backend(cfg,devices[0]['uuid'],log)
                backend.start();write_new(root/'backend.json',backend.ready)
                failure_stage='tokenization_preflight'
                if cfg['execution_purpose']==ADMISSION_PURPOSE:
                    tokenized=backend.tokenize_prompts(prompts)
                    tokenized.update(workload_manifest_sha256=cfg['workload_manifest_sha256'],
                        model_id=cfg['model_id'],model_revision=cfg['model_revision'],reasoning_mode=cfg['reasoning_mode'])
                    write_new(root/'tokenization.json',tokenized)
                    validate_tokenization(tokenized,cfg,[t['task_id'] for t in prompts])
                    if cfg.get('cap_chain_protocol')=='native-admission-chain-v3':
                        from lcb_admission_v3 import verify_tokenization_pair
                        verify_tokenization_pair(cfg,tokenized)
                    if native.active(cfg):native_prompts={r['task_id']:r for r in tokenized['rows']}
                failure_stage='service_window'
                def generate(jobs):
                    packed=[{'task_id':t['task_id'],'candidate_id':j,'prompt':t['prompt'],
                             'seed':seed_for(t['task_id'],j),'sampling_seed_policy':cfg['sampling_seed_policy'],
                             'replicate_id':cfg.get('replicate_id')} for t,j in jobs]
                    return backend.generate(packed,float(cfg['generation_timeout_s']),on_sample)
                def select(t,samples):return online_selection(t,samples,private[t['task_id']],judge,cfg['weak_size'])
                records=run_cohort(tasks,offsets,pool_id=cfg['pool_id'],concurrency=cfg['concurrency'],
                                   k=cfg['k'],generate=generate,select=None if deferred else select,emit=emit,
                                   selection_mode='deferred' if deferred else 'online')
                write_new(root/'episodes.jsonl',records,True)
                state='collected_not_audited';generation_end=time.time_ns()
        except BaseException as exc:
            caught=exc;reason=type(exc).__name__+': '+str(exc)
        finally:
            try:
                if backend is not None:release=backend.close()
            except BaseException as exc:
                release={'release_status':'timeout','engine_release_wall_ns':None,'last_nvidia_smi':None,
                         'errors':['Cleanup interrupted: '+type(exc).__name__+': '+str(exc)]}
            finally:
                stop.set();telemetry.join(timeout=12)
                log.flush()
    log_snapshot=(root/'backend.log').read_bytes()
    cache_observation=observe_cache(log_snapshot.decode(errors='replace'),cfg['compile_cache_dir'])
    cache_observation.update(backend_log_sha256_at_observation=digest(log_snapshot),
                             backend_log_bytes_at_observation=len(log_snapshot),observation_wall_ns=time.time_ns())
    resources=None
    if not deferred and state=='collected_not_audited':
        try:resources=resource_ledger(metadata,read_rows(root/'schedule.jsonl'),read_rows(root/'gpu.jsonl'),read_rows(root/'episodes.jsonl'))
        except (ValueError,KeyError) as exc:resources={'schema':'lcb-service-resources-v2','status':'incomplete','error':str(exc)}
        write_new(root/'resources.json',resources)
    write_new(root/'completion.json',{'schema':'lcb-owner-completion-v2','status':state,'error':reason,
              'failure_stage':failure_stage if caught is not None else None,
              'attempt_end_monotonic_s':time.monotonic(),
              'resources_sha256':file_sha(root/'resources.json') if resources is not None else None,
              'pause_review':bool(resources and resources.get('pause_review')),
              'pause_reasons':resources.get('pause_reasons',[]) if resources else [],
              'generation_end_wall_ns':generation_end,'end_wall_ns':time.time_ns(),
              'release_status':release['release_status'],'engine_release_wall_ns':release['engine_release_wall_ns'],
              'last_nvidia_smi':release.get('last_nvidia_smi'),'release_details':release,
              'cache_observation':cache_observation,'execution_purpose':cfg['execution_purpose'],
              'telemetry_stopped':not telemetry.is_alive(),
              'judge_mode':cfg.get('judge','online'),'candidate_execution':False if deferred else None,
              'samples_sha256':file_sha(root/'samples.jsonl') if (root/'samples.jsonl').exists() else None,
              'artifacts_sha256':{p.name:file_sha(p) for p in (root/x for x in
                  ('run.json','backend.json','samples.jsonl','episodes.jsonl','schedule.jsonl','gpu.jsonl','resources.json','tokenization.json')) if p.is_file()},
              'not_a_market_profile':True})
    if caught is not None:raise caught
    if telemetry.is_alive():raise RuntimeError('Telemetry did not stop; refuse next cell')
    if release['release_status']!='released':
        raise RuntimeError('Generation may be complete, but backend release is unconfirmed; stop subsequent cells')
    require_resource_review_clear(resources)


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--prepared',required=True)
    p.add_argument('--output',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    collect(read_json(a.config),a.prepared,a.output,a.execute)


if __name__=='__main__':main()
