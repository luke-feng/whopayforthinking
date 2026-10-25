#!/usr/bin/env python3
"""Owner-run pilot. Never executes generated code; inference is opt-in/loopback-only."""
from __future__ import annotations
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def digest(value):
    return hashlib.sha256(value if isinstance(value,bytes) else value.encode()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def read_rows(path):
    return [json.loads(x) for x in Path(path).read_text(encoding='utf-8').splitlines() if x.strip()]


def write_new(path,value,jsonl=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as out:
        if jsonl:
            for row in value:out.write(json.dumps(row,ensure_ascii=False)+'\n')
        else:json.dump(value,out,ensure_ascii=False,indent=2)


def prepare(args):
    cfg=read_json(args.config);raw=Path(args.dataset).read_bytes()
    plain=gzip.decompress(raw) if raw[:2]==b'\x1f\x8b' else raw
    data={row['task_id']:row for row in map(json.loads,plain.decode().splitlines())}
    selected=[data[t] for t in cfg['task_ids']]
    required={'prompt','entry_point','contract','canonical_solution','base_input','plus_input','atol'}
    for row in selected:
        if not required.issubset(row):raise ValueError('Incomplete dataset task '+row['task_id'])
    root=Path(args.output)
    if root.exists():raise ValueError('Use a new preparation directory')
    write_new(root/'tasks.evalplus.jsonl',selected,True)
    write_new(root/'prompts.jsonl',[{k:r[k] for k in ('task_id','prompt','entry_point')} for r in selected],True)
    write_new(root/'manifest.json',{'config':cfg,'config_sha256':digest(Path(args.config).read_bytes()),
                                  'dataset_sha256':digest(plain),'compressed_sha256':digest(raw),
                                  'selected_dataset_sha256':digest((root/'tasks.evalplus.jsonl').read_bytes())})
    print(json.dumps({'prepared_tasks':len(selected),'no_inference_executed':True}))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('Inference redirects are blocked')


def local_endpoint(url):
    p=urllib.parse.urlparse(url)
    if p.scheme not in ('http','https') or p.hostname not in ('localhost','127.0.0.1','::1'):
        raise ValueError('Use an owner-controlled loopback endpoint, with SSH forwarding if needed')
    if p.username or p.password or p.query or p.fragment:raise ValueError('Unsafe base URL')
    return url.rstrip('/')


def sse_event(raw):
    if len(raw)>4*1024*1024:raise ValueError('Oversized SSE event')
    line=raw.decode('utf-8').strip()
    if not line.startswith('data:'):return None
    payload=line[5:].strip()
    if payload=='[DONE]':return 'DONE'
    event=json.loads(payload)
    if event.get('error'):raise RuntimeError('Server error: '+json.dumps(event['error'])[:4096])
    return event


def gpu_sample(selector):
    if not selector or selector.startswith('-') or any(c.isspace() for c in selector):
        raise ValueError('Explicit allocated GPU IDs/UUIDs required')
    query='index,uuid,name,memory.total,memory.used,utilization.gpu,power.draw'
    run=subprocess.run(['nvidia-smi','-i',selector,'--query-gpu='+query,'--format=csv,noheader,nounits'],
                       capture_output=True,text=True,timeout=8,check=True)
    def number(s):
        try:return float(s)
        except ValueError:return None
    rows=[]
    for line in run.stdout.splitlines():
        p=[x.strip() for x in line.split(',')]
        if len(p)!=7:raise ValueError('Unexpected GPU telemetry')
        rows.append({'index':p[0],'uuid':p[1],'name':p[2],'memory_total_mib':number(p[3]),
                     'memory_used_mib':number(p[4]),'gpu_util_percent':number(p[5]),'power_w':number(p[6])})
    if not rows:raise ValueError('No visible NVIDIA GPU')
    return rows


def collect(args):
    base=local_endpoint(args.base_url);prep=Path(args.prepared)
    manifest=read_json(prep/'manifest.json');cfg=manifest['config'];prompts=read_rows(prep/'prompts.jsonl')
    count=args.candidates or cfg['candidates_per_task']
    if not 1<=count<=cfg['candidates_per_task'] or args.concurrency<1:raise ValueError('Invalid run size')
    print(json.dumps({'planned_requests':len(prompts)*count,'execute':args.execute,'endpoint':base}))
    if not args.execute:return
    if not args.server_manifest:raise ValueError('Owner server manifest required')
    server=read_json(args.server_manifest)
    for key in ('gpu_model','gpu_selector','vllm_version','model_revision','cache_mode','launch_command'):
        if not server.get(key):raise ValueError('Missing server manifest '+key)
        if 'OWNER_' in str(server[key]):raise ValueError('Server manifest is still a template')
    if server['model_revision']!=cfg['model_revision'] or server['cache_mode']!=args.cache_mode:
        raise ValueError('Server metadata does not match protocol')
    root=Path(args.output)
    if root.exists():raise ValueError('Never overwrite a run')
    gpu_sample(server['gpu_selector'])
    with urllib.request.build_opener(NoRedirect).open(base+'/models',timeout=10) as reply:
        available=json.load(reply)
    if cfg['model'] not in [x.get('id') for x in available.get('data',[])]:raise ValueError('Expected model not served')
    root.mkdir(parents=True)
    meta={'evidence':'measured','run_id':root.name,'config':cfg,'config_sha256':manifest['config_sha256'],
          'dataset_sha256':manifest['dataset_sha256'],'selected_dataset_sha256':manifest['selected_dataset_sha256'],
          'server_manifest_sha256':digest(Path(args.server_manifest).read_bytes()),'server':server,'candidates_per_task':count,
          'cache_mode':args.cache_mode,'cache_state':args.cache_state,'concurrency':args.concurrency,
          'started_at_utc':datetime.now(timezone.utc).isoformat(),
          'memory_warning':'NVML process-wide sampled occupancy, not active KV or exact per-request peak'}
    write_new(root/'run.json',meta)
    stop=threading.Event()
    def monitor():
        with (root/'gpu.jsonl').open('x',encoding='utf-8') as out:
            while not stop.is_set():
                row={'timestamp_ns':time.time_ns()}
                try:row['gpus']=gpu_sample(server['gpu_selector'])
                except Exception as e:row['telemetry_error']=str(e)
                out.write(json.dumps(row)+'\n');out.flush();stop.wait(.2)
    worker=threading.Thread(target=monitor,daemon=True);worker.start()
    def request(task,index):
        seed=cfg['seed']+cfg['task_ids'].index(task['task_id'])*cfg['candidates_per_task']+index
        body={'model':cfg['model'],'messages':[{'role':'system','content':cfg['system_prompt']},
                                             {'role':'user','content':task['prompt']}],
              'temperature':cfg['temperature'],'top_p':cfg['top_p'],'max_tokens':cfg['max_tokens'],
              'seed':seed,'stream':True,'stream_options':{'include_usage':True}}
        row={'evidence':'measured','run_id':root.name,'task_id':task['task_id'],'candidate_id':index,
             'seed':seed,'prompt_sha256':digest(task['prompt']),'model_revision':cfg['model_revision'],
             'cache_mode':args.cache_mode,'cache_state':args.cache_state,'concurrency':args.concurrency,'status':'error',
             'input_tokens':None,'output_tokens':None,'ttft_s':None,'tpot_s':None,
             'cached_prompt_tokens':None,'finish_reason':None,'solution':'raise RuntimeError("generation failed")\n'}
        row['start_ns']=time.time_ns();start=time.perf_counter();first=None;parts=[]
        try:
            req=urllib.request.Request(base+'/chat/completions',data=json.dumps(body).encode(),
                                       headers={'Content-Type':'application/json'})
            with urllib.request.build_opener(NoRedirect).open(req,timeout=args.timeout) as response:
                for raw in response:
                    if time.perf_counter()-start>args.timeout:raise TimeoutError('Request wall-time limit')
                    event=sse_event(raw)
                    if event is None:continue
                    if event=='DONE':break
                    if event.get('usage'):
                        usage=event['usage'];row['input_tokens']=usage.get('prompt_tokens');row['output_tokens']=usage.get('completion_tokens')
                        row['cached_prompt_tokens']=(usage.get('prompt_tokens_details') or {}).get('cached_tokens')
                    for choice in event.get('choices',[]):
                        chunk=choice.get('delta',{}).get('content') or ''
                        if chunk:
                            if first is None:first=time.perf_counter()-start
                            parts.append(chunk)
                        if choice.get('finish_reason') is not None:row['finish_reason']=choice['finish_reason']
            if row['finish_reason'] is None:raise ValueError('Incomplete response stream')
            raw_text=''.join(parts);clean=raw_text.strip();extraction='none'
            if clean.startswith('```') and clean.endswith('```') and '\n' in clean:
                clean=clean.split('\n',1)[1].rsplit('```',1)[0].strip();extraction='single_outer_fence'
            row.update(status='ok',raw_text=raw_text,solution=clean,extraction=extraction)
        except Exception as e:
            row.update(error=type(e).__name__+': '+str(e),partial_text=''.join(parts))
            if isinstance(e,urllib.error.HTTPError):
                row['http_status']=e.code;row['error_body']=e.read(4096).decode('utf-8',errors='replace')
        row['e2e_s']=time.perf_counter()-start;row['end_ns']=time.time_ns();row['ttft_s']=first
        if first is not None and isinstance(row['output_tokens'],int) and row['output_tokens']>1:
            row['tpot_s']=(row['e2e_s']-first)/(row['output_tokens']-1)
        row['solution_sha256']=digest(row['solution']);return row
    rows=[]
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures=[pool.submit(request,t,i) for t in prompts for i in range(count)]
            with (root/'requests.jsonl').open('x',encoding='utf-8') as out:
                for f in as_completed(futures):
                    row=f.result();rows.append(row);out.write(json.dumps(row,ensure_ascii=False)+'\n');out.flush()
    finally:stop.set();worker.join(timeout=12)
    rows.sort(key=lambda r:(cfg['task_ids'].index(r['task_id']),r['candidate_id']))
    write_new(root/'samples.jsonl',[{'task_id':r['task_id'],'solution':r['solution']} for r in rows],True)
    print(json.dumps({'requests':len(rows),'errors':sum(r['status']!='ok' for r in rows),'not_yet_evaluated':True}))


def join(args):
    run=Path(args.run);meta=read_json(run/'run.json');rows=read_rows(run/'requests.jsonl')
    evaluation=read_json(args.evaluation);telemetry=read_rows(run/'gpu.jsonl')
    if 'eval' not in evaluation:raise ValueError('Expected raw EvalPlus results')
    sandbox=evaluation.get('_sandbox',{})
    if sandbox.get('tasks_sha256')!=meta['selected_dataset_sha256']:
        raise ValueError('Evaluation dataset hash mismatch')
    if sandbox.get('samples_sha256')!=digest((run/'samples.jsonl').read_bytes()):
        raise ValueError('Evaluation samples hash mismatch')
    if sandbox.get('network')!='none' or sandbox.get('uid')!=65534:
        raise ValueError('Missing expected isolation provenance')
    grouped=defaultdict(list)
    for row in rows:grouped[row['task_id']].append(row)
    if set(grouped)!=set(meta['config']['task_ids']):raise ValueError('Task coverage mismatch')
    output=[]
    for task in meta['config']['task_ids']:
        ordered=sorted(grouped[task],key=lambda r:r['candidate_id']);results=evaluation['eval'].get(task,[])
        if len(ordered)!=meta['candidates_per_task'] or len(results)!=len(ordered):raise ValueError('Missing labels '+task)
        if [r['candidate_id'] for r in ordered]!=list(range(len(ordered))):raise ValueError('Candidate ID mismatch')
        for row,result in zip(ordered,results):
            if result.get('solution')!=row['solution']:raise ValueError('Solution/order mismatch '+task)
            if result.get('base_status') is None:raise ValueError('Missing base evaluation')
            if result['base_status']=='pass' and result.get('plus_status') is None:raise ValueError('Missing audit')
            weak=result['base_status']=='pass' and row['status']=='ok';audit=weak and result.get('plus_status')=='pass'
            peaks={}
            for sample in telemetry:
                if row['start_ns']<=sample['timestamp_ns']<=row['end_ns']:
                    for gpu in sample.get('gpus',[]):
                        if gpu['memory_used_mib'] is not None:
                            peaks[gpu['uuid']]=max(peaks.get(gpu['uuid'],0),gpu['memory_used_mib'])
            output.append(dict(row,weak_pass=weak,audit_pass=audit,base_status=result['base_status'],
                               plus_status=result.get('plus_status'),audit_definition='base_and_plus',
                               observed_device_memory_peak_mib=peaks or None,kv_active_bytes=None,
                               memory_attribution='whole device; sampled; concurrent requests not separable'))
    write_new(args.output,output,True)


def choose(n,k):return math.comb(n,k) if 0<=k<=n else 0


def task_curve(rows,k):
    n=len(rows);w=sum(r['weak_pass'] for r in rows);a=sum(r['audit_pass'] for r in rows)
    tp=sum(r['weak_pass'] and r['audit_pass'] for r in rows)
    oracle=1-choose(n-a,k)/choose(n,k);found=1-choose(n-w,k)/choose(n,k)
    delivered=found*tp/w if w else 0.0
    first=next((r for r in rows[:k] if r['weak_pass']),None)
    calls=sum(choose(n-w,j)/choose(n,j) for j in range(k))
    tokens=None
    if all(isinstance(r.get('output_tokens'),int) for r in rows):
        tokens=sum(r['output_tokens']/n*sum(choose(n-1-w+int(r['weak_pass']),j)/choose(n-1,j)
                                           for j in range(k)) for r in rows)
    return {'oracle_pass_at_k':oracle,'random_order_weak_delivery':delivered,
            'observed_order_weak_delivery':float(bool(first and first['audit_pass'])),
            'oracle_delivery_gap':oracle-delivered,'expected_attempts_before_weak_acceptance':calls,
            'replayed_generated_tokens':tokens}


def analyze_rows(rows,task_ids,n,k_values,allow_fixture=False):
    if not rows:raise ValueError('No samples; cannot manufacture pilot results')
    grouped=defaultdict(list);strata=set()
    for row in rows:
        if row.get('evidence')!='measured' and not allow_fixture:raise ValueError('Non-measured evidence refused')
        if type(row.get('weak_pass')) is not bool or type(row.get('audit_pass')) is not bool:raise ValueError('Missing labels')
        if row['audit_pass'] and not row['weak_pass']:raise ValueError('Nested audit cannot pass when base fails')
        for key in ('input_tokens','output_tokens'):
            if row.get(key) is not None and (type(row[key]) is not int or row[key]<0):raise ValueError('Invalid token meter')
        strata.add((row.get('run_id'),row.get('model_revision'),row.get('cache_mode'),row.get('cache_state'),row.get('concurrency')))
        grouped[row['task_id']].append(row)
    if len(strata)!=1:raise ValueError('Do not pool hardware/cache/replicate strata silently')
    if set(grouped)!=set(task_ids):raise ValueError('Task coverage mismatch')
    for task in task_ids:
        grouped[task].sort(key=lambda r:r['candidate_id'])
        if len(grouped[task])!=n or [r['candidate_id'] for r in grouped[task]]!=list(range(n)):raise ValueError('Candidate coverage mismatch')
    confusion={key:0 for key in ('TP','FP','FN','TN')}
    for r in rows:
        if r.get('status')!='ok':continue  # No generated candidate is not a verifier true negative.
        confusion[('T' if r['audit_pass']==r['weak_pass'] else 'F')+('P' if r['weak_pass'] else 'N')]+=1
    tp,fp,fn,tn=(confusion[k] for k in ('TP','FP','FN','TN'));ratio=lambda x,d:x/d if d else None
    curves={}
    for k in k_values:
        if not 1<=k<=n:raise ValueError('k outside sampled range')
        values=[task_curve(grouped[t],k) for t in task_ids]
        curves[str(k)]={f:sum(x[f] for x in values)/len(values) if all(x[f] is not None for x in values) else None for f in values[0]}
        rng=random.Random(20261006+k)
        gaps=sorted(sum(rng.choice(values)['oracle_delivery_gap'] for _ in task_ids)/len(task_ids) for _ in range(1000))
        curves[str(k)]['gap_task_bootstrap_95pct']=[gaps[24],gaps[974]]
    return {'evidence':'fixture' if allow_fixture else 'measured','tasks':len(task_ids),'samples':len(rows),
            'curve_scope':'obtained-candidate coverage and service delivery; generation failures are unavailable slots, not latent model errors',
            'order_definition':'candidate_id submission order, not fastest-completion order',
            'generation_errors':sum(r.get('status')!='ok' for r in rows),
            'verifier_scored_candidates':sum(confusion.values()),
            'truncated_samples':sum(r.get('finish_reason')=='length' for r in rows),
            'metering_complete':all(isinstance(r.get('output_tokens'),int) for r in rows),
            'confusion':confusion,'weak_accept_precision':ratio(tp,tp+fp),'weak_FPR':ratio(fp,fp+tn),
            'weak_TPR':ratio(tp,tp+fn),'TPR_caveat':'Nested base_and_plus makes TPR=1 by construction when defined',
            'curves':curves,'scope':'pilot diagnostic, not perfect correctness; token replay is not measured policy latency'}


def main():
    p=argparse.ArgumentParser();s=p.add_subparsers(dest='cmd',required=True)
    a=s.add_parser('prepare');a.add_argument('--config',required=True);a.add_argument('--dataset',required=True);a.add_argument('--output',required=True)
    a=s.add_parser('collect');a.add_argument('--prepared',required=True);a.add_argument('--output',required=True)
    a.add_argument('--base-url',default='http://127.0.0.1:8000/v1');a.add_argument('--server-manifest')
    a.add_argument('--cache-mode',choices=['off','on'],required=True);a.add_argument('--concurrency',type=int,default=1)
    a.add_argument('--cache-state',choices=['fresh_process','after_previous_run','owner_prewarmed','unspecified'],default='unspecified')
    a.add_argument('--candidates',type=int);a.add_argument('--timeout',type=int,default=180);a.add_argument('--execute',action='store_true')
    a=s.add_parser('join');a.add_argument('--run',required=True);a.add_argument('--evaluation',required=True);a.add_argument('--output',required=True)
    a=s.add_parser('analyze');a.add_argument('--config',required=True);a.add_argument('--samples',required=True);a.add_argument('--output',required=True)
    a.add_argument('--candidates',type=int,help='For the 1-candidate hardware matrix only; k grid is truncated accordingly')
    args=p.parse_args()
    if args.cmd=='prepare':prepare(args)
    elif args.cmd=='collect':collect(args)
    elif args.cmd=='join':join(args)
    else:
        cfg=read_json(args.config);n=args.candidates or cfg['candidates_per_task']
        if n not in (1,cfg['candidates_per_task']):raise ValueError('Unexpected run size')
        report=analyze_rows(read_rows(args.samples),cfg['task_ids'],n,[k for k in cfg['k_values'] if k<=n])
        write_new(args.output,report);print(json.dumps(report,indent=2))


if __name__=='__main__':main()
