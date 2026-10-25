"""Read-only per-model output-cap recommendation from owner pilot originals.

No model/tokenizer imports, new requests, labels, or execution authorization.
All-workload prompt lengths must come from the recorded native tokenizer.
"""
import argparse
import hashlib
import json
from pathlib import Path

from pilot import read_json,read_rows,write_new
from lcb_sandbox import file_sha
from lcb_seeds import verify_appendix
from lcb_generation_report import summarize
from lcb_delivery import eligible
from lcb_feasibility import dispatch_summary
from theory_panel import select_modern_cap
import lcb_native_generation as native

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=ROOT/'data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json'
SEEDS=ROOT/'data/calibration/lcb-generation-seeds-v1.proposal.json'


def verify_inherited_cap(cfg):
    path=Path(cfg.get('inherited_cap_receipt',''))
    if not path.is_file() or file_sha(path)!=cfg.get('inherited_cap_receipt_sha256'):
        raise ValueError('Thinking-off requires the original on-mode cap receipt')
    value=read_json(path)
    if value.get('schema')=='lcb-model-cap-recommendation-v2':
        from lcb_admission_v2 import verify_inherited
        return verify_inherited(cfg,value)
    if (value.get('schema')!='lcb-model-cap-recommendation-v1' or value.get('stratum_id')!='q38-thinking'
        or value.get('status')!='cap_recommended' or value.get('max_tokens')!=cfg.get('max_tokens')):
        raise ValueError('Do not independently select the Qwen thinking-off cap')
    if (cfg.get('max_model_len')!=16384 or value['max_tokens'] not in (8192,12288)
        or value.get('observed_truncation',{}).get(str(value['max_tokens']),{}).get('truncated',129)>6):
        raise ValueError('Legacy failed-12288 fallback is superseded; use the three-stage receipt')
    for run in value.get('source_runs',[]):
        if read_json(Path(run)/'run.json')['config'].get('stratum_id')!='q38-thinking':
            raise ValueError('Inherited receipt must refer only to on-mode runs, not itself/off mode')
    rebuilt=report([Path(p) for p in value['source_runs']])
    if rebuilt!=value:raise ValueError('Inherited cap receipt is not reproduced from originals')
    return value


def load_run(path,*,allow_fixture=False):
    # Import lazily: config validation calls verify_inherited_cap for off mode.
    from lcb_collector import validate_config,source_hashes
    path=Path(path).resolve(strict=True)
    meta=read_json(path/'run.json');done=read_json(path/'completion.json');cfg=meta['config']
    if meta.get('evidence') not in ({'fixture','measured'} if allow_fixture else {'measured'}):
        raise ValueError('Observed pilot originals required; fixtures are not production evidence')
    validate_config(cfg)
    if (cfg.get('execution_purpose')!='model_admission_pilot' or cfg.get('replicate_id')!=0
        or cfg.get('subset')!='pilot' or cfg.get('judge')!='deferred'
        or meta.get('candidate_execution') is not False or done.get('candidate_execution') is not False):
        raise ValueError('Cap selection uses the paired replicate-0 generation-only admission pilot')
    if (done.get('status')!='collected_not_audited' or done.get('release_status')!='released'
        or done.get('error') is not None or done.get('telemetry_stopped') is not True):
        raise ValueError('Incomplete or unreleased pilot; return to review')
    release=done.get('release_details',{})
    if (release.get('reader_stopped') is not True or release.get('errors') or release.get('remaining_backend_pids')
        or done.get('last_nvidia_smi',{}).get('apps')!=[]):
        raise ValueError('Pilot cleanup evidence incomplete')
    manifest=read_json(MANIFEST);manifest_raw=MANIFEST.read_bytes()
    if (cfg['workload_manifest_sha256']!=file_sha(MANIFEST) or meta['preparation_sha256']!=file_sha(MANIFEST)
        or meta['task_ids']!=manifest['pilot_task_ids'] or len(meta['task_ids'])!=16):
        raise ValueError('Use the exact frozen 16-task pilot, not selected successful tasks')
    if meta.get('source_files_sha256')!=source_hashes():raise ValueError('Pilot source checkout changed')
    required={'run.json','backend.json','samples.jsonl','episodes.jsonl','schedule.jsonl','gpu.jsonl','tokenization.json'}
    hashes=done['artifacts_sha256']
    if set(hashes)!=required or any(file_sha(path/n)!=h for n,h in hashes.items()):
        raise ValueError('Pilot original artifact hashes changed')
    if done['samples_sha256']!=hashes['samples.jsonl']:raise ValueError('Samples changed')
    ready=read_json(path/'backend.json')
    if native.active(cfg):
        from lcb_feasibility import generation_settings
        if native.canonical(meta.get('generation_settings'))!=native.canonical(generation_settings(cfg)):
            raise ValueError('Admission run generation settings differ')
        native.validate_backend_evidence(ready.get('native_generation'),cfg)
    if (ready['gpu_name']!=cfg['expected_gpu_name'] or ready['vllm_version']!=cfg['expected_vllm_version']
        or meta['gpu_devices'][0]['name']!=cfg['expected_gpu_name']):raise ValueError('Pilot hardware/version mismatch')
    tokenization=read_json(path/'tokenization.json')
    if (tokenization.get('event')!='tokenized_prompts' or tokenization.get('generation_executed') is not False
        or tokenization['workload_manifest_sha256']!=cfg['workload_manifest_sha256']
        or any(tokenization[k]!=cfg[k] for k in ('model_id','model_revision','reasoning_mode'))):
        raise ValueError('Tokenization provenance differs from native-mode pilot')
    entries=tokenization['rows'];lengths={r['task_id']:r['input_tokens'] for r in entries}
    if native.active(cfg):
        from lcb_admission import validate_tokenization
        validate_tokenization(tokenization,cfg,manifest['pilot_task_ids']+manifest['main_task_ids'])
    wanted={r['task_id'] for r in manifest['eligible_tasks']}
    if (len(entries)!=len(lengths) or set(lengths)!=wanted
        or any(type(n) is not int or n<1 for n in lengths.values())):
        raise ValueError('Tokenize every frozen pilot/main task without filtering')
    seed_map=verify_appendix(read_json(SEEDS),manifest_raw,cfg['seed'])
    if cfg['seed_appendix_sha256']!=file_sha(SEEDS):raise ValueError('Seed appendix changed')
    samples=read_rows(path/'samples.jsonl');episodes=read_rows(path/'episodes.jsonl')
    receipt=summarize(meta,samples,episodes)
    if receipt['candidates']!=128 or receipt['episodes']!=16:raise ValueError('Full 16 by 8 candidate coverage required')
    lookup={r['task_id']:r for r in entries}
    for row in samples:
        if native.active(cfg):
            native.validate_sample(row,cfg)
            native.match_prompt_evidence(row,lookup[row['task_id']])
        ids=row['input_token_ids'];cap=cfg['max_tokens']
        eligible(row,strict=True)
        if (row['seed']!=seed_map[0,row['task_id'],row['candidate_id']] or row.get('replicate_id')!=0
            or row.get('sampling_seed_policy')!=cfg['sampling_seed_policy']):raise ValueError('Candidate seed mismatch')
        if (type(row.get('truncated')) is not bool or row['truncated']!=(row['finish_reason']=='length')
            or row['finish_reason'] not in ('stop','length') or not 0<=row['output_tokens']<=cap):
            raise ValueError('Invalid candidate completion/cap evidence')
        if (not ids or any(type(x) is not int or x<0 for x in ids) or len(ids)!=row['input_tokens']
            or len(ids)!=lengths[row['task_id']]
            or hashlib.sha256(json.dumps(ids,separators=(',',':')).encode()).hexdigest()!=lookup[row['task_id']]['input_ids_sha256']):
            raise ValueError('Candidate prompt differs from recorded native tokenization')
    concurrency=dispatch_summary(read_rows(path/'schedule.jsonl'),meta['task_ids'],k=8,pool_id=1,
        concurrency=16,max_num_seqs=cfg['max_num_seqs'])
    signature={k:cfg[k] for k in ('stratum_id','model_id','model_revision','reasoning_mode','max_model_len',
        'max_num_seqs','gpu_memory_utilization','temperature','top_p','seed','replicate_id','system_prompt',
        'expected_gpu_name','expected_vllm_version','inference_sif_sha256','inference_text_only','cache_mode')}
    if native.active(cfg):signature.update(native.profile_settings(cfg))
    return {'path':str(path),'cfg':cfg,'samples':sorted(samples,key=lambda r:(meta['task_ids'].index(r['task_id']),r['candidate_id'])),
            'signature':signature,'lengths':lengths,'tokenization_rows':entries,'concurrency':concurrency,
            'original_hashes':{**hashes,'completion.json':file_sha(path/'completion.json')},'receipt':receipt}


def choose(records):
    if not records or len(records)>2:raise ValueError('One model and at most two candidate caps per report')
    first=records[0];cfg=first['cfg'];name=cfg['stratum_id']
    if any(r['signature']!=first['signature'] or r['tokenization_rows']!=first['tokenization_rows'] for r in records):
        raise ValueError('Keep native template, workload, hardware and generation settings paired across caps')
    caps={r['cfg']['max_tokens']:r['samples'] for r in records}
    if len(caps)!=len(records):raise ValueError('Repeated cap runs are not extra evidence or replaceable seeds')
    lengths=list(first['lengths'].values())
    if name in ('coder-nonthinking','q38-nonthinking'):
        cap=cfg['max_tokens']
        if len(caps)!=1 or (name=='coder-nonthinking' and cap!=4096):raise ValueError('Control cap is inherited/fixed, not optimized')
        if max(lengths)+cap>16384:raise ValueError('Frozen task/context mismatch; no task may be dropped')
        result={'max_tokens':cap,'observed_truncation':{cap:{'truncated':sum(r['truncated'] for r in caps[cap]),'candidates':128}},
                'control_rule':'fixed_4096' if name=='coder-nonthinking' else 'inherit_verified_q38_on_receipt'}
    else:
        if 8192 not in caps:raise ValueError('The smaller cap must be evaluated first')
        if sum(r['truncated'] for r in caps[8192])*20>128 and 12288 not in caps:
            return {'status':'needs_larger_cap_pilot','next_max_tokens':12288,'max_tokens':None,
                    'observed_truncation':{8192:{'truncated':sum(r['truncated'] for r in caps[8192]),'candidates':128}}}
        result=select_modern_cap(caps,lengths)
    return {'status':'cap_recommended',**result}


def report(paths):
    records=[load_run(p) for p in paths];records.sort(key=lambda r:r['cfg']['max_tokens'])
    result=choose(records)
    value={'schema':'lcb-model-cap-recommendation-v1',**result,'stratum_id':records[0]['cfg']['stratum_id'],
        'source_runs':[r['path'] for r in records],
        'sources':[{'run':r['path'],'hashes':r['original_hashes'],'submission':r['concurrency']} for r in records],
        'frozen_workload_sha256':file_sha(MANIFEST),'model_settings':records[0]['signature'],
        'native_mode_contrast':'includes native template, input, reasoning and final-output differences',
        'token_cap_scope':'reasoning plus final output; every length-truncated candidate is charged and has no deliverable answer',
        'quality_admission':'pending_isolated_audit_labels_and_saturation_review',
        'reviewer_frozen':False,'execution_authorized':False,'main_matrix_authorized':False,
        'inference_calls':0,'candidate_execution':False}
    return json.loads(json.dumps(value,allow_nan=False))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs',nargs='+',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();value=report(args.runs);write_new(args.output,value)
    print(json.dumps({'status':value['status'],'max_tokens':value['max_tokens'],'execution_authorized':False}))


if __name__=='__main__':main()
