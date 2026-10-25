"""Generation-only receipt. No labels, candidate execution, quality or welfare."""
import argparse
from collections import Counter
import json
from pathlib import Path

from pilot import read_json,read_rows,write_new
from lcb_sandbox import file_sha
from lcb_metering import deferred_meters
from lcb_timing import episode_timing


def summarize(meta,samples,episodes):
    if meta.get('judge_mode')!='deferred' or meta.get('measurement_scope')!='generation_only_deferred':
        raise ValueError('Explicit deferred-generation receipt required')
    if meta.get('candidate_execution') is not False:raise ValueError('Unexpected execution scope')
    wanted=meta['task_ids'];k=meta['config']['k']
    pool=meta['config']['pool_id'];nominal_concurrency=meta['config']['concurrency']
    if type(pool) is not int or pool not in (0,1) or type(nominal_concurrency) is not int or nominal_concurrency<1:
        raise ValueError('Explicit pool and nominal concurrency required for protocol grouping')
    if not wanted or len(set(wanted))!=len(wanted) or type(k) is not int or k<1:
        raise ValueError('Invalid cohort')
    lookup={(s['task_id'],s['candidate_id']):s for s in samples}
    expected={(t,j) for t in wanted for j in range(k)}
    ep={e['task_id']:e for e in episodes}
    if len(lookup)!=len(samples) or set(lookup)!=expected or len(ep)!=len(episodes) or set(ep)!=set(wanted):
        raise ValueError('Missing or duplicate generation/episode')
    for sample in samples:
        ids=sample.get('output_token_ids')
        if not isinstance(ids,list) or any(type(x) is not int or x<0 for x in ids) or sample.get('output_tokens')!=len(ids):
            raise ValueError('Output token count mismatch')
    for t in wanted:
        row=ep[t];part=[lookup[t,j] for j in range(k)]
        if row.get('selection_status')!='deferred' or row.get('delivery_latency_semantics')!='unobserved_judge_deferred':
            raise ValueError('Deferred semantics changed')
        for key in ('selected_id','refusal','audit_label','delivery_latency_s','latency_s','complete_offset_s',
                    'verification_start_offset_s','post_barrier_to_verification_s','selection_elapsed_s','online_checks'):
            if key not in row or row[key] is not None:raise ValueError('Unobserved field must be explicitly null: '+key)
        timing=episode_timing(part,row['cohort_start_monotonic_s'],row['arrival_offset_s'],
                              row['dispatch_offset_s'],row['generation_barrier_offset_s'])
        if any(row.get(key)!=value for key,value in timing.items() if key!='delivery_latency_semantics'):
            raise ValueError('Generation timing mismatch')
        if row['meters']!=deferred_meters(part):raise ValueError('Deferred meter mismatch')
    lengths=[s['output_tokens'] for s in samples]
    missing=Counter(s.get('metering_error') or 'missing_token_partition' for s in samples if s.get('token_partition') is None)
    barriers=[e['generation_barrier_offset_s'] for e in episodes]
    return {'schema':'lcb-generation-receipt-v1','evidence':meta.get('evidence'),
        'measurement_scope':'generation_only_deferred','candidate_execution':False,'not_a_market_profile':True,
        'gpu_name':meta['gpu_name'],'episodes':len(wanted),'candidates':len(samples),
        'submission_protocol':{'pool_id':pool,'k_cap':k,
            'effective_episode_concurrency':1 if pool==0 else nominal_concurrency},
        'nominal_concurrency_run_label':nominal_concurrency,
        'pool_zero_concurrency_labels_are_repeats':pool==0,
        'protocol_grouping_scope':'Compare only within the same model, hardware, cohort, arrivals and generation settings. Pool=0 concurrency labels are repeated runs of one protocol, not independent candidate draws.',
        'output_tokens_total':sum(lengths),'output_lengths':lengths,
        'mean_output_tokens':sum(lengths)/len(lengths),'max_output_tokens':max(lengths),
        'finish_reason_counts':dict(Counter(s.get('finish_reason','missing') for s in samples)),
        'metering_complete_candidates':len(samples)-sum(missing.values()),'metering_missing_reasons':dict(missing),
        'engine_generation_latency_s':[ep[t]['generation_latency_s'] for t in wanted],
        'cohort_to_last_generation_barrier_s':max(barriers),
        'q_correct':None,'q_wrong':None,'pass_at_k':None,'delivery_latency_s':None,
        'warning':'No judging/selection observed. Deferred scheduling differs from online serial judging; do not add later CPU durations to reconstruct delivery. Not full job/GPU allocation time.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    root=Path(args.run);completion=read_json(root/'completion.json')
    if completion.get('status')!='collected_not_audited' or completion.get('judge_mode')!='deferred':
        raise ValueError('Complete deferred cell required')
    if completion['samples_sha256']!=file_sha(root/'samples.jsonl'):raise ValueError('Samples changed')
    meta=read_json(root/'run.json')
    result=summarize(meta,read_rows(root/'samples.jsonl'),read_rows(root/'episodes.jsonl'))
    if meta.get('schema')=='lcb-owner-cell-v3':
        # A generation receipt is still allowed for completed samples after a
        # release failure, but cannot hide that failure or authorize a new cell.
        result.update(execution_purpose=meta['execution_purpose'],
                      release_status=completion['release_status'],
                      engine_release_wall_ns=completion['engine_release_wall_ns'],
                      cache_observation=completion['cache_observation'])
    result['source_sha256']={n:file_sha(root/n) for n in ('run.json','completion.json','samples.jsonl','episodes.jsonl','schedule.jsonl')}
    write_new(args.output,result)
    print(json.dumps({'output':args.output,'candidates':result['candidates'],'no_judging':True}))


if __name__=='__main__':main()
