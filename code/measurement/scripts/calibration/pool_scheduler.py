"""Exclusive synchronous submission adapter; NOT a continuous batching engine.

pi=0 submits one episode's candidates at a time; pi=1 may merge due episodes.
The same arrival offsets apply to both. Internal GPU batches remain unobserved.
"""
import math
import time
from lcb_timing import episode_timing
from lcb_metering import deferred_meters


def validate_arrivals(tasks,offsets):
    if not tasks or len(tasks)!=len(offsets) or len({t['task_id'] for t in tasks})!=len(tasks):
        raise ValueError('Task/arrival coverage or duplicate task')
    if any(not math.isfinite(x) or x<0 for x in offsets) or offsets!=sorted(offsets):
        raise ValueError('Arrival offsets must be sorted, finite and nonnegative')


def run_cohort(tasks,offsets,*,pool_id,concurrency,k,generate,select,emit,
               clock=time.monotonic,sleep=time.sleep,selection_mode='online'):
    validate_arrivals(tasks,offsets)
    if selection_mode not in ('online','deferred'):raise ValueError('Unknown selection mode')
    if selection_mode=='deferred' and select is not None:raise ValueError('Deferred mode must not have a selector')
    if type(pool_id) is not int or pool_id not in (0,1) or type(concurrency) is not int or concurrency<1 or type(k) is not int or k<1:
        raise ValueError('Invalid pool/concurrency/k')
    start=clock();cursor=0;batch_id=0;records=[]
    emit({'event':'cohort_start','pool_id':pool_id,'concurrency':concurrency,'k':k,
          'arrivals':dict(zip((t['task_id'] for t in tasks),offsets)),
          'scheduler':'exclusive_synchronous_submission','internal_gpu_batch_observed':False,
          'selection_mode':selection_mode,
          'cohort_start_monotonic_s':start})
    while cursor<len(tasks):
        elapsed=clock()-start
        if offsets[cursor]>elapsed:sleep(offsets[cursor]-elapsed)
        due=cursor
        while due<len(tasks) and offsets[due]<=clock()-start:due+=1
        stop=min(due,cursor+(1 if pool_id==0 else concurrency))
        if stop<=cursor:continue
        active=tasks[cursor:stop];jobs=[(t,j) for t in active for j in range(k)]
        dispatch=clock()-start
        emit({'event':'dispatch','batch_id':batch_id,'since_start_s':dispatch,
              'episodes':[t['task_id'] for t in active],'candidate_count':len(jobs),
              'submitted_batch_only':True})
        try:outputs=generate(jobs)
        except Exception as exc:
            emit({'event':'generation_batch_failure','batch_id':batch_id,
                  'error':type(exc).__name__+': '+str(exc),'pending_episode_ids':[t['task_id'] for t in tasks[cursor:]]})
            raise
        expected={(t['task_id'],j) for t,j in jobs}
        observed={(r['task_id'],r['candidate_id']) for r in outputs}
        if len(outputs)!=len(expected) or observed!=expected:
            raise ValueError('Backend candidate coverage/order mismatch')
        barrier=clock()-start
        emit({'event':'generation_barrier','batch_id':batch_id,'since_start_s':barrier})
        # Validate the WHOLE batch before any candidate can reach the judge.
        batch_samples={t['task_id']:sorted((r for r in outputs if r['task_id']==t['task_id']),key=lambda r:r['candidate_id']) for t in active}
        timing={t['task_id']:episode_timing(batch_samples[t['task_id']],start,arrival,dispatch,barrier)
                for t,arrival in zip(active,offsets[cursor:stop])}
        for t,arrival in zip(active,offsets[cursor:stop]):
            if selection_mode=='deferred':
                samples=batch_samples[t['task_id']]
                records.append({'task_id':t['task_id'],'arrival_offset_s':arrival,'batch_id':batch_id,
                    'cohort_start_monotonic_s':start,'dispatch_offset_s':dispatch,
                    'samples':samples,**timing[t['task_id']],
                    'selection_status':'deferred','selected_id':None,'refusal':None,'audit_label':None,
                    'meters':deferred_meters(samples),'online_checks':None,'verification_wall_s':None,
                    'verification_start_offset_s':None,'post_barrier_to_verification_s':None,
                    'selection_elapsed_s':None,'complete_offset_s':None,'latency_s':None,
                    'delivery_latency_s':None,'delivery_latency_semantics':'unobserved_judge_deferred',
                    'collection_complete_offset_s':clock()-start})
                emit({'event':'episode_collected','batch_id':batch_id,'task_id':t['task_id'],
                      'selection_status':'deferred','since_start_s':clock()-start})
                continue
            samples=batch_samples[t['task_id']];selection_start=clock()-start
            try:decision=select(t,samples)
            except Exception as exc:
                emit({'event':'selection_infrastructure_failure','task_id':t['task_id'],
                      'error':type(exc).__name__+': '+str(exc)})
                raise
            completed=clock()-start
            record={'task_id':t['task_id'],'arrival_offset_s':arrival,'batch_id':batch_id,
                    'cohort_start_monotonic_s':start,
                    'complete_offset_s':completed,'latency_s':completed-arrival,
                    'dispatch_offset_s':dispatch,'verification_start_offset_s':selection_start,
                    'post_barrier_to_verification_s':selection_start-barrier,
                    'selection_elapsed_s':completed-selection_start,
                    'delivery_latency_s':completed-arrival,
                    'samples':samples,**timing[t['task_id']],**decision}
            records.append(record)
            emit({'event':'episode_complete','batch_id':batch_id,'task_id':t['task_id'],
                  'since_start_s':record['complete_offset_s'],'selected_id':decision.get('selected_id')})
        emit({'event':'release','batch_id':batch_id,'since_start_s':clock()-start})
        cursor=stop;batch_id+=1
    emit({'event':'cohort_end','elapsed_s':clock()-start,'episodes':len(records)})
    return records
