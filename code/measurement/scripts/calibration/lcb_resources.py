"""Whole service-cohort resource ledger from observed scheduler/telemetry data."""
from fractions import Fraction as F
import math
from lcb_cpu import total_cpu

# Reviewer-declared ceiling for missing H100 HBM3 power segments only.
# Other models/variants require a separate reviewed ceiling, never this fallback.
POWER_CEILINGS={'NVIDIA H100 80GB HBM3':F(700)}


def number(x):
    if isinstance(x,bool) or x is None: raise ValueError('Missing numeric observation')
    if isinstance(x,float) and not math.isfinite(x): raise ValueError('Nonfinite observation')
    return F(str(x))


def cpu_from_episodes(episodes):
    cases=[];ids=set()
    for ep in episodes:
        episode_cases=[]
        if not isinstance(ep.get('online_checks'),list): raise ValueError('Online checks not observed')
        for check in ep['online_checks']:
            if check['status']=='no_executable_final': continue
            if check['status']!='evaluated': raise ValueError('Incomplete online verification')
            for case in check['result']['cases']:
                cpu=case['cpu_accounting'];ident=cpu['case_id']
                if ident in ids: raise ValueError('Repeated case CPU record')
                ids.add(ident);cases.append(cpu);episode_cases.append(cpu)
        if ep.get('cpu_accounting')!=total_cpu(episode_cases):raise ValueError('Episode CPU aggregate differs from raw cases')
    return total_cpu(cases)


def summarize(meta, events, telemetry, episodes, *, max_gap_s=F(2)):
    if meta.get('judge_mode')!='online': raise ValueError('Deferred runs have no complete service resource ledger')
    starts=[e for e in events if e['event']=='cohort_start'];ends=[e for e in events if e['event']=='cohort_end']
    if len(starts)!=1 or len(ends)!=1: raise ValueError('Complete single service window required')
    begin=number(starts[0]['cohort_start_monotonic_s']);duration=number(ends[0]['elapsed_s']);end=begin+duration
    if duration<=0 or len(episodes)!=len(meta['task_ids']): raise ValueError('Invalid cohort duration or coverage')
    uuid=meta['gpu_devices'][0]['uuid'];points=[]
    for row in telemetry:
        if row.get('error'): raise ValueError('Telemetry gap or query error; do not fill zero')
        gpus=row.get('gpus',[])
        if len(gpus)!=1 or gpus[0]['uuid']!=uuid: raise ValueError('GPU identity/coverage changed')
        t=number(row['monotonic_ns'])/1000000000;p=number(gpus[0]['power_w'])
        if p<0 or (points and t<=points[-1][0]): raise ValueError('Invalid ordered power observations')
        points.append((t,p))
    if len(points)<2 or points[0][0]>begin or points[-1][0]<end: raise ValueError('Power samples do not bracket the full service window')
    joules=F(0);diagnostic_joules=F(0);covered=F(0);gap=F(0);missing=[]
    ceiling=POWER_CEILINGS.get(meta['gpu_devices'][0]['name'])
    for (t0,p0),(t1,p1) in zip(points,points[1:]):
        left,right=max(t0,begin),min(t1,end)
        if right<=left:continue
        pl=p0+(p1-p0)*(left-t0)/(t1-t0);pr=p0+(p1-p0)*(right-t0)/(t1-t0)
        estimate=(pl+pr)*(right-left)/2
        diagnostic_joules+=estimate;covered+=right-left
        if t1-t0>max_gap_s:
            if ceiling is None:raise ValueError('Missing reviewed power ceiling for this exact GPU variant')
            if any(p>ceiling for _,p in points):raise ValueError('Observed power exceeds declared missing-segment ceiling')
            gap+=right-left
            missing.append({'left_monotonic_s':str(left),'right_monotonic_s':str(right),
                'sample_interval_seconds':str(t1-t0),'missing_seconds':str(right-left),
                'energy_joules_bounds':['0',str(ceiling*(right-left))]})
        else:joules+=estimate
    if covered!=duration:raise ValueError('Incomplete power coverage')
    cpu=cpu_from_episodes(episodes)
    energy=joules/3600000;upper=(joules+(ceiling*gap if gap else 0))/3600000
    paused=gap/duration>F(1,20)
    return {'schema':'lcb-service-resources-v2','status':'recorded','gpu_uuid':uuid,
        'cohort_size':len(episodes),'service_start_monotonic_s':str(begin),'service_end_monotonic_s':str(end),
        'gpu_allocated_seconds_total':str(duration),'energy_kwh_total':None if gap else str(energy),
        'energy_kwh_bounds':[str(energy),str(upper)],'observed_segment_energy_kwh':str(energy),
        'interpolated_energy_kwh_diagnostic':str(diagnostic_joules/3600000),
        'gap_seconds':str(gap),'gap_fraction':str(gap/duration),'power_gap_segments':missing,
        'power_ceiling_w':None if ceiling is None else str(ceiling),
        'pause_review':paused,'pause_reasons':['power_gaps_above_5_percent'] if paused else [],
        'energy_method':'observed <=2s trapezoids plus declared [0,ceiling*gap] for longer intervals; total point null when gaps exist; interpolation diagnostic never fills a missing segment',
        'max_power_gap_seconds':str(max_gap_s),**cpu,
        'scope':'one exclusive GPU for the entire arrival/generation/online-selection cohort; startup and teardown recorded separately'}
