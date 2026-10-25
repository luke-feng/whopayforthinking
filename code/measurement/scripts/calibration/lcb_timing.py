"""Explicit engine clock adapters; no vLLM import and no barrier fallback.

The pinned engine source must match the selected schema. V1 last_token_ts is
an engine-output timestamp proxy, NOT a RequestMetrics.finished_time field.
"""
import math
import os
from pathlib import Path
import time

SCHEMAS=('request_metrics_wall_v1','request_state_stats_mixed_v1')
SEMANTICS={SCHEMAS[0]:'request_finished',SCHEMAS[1]:'last_token_engine_output_proxy'}
CLOCK_CHECK_TOLERANCE_S=.01


def finite(value):
    return type(value) in (int,float) and math.isfinite(value)


def clock_identity():
    """Local Linux only; mismatched time namespaces are unsupported."""
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'time_namespace':os.readlink('/proc/self/ns/time')}


def verify_clock_identity(host,backend):
    keys=('boot_id','time_namespace')
    if any(not host.get(k) or host.get(k)!=backend.get(k) for k in keys):
        raise ValueError('GPU backend and collector do not share the checked Linux clock domain')


def clock_anchor():
    before=time.monotonic();wall=time.time();after=time.monotonic()
    return {'monotonic_before_s':before,'wall_s':wall,'monotonic_after_s':after}


def anchor_offset(anchor):
    a,b,w=(anchor[k] for k in ('monotonic_before_s','monotonic_after_s','wall_s'))
    if not all(finite(x) for x in (a,b,w)) or b<a or b-a>CLOCK_CHECK_TOLERANCE_S:
        raise ValueError('Invalid or too-wide clock anchor')
    return (a+b)/2-w,(b-a)/2


def normalize_metrics(request,schema,before,after):
    if schema not in SCHEMAS:raise ValueError('Unreviewed engine metrics schema')
    if getattr(request,'finished',False) is not True:raise ValueError('Unfinished engine request')
    metrics=getattr(request,'metrics',None)
    if metrics is None:raise ValueError('Engine request metrics unavailable; no barrier substitution')
    offset,error=anchor_offset(before);offset_end,error_end=anchor_offset(after)
    drift=abs(offset_end-offset)
    if drift+error+error_end>CLOCK_CHECK_TOLERANCE_S:
        raise ValueError('Wall/monotonic clock relation changed beyond tolerance')
    fields=(('arrival_time','first_token_time','finished_time') if schema==SCHEMAS[0]
            else ('arrival_time','first_token_ts','last_token_ts'))
    raw={k:getattr(metrics,k,None) for k in fields}
    if not all(finite(v) and v>0 for v in raw.values()):
        raise ValueError('Missing, nonfinite or uninitialized engine timestamps')
    arrival=raw[fields[0]]+offset
    first=raw[fields[1]]+(offset if schema==SCHEMAS[0] else 0)
    finished=raw[fields[2]]+(offset if schema==SCHEMAS[0] else 0)
    # Conversion noise is recorded, not hidden by clamping invalid event order.
    if not before['monotonic_before_s']<=arrival<=first<=finished<=after['monotonic_after_s']:
        raise ValueError('Engine timestamps outside the generation call or incorrectly ordered')
    return {'schema':schema,'completion_semantics':SEMANTICS[schema],'raw_metrics':raw,
            'arrival_monotonic_s':arrival,'first_token_monotonic_s':first,
            'generation_complete_monotonic_s':finished,
            'clock_anchors':{'before':before,'after':after},
            'observed_offset_drift_s':drift,'clock_check_tolerance_s':CLOCK_CHECK_TOLERANCE_S,
            'clock_assumption':'shared local Linux monotonic domain; stable wall offset within call'}


def episode_timing(samples,cohort_start,arrival,dispatch,barrier):
    """Generation finish uses max candidate event, never max batch return."""
    timings=[s.get('engine_timing') for s in samples]
    if not timings or any(not isinstance(t,dict) for t in timings):
        raise ValueError('Missing per-candidate engine timing')
    schemas={t.get('schema') for t in timings}
    if len(schemas)!=1 or next(iter(schemas)) not in SCHEMAS:
        raise ValueError('Mixed or unknown engine timing schemas')
    schema=next(iter(schemas))
    for t in timings:
        if t.get('completion_semantics')!=SEMANTICS[schema]:raise ValueError('Timing semantics mismatch')
        values=[t.get(k) for k in ('arrival_monotonic_s','first_token_monotonic_s','generation_complete_monotonic_s')]
        if not all(finite(x) for x in values) or not cohort_start+dispatch<=values[0]<=values[1]<=values[2]<=cohort_start+barrier:
            raise ValueError('Invalid engine timing in collector clock domain')
    completed=max(t['generation_complete_monotonic_s'] for t in timings)-cohort_start
    return {'engine_timing_schema':schema,'generation_completion_semantics':SEMANTICS[schema],
            'generation_complete_offset_s':completed,'generation_latency_s':completed-arrival,
            'generation_barrier_offset_s':barrier,
            'post_generation_to_barrier_s':barrier-completed,
            'delivery_latency_semantics':'synchronous_batch_barrier_then_serial_verification'}
