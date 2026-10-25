"""Complete-or-evidenced-infeasible menus; no costs fabricated for failures."""
from fractions import Fraction as F
import hashlib
import json
import re

CONFIGS = ('serial', 'batch16', 'batch64')
ACTIONS = ('L', 'H')
FAILURE = 'infeasible_at_frozen_parameters'
ATTEMPT = 'resource_admission_failure'
REASONS = ('kv_capacity', 'gpu_memory_reservation', 'engine_resource_rejection')


def generation_settings(cfg):
    keys=('model_id','model_revision','reasoning_mode','temperature','top_p','max_tokens',
          'max_model_len','max_num_seqs','gpu_memory_utilization','system_prompt','cache_mode','expected_vllm_version')
    import lcb_native_generation as native
    explicit=native.profile_settings(cfg) if native.active(cfg) else {}
    return {**{k:cfg[k] for k in keys},**explicit,'dtype':'bfloat16','tensor_parallel_size':1,
            'inference_sif_sha256':cfg.get('inference_sif_sha256'),
            'inference_text_only':cfg.get('inference_text_only',False)}


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def is_failure(cell):
    return cell.get('status') in (FAILURE, ATTEMPT, 'failed_attempt')


def failure_record(cell, *, allow_fixture=False):
    """Check an exported adjudicated record; raw-file binding is done at export."""
    if cell.get('status') != ATTEMPT or cell.get('failure_stage') != 'resource_admission':
        raise ValueError('Not a reviewed resource-admission failure')
    if cell.get('failure_reason') not in REASONS:
        raise ValueError('Infrastructure failures are not physical infeasibility')
    if cell.get('evidence') not in ({'measured', 'fixture'} if allow_fixture else {'measured'}):
        raise ValueError('Unobserved failure evidence')
    if any(k in cell for k in ('profile', 'prompt_blocks', 'resource_cost', 'cost')):
        raise ValueError('Do not fabricate profiles or costs for an unavailable configuration')
    if type(cell.get('executed_candidate_requests')) is not int or cell['executed_candidate_requests'] != 0:
        raise ValueError('Resource admission must precede candidate dispatch')
    if cell.get('clean_baseline_verified') is not True or cell.get('release_verified') is not True:
        raise ValueError('Unclean or unreleased failure cannot establish infeasibility')
    proof = cell.get('failure_evidence', {})
    if proof.get('reviewer_approved') is not True or not proof.get('review_reference'):
        raise ValueError('Failure diagnosis requires a source-bound review')
    required = {'run.json', 'completion.json', 'backend.log', 'schedule.jsonl', 'samples.jsonl',
                'gpu.jsonl', 'adjudication.json'}
    hashes = cell.get('original_artifacts_sha256', {})
    if set(hashes) != required or any(not re.fullmatch('[0-9a-f]{64}', str(v)) for v in hashes.values()):
        raise ValueError('Incomplete failure evidence hashes')
    if cell.get('run_manifest_sha256') != hashes['run.json']:
        raise ValueError('Failure identity differs from its raw run')
    parameters=cell.get('frozen_parameters')
    if (not isinstance(parameters,dict) or cell.get('frozen_parameters_sha256')!=canonical_hash(parameters)
        or parameters.get('generation_settings')!=cell.get('generation_settings')
        or any(parameters.get(k)!=cell.get(k) for k in ('config_id','action_id'))):
        raise ValueError('Failure frozen-parameter identity mismatch')
    interval = cell.get('allocation_accounting', {})
    if interval.get('scope') != 'single_gpu_attempt_including_startup_and_release':
        raise ValueError('Explicit failure allocation window required')
    try:
        start, end, duration = (F(str(interval[k])) for k in ('start_monotonic_s', 'end_monotonic_s', 'gpu_seconds'))
    except (KeyError, ValueError, ZeroDivisionError):
        raise ValueError('Invalid allocation window')
    if start < 0 or end <= start or duration != end-start:
        raise ValueError('Startup GPU time must remain in allocation accounting')
    if not isinstance(interval.get('slurm_job_id'), str) or not interval['slurm_job_id']:
        raise ValueError('Failure allocation identity required')
    return cell


def availability(measurements, *, allow_fixture=False):
    """Validate the whole nominal grid, retaining asymmetric failure records."""
    configs = measurements['configurations']
    if configs not in (['serial', 'batch16'], ['serial', 'batch16', 'batch64']):
        raise ValueError('Declared nominal configuration menu required')
    groups = {}; ids = set()
    for cell in measurements['cells']:
        config, action, rep = (cell[k] for k in ('config_id', 'action_id', 'replicate_id'))
        if config not in configs or action not in ACTIONS or type(rep) is not int or rep not in (0, 1, 2):
            raise ValueError('Unexpected nominal cell')
        group = groups.setdefault((config, action), {})
        if rep in group:
            raise ValueError('Duplicate replicate')
        group[rep] = cell
        if is_failure(cell) and cell.get('status')==ATTEMPT:
            params=cell.get('frozen_parameters',{})
            for key in ('stratum_id','workload_manifest_sha256','task_ids'):
                if key in measurements and params.get(key)!=measurements[key]:
                    raise ValueError('Failure is from a different frozen workload/stratum')
            if 'generation_settings' in measurements and cell.get('generation_settings')!=measurements['generation_settings']:
                raise ValueError('Failure generation parameters changed')
        identity = cell.get('run_manifest_sha256') if is_failure(cell) else cell['profile'].get('run_manifest_sha256', cell['profile']['profile_id'])
        if not identity or identity in ids:
            raise ValueError('Distinct source run / attempt identities required')
        ids.add(identity)
    expected = {(c, a) for c in configs for a in ACTIONS}
    if set(groups) != expected or any(set(g) != {0, 1, 2} for g in groups.values()):
        raise ValueError('Every nominal config/action needs all three attempts; do not drop failures')
    feasible = {a: [] for a in ACTIONS}; unavailable = []; paused = []; failures = []
    for config in configs:
        for action in ACTIONS:
            runs = [groups[config, action][r] for r in range(3)]
            failed = [is_failure(c) for c in runs]
            if not any(failed):
                if any(c['profile'].get('feasible') is not True for c in runs):
                    raise ValueError('Success requires explicit observed feasibility')
                feasible[action].append(config)
                continue
            failures.extend(c for c in runs if is_failure(c))
            if not all(failed):
                paused.append({'config_id': config, 'action_id': action, 'reason': 'mixed_success_failure'})
                continue
            try:
                for c in runs:
                    failure_record(c, allow_fixture=allow_fixture)
                signatures = {(c['failure_reason'], c['frozen_parameters_sha256']) for c in runs}
                if len(signatures) != 1:
                    raise ValueError('Resource failures disagree on diagnosis or frozen parameters')
            except (ValueError, KeyError) as exc:
                paused.append({'config_id': config, 'action_id': action, 'reason': str(exc)})
                continue
            unavailable.append({'config_id': config, 'action_id': action, 'status': FAILURE,
                                'attempts': runs})
    serial_missing = [a for a in ACTIONS if 'serial' not in feasible[a]]
    status = 'paused_review' if paused else 'no_result_serial_unavailable' if serial_missing else 'ready'
    return {'status': status, 'feasible_by_action': feasible, 'infeasible_cells': unavailable,
            'paused_cells': paused, 'serial_unavailable_actions': serial_missing,
            'failure_records': failures,
            'fixed_configurations': [c for c in configs if all(c in feasible[a] for a in ACTIONS)],
            'main_matrix_authorized': False}


def successful_cells(measurements):
    return [c for c in measurements['cells'] if not is_failure(c)]


def dispatch_summary(events, task_ids, *, k, pool_id, concurrency, max_num_seqs):
    """Observed *submission* batch sizes, never GPU-resident sequence counts."""
    if type(k) is not int or k < 1 or type(concurrency) is not int or concurrency < 1:
        raise ValueError('Invalid submission configuration')
    if type(pool_id) is not int or pool_id not in (0, 1):
        raise ValueError('Invalid pooling mode')
    if type(max_num_seqs) is not int or max_num_seqs < 1:
        raise ValueError('Configured engine sequence limit required')
    rows = [e for e in events if e.get('event') == 'dispatch']; seen = []; batch_ids = set()
    for row in rows:
        tasks = row['episodes']; batch = row['batch_id']
        if type(batch) is not int or batch in batch_ids or not tasks or len(tasks) > (1 if pool_id == 0 else concurrency):
            raise ValueError('Invalid dispatch batch')
        if row.get('submitted_batch_only') is not True or type(row.get('candidate_count')) is not int or row['candidate_count'] != len(tasks)*k:
            raise ValueError('Dispatch candidate count differs from observed episode count')
        batch_ids.add(batch); seen.extend(tasks)
    if not rows or seen != task_ids or len(set(seen)) != len(seen):
        raise ValueError('Dispatch must cover the entire frozen cohort once in order')
    return {'observed_concurrency': max(len(e['episodes']) for e in rows),
            'observed_candidate_batch_max': max(e['candidate_count'] for e in rows),
            'supported_concurrency_max': concurrency,
            'concurrency_scope': 'maximum_observed_episodes_per_submission',
            'engine_internal_concurrency': 'unobserved', 'configured_max_num_seqs': max_num_seqs,
            'dispatch_batches': len(rows)}
