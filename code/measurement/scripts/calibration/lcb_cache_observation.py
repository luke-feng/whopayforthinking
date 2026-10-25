"""Pinned-log observations, not a claim of warm steady-state performance."""
import re


def observe_cache(log_text, cache_dir):
    compile_times = [float(x) for x in re.findall(r'torch\.compile took ([0-9.]+) s', log_text)]
    hits = len(re.findall(r'Directly load AOT compilation from path', log_text))
    jit = len(re.findall(r'Triton kernel JIT compilation during inference:', log_text))
    return {'schema': 'lcb-cache-observation-v1', 'persistent_cache_dir': cache_dir,
            'torch_compile_seconds_observed': compile_times or None,
            'aot_cache_hit_observed': True if hits else None, 'aot_cache_hit_log_count': hits,
            'inference_jit_warning_count': jit,
            'steady_state_verified': False,
            'scope': 'Log observations only. Absent hit message is unknown, not a cache miss. '
                     'Directory persistence/low compile time/no warning alone does not prove all inference paths warm. '
                     'Do not subtract guessed JIT time from observed generation windows.'}


def summarize_trial_cache(observations):
    """Describe three acceptance trials; never apply a scientific pause/pass gate."""
    if len(observations) != 3:
        raise ValueError('Three cache observations required')
    counts = [x['inference_jit_warning_count'] for x in observations]
    deltas = [b-a for a,b in zip(counts, counts[1:])]
    return {'schema': 'lcb-acceptance-cache-summary-v1',
            'torch_compile_seconds_by_trial': [x['torch_compile_seconds_observed'] for x in observations],
            'compile_over_one_second_by_trial': [None if x['torch_compile_seconds_observed'] is None
                else any(t > 1.0 for t in x['torch_compile_seconds_observed']) for x in observations],
            'aot_cache_hit_observed_by_trial': [x['aot_cache_hit_observed'] for x in observations],
            'aot_cache_hit_log_counts': [x['aot_cache_hit_log_count'] for x in observations],
            'inference_jit_warning_counts': counts, 'adjacent_warning_count_changes': deltas,
            'warnings_nonincreasing': all(d <= 0 for d in deltas),
            'warnings_strictly_decreasing': all(d < 0 for d in deltas),
            'warnings_any_decrease': any(d < 0 for d in deltas),
            'steady_state_verified': False, 'affects_acceptance': False,
            'scope': 'Whole trial-log observations, not proof of cache hits, path coverage or causality. '
                     'Acceptance runs are not measurement cells; no 10-percent scientific pause test here.'}
