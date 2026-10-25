"""Three-stage, pre-main-data admission rule; no inference or authorization."""
POLICY = 'thinking-cap-three-stage-v2'
STAGES = {8192: 16384, 12288: 16384, 24576: 32768}


def generation_timeout(cap):
    return 3600 if cap == 24576 else 1800


def envelope(name, cap):
    allowed = {4096: 16384} if name == 'coder-nonthinking' else STAGES
    if type(cap) is not int or cap not in allowed:
        raise ValueError('Unknown frozen cap/context pair')
    return allowed[cap]


def select(pilots, prompt_lengths):
    if not prompt_lengths or any(type(n) is not int or n < 1 for n in prompt_lengths):
        raise ValueError('All native prompt lengths required')
    if not pilots or any(type(c) is not int or c not in STAGES for c in pilots):
        raise ValueError('Only the three preregistered stages are allowed')
    rates = {}; reference = None
    for cap, context in STAGES.items():
        if cap not in pilots:
            raise ValueError('Missing prerequisite stage')
        if max(prompt_lengths) + cap > context:
            raise ValueError('Full workload does not fit this observed stage')
        rows = pilots[cap]
        ids = [(r['task_id'], r['candidate_id'], r['seed']) for r in rows]
        tasks = {r['task_id'] for r in rows}
        if (len(rows) != 128 or len(set(ids)) != 128 or len(tasks) != 16
                or any(type(r['candidate_id']) is not int or type(r['seed']) is not int for r in rows)
                or any(sorted(r['candidate_id'] for r in rows if r['task_id'] == t) != list(range(8)) for t in tasks)):
            raise ValueError('Full 16 by 8 stage required')
        if reference is not None and ids != reference:
            raise ValueError('Stages must use paired task/candidate seeds and order')
        reference = ids
        if any(type(r.get('truncated')) is not bool or type(r.get('output_tokens')) is not int
               or not 0 <= r['output_tokens'] <= cap for r in rows):
            raise ValueError('Actual cap-bounded completions required')
        cut = sum(r['truncated'] for r in rows)
        rates[cap] = {'truncated': cut, 'candidates': 128, 'rate': f'{cut}/128'}
        passed = cut <= 6
        final = cap == 24576
        if passed or final:
            if set(pilots) != set(rates):
                raise ValueError('Extra stages after the stopping rule are not selectable')
            return {'status': 'cap_recommended', 'max_tokens': cap, 'max_model_len': context,
                    'observed_truncation': rates, 'threshold_met': passed,
                    'terminal_stage': final, 'residual_truncation_report_required': not passed,
                    'next_max_tokens': None, 'next_max_model_len': None}
        next_cap = next(c for c in STAGES if c > cap)
        if next_cap not in pilots:
            if set(pilots) != set(rates):
                raise ValueError('Skipped middle stage')
            return {'status': 'needs_larger_cap_pilot', 'max_tokens': None, 'max_model_len': None,
                    'observed_truncation': rates, 'threshold_met': False, 'terminal_stage': False,
                    'residual_truncation_report_required': False,
                    'next_max_tokens': next_cap, 'next_max_model_len': STAGES[next_cap]}
    raise AssertionError('Unreachable cap state')
