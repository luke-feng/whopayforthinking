"""Pure native-mode cap state machine. No labels, inference or approval."""
POLICY = 'vendor-native-cap-v3'
STAGES = {12288: (16384, 1800), 24576: (32768, 3600)}
THINKING = ('q38-thinking', 'q35-thinking', 'nemotron-thinking')


def envelope(name, cap):
    values = {4096: (16384, 1800)} if name == 'coder-nonthinking' else STAGES
    if name not in (*THINKING, 'coder-nonthinking', 'q38-nonthinking') or type(cap) is not int or cap not in values:
        raise ValueError('Unknown native cap/context/deadline pair')
    return values[cap]


def select(name, observations):
    """Ordered (effort, cap, cuts) triples, already audited as 128 candidates."""
    if name not in (*THINKING, 'coder-nonthinking') or not observations or len(observations) > 4:
        raise ValueError('One bounded on-mode chain or the fixed Coder control required')
    expected = ('medium' if name == 'q38-thinking' else None, 4096 if name == 'coder-nonthinking' else 12288)
    history = []
    for index, (effort, cap, cuts) in enumerate(observations):
        if (effort, cap) != expected or type(cap) is not int or type(cuts) is not int or not 0 <= cuts <= 128:
            raise ValueError('Skipped, repeated, reordered or invalid native stage')
        context, deadline = envelope(name, cap)
        history.append({'reasoning_effort': effort, 'max_tokens': cap, 'max_model_len': context,
                        'generation_timeout_s': deadline, 'truncated': cuts, 'candidates': 128})
        passed = cuts <= 6
        final = name == 'coder-nonthinking' or passed or cap == 24576
        fallback = name == 'q38-thinking' and effort == 'medium' and cap == 24576 and cuts > 32
        if fallback:
            final = False
            expected = ('low', 12288)
        elif not final:
            expected = (effort, 24576)
        if final:
            if index != len(observations) - 1:
                raise ValueError('Extra stages after the stopping rule')
            return {'status': 'cap_recommended', 'max_tokens': cap, 'max_model_len': context,
                    'generation_timeout_s': deadline, 'recommended_effort': effort,
                    'threshold_met': passed, 'residual_truncation_report_required': not passed,
                    'observed_stages': history, 'next_stage': None}
        if index == len(observations) - 1:
            next_context, next_deadline = envelope(name, expected[1])
            return {'status': 'needs_low_restart' if fallback else 'needs_larger_cap_pilot',
                    'max_tokens': None, 'max_model_len': None, 'generation_timeout_s': None,
                    'recommended_effort': None, 'threshold_met': False,
                    'residual_truncation_report_required': False, 'observed_stages': history,
                    'next_stage': {'reasoning_effort': expected[0], 'max_tokens': expected[1],
                                   'max_model_len': next_context, 'generation_timeout_s': next_deadline}}
    raise AssertionError('Unreachable')
