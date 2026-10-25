"""Enumerate theory-serving measurement cells only, never schedule experiments."""
from itertools import product
import re


def enumerate_cells(panel, include_secondary=True):
    if panel.get('schema') != 'www-model-panel-theory-aligned-v2':
        raise ValueError('Theory-aligned v2 panel required')
    if panel.get('k') != [1, 8] or panel.get('replicate_ids') != [0, 1, 2]:
        raise ValueError('Frozen L/H and replicate axes required')
    configs = panel['configurations']
    if configs != {'serial': {'pool_id': 0, 'concurrency': 1},
                   'batch16': {'pool_id': 1, 'concurrency': 16},
                   'batch64': {'pool_id': 1, 'concurrency': 64}}:
        raise ValueError('Three distinct episode submission protocols required')
    strata = panel['strata']; ids = set(); cells = []
    if len(strata) != 5:
        raise ValueError('Four models plus the Qwen3.8 thinking-off control required')
    for s in strata:
        if s['stratum_id'] in ids or not re.fullmatch('[0-9a-f]{40}', s['revision']):
            raise ValueError('Unique pinned stratum required')
        ids.add(s['stratum_id'])
        if s['reasoning_mode'] not in ('none', 'think_tags') or not s.get('role'):
            raise ValueError('Every stratum needs a thinking protocol and theoretical role')
        expected_mode = 'none' if s['stratum_id'] in ('coder-nonthinking', 'q38-nonthinking') else 'think_tags'
        if s['reasoning_mode'] != expected_mode:
            raise ValueError('Modern main strata must enable thinking')
        for axis in ('hardware', 'configurations'):
            if not s[axis] or len(set(s[axis])) != len(s[axis]):
                raise ValueError('Nonempty unique axes required')
        if s['configurations'][0] != 'serial' or set(s['configurations']) - set(configs):
            raise ValueError('Every menu must contain serial')
        for hardware, config, k, rep in product(s['hardware'], s['configurations'], panel['k'], panel['replicate_ids']):
            if not include_secondary and hardware == 'A100-80GB-conditional':
                continue
            cells.append({'cell_id': f"{s['stratum_id']}|{hardware}|{config}|k{k}|r{rep}",
                'stratum_id': s['stratum_id'], 'model_id': s['model_id'], 'revision': s['revision'],
                'hardware': hardware, 'reasoning_mode': s['reasoning_mode'], 'config_id': config,
                'k': k, 'replicate_id': rep, **configs[config], 'theory_role': s['role'],
                'estimands': ['q_plus', 'q_minus', 'H', 'tau', 'C0' if config == 'serial' else 'C1_menu'],
                'execution_authorized': False})
    on = next(s for s in strata if s['stratum_id'] == 'q38-thinking')
    off = next(s for s in strata if s['stratum_id'] == 'q38-nonthinking')
    if (on['model_id'], on['revision']) != (off['model_id'], off['revision']) or off['reasoning_mode'] != 'none':
        raise ValueError('Thinking-off contrast must use the same weights')
    if include_secondary and (len(cells) != panel['nominal_cells'] or sum(c['k'] for c in cells) != panel['candidate_generations_per_main_task']):
        raise ValueError('Declared panel budget differs from enumeration')
    if include_secondary:
        prototypes = {(c['stratum_id'], c['hardware'], c['config_id'], c['k']) for c in cells}
        family = panel['statistical_family']
        dimensions = len(prototypes)*family['raw_prompt_coordinates_per_config_action'] + sum(
            config != 'serial' for _, _, config, _ in prototypes)*family['paired_quality_coordinates_per_batch_action']
        if dimensions != family['global_coordinate_budget']:
            raise ValueError('Simultaneous coordinate family differs from panel')
    return cells


def select_modern_cap(pilots, prompt_lengths):
    """Metadata from owner-run k8 pilots; never generate more samples here."""
    if not prompt_lengths or any(type(n) is not int or n < 1 for n in prompt_lengths):
        raise ValueError('All tokenized prompt lengths required')
    rates = {}; reference = None; chosen = None
    for cap in (8192, 12288):
        if cap not in pilots:
            if chosen is not None: break
            raise ValueError('Missing required pilot cap')
        rows = pilots[cap]
        identities = [(r['task_id'], r['candidate_id'], r['seed']) for r in rows]
        if (len(rows) != 128 or len(set(identities)) != 128 or
            len({r['task_id'] for r in rows}) != 16 or
            any(sorted(r['candidate_id'] for r in rows if r['task_id'] == t) != list(range(8))
                for t in {r['task_id'] for r in rows})):
            raise ValueError('Complete 16-task k8 pilot required')
        if reference is not None and identities != reference:
            raise ValueError('Caps must retain paired task/candidate seeds and order')
        reference = identities
        if any(type(r.get('truncated')) is not bool or type(r.get('output_tokens')) is not int
               or not 0 <= r['output_tokens'] <= cap for r in rows):
            raise ValueError('Actual cap-bounded token counts and truncation flags required')
        truncated = sum(r['truncated'] for r in rows)
        rates[cap] = {'truncated': truncated, 'candidates': 128, 'rate': f'{truncated}/128'}
        if truncated*20 <= 128:
            chosen = cap; break
    chosen = chosen or 12288
    if max(prompt_lengths)+chosen > 16384:
        raise ValueError('Frozen prompt plus selected total-output cap exceeds context; return to review')
    return {'max_tokens': chosen, 'observed_truncation': rates,
            'threshold_met': rates[chosen]['truncated']*20 <= 128,
            'same_cap_required_for_thinking_off': True, 'execution_authorized': False}
