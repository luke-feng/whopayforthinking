"""Paired prompt bootstrap conditional on observed seed-specific window costs.

No candidates or hardware are run here. Fractions preserve exact game ties;
undefined ratios and nonunique terminal correspondences are not dropped.
"""
from collections import Counter
from fractions import Fraction as F
from functools import lru_cache
from hashlib import sha256
from math import lcm
import platform
import random
import struct

import thinking_market as tm
from theory_effects import metrics
from lcb_feasibility import successful_cells


def percentile(values, probability):
    ordered = sorted(values); position = (len(ordered)-1)*probability
    lo = position.numerator//position.denominator; fraction = position-lo
    return ordered[lo]*(1-fraction)+ordered[min(lo+1, len(ordered)-1)]*fraction


def paired_percentiles(columns, statistic, *, draws=10000, seed=20261010):
    if type(draws) is not int or draws < 2 or not columns:
        raise ValueError('Nonempty paired columns and at least two bootstrap draws required')
    lengths = {len(v) for v in columns.values()}
    if len(lengths) != 1 or not next(iter(lengths)):
        raise ValueError('Every column must contain the same complete prompt blocks')
    n = next(iter(lengths)); keys = list(columns)
    # Deduplicate identical columns, not observations. Integer dot products avoid
    # floating-point perturbations of zero-profit and equal-welfare boundaries.
    unique = {}; references = []
    for key in keys:
        values = tuple(map(tm.number, columns[key]))
        if values not in unique: unique[values] = len(unique)
        references.append(unique[values])
    compiled = []
    for values in unique:
        denominator = lcm(*(v.denominator for v in values))
        compiled.append((values[0] if len(set(values)) == 1 else None,
                         [int(v*denominator) for v in values], denominator*n))
    @lru_cache(maxsize=32)
    def evaluate(values):
        return statistic({key: values[ref] for key, ref in zip(keys, references)})
    point = evaluate(tuple(sum(values, F(0))/n for values in unique))
    samples = {key: [] for key in point}; invalid = Counter(); digest = sha256()
    rng = random.Random(seed)
    for _ in range(draws):
        indices = [rng.randrange(n) for _ in range(n)]
        digest.update(struct.pack(f'<{n}I', *indices))
        counts = Counter(indices)
        means = tuple(constant if constant is not None else F(sum(values[i]*count for i,count in counts.items()), denominator)
                      for constant,values,denominator in compiled)
        result = evaluate(means)
        if result.keys() != point.keys(): raise ValueError('Statistic schema changed across draws')
        for key, value in result.items():
            if value is None: invalid[key] += 1
            else: samples[key].append(tm.number(value))
    return {'draws': draws, 'seed': seed, 'n_prompts': n, 'python_version': platform.python_version(),
        'resample_indices_sha256': digest.hexdigest(), 'resampling': 'one shared index vector across every column per draw',
        'metrics': {key: {'point': value, 'percentile_95': None if invalid[key] else
                    [percentile(samples[key], F(1,40)), percentile(samples[key], F(39,40))],
                    'defined_draws': len(samples[key]), 'undefined_draws': invalid[key],
                    'status': 'unidentified_in_resamples' if invalid[key] else 'percentile_pointwise'}
                    for key,value in point.items()},
        'nonunique_equilibrium_draws': {key: sum(v==0 for v in samples[key]) for key in samples if key.endswith('_unique')},
        'coverage': 'asymptotic under regularity and prompt-block sampling assumptions; no finite-sample or simultaneous guarantee'}


def infer_measurements(measurements, scenario, menus, *, allow_fixture=False, draws=None, rules=None):
    import theory_estimands as te
    rules = rules or te.json.loads(te.RULES.read_text())
    declared_draws = rules['quality']['bootstrap_draws']
    if draws is None: draws = declared_draws
    if not allow_fixture and draws != declared_draws:
        raise ValueError('Production inference uses the frozen 10000-draw design')
    if any(m['status'] != 'menu_estimated' for m in menus.values()):
        raise ValueError('Cost spread pause must be resolved before inference')
    cells = {(c['replicate_id'], c['action_id'], c['config_id']): c for c in successful_cells(measurements)}
    columns = {(rep, action, config, field): [tm.number(b[field]) for b in cell['prompt_blocks']]
               for (rep,action,config),cell in cells.items() for field in te.FIELDS}
    costs = {key: tm.number(tm.accounting(cell['profile'], scenario, 'share', 'A')[1]['resource_cost_usd_per_request'])
             for key,cell in cells.items()}
    alpha, outside = tm.number(scenario['alpha']), tm.number(scenario['outside_usd'])
    rent = tm.number(scenario['fixed_capacity_fee_total_usd'])/len(measurements['task_ids'])
    rates = [tm.number(scenario[k])/1000000 for k in ('input_usd_per_million','visible_usd_per_million','hidden_usd_per_million')]
    v, damage, ell = [tm.number(scenario[k]) for k in ('value_correct_usd','wrong_damage_usd','delay_usd_per_s')]
    base = tm.number(scenario['base_response_usd'])
    intercept = tm.number(scenario['all_candidates_intercept_usd']) if scenario['schema_version']=='thinking-scenario-v3' else base
    def statistic(means):
        out = {}
        for rep in range(3):
            for action in ('L','H'):
                for config in measurements['configurations'][1:]:
                    if (rep,action,config) not in cells:continue
                    for field in te.FIELDS:
                        out[f'{rep}/configuration/{config}/{action}/{field}'] = means[rep,action,config,field]-means[rep,action,'serial',field]
                    out[f'{rep}/configuration/{config}/{action}/H_all_non_delivered'] = sum(
                        means[rep,action,config,f]-means[rep,action,'serial',f] for f in ('reasoning_tokens_all','unselected_final_tokens'))
            for policy, menu in menus.items():
                for billing in ('D','A'):
                    z = {}
                    for pi in (0,1):
                        for action in ('L','H'):
                            config = 'serial' if pi==0 else menu['selected_by_action'][action]
                            x = {f: means[rep,action,config,f] for f in te.FIELDS}
                            h = x['reasoning_tokens_all'] + (x['unselected_final_tokens'] if scenario['hidden_billing']=='all_non_delivered' else 0)
                            bill = base if billing=='D' else intercept+sum(a*b for a,b in zip(rates,(x['billed_input_tokens'],x['delivered_output_tokens'],h)))
                            value = v*x['q_correct']-damage*x['q_wrong']-ell*x['mean_latency_s']
                            z[pi,action] = {'C': costs[rep,action,config], 'B': bill, 'V': value,
                                           'q_plus': x['q_correct'], 'q_minus': x['q_wrong'], 'tau': x['mean_latency_s']}
                    for key,value in metrics(z,alpha,rent,outside).items():
                        out[f'{rep}/{policy}/{billing}/{key}'] = value
                    for pi in (0,1):
                        dq = z[pi,'H']['q_plus']-z[pi,'L']['q_plus']
                        numerator = (damage*(z[pi,'H']['q_minus']-z[pi,'L']['q_minus'])+
                                     ell*(z[pi,'H']['tau']-z[pi,'L']['tau'])+z[pi,'H']['C']-z[pi,'L']['C'])
                        out[f'{rep}/{policy}/{billing}/v_W{pi}'] = numerator/dq if dq>0 else None
                    high,low=z[1,'H'],z[0,'L'];dq=high['q_plus']-low['q_plus']
                    numerator=damage*(high['q_minus']-low['q_minus'])+ell*(high['tau']-low['tau'])+high['C']-low['C']
                    out[f'{rep}/{policy}/{billing}/v_W_cross_pool'] = numerator/dq if dq>0 else None
        return out
    boot = paired_percentiles(columns, statistic, draws=draws, seed=rules['quality']['bootstrap_seed'])
    per_seed = {str(rep): {} for rep in range(3)}
    for name, value in boot.pop('metrics').items():
        rep, key = name.split('/', 1); per_seed[rep][key] = value
    ranges = {}
    for key in per_seed['0']:
        points = [per_seed[str(rep)][key]['point'] for rep in range(3)]
        intervals = [per_seed[str(rep)][key]['percentile_95'] for rep in range(3)]
        ranges[key] = {'point_range': None if None in points else [min(points), max(points)],
                       'interval_endpoint_range': None if any(x is None for x in intervals) else
                           [min(x[0] for x in intervals), max(x[1] for x in intervals)],
                       'scope': 'range of three separate seed reports, not a pooled confidence interval'}
    return te.serializable({**boot, 'replicates': per_seed, 'across_seed_ranges': ranges,
        'cost_scope': 'seed-specific observed whole-window costs held fixed; cost bootstrap intervals may be degenerate and are not cost evidence',
        'contract_scope': 'posted prices, D fee, rent L, preferences and reference normalization fixed before resampling',
        'selection_scope': 'same implementation selected from three-run mean costs in every resample; possible cost minimizers remain in secondary envelope analysis',
        'DID_scope': 'lower and upper equilibrium-set endpoints retained; nonunique draws are not assigned a favorable tie',
        'source_roster_sha256': sha256(te.json.dumps(measurements['task_ids'],separators=(',',':')).encode()).hexdigest()})
