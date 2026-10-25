"""Offline theory objects and P2 channel checks. No inference or judging.

Exact points and bootstrap use rational arithmetic. Hoeffding is secondary;
three-window cost ranges are declared envelopes, not statistical CIs.
"""
import argparse
from copy import deepcopy
from fractions import Fraction as F
import hashlib
import json
from pathlib import Path

import thinking_market as tm
from theory_effects import did_from_games
from box_certification import rational_hoeffding_band
from lcb_feasibility import availability,successful_cells
import lcb_native_generation as native

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT/'experiments/calibration/theory-alignment-rules-v1.json'
FIELDS = ('q_correct', 'q_wrong', 'mean_latency_s', 'billed_input_tokens',
          'delivered_output_tokens', 'reasoning_tokens_all', 'unselected_final_tokens')
RESOURCES = ('gpu_allocated_seconds_total', 'energy_kwh_total', 'verifier_cpu_seconds_total')


def serializable(x):
    if isinstance(x, F): return str(x)
    if isinstance(x, dict): return {k: serializable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)): return [serializable(v) for v in x]
    return x


def mean(values):
    return sum(values, F(0))/len(values)


def add(a, b):
    return None if a is None or b is None else [a[0]+b[0], a[1]+b[1]]


def subtract(a, b):
    return None if a is None or b is None else [a[0]-b[1], a[1]-b[0]]


def scale(a, x):
    return None if a is None else sorted([a[0]*x, a[1]*x])


def hull(bands):
    return None if any(b is None for b in bands) else [min(b[0] for b in bands), max(b[1] for b in bands)]


def ratio(n, d):
    if n is None or d is None:
        return {'bounds': None, 'status': 'missing_primitive_bounds'}
    if d[0] <= 0:
        return {'bounds': None, 'status': 'denominator_not_strictly_positive', 'denominator_bounds': d}
    return {'bounds': [min(x/y for x in n for y in d), max(x/y for x in n for y in d)],
            'status': 'conservative_outer_bounds'}


def cost_envelope(values):
    xs = list(map(tm.number, values))
    if len(xs) != 3 or any(x < 0 for x in xs):
        raise ValueError('Exactly three nonnegative replicate-window costs required')
    center = mean(xs)
    return {'point': center, 'bounds': [F(9, 10)*min(xs), F(11, 10)*max(xs)],
            'run_costs': xs, 'pause_review': max(xs)-min(xs) > center/10,
            'interpretation': 'declared_envelope_no_statistical_coverage'}


def band(values, support, rules):
    if support is None: return None
    b = rational_hoeffding_band(values, support, rules['quality']['global_coordinate_budget'],
                               rules['quality']['delta'])
    return [b['lower'], b['upper']]


def build_menu(measurements, scenario, rules=None, *, allow_fixture=False, fixed_configuration=None):
    """Three replicate cells per config/action -> four solver profiles.

    Each cell includes an existing v2 profile and complete per-prompt delivery
    moments. Deferred generation alone cannot supply this interface.
    """
    rules = rules or json.loads(RULES.read_text())
    if measurements.get('schema') != 'thinking-menu-measurements-v1' or measurements.get('resource_scope') != 'entire_fixed_cohort':
        raise ValueError('Complete fixed-cohort menu measurements required')
    tm.validate_scenario(scenario, allow_counterfactual_admission=True)
    roster = measurements['task_ids']; configs = measurements['configurations']
    if not roster or len(set(roster)) != len(roster) or configs not in (['serial', 'batch16'], ['serial', 'batch16', 'batch64']):
        raise ValueError('Unique full roster and prespecified configuration menu required')
    if fixed_configuration is not None and fixed_configuration not in configs[1:]:
        raise ValueError('Fixed robustness configuration must have been measured')
    feasible=availability(measurements,allow_fixture=allow_fixture)
    if feasible['status']!='ready':
        return {'status':feasible['status'],'feasibility':feasible,'solver_profiles':None,'main_matrix_authorized':False}
    if fixed_configuration is not None and fixed_configuration not in feasible['fixed_configurations']:
        return {'status':'fixed_configuration_unavailable','feasibility':feasible,'solver_profiles':None,'main_matrix_authorized':False}
    observed=successful_cells(measurements)
    if not allow_fixture:
        validate_cost_convention(scenario)
    measured = any(c['profile'].get('evidence') == 'measured' for c in observed)
    if measured:
        manifest_raw = (ROOT/'data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json').read_bytes()
        manifest = json.loads(manifest_raw)
        if (measurements.get('workload_manifest_sha256') != hashlib.sha256(manifest_raw).hexdigest()
            or roster != manifest['main_task_ids']):
            raise ValueError('Measured menu must use the complete frozen main roster and manifest bytes')
        settings = measurements.get('generation_settings', {})
        native.validate(settings)
        if (settings.get('reasoning_mode') not in ('none', 'think_tags') or
            not {'temperature', 'top_p', 'max_tokens', 'max_model_len'} <= set(settings)):
            raise ValueError('Explicit common generation settings required')
        allowed=({4096:16384} if settings['stratum_id']=='coder-nonthinking' else {12288:16384,24576:32768})
        if (type(settings['max_tokens']) is not int or settings['max_tokens'] not in allowed
            or settings['max_model_len'] != allowed[settings['max_tokens']] or settings['temperature'] is None or settings['top_p'] is None
            or isinstance(settings['temperature'], bool) or isinstance(settings['top_p'], bool)
            or not 0 < F(str(settings['top_p'])) <= 1 or F(str(settings['temperature'])) < 0):
            raise ValueError('Invalid common generation parameters')
        if any(c['profile'].get('evidence') != 'measured' or c.get('generation_settings') != settings
               or c['profile'].get('generation_settings') != settings
               or c['profile'].get('model_id') != settings['model_id']
               or c['profile'].get('model_revision') != settings['model_revision']
               for c in observed):
            raise ValueError('Do not mix generation settings, thinking modes or evidence within a stratum')
        shas = [c['profile'].get('run_manifest_sha256') for c in observed]
        if len(set(shas)) != len(shas):
            raise ValueError('Distinct source run manifests required, not duplicated windows')
    groups = {}; common = set(); profile_ids = set()
    for cell in observed:
        config, action, rep = cell['config_id'], cell['action_id'], cell['replicate_id']
        if config not in configs or action not in ('L', 'H') or type(rep) is not int or rep not in (0, 1, 2):
            raise ValueError('Unexpected measured cell')
        p = cell['profile']; declared = rules['configurations'][config]
        if (p['action_id'] != action or p['config_id'] != config or type(p['pool_id']) is not int
            or p['pool_id'] != declared['pool_id'] or p['k_cap'] != rules['actions'][action]):
            raise ValueError('Measured protocol does not implement the theory cell')
        if (not 1 <= p['observed_concurrency'] <= declared['concurrency'] or p['supported_concurrency_max'] < declared['concurrency']
            or p['cohort_size'] != len(roster) or p['feasible'] is not True):
            raise ValueError('Unmeasured/extrapolated configuration or incomplete cohort')
        if p['evidence'] != 'measured' and not (allow_fixture and p['evidence'] == 'fixture'):
            raise ValueError('Measured profiles required')
        if p['evidence'] == 'measured':
            tm.sha(p, 'run_manifest_sha256')
            if measurements.get('delivery_evidence') != 'online_observed':
                raise ValueError('Deferred replay cannot supply measured delivery latency')
        common.add(tuple(p[key] for key in tm.COMMON))
        if p['profile_id'] in profile_ids: raise ValueError('Duplicate run profile ID')
        profile_ids.add(p['profile_id'])
        blocks = cell['prompt_blocks']
        if [b['task_id'] for b in blocks] != roster: raise ValueError('Prompt blocks must preserve the complete frozen roster')
        for b in blocks:
            xs = {key: tm.nonnegative(b, key) for key in FIELDS}
            if xs['q_correct']+xs['q_wrong'] > 1: raise ValueError('Delivery labels overlap')
            if p['evidence'] == 'measured' and any(xs[key] not in (0, 1) for key in ('q_correct', 'q_wrong')):
                raise ValueError('One actual delivery indicator per prompt/replicate required')
        for key in FIELDS:
            if mean([tm.number(b[key]) for b in blocks]) != tm.number(p[key]):
                raise ValueError('Profile does not equal its prompt moments: '+key)
        for key in RESOURCES: tm.nonnegative(p, key)
        key = (action, config)
        if rep in groups.setdefault(key, {}): raise ValueError('Duplicate replicate window')
        groups[key][rep] = cell
    expected = {(action, config) for action in ('L', 'H') for config in feasible['feasible_by_action'][action]}
    if set(groups) != expected or len(common) != 1 or any(set(v) != {0, 1, 2} for v in groups.values()):
        raise ValueError('Complete paired three-window menu in one technical stratum required')
    summaries = {}; paused = []
    for (action, config), runs in groups.items():
        ordered = [runs[i] for i in range(3)]
        p = deepcopy(ordered[0]['profile'])
        for key in FIELDS+RESOURCES:
            p[key] = str(mean([tm.number(c['profile'][key]) for c in ordered]))
        p['profile_id'] = f"{measurements['stratum_id']}|{action}|{config}"
        p['run_manifest_sha256'] = hashlib.sha256(json.dumps(ordered, sort_keys=True).encode()).hexdigest()
        prompt_means = {key: [mean([tm.number(c['prompt_blocks'][i][key]) for c in ordered])
                            for i in range(len(roster))] for key in FIELDS}
        bounds = {}
        for key in FIELDS:
            support = [0, 1] if key in ('q_correct', 'q_wrong') else measurements.get('supports', {}).get(action, {}).get(key)
            bounds[key] = band(prompt_means[key], support, rules)
        costs = [tm.number(tm.accounting(c['profile'], scenario, 'share', 'A')[1]['resource_cost_usd_per_request']) for c in ordered]
        envelope = cost_envelope(costs); bounds['cost'] = envelope['bounds']
        if envelope['pause_review']: paused.append({'action': action, 'config_id': config, 'cost': envelope})
        summaries[action, config] = {'profile': p, 'bounds': bounds, 'prompt_means': prompt_means, 'cost': envelope}
    if paused:
        return {'status': 'paused_cost_spread', 'paused_cells': serializable(paused),
                'solver_profiles': None, 'main_matrix_authorized': False}
    selected = []; bounds_out = {}; menu_report = []
    selected_by_action = {}
    for action in ('L', 'H'):
        options=feasible['feasible_by_action'][action]
        base = summaries[action, 'serial']; candidates = [summaries[action, c] for c in options]; records = []
        for config in options[1:]:
            candidate = summaries[action, config]
            differences = [a-b for a, b in zip(candidate['prompt_means']['q_correct'], base['prompt_means']['q_correct'])]
            interval = band(differences, [-1, 1], rules)
            records.append({'config_id': config, 'paired_q_difference': mean(differences),
                'paired_q_difference_secondary_hoeffding_bounds': interval, 'included_without_quality_gate': True,
                'cost': candidate['cost']})
        if fixed_configuration is not None: candidates = [summaries[action, fixed_configuration]]
        chosen = min(candidates, key=lambda c: (c['cost']['point'], rules['cost_menu']['tie_priority'].index(c['profile']['config_id'])))
        selected_by_action[action] = chosen['profile']['config_id']
        min_hi = min(c['bounds']['cost'][1] for c in candidates)
        possible = [c for c in candidates if c['bounds']['cost'][0] <= min_hi]
        for pi, source in ((0, base), (1, chosen)):
            p = deepcopy(source['profile']); p['pool_id'] = pi; p['profile_id'] += f'|menu{pi}'
            p['feasibility_basis'] = 'precommitted cost-minimum or fixed implementation; measured quality retained'
            selected.append(p)
            if pi == 0: bounds_out[p['profile_id']] = source['bounds']
            else:
                b = {key: hull([c['bounds'][key] for c in possible]) for key in FIELDS}
                b['cost'] = [min(c['bounds']['cost'][0] for c in candidates), min_hi]
                bounds_out[p['profile_id']] = b
        menu_report.append({'action': action, 'selected_config_id': chosen['profile']['config_id'],
            'possible_minimizers_in_cost_envelope': [c['profile']['config_id'] for c in possible],
            'serial': base['cost'], 'batch_comparisons': records})
    artifact = {'schema_version': 'thinking-profile-v2', 'resource_scope': 'entire_fixed_cohort', 'profiles': selected}
    tm.validate_profiles(artifact, allow_fixture=allow_fixture)
    return {'status': 'menu_estimated', 'solver_profiles': artifact, 'primitive_bounds': bounds_out,
            'feasibility':feasible,
            'menu': serializable(menu_report), 'main_matrix_authorized': False,
            'selected_by_action': selected_by_action,
            'implementation_policy': fixed_configuration or 'minimum_cost',
            'quality_gate_applied': False,
            'uncertainty': 'secondary Hoeffding bounds plus declared cost envelope; primary bootstrap is reported separately'}


def validate_cost_convention(s):
    required = {'capacity': 'energy_exclusive_capital_and_hosting',
                'electricity': 'measured_kwh_separate', 'cpu': 'separate_nonoverlapping',
                'public_rental_rates': 'payment_L_only'}
    if s.get('resource_cost_convention') != required:
        raise ValueError('Explicit energy-exclusive resource costs required; public rent is payment L only')


def primitives(artifact, scenario, billing, bounds=None, allow_fixture=False):
    rows = tm.validate_profiles(artifact, allow_fixture=allow_fixture)
    actions = sorted({(p['k_cap'], p['action_id']) for p in rows})
    if len(actions) != 2: raise ValueError('P1/P2 estimands require two sampling actions')
    action_names = {'L': actions[0][1], 'H': actions[1][1]}
    result = {}
    for p in rows:
        if not p['feasible']: raise ValueError('Both actions must be physically profiled before applying P2')
        action = next(key for key, val in action_names.items() if val == p['action_id'])
        o, acc = tm.accounting(p, scenario, 'share', billing)
        h = tm.number(p['reasoning_tokens_all'])
        if scenario['hidden_billing'] == 'all_non_delivered': h += tm.number(p['unselected_final_tokens'])
        point = {'C': tm.number(acc['resource_cost_usd_per_request']), 'B': tm.number(acc['bill_usd_per_request']),
                 'V': tm.number(acc['value_net_outside_usd'])+tm.number(scenario['outside_usd']),
                 'H': h, 'q_plus': tm.number(p['q_correct']), 'q_minus': tm.number(p['q_wrong']),
                 'tau': tm.number(p['mean_latency_s'])}
        if bounds is None and p['evidence'] == 'fixture':
            bands = {k: [v, v] for k, v in point.items()}
        else:
            b = {}
            for key, pair in (bounds or {}).get(p['profile_id'], {}).items():
                if pair is None: b[key] = None; continue
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    raise ValueError('Two endpoints required for primitive bounds')
                b[key] = list(map(tm.number, pair))
                if b[key][0] > b[key][1]: raise ValueError('Empty primitive bounds')
            hidden = b.get('reasoning_tokens_all')
            if scenario['hidden_billing'] == 'all_non_delivered': hidden = add(hidden, b.get('unselected_final_tokens'))
            intercept = tm.number(scenario.get('all_candidates_intercept_usd', scenario['base_response_usd']))
            bill = [intercept, intercept]
            if billing == 'A':
                for field, rate in ((b.get('billed_input_tokens'), scenario['input_usd_per_million']),
                                    (b.get('delivered_output_tokens'), scenario['visible_usd_per_million']),
                                    (hidden, scenario['hidden_usd_per_million'])):
                    bill = add(bill, scale(field, tm.number(rate)/1000000)) if tm.number(rate) else bill
            else: bill = [tm.number(scenario['base_response_usd'])]*2
            value = scale(b.get('q_correct'), tm.number(scenario['value_correct_usd']))
            if tm.number(scenario['wrong_damage_usd']): value = subtract(value, scale(b.get('q_wrong'), tm.number(scenario['wrong_damage_usd'])))
            if tm.number(scenario['delay_usd_per_s']): value = subtract(value, scale(b.get('mean_latency_s'), tm.number(scenario['delay_usd_per_s'])))
            bands = {'C': b.get('cost'), 'B': bill, 'V': value, 'H': hidden,
                     'q_plus': b.get('q_correct'), 'q_minus': b.get('q_wrong'), 'tau': b.get('mean_latency_s')}
        result[p['pool_id'], action] = {'point': point, 'bounds': bands, 'profile': p}
    return result, action_names


def estimate_profiles(artifact, scenario, billing='A', bounds=None, *, allow_fixture=False):
    tm.validate_scenario(scenario, allow_counterfactual_admission=True)
    tm.validate_retail_reference(artifact['profiles'], scenario)
    z, _ = primitives(artifact, scenario, billing, bounds, allow_fixture)
    def diff(a, b, key):
        return {'point': z[a]['point'][key]-z[b]['point'][key], 'bounds': subtract(z[a]['bounds'][key], z[b]['bounds'][key])}
    d0 = diff((0, 'H'), (0, 'L'), 'C'); d1 = diff((1, 'H'), (1, 'L'), 'C')
    sl = diff((0, 'L'), (1, 'L'), 'C'); sh = diff((0, 'H'), (1, 'H'), 'C')
    alpha = {}; social = {}; overthinking = {}
    for pi in (0, 1):
        dc = d0 if pi == 0 else d1
        db = diff((pi, 'H'), (pi, 'L'), 'B'); dh = diff((pi, 'H'), (pi, 'L'), 'H')
        hidden_bill = tm.number(scenario['hidden_usd_per_million'])*dh['point']/1000000 if billing == 'A' else F(0)
        threshold = dc['point']/db['point'] if db['point'] > 0 else None
        alpha[str(pi)] = {'point': threshold, 'internal_to_unit_share_domain': threshold is not None and 0 < threshold < 1,
            'delta_B': db, 'delta_H': dh, 'hidden_only_form_applicable': db['point'] > 0 and hidden_bill == db['point'],
            'interval': ratio(dc['bounds'], db['bounds']),
            'scope': 'cloud marginal boundary; actual participation checked separately'}
        social[str(pi)] = social_boundary(z, (pi, 'H'), (pi, 'L'), scenario)
        bl, bh = z[pi, 'L']['point']['B'], z[pi, 'H']['point']['B']
        c_l, c_h = z[pi, 'L']['point']['C'], z[pi, 'H']['point']['C']
        u0 = tm.number(scenario['outside_usd'])
        participants = all(z[pi, k]['point']['V']-z[pi, k]['point']['B']-u0 > 0 for k in ('L', 'H'))
        social_low = z[pi, 'H']['point']['V']-z[pi, 'L']['point']['V'] < dc['point']
        lower = max(F(0), threshold, c_l/bl, c_h/bh) if threshold is not None and bh > bl > 0 else None
        nonempty = lower is not None and lower < 1 and participants and social_low
        overthinking[str(pi)] = {'open_alpha_interval': [lower, F(1)] if nonempty else None,
            'width': F(1)-lower if nonempty else F(0), 'user_strict_both': participants,
            'planner_prefers_low': social_low, 'scope': 'point cloud-share versus planner region with both share actions strictly participating; fixed-fee comparison checked in solver'}
    social['cross_pool_H_vs_L'] = social_boundary(z, (1, 'H'), (0, 'L'), scenario)
    c0l, c0h, c1h = (z[key]['point']['C'] for key in ((0, 'L'), (0, 'H'), (1, 'H')))
    bl, bh, b1h = z[0, 'L']['point']['B'], z[0, 'H']['point']['B'], z[1, 'H']['point']['B']
    stable_bill = all(z[0, k]['point']['B'] == z[1, k]['point']['B'] for k in ('L', 'H'))
    admission = {'applicable': min(bl, bh, b1h) > 0,
                 'status': 'positive_mode_specific_bills_required', 'open': True}
    if admission['applicable']:
        lower, upper = max(c0l/bl, c1h/b1h), min(c0h/bh, F(1))
        boundary_bands = [ratio(z[key]['bounds']['C'], z[key]['bounds']['B'])
                          for key in ((0, 'L'), (1, 'H'), (0, 'H'))]
        interval = None
        if all(x['bounds'] is not None for x in boundary_bands):
            a, b, c = [x['bounds'] for x in boundary_bands]
            interval = {'lower_boundary_bounds': [max(a[0], b[0]), max(a[1], b[1])],
                        'upper_boundary_bounds': [min(c[0], F(1)), min(c[1], F(1))],
                        'common_open_interval': [max(a[1], b[1]), min(c[0], F(1))]}
            interval['common_interval_nonempty'] = interval['common_open_interval'][0] < interval['common_open_interval'][1]
        admission.update(status='computed', point=[lower, upper], nonempty=lower < upper, bounds=interval,
                         scope='cloud admission only; model, user and welfare side conditions remain separate')
    gap = diff((1, 'H'), (0, 'L'), 'V')
    welfare = {'point': gap['point']-d1['point']+sl['point'],
               'bounds': subtract(gap['bounds'], subtract(z[1, 'H']['bounds']['C'], z[0, 'L']['bounds']['C']))}
    cost_part = {'point': d0['point']-d1['point'], 'bounds': subtract(d0['bounds'], d1['bounds'])}
    db0, db1 = diff((0, 'H'), (0, 'L'), 'B'), diff((1, 'H'), (1, 'L'), 'B')
    a = tm.number(scenario['alpha'])
    bill_part = {'point': a*(db1['point']-db0['point']), 'bounds': scale(subtract(db1['bounds'], db0['bounds']), a)}
    margin0, margin1 = a*db0['point']-d0['point'], a*db1['point']-d1['point']
    assert margin1-margin0 == cost_part['point']+bill_part['point']
    same_low = diff((1, 'L'), (0, 'L'), 'V')
    return serializable({'schema': 'thinking-theory-estimands-v2', 'billing': billing,
        'd0': d0, 'd1': d1, 's_L': sl, 's_H': sh, 's_H_minus_s_L':
        {'point': sh['point']-sl['point'], 'bounds': subtract(sh['bounds'], sl['bounds'])},
        'alpha_C': alpha, 'admission_interval': admission, 'v_W': social,
        'cloud_share_overthinking_region': overthinking,
        'cross_pool_welfare_change_H_vs_L': welfare, 'same_bill_across_pool': stable_bill,
        'cloud_marginal_decomposition': {'cost_component': cost_part, 'billing_component': bill_part,
            'margin0': margin0, 'margin1': margin1,
            'cost_only_switch': margin0 < 0 < margin0+cost_part['point'],
            'bill_only_switch': margin0 < 0 < margin0+bill_part['point'],
            'interval_scope': 'cost component uses the declared window-cost envelope, not a prompt-bootstrap CI'},
        'billing_shift_H': diff((1, 'H'), (0, 'H'), 'B'),
        'same_low_pooling_value_change': same_low,
        'same_low_pooling_welfare_change': {'point': same_low['point']+sl['point'], 'bounds': add(same_low['bounds'], sl['bounds'])},
        'DID_if_rent_LL_share_LH': {'point': z[1, 'H']['point']['V']-z[1, 'L']['point']['V']-d1['point'],
            'bounds': subtract(subtract(z[1, 'H']['bounds']['V'], z[1, 'L']['bounds']['V']), d1['bounds'])},
        'uncertainty_scope': 'outer bounds from prompt bands and declared cost envelopes; not a joint statistical confidence claim',
        'primitives': {f'{pi}{k}': {'point': x['point'], 'bounds': x['bounds']} for (pi, k), x in z.items()}})


def social_boundary(z, high, low, scenario):
    def delta(key):
        return z[high]['point'][key]-z[low]['point'][key], subtract(z[high]['bounds'][key], z[low]['bounds'][key])
    qp, iq = delta('q_plus'); qm, im = delta('q_minus'); dt, it = delta('tau'); dc, ic = delta('C')
    d, ell = tm.number(scenario['wrong_damage_usd']), tm.number(scenario['delay_usd_per_s'])
    n = d*qm+ell*dt+dc; ni = ic
    if d: ni = add(ni, scale(im, d))
    if ell: ni = add(ni, scale(it, ell))
    return {'point': n/qp if qp > 0 else None, 'interval': ratio(ni, iq),
            'delta_q_plus': qp, 'raw_welfare_difference': tm.number(scenario['value_correct_usd'])*qp-n,
            'status': 'positive_quality_denominator' if qp > 0 else 'use_raw_welfare_difference'}


def channel_conditions(artifact, scenario, controller, contract, billing, allow_fixture=False, estimands=None):
    z, _ = primitives(artifact, scenario, billing, allow_fixture=allow_fixture)
    estimands = estimands or estimate_profiles(artifact, scenario, billing, allow_fixture=allow_fixture)
    for (pi, k), row in z.items():
        row['point'] = {key: tm.number(value) for key, value in estimands['primitives'][f'{pi}{k}']['point'].items()}
    p = lambda pi, k, key: z[pi, k]['point'][key]
    c0l, c0h, c1l, c1h = [p(pi, k, 'C') for pi, k in ((0, 'L'), (0, 'H'), (1, 'L'), (1, 'H'))]
    bl, bh = p(0, 'L', 'B'), p(0, 'H', 'B'); alpha = tm.number(scenario['alpha'])
    d0, d1 = tm.number(estimands['d0']['point']), tm.number(estimands['d1']['point'])
    shared = {'nested_cost_L': c1l <= c0l, 'nested_cost_H': c1h <= c0h,
              'negative_structural_DID': tm.number(estimands['DID_if_rent_LL_share_LH']['point']) < 0}
    def leaf(pi, k, payment): return tm.accounting(z[pi, k]['profile'], scenario, payment, billing)[0]
    if controller == 'C' and contract == 'share':
        checks = {**shared, 'interior_alpha': 0 < alpha < 1,
            'positive_d0': d0 > 0, 'positive_d1': d1 > 0, 'cloud_before_L': alpha*(bh-bl) < d0,
            'cloud_after_H': alpha*(p(1, 'H', 'B')-p(1, 'L', 'B')) > d1,
            'strong_two_action_participation': all(min(leaf(pi, k, payment).model,
                leaf(pi, k, payment).cloud, leaf(pi, k, payment).consumer) > 0
                for pi in (0, 1) for k in ('L', 'H') for payment in ('rent', 'share'))}
        return 'P2(a)', checks
    if controller == 'M':
        l0, h0, l1, h1 = [leaf(pi, k, contract) for pi, k in ((0, 'L'), (0, 'H'), (1, 'L'), (1, 'H'))]
        checks = {**shared, 'model_strict_high_preference': h0.model > l0.model > 0 and h1.model > l1.model > 0,
            'cloud_before_accept_L': l0.cloud > 0, 'cloud_before_refuse_H': h0.cloud < 0,
            'cloud_after_accept_H': h1.cloud > 0,
            'user_strict_all': all(x.consumer > 0 for x in (l0, h0, l1, h1))}
        if contract == 'share': checks['interior_alpha'] = 0 < alpha < 1
        return 'P2(b)', checks
    return 'unexplained', {**shared, 'covered_controller_contract': False}


def contract_effect(artifact, s, controller, billing, regimes, estimate, allow_fixture=False):
    z, actions = primitives(artifact, s, billing, allow_fixture=allow_fixture)
    reverse = {value: key for key, value in actions.items()}
    result = {}
    for r in regimes:
        if r['controller'] != controller or r['billing'] != billing: continue
        result[r['contract'], r['pool_id']] = {tm.Outcome(o['profile'], reverse.get(o['action'], o['action']),
            *[tm.number(o[k]) for k in ('model', 'cloud', 'consumer', 'welfare')]) for o in r['outcomes']}
    effect = did_from_games(result)
    theorem, checks = channel_conditions(artifact, s, controller, 'share', billing, allow_fixture, estimate)
    u0 = tm.number(s['outside_usd'])
    user_changed = any((z[0,k]['point']['V']-z[0,k]['point']['B']-u0 > 0) !=
                       (z[1,k]['point']['V']-z[1,k]['point']['B']-u0 > 0) for k in ('L','H'))
    checks.update(rent_LL_share_LH=effect['rent_LL_share_LH'], actual_trades_strict=effect['actual_trades_strict'])
    if effect['rent_LL_share_LH']:
        assert effect['point'] == tm.number(estimate['DID_if_rent_LL_share_LH']['point'])
    decomposition = estimate['cloud_marginal_decomposition']
    cost = decomposition['cost_component'] if controller == 'C' else estimate['s_H']
    cost_bounds = cost['bounds']
    cost_supported = tm.number(cost['point']) > 0 and cost_bounds is not None and tm.number(cost_bounds[0]) > 0
    drift = (decomposition['bill_only_switch'] if controller == 'C' else
             tm.number(s['alpha'])*z[1,'H']['point']['B'] > z[0,'H']['point']['C'])
    participation = user_changed or not effect['actual_trades_strict']
    label = 'unexplained'
    if participation:
        label = 'participation_changed'
    elif all(checks.values()) and effect['range'][1] < 0:
        if cost_supported: label = 'cost_driven_P2a' if controller == 'C' else 'P2(b)'
        elif tm.number(cost['point']) <= 0 and drift: label = 'billing_drift'
    elif (effect['point'] == 0 and (effect['rent_LL_share_LH'] or effect['common_terminal_action'])
          and (effect['absolute_share_change'][0] != 0 or effect['absolute_rent_change'][0] != 0)):
        label = 'same_action_pooling_value'
    return serializable({**effect, 'channel': label, 'theorem_channel': theorem,
        'failed_conditions': [k for k,v in checks.items() if not v],
        'cost_component_positive_over_declared_envelope': cost_supported,
        'cost_evidence_scope': 'known mathematical values' if all(p['evidence']=='fixture' for p in artifact['profiles'])
                               else 'conditional on declared three-window cost envelope, not a statistical cost CI',
        'user_participation_changed': user_changed,
        'same_low_pooling_value_change': estimate['same_low_pooling_value_change'],
        'same_low_pooling_welfare_change': estimate['same_low_pooling_welfare_change'],
        'absolute_drop_also_holds': effect['absolute_share_change'][1] < 0,
        'supports_cost_mechanism': label in ('cost_driven_P2a', 'P2(b)')})


def secondary_mode_box(estimate, s, controller, cohort_size):
    """Fixed-scenario margins are affine; evaluate their worst box corners.

    Shared raw-coordinate constraints only shrink this outer box. Missing bounds
    cannot certify anything. Cost envelopes have no sampling coverage guarantee.
    """
    rows = estimate['primitives']; alpha = tm.number(s['alpha'])
    rent = tm.number(s['fixed_capacity_fee_total_usd'])/cohort_size; u0 = tm.number(s['outside_usd'])
    def b(pi, k, field):
        row = rows[f'{pi}{k}']; pair = row['bounds'][field]
        if pair is None: return None
        pair = list(map(tm.number, pair))
        if not pair[0] <= tm.number(row['point'][field]) <= pair[1]:
            raise ValueError('Point witness outside declared primitive box')
        return pair
    def constant(x): return [x,x]
    c0l,c0h,c1l,c1h = [b(pi,k,'C') for pi,k in ((0,'L'),(0,'H'),(1,'L'),(1,'H'))]
    d0,d1 = subtract(c0h,c0l), subtract(c1h,c1l)
    strict = {'alpha_positive': constant(alpha), 'alpha_below_one': constant(1-alpha),
        'negative_DID': subtract(d1, subtract(b(1,'H','V'), b(1,'L','V')))}
    weak = {'pool_saving_L': subtract(c0l,c1l), 'pool_saving_H': subtract(c0h,c1h)}
    for pi in (0,1):
        for k in ('L','H'):
            bill,cost,value = b(pi,k,'B'),b(pi,k,'C'),b(pi,k,'V')
            strict[f'user_{pi}_{k}'] = subtract(subtract(value,bill),constant(u0))
            strict[f'model_share_{pi}_{k}'] = scale(bill,1-alpha)
        if controller == 'M':
            strict[f'model_high_ranking_{pi}'] = scale(subtract(b(pi,'H','B'),b(pi,'L','B')),1-alpha)
    if controller == 'C':
        strict.update(positive_d0=d0, positive_d1=d1, cost_component_positive=subtract(d0,d1),
            cloud_before_low=subtract(d0,scale(subtract(b(0,'H','B'),b(0,'L','B')),alpha)),
            cloud_after_high=subtract(scale(subtract(b(1,'H','B'),b(1,'L','B')),alpha),d1))
        for pi in (0,1):
            for k in ('L','H'):
                strict[f'cloud_share_{pi}_{k}'] = subtract(scale(b(pi,k,'B'),alpha),b(pi,k,'C'))
                strict[f'cloud_rent_{pi}_{k}'] = subtract(constant(rent),b(pi,k,'C'))
                strict[f'model_rent_{pi}_{k}'] = subtract(b(pi,k,'B'),constant(rent))
    else:
        strict.update(cost_saving_H_positive=subtract(c0h,c1h),
            cloud_before_low=subtract(scale(b(0,'L','B'),alpha),c0l),
            cloud_before_high_refusal=subtract(c0h,scale(b(0,'H','B'),alpha)),
            cloud_after_high=subtract(scale(b(1,'H','B'),alpha),c1h))
        for pi in (0,1):
            strict[f'rent_accept_L_{pi}'] = subtract(constant(rent),b(pi,'L','C'))
            strict[f'rent_refuse_H_{pi}'] = subtract(b(pi,'H','C'),constant(rent))
            strict[f'model_rent_L_{pi}'] = subtract(b(pi,'L','B'),constant(rent))
    passed = all(v is not None and v[0] > 0 for v in strict.values()) and all(v is not None and v[0]>=0 for v in weak.values())
    return serializable({'status':'certified' if passed else 'not_certified',
        'method':'fixed_alpha_affine_box_corner_bounds',
        'scope':'secondary outer box; conditional on prompt bounds, declared cost envelope and economic scenario',
        'strict_lower_bounds':{k:None if v is None else v[0] for k,v in strict.items()},
        'weak_lower_bounds':{k:None if v is None else v[0] for k,v in weak.items()}})


def scan_aligned(artifact, scenarios, *, allow_fixture=False, bounds=None):
    """List every decrease for pooling, rent->share and D->A comparisons."""
    if not allow_fixture:
        for s in scenarios: validate_cost_convention(s)
    estimates = {s['scenario_id']: {billing: estimate_profiles(artifact, s, billing, bounds, allow_fixture=allow_fixture)
                 for billing in ('D', 'A')} for s in scenarios}
    scan = tm.scan(artifact, scenarios, allow_fixture=allow_fixture, allow_counterfactual_admission=True)
    annotated = {}; unexplained = []
    for s in scenarios:
        result = scan['results'][s['scenario_id']]; regimes = result['regimes']; reversals = []
        effects = {f'{controller}|{billing}': contract_effect(artifact, s, controller, billing, regimes,
                    estimates[s['scenario_id']][billing], allow_fixture)
                   for controller in ('M','C') for billing in ('D','A')}
        secondary = {f'{controller}|{billing}': secondary_mode_box(estimates[s['scenario_id']][billing],s,controller,
                     artifact['profiles'][0]['cohort_size']) for controller in ('M','C') for billing in ('D','A')}
        _, actions = primitives(artifact, s, 'A', allow_fixture=allow_fixture)
        pairs = []
        for before in regimes:
            for axis, source, target, name in (('pool_id', 0, 1, 'pool0_to_pool1'),
                    ('contract', 'rent', 'share', 'rent_to_share'), ('billing', 'D', 'A', 'D_to_A')):
                if before[axis] != source: continue
                after = next(r for r in regimes if r[axis] == target and all(r[k] == before[k]
                    for k in ('pool_id', 'controller', 'contract', 'billing') if k != axis))
                pairs.append((before, after, name))
        for before, after, comparison in pairs:
            effect = effects[f"{before['controller']}|{before['billing']}"]
            strict_jump = (len(before['outcomes']) == len(after['outcomes']) == 1 and
                           before['outcomes'][0]['action'] == actions['L'] and after['outcomes'][0]['action'] == actions['H'])
            for old in before['outcomes']:
                for new in after['outcomes']:
                    change = tm.number(new['welfare'])-tm.number(old['welfare'])
                    if change >= 0: continue
                    same_action = old['action'] == new['action'] and old['action'] != 'outside'
                    label = effect['channel']
                    if effect['channel'] == 'participation_changed': pass
                    elif same_action and comparison == 'pool0_to_pool1': label = 'same_action_pooling_value'
                    elif comparison == 'D_to_A': label = 'unexplained'
                    elif not strict_jump and label in ('cost_driven_P2a','P2(b)'): label = 'unexplained'
                    record = {'comparison': comparison, **{k: before[k] for k in ('controller', 'contract', 'billing')},
                        'before_regime': {k: before[k] for k in ('controller','contract','billing','pool_id')},
                        'after_regime': {k: after[k] for k in ('controller','contract','billing','pool_id')},
                        'before': old, 'after': new, 'welfare_change': str(change),
                        'channel': label, 'DID_range': effect['range'],
                        'failed_conditions': effect['failed_conditions']+([] if strict_jump else ['unique_L_to_H']),
                        'same_action_value_change': same_action,
                        'classification_scope': 'conditional mechanism label with actual equilibrium DID; not finite-sample statistical certification'}
                    reversals.append(record)
                    if record['channel'] == 'unexplained': unexplained.append({'scenario_id': s['scenario_id'], **record})
        annotated[s['scenario_id']] = {'estimands': estimates[s['scenario_id']], 'contract_pooling_effects': effects,
                                       'secondary_box_certification': secondary, 'reversals': reversals}
    return {'schema': 'thinking-theory-aligned-results-v2', 'solver': scan, 'scenarios': annotated,
            'unexplained_reversals': unexplained, 'main_matrix_authorized': False,
            'primary_summary': 'contract-by-pooling DID and mode-specific theory boundaries'}


def analyse_measurements(measurements, scenario, *, allow_fixture=False, bootstrap_draws=None):
    from theory_bootstrap import infer_measurements
    menus = {policy: build_menu(measurements, scenario, allow_fixture=allow_fixture,
                              fixed_configuration=None if policy=='minimum_cost' else policy)
             for policy in ['minimum_cost']+measurements['configurations'][1:]}
    unavailable={p:m for p,m in menus.items() if m['status']=='fixed_configuration_unavailable'}
    menus={p:m for p,m in menus.items() if p not in unavailable}
    if any(m['status'] != 'menu_estimated' for m in menus.values()):
        return {'status':next(m['status'] for m in menus.values() if m['status']!='menu_estimated'),
                'menus':menus,'unavailable_fixed_implementations':unavailable,'primary_bootstrap':None}
    results = {policy: {'menu': menu, 'analysis': scan_aligned(menu['solver_profiles'], [scenario],
                bounds=menu['primitive_bounds'], allow_fixture=allow_fixture)} for policy,menu in menus.items()}
    # Fees were posted using the original point reference. They must not be
    # re-anchored on each generation seed or on each bootstrap realization.
    seed_scenario = deepcopy(scenario)
    if seed_scenario.get('retail_intercept_rule') == 'equal_at_reference':
        seed_scenario.update(retail_intercept_rule='independent_nonnegative',
            frozen_reference_profile_id=seed_scenario.pop('reference_profile_id'),
            reference_scope='original point reference; all posted monetary terms unchanged')
    for policy, menu in menus.items():
        results[policy]['replicate_point_analyses'] = {}
        for rep in range(3):
            profiles, seed_bounds = replicate_profiles(measurements, scenario, menu, rep)
            results[policy]['replicate_point_analyses'][str(rep)] = scan_aligned(profiles, [seed_scenario],
                bounds=seed_bounds, allow_fixture=allow_fixture)
    inference = infer_measurements(measurements, scenario, menus, allow_fixture=allow_fixture, draws=bootstrap_draws)
    return {'status':'analysed','implementations':results,'primary_bootstrap':inference,
            'unavailable_fixed_implementations':unavailable,
            'main_matrix_authorized':False}


def replicate_profiles(measurements, scenario, menu, rep):
    rules = json.loads(RULES.read_text())
    cells = {(c['replicate_id'],c['action_id'],c['config_id']): c for c in successful_cells(measurements)}
    profiles, bounds = [], {}
    for pi in (0,1):
        for action in ('L','H'):
            config = 'serial' if pi==0 else menu['selected_by_action'][action]
            cell = cells[rep,action,config]; p = deepcopy(cell['profile'])
            p['pool_id'] = pi; p['profile_id'] += f'|menu{pi}|replicate{rep}'
            b = {}
            for field in FIELDS:
                support = [0,1] if field in ('q_correct','q_wrong') else measurements.get('supports',{}).get(action,{}).get(field)
                b[field] = band([tm.number(x[field]) for x in cell['prompt_blocks']],support,rules)
            costs = [tm.accounting(cells[r,action,config]['profile'],scenario,'share','A')[1]['resource_cost_usd_per_request'] for r in range(3)]
            b['cost'] = cost_envelope(costs)['bounds']
            profiles.append(p); bounds[p['profile_id']] = b
    return {'schema_version':'thinking-profile-v2','resource_scope':'entire_fixed_cohort','profiles':profiles}, bounds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profiles', required=True); parser.add_argument('--scenarios', required=True)
    parser.add_argument('--output', required=True); args = parser.parse_args()
    source = Path(args.profiles).read_bytes(); scenarios = json.loads(Path(args.scenarios).read_text())
    artifact = json.loads(source); results = []
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError('Nonempty reviewed scenario list required')
    for s in scenarios:
        if artifact.get('schema') == 'thinking-menu-measurements-v1':
            result = analyse_measurements(artifact, s)
        else:
            result = scan_aligned(artifact, [s])
            result['primary_bootstrap_status'] = 'unavailable_without_paired_prompt_blocks'
        results.append(result)
    output = {'source_sha256': hashlib.sha256(source).hexdigest(), 'results': results,
              'inference_calls': 0, 'candidate_execution': False}
    with Path(args.output).open('x') as stream:
        json.dump(serializable(output), stream, indent=2, allow_nan=False)


if __name__ == '__main__': main()
