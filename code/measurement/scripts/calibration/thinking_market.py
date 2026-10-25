"""Exact prescribed-contract game, schema thinking-profile-v2.

One fixed model/cloud/cohort per artifact. Controller chooses the sampling
action; the other firm can refuse before activation; the user then participates.
Costs and transfers occur only on activation. All pure terminal ties are kept.
Measured technology does not make computed strategic behavior an observation.
"""
from dataclasses import dataclass
from fractions import Fraction as F
from itertools import product
import re


def number(value):
    # Decimal measurements must be serialized as strings, never binary floats.
    if isinstance(value, bool) or not isinstance(value, (str, int, F)):
        raise ValueError('Expected an integer or exact rational/decimal string')
    try:
        return F(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError('Invalid finite rational') from exc


def nonnegative(obj, key):
    val = number(obj[key])
    if val < 0:
        raise ValueError('Negative '+key)
    return val


def identifier(obj, key):
    val = obj.get(key)
    if not isinstance(val, str) or not val or val.startswith(('TEMPLATE', 'OWNER_', 'MISSING')):
        raise ValueError('Missing identity '+key)
    return val


def sha(obj, key):
    if not isinstance(obj.get(key), str) or not re.fullmatch('[0-9a-f]{64}', obj[key]):
        raise ValueError('Invalid provenance SHA '+key)


COMMON = ('menu_id', 'model_id', 'model_revision', 'cloud_id', 'hardware_id',
          'task_mix_id', 'policy', 'cache_mode', 'arrival_pattern_id')
METERS = ('mean_latency_s', 'billed_input_tokens', 'delivered_output_tokens',
          'reasoning_tokens_all', 'unselected_final_tokens',
          'gpu_allocated_seconds_total', 'energy_kwh_total', 'verifier_cpu_seconds_total')


def validate_profiles(artifact, allow_fixture=False, allow_composed=False):
    if not isinstance(artifact, dict) or artifact.get('schema_version') != 'thinking-profile-v2':
        raise ValueError('Explicit thinking-profile-v2 artifact required')
    rows = artifact.get('profiles')
    if not isinstance(rows, list) or not rows:
        raise ValueError('No profiles; cannot produce an empirical report')
    if artifact.get('resource_scope') != 'entire_fixed_cohort':
        raise ValueError('Pool costs must cover the entire fixed cohort')
    common, sizes, cells, ids, actions = set(), set(), set(), set(), {}
    for p in rows:
        if not isinstance(p, dict):
            raise ValueError('Each profile must be an object')
        for key in COMMON + ('profile_id', 'action_id', 'config_id', 'feasibility_basis'):
            identifier(p, key)
        allowed = {'measured'} | ({'fixture'} if allow_fixture else set())
        if allow_composed:
            allowed.add('calibrated_composition')
        if p.get('evidence') not in allowed:
            raise ValueError('Profile provenance is not authorized')
        if p['evidence'] != 'fixture':
            sha(p, 'run_manifest_sha256')
        if p['evidence'] == 'calibrated_composition' and not p.get('composition_assumptions'):
            raise ValueError('Composition assumptions required')
        if type(p.get('pool_id')) is not int or p['pool_id'] not in (0, 1):
            raise ValueError('Pool id must be integer 0 or 1')
        for key in ('cohort_size', 'k_cap', 'observed_concurrency', 'supported_concurrency_max'):
            if type(p.get(key)) is not int or p[key] < 1:
                raise ValueError('Positive integer required for '+key)
        if p['observed_concurrency'] > p['supported_concurrency_max']:
            raise ValueError('Concurrency extrapolation refused')
        if type(p.get('feasible')) is not bool:
            raise ValueError('Explicit feasibility label required')
        cell = (p['pool_id'], p['action_id'])
        if cell in cells or p['profile_id'] in ids:
            raise ValueError('Duplicate action/pool cell or profile id')
        cells.add(cell); ids.add(p['profile_id'])
        common.add(tuple(p[key] for key in COMMON)); sizes.add(p['cohort_size'])
        action = (p['k_cap'], p['policy'])
        if p['action_id'] in actions and actions[p['action_id']] != action:
            raise ValueError('An action must preserve k and policy across pools')
        actions[p['action_id']] = action
        if p['feasible']:
            qp, qm = nonnegative(p, 'q_correct'), nonnegative(p, 'q_wrong')
            if qp+qm > 1:
                raise ValueError('Correct and wrong delivery probabilities exceed one')
            for key in METERS:
                nonnegative(p, key)
    if len(common) != 1 or len(sizes) != 1:
        raise ValueError('Separate model, hardware, cache, workload, or cohort strata')
    expected = {(pi, action) for pi in (0, 1) for action in actions}
    if cells != expected:
        raise ValueError('Missing cells must be recorded, not silently dropped')
    return rows


def validate_scenario(s, allow_counterfactual_admission=False):
    if s.get('schema_version') not in ('thinking-scenario-v2','thinking-scenario-v3'):
        raise ValueError('Explicit thinking-scenario-v2/v3 scenario required')
    if s['schema_version']=='thinking-scenario-v3':
        nonnegative(s,'all_candidates_intercept_usd')
        if s.get('retail_intercept_rule') not in ('independent_nonnegative','equal_at_reference'):
            raise ValueError('Explicit retail intercept rule required')
        if s['retail_intercept_rule']=='equal_at_reference':identifier(s,'reference_profile_id')
    elif any(key in s for key in ('all_candidates_intercept_usd','retail_intercept_rule','reference_profile_id')):
        raise ValueError('Independent intercepts require v3; do not silently change v2')
    for key in ('scenario_id', 'price_basis', 'cost_basis', 'preference_basis'):
        identifier(s, key)
    alpha = number(s['alpha'])
    if not 0 <= alpha <= 1:
        raise ValueError('Invalid cloud share')
    for key in ('base_response_usd', 'input_usd_per_million', 'visible_usd_per_million',
                'hidden_usd_per_million', 'value_correct_usd', 'wrong_damage_usd',
                'delay_usd_per_s', 'outside_usd', 'fixed_capacity_fee_total_usd',
                'capacity_resource_usd_per_gpu_second', 'electricity_usd_per_kwh',
                'activation_resource_total_usd', 'cpu_resource_usd_per_second'):
        nonnegative(s, key)
    if s.get('hidden_billing') not in ('reasoning_only', 'all_non_delivered'):
        raise ValueError('Unspecified hidden billing meter')
    if s.get('response_rule') != 'fixed_fee_including_abstention':
        raise ValueError('Refund/answer-dependent fixed fees require another model')
    admission = s.get('admission', {})
    if admission.get('rule') != 'pre_activation_refusal_zero_fee':
        raise ValueError('This game is not prepaid irrevocable IaaS')
    if admission.get('status') == 'observed':
        sha(admission, 'evidence_sha256')
        identifier(admission, 'evidence_reference')
    elif admission.get('status') in ('counterfactual', 'unverified'):
        if not allow_counterfactual_admission:
            raise ValueError('Explicit counterfactual-admission opt-in required')
        identifier(admission, 'reason')
    else:
        raise ValueError('Admission evidence status required')


@dataclass(frozen=True)
class Outcome:
    profile: str
    action: str
    model: F
    cloud: F
    consumer: F
    welfare: F


OUTSIDE = Outcome('outside', 'outside', F(0), F(0), F(0), F(0))


def choose(branches, player):
    """Pure SPE terminal correspondence, including adverse off-path ties."""
    if not branches or any(not branch for branch in branches):
        raise ValueError('Every decision branch needs a continuation')
    floors = [min(getattr(o, player) for o in branch) for branch in branches]
    result = set()
    for i, branch in enumerate(branches):
        other = floors[:i]+floors[i+1:]
        for o in branch:
            if not other or getattr(o, player) >= max(other):
                result.add(o)
    return result


def accounting(p, s, contract, billing):
    n = p['cohort_size']
    base = number(s['base_response_usd'])
    hidden = number(p['reasoning_tokens_all'])
    if s['hidden_billing'] == 'all_non_delivered':
        hidden += number(p['unselected_final_tokens'])
    bill = number(s['all_candidates_intercept_usd']) if billing=='A' and s['schema_version']=='thinking-scenario-v3' else base
    if billing == 'A':
        bill += (number(s['input_usd_per_million'])*number(p['billed_input_tokens'])
                 + number(s['visible_usd_per_million'])*number(p['delivered_output_tokens'])
                 + number(s['hidden_usd_per_million'])*hidden)/1000000
    cost_total = (number(s['capacity_resource_usd_per_gpu_second'])*number(p['gpu_allocated_seconds_total'])
                  + number(s['electricity_usd_per_kwh'])*number(p['energy_kwh_total'])
                  + number(s['cpu_resource_usd_per_second'])*number(p['verifier_cpu_seconds_total'])
                  + number(s['activation_resource_total_usd']))
    cost = cost_total/n
    gross = (number(s['value_correct_usd'])*number(p['q_correct'])
             - number(s['wrong_damage_usd'])*number(p['q_wrong'])
             - number(s['delay_usd_per_s'])*number(p['mean_latency_s'])
             - number(s['outside_usd']))
    transfer = number(s['fixed_capacity_fee_total_usd'])/n if contract == 'rent' else number(s['alpha'])*bill
    o = Outcome(p['profile_id'], p['action_id'], bill-transfer, transfer-cost, gross-bill, gross-cost)
    if o.model+o.cloud+o.consumer != o.welfare:
        raise AssertionError('Transfers failed to cancel')
    return o, {'bill_usd_per_request': str(bill), 'hidden_billed_tokens': str(hidden if billing=='A' else 0),
               'resource_cost_usd_per_request': str(cost), 'resource_cost_total_usd': str(cost_total),
               'transfer_usd_per_request': str(transfer), 'value_net_outside_usd': str(gross)}


def validate_retail_reference(rows,s):
    if s.get('retail_intercept_rule')!='equal_at_reference':return
    refs=[p for p in rows if p['profile_id']==s['reference_profile_id']]
    if len(refs)!=1 or not refs[0]['feasible'] or refs[0]['pool_id']!=0 or refs[0]['k_cap']!=1:
        raise ValueError('Retail equality requires feasible pool=0 k=1 reference')
    if number(s['all_candidates_intercept_usd'])!=0:
        raise ValueError('Equal-at-reference main rule requires zero A intercept')
    bills=[accounting(refs[0],s,'share',b)[1]['bill_usd_per_request'] for b in ('D','A')]
    if number(bills[0])!=number(bills[1]):raise ValueError('D/A bills are not equal at the declared reference')


def solve(artifact, scenario, controller, contract, billing, pool_id, *,
          allow_fixture=False, allow_composed=False, allow_counterfactual_admission=False):
    rows = validate_profiles(artifact, allow_fixture, allow_composed)
    validate_scenario(scenario, allow_counterfactual_admission)
    validate_retail_reference(rows,scenario)
    if controller not in ('M', 'C') or contract not in ('rent', 'share') or billing not in ('D', 'A'):
        raise ValueError('Unknown game regime')
    if type(pool_id) is not int or pool_id not in (0, 1):
        raise ValueError('Unknown pool')
    gate = 'cloud' if controller == 'M' else 'model'
    root = [{OUTSIDE}]
    diagnostics = []
    for p in rows:
        if p['pool_id'] != pool_id:
            continue
        if not p['feasible']:
            diagnostics.append({'profile': p['profile_id'], 'status': 'physically_infeasible',
                                'reason': p['feasibility_basis']})
            continue
        leaf, accounts = accounting(p, scenario, contract, billing)
        # User's equality is also a genuine tie, not automatic acceptance.
        user_continuation = choose([{OUTSIDE}, {leaf}], 'consumer')
        gate_continuation = choose([{OUTSIDE}, user_continuation], gate)
        root.append(gate_continuation)
        diagnostics.append({'profile': p['profile_id'], 'action': p['action_id'],
                            'status': 'offered_menu_action', 'conditional_payoffs': as_dict(leaf), **accounts})
    outcomes = choose(root, 'model' if controller == 'M' else 'cloud')
    if len(root) == 1:
        diagnostics.append({'pool_id': pool_id, 'status': 'no_feasible_actions',
                            'reason': 'This pool has no physically feasible sampling actions'})
    if any(min(o.model, o.cloud, o.consumer) < 0 for o in outcomes):
        raise AssertionError('An equilibrium participant receives negative payoff')
    return outcomes, diagnostics


def as_dict(o):
    return {'profile': o.profile, 'action': o.action, **{k: str(getattr(o,k))
            for k in ('model', 'cloud', 'consumer', 'welfare')}}


def scan(artifact, scenarios, *, allow_fixture=False, allow_composed=False,
         allow_counterfactual_admission=False):
    rows = validate_profiles(artifact, allow_fixture, allow_composed)
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError('No economic scenarios')
    ids = [s['scenario_id'] for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate scenario id')
    result = {'schema_version': 'thinking-results-v2',
              'interpretation': 'computed_contract_counterfactual_not_observed_strategic_behavior',
              'technology_evidence': sorted({p['evidence'] for p in rows}),
              'scope': 'one model/cloud, fixed cohort; controller chooses k then counterparty/user participate',
              'results': {}}
    for s in scenarios:
        regimes = []
        for controller, contract, billing, pi in product(('M','C'),('rent','share'),('D','A'),(0,1)):
            outcomes, diagnostics = solve(artifact,s,controller,contract,billing,pi,
                allow_fixture=allow_fixture,allow_composed=allow_composed,
                allow_counterfactual_admission=allow_counterfactual_admission)
            regimes.append({'controller': controller, 'contract': contract, 'billing': billing, 'pool_id': pi,
                            'outcomes': [as_dict(o) for o in sorted(outcomes,key=lambda o:o.profile)],
                            'welfare_range': [str(min(o.welfare for o in outcomes)),str(max(o.welfare for o in outcomes))],
                            'diagnostics': diagnostics})
        result['results'][s['scenario_id']] = {'admission': s['admission'], 'regimes': regimes,
            'scenario_schema_version':s['schema_version'],
            'retail_intercept_rule':s.get('retail_intercept_rule','legacy_common_intercept')}
    return result
