"""Rational two-action accounting for point analysis and paired bootstrap.

The terminal correspondence uses the existing game tree's choose operator.
No new tie rule and no configuration or sampling execution is introduced.
"""
from fractions import Fraction as F
import thinking_market as tm


def games(z, alpha, rent, outside, controller):
    result = {}
    for payment in ('rent', 'share'):
        for pi in (0, 1):
            branches = [{tm.OUTSIDE}]
            for k in ('L', 'H'):
                p = z[pi, k]; b, c, v = p['B'], p['C'], p['V']
                transfer = rent if payment == 'rent' else alpha*b
                leaf = tm.Outcome(f'{pi}{k}', k, b-transfer, transfer-c, v-b-outside, v-c-outside)
                user = tm.choose([{tm.OUTSIDE}, {leaf}], 'consumer')
                gate = tm.choose([{tm.OUTSIDE}, user], 'cloud' if controller == 'M' else 'model')
                branches.append(gate)
            result[payment, pi] = tm.choose(branches, 'model' if controller == 'M' else 'cloud')
    return result


def did_from_games(result):
    values = {key: [o.welfare for o in outcomes] for key, outcomes in result.items()}
    s0, s1, r0, r1 = [values[key] for key in (('share', 0), ('share', 1), ('rent', 0), ('rent', 1))]
    lo, hi = min(s1)-max(s0)-max(r1)+min(r0), max(s1)-min(s0)-min(r1)+max(r0)
    structure = all(len(result[key]) == 1 and next(iter(result[key])).action == action
                    for key, action in ((('share', 0), 'L'), (('share', 1), 'H'),
                                        (('rent', 0), 'L'), (('rent', 1), 'L')))
    strict = all(o.action != 'outside' and min(o.model, o.cloud, o.consumer) > 0
                 for outcomes in result.values() for o in outcomes)
    return {'point': lo if lo == hi else None, 'range': [lo, hi],
            'absolute_share_change': [min(s1)-max(s0), max(s1)-min(s0)],
            'absolute_rent_change': [min(r1)-max(r0), max(r1)-min(r0)],
            'rent_LL_share_LH': structure, 'actual_trades_strict': strict,
            'common_terminal_action': all(len(x)==1 for x in result.values()) and len({next(iter(x)).action for x in result.values()})==1,
            'unique_terminals': all(len(x) == 1 for x in result.values())}


def metrics(z, alpha, rent, outside):
    c = lambda pi, k: z[pi, k]['C']
    b = lambda pi, k: z[pi, k]['B']
    d0, d1 = c(0, 'H')-c(0, 'L'), c(1, 'H')-c(1, 'L')
    db0, db1 = b(0, 'H')-b(0, 'L'), b(1, 'H')-b(1, 'L')
    cost, billing = d0-d1, alpha*(db1-db0)
    m0, m1 = alpha*db0-d0, alpha*db1-d1
    assert m1-m0 == cost+billing
    result = {'d0': d0, 'd1': d1, 's_L': c(0, 'L')-c(1, 'L'), 's_H': c(0, 'H')-c(1, 'H'),
              'delta_B0': db0, 'delta_B1': db1, 'cost_component': cost, 'billing_component': billing,
              'cloud_margin0': m0, 'cloud_margin1': m1,
              'billing_shift_H': b(1, 'H')-b(0, 'H'),
              'alpha_C0': d0/db0 if db0 > 0 else None, 'alpha_C1': d1/db1 if db1 > 0 else None,
              'same_low_value_change': z[1, 'L']['V']-z[0, 'L']['V'],
              'same_low_welfare_change': z[1, 'L']['V']-z[0, 'L']['V']+c(0, 'L')-c(1, 'L'),
              'structural_DID': z[1, 'H']['V']-z[1, 'L']['V']-d1,
              'structural_absolute_change': z[1, 'H']['V']-z[0, 'L']['V']-c(1, 'H')+c(0, 'L')}
    valid = min(b(0, 'L'), b(1, 'H'), b(0, 'H')) > 0
    result['admission_lower'] = max(c(0, 'L')/b(0, 'L'), c(1, 'H')/b(1, 'H')) if valid else None
    result['admission_upper'] = min(c(0, 'H')/b(0, 'H'), F(1)) if valid else None
    for controller in ('M', 'C'):
        effect = did_from_games(games(z, alpha, rent, outside, controller))
        result[f'DID_{controller}_lower'], result[f'DID_{controller}_upper'] = effect['range']
        for payment in ('share','rent'):
            result[f'{payment}_change_{controller}_lower'], result[f'{payment}_change_{controller}_upper'] = effect[f'absolute_{payment}_change']
        result[f'rent_LL_share_LH_{controller}'] = F(effect['rent_LL_share_LH'])
        result[f'DID_{controller}_unique'] = F(effect['unique_terminals'])
        result[f'actual_trades_strict_{controller}'] = F(effect['actual_trades_strict'])
    return result
