"""Exact synthetic checks for the retail-pricing propositions, not experiments."""
from collections import Counter
from fractions import Fraction as F
from itertools import product
import json

from check_generalizations import game


def check():
    counts = Counter()
    zero = (F(0), F(0))

    # Compare each table prediction with complete downstream-strategy
    # enumeration, including the zero-margin case. Both tariffs must meet
    # the proposition's strong participation assumption before comparison.
    for low, delta, c0, dc, t0, dt, rate, alpha in product(
            (8, 16), (2, 6), (F(1, 2), F(2)), (F(1), F(3)),
            (1, 2), (F(1, 2), F(1), F(3)), (F(1), F(2)),
            (F(1, 4), F(1, 2), F(3, 4))):
        billed = (F(low), F(low+delta))
        fixed = (sum(billed)/2,)*2
        cost, times = (c0, c0+dc), (F(t0), F(t0)+dt)
        value = (F(100), F(100))
        for kind in ('hour', 'fee', 'share'):
            payments = [tuple(rate*t for t in times)]*2 if kind == 'hour' else (
                [(F(5),)*2]*2 if kind == 'fee' else
                [tuple(alpha*b for b in bill) for bill in (billed, fixed)])
            if not all(b > e > c for bill, transfer in zip((billed, fixed), payments)
                       for b, e, c in zip(bill, transfer, cost)):
                continue
            predicted = {
                ('hour', 'M'): (F(delta)-rate*dt, -rate*dt),
                ('hour', 'C'): (rate*dt-dc, rate*dt-dc),
                ('fee', 'M'): (F(delta), F(0)),
                ('fee', 'C'): (-dc, -dc),
                ('share', 'M'): ((1-alpha)*delta, F(0)),
                ('share', 'C'): (alpha*delta-dc, -dc),
            }
            for who in ('M', 'C'):
                for bill, transfer, margin in zip((billed, fixed), payments, predicted[kind, who]):
                    expect = {1} if margin > 0 else {0} if margin < 0 else {0, 1}
                    assert game(bill, transfer, zero, cost, value, who) == expect
                    counts[f'budget_{kind}_{who}'] += 1

    # Reference-matched prices and full equilibrium outcomes for the
    # participation switch. Test both assignments of control.
    for low, delta, alpha, weight in product(
            (2, 5, 10), (2, 4, 8), (F(1, 3), F(1, 2), F(2, 3)),
            (F(1, 4), F(1, 2), F(3, 4))):
        bill = (F(low), F(low+delta))
        price = bill[0]+weight*delta
        fixed = (price, price)
        ea, ed = tuple(alpha*b for b in bill), (alpha*price,)*2
        cost = ((ea[0]+ed[0])/2, (ed[1]+ea[1])/2)
        value = (bill[1]+100,)*2
        for who in ('M', 'C'):
            assert game(bill, ea, zero, cost, value, who) == {1}
            assert game(fixed, ed, zero, cost, value, who) == {0}
            counts['participation_switch'] += 1
        # At the excluded boundary, model control can retain both outcomes.
        assert game(fixed, ed, zero, (cost[0], ed[1]), value, 'M') == {0, 1}
        counts['participation_boundary_ties'] += 1

    for d1, s, alpha, epsilon in product(
            (F(2), F(3)), (F(1, 4), F(1, 2)),
            (F(1, 4), F(1, 2), F(3, 4)), (F(1, 4), F(1, 2))):
        c0, c1 = (F(2), 2+d1+2), (2-s, 2-s+d1)
        margin = d1+1
        low = (c0[1]+1)/alpha+1
        bill = (low, low+margin/alpha)
        fixed = (sum(bill)/2,)*2
        ea, ed = tuple(alpha*b for b in bill), tuple(alpha*b for b in fixed)
        value = (bill[1]+100, bill[1]+100+d1-s-epsilon)
        assert all(b > e > c for bvec, evec in ((bill, ea), (fixed, ed))
                   for costs in (c0, c1) for b, e, c in zip(bvec, evec, costs))
        assert game(bill, ea, zero, c0, value, 'C') == {0}
        assert game(bill, ea, zero, c1, value, 'C') == {1}
        assert game(fixed, ed, zero, c0, value, 'C') == {0}
        assert game(fixed, ed, zero, c1, value, 'C') == {0}
        assert value[1]-c1[1]-(value[0]-c0[0]) == -epsilon
        assert value[0]-c1[0]-(value[0]-c0[0]) == s
        counts['pooling_margin'] += 1

    for low, delta, alpha, weight in product(
            (4, 8), (2, 6), (F(1, 3), F(1, 2), F(2, 3)),
            (F(1, 4), F(1, 2), F(3, 4))):
        bill = (F(low), F(low+delta))
        fixed = (bill[0]+weight*delta,)*2
        ea, ed = tuple(alpha*b for b in bill), tuple(alpha*b for b in fixed)
        c0 = (ea[0]/2, ea[1]+2)
        c1 = (c0[0]/2, (ed[1]+ea[1])/2)
        saving = c0[0]-c1[0]
        increment = c1[1]-c1[0]
        dv = (increment-saving)/2
        value = (bill[1]+100, bill[1]+100+dv)
        assert game(bill, ea, zero, c0, value, 'M') == {0}
        assert game(bill, ea, zero, c1, value, 'M') == {1}
        assert game(fixed, ed, zero, c0, value, 'M') == {0}
        assert game(fixed, ed, zero, c1, value, 'M') == {0}
        assert value[1]-c1[1]-(value[0]-c0[0]) < 0
        counts['pooling_participation'] += 1

    # Equal savings need not remove the participation mechanism.
    bill, fixed, ea, ed = (F(10), F(14)), (F(12),)*2, (F(5), F(7)), (F(6),)*2
    c0, c1, value = (F(4), F(8)), (F(5, 2), F(13, 2)), (F(21), F(22))
    assert c0[1]-c0[0] == c1[1]-c1[0]
    assert game(bill, ea, zero, c0, value, 'M') == {0}
    assert game(bill, ea, zero, c1, value, 'M') == {1}
    assert game(fixed, ed, zero, c1, value, 'M') == {0}
    counts['equal_savings_participation'] += 1

    # Positive firm costs turn the fixed-price tie into a strict low choice.
    for alpha, dc in product((F(1, 4), F(1, 2), F(3, 4)), (F(1, 4), F(1, 2))):
        bill, fixed, cost, own = (F(20), F(28)), (F(24),)*2, (F(1), F(2)), (F(1), 1+dc)
        assert 0 < dc < (1-alpha)*8
        assert game(bill, tuple(alpha*b for b in bill), own, cost, (40, 40), 'M') == {1}
        assert game(fixed, tuple(alpha*b for b in fixed), own, cost, (40, 40), 'M') == {0}
        counts['model_cost_breaks_tie'] += 1

    assert all(counts[f'budget_{kind}_{who}'] for kind in ('hour', 'fee', 'share') for who in ('M', 'C'))
    return {'status': 'exact_retail_checks_passed', 'counts': dict(counts),
            'empirical_data_used': False, 'experiments_run': False}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
