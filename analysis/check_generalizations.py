"""Exact checks for cost sharing, menu order, and contract benchmarks.

Standard library only. Prints a JSON record and never runs candidates or a
backend. Pure strategies are enumerated independently of the paper's terminal
set recursion. Analytic proofs remain necessary.
"""
from fractions import Fraction as F
from itertools import combinations_with_replacement, product
import json


def maximizers(values):
    top = max(values)
    return frozenset(i for i, value in enumerate(values) if value == top)


def pure_outcomes(model, cloud, user, controller):
    """Enumerate all downstream best-response strategies, then the controller."""
    n = len(model)
    assert n and len(cloud) == n and len(user) == n
    own, other = (model, cloud) if controller == "M" else (cloud, model)
    outcomes = set()
    user_actions = [(True,) if u > 0 else (False,) if u < 0
                    else (False, True) for u in user]
    for buy in product(*user_actions):
        responses = []
        for k in range(n):
            accept_payoff = other[k] if buy[k] else F(0)
            responses.append((True,) if accept_payoff > 0 else (False,)
                             if accept_payoff < 0 else (False, True))
        for accept in product(*responses):
            traded = [buy[k] and accept[k] for k in range(n)]
            values = [F(0)] + [own[k] if traded[k] else F(0)
                               for k in range(n)]
            for action in maximizers(values):
                outcomes.add(action - 1 if action and traded[action - 1]
                             else None)
    return frozenset(outcomes)


def game(bill, transfer, model_cost, cloud_cost, value, controller):
    model = tuple(b-e-d for b, e, d in zip(bill, transfer, model_cost))
    cloud = tuple(e-c for e, c in zip(transfer, cloud_cost))
    user = tuple(v-b for v, b in zip(value, bill))
    return pure_outcomes(model, cloud, user, controller)


def displayed(outcomes):
    return ["exit" if k is None else k + 1
            for k in sorted(outcomes, key=lambda k: -1 if k is None else k)]


def monotone(values):
    return all(a <= b for a, b in zip(values, values[1:]))


def supported_contract_optima(bill, model_cost, cloud_cost, contracts, controller):
    """Optimize over the independent downstream-strategy enumeration.

    Exit is always available. At indifference we retain every pure continuation,
    including acceptance and refusal, and report the best supportable profit.
    """
    value = tuple(b + 10 for b in bill)
    best, choices = F(0), {None}
    for transfer in contracts:
        outcomes = game(bill, transfer, model_cost, cloud_cost, value, controller)
        for k in outcomes - {None}:
            profit = bill[k] - transfer[k] - model_cost[k]
            if profit > best:
                best, choices = profit, {k}
            elif profit == best:
                choices.add(k)
    return best, frozenset(choices)


def best_supported_profit(bill, model_cost, cloud_cost, contracts, controller):
    return supported_contract_optima(bill, model_cost, cloud_cost, contracts, controller)[0]


def contract_checks():
    counts = {"endogenous_model_fee_cases": 0,
              "endogenous_cloud_fee_cases": 0,
              "cloud_fee_epsilon_profiles": 0,
              "endogenous_cloud_share_cases": 0,
              "endogenous_cloud_two_part_cases": 0,
              "strict_supplier_planner_ranking_cases": 0}
    for b0, db, c0, dc, d0, d1 in product(
            (4, 6), (1, 3), (0, 1, 3, 5), (1, 2, 4), (0, 1), (0, 1)):
        bill = tuple(map(F, (b0, b0 + db)))
        cost = tuple(map(F, (c0, c0 + dc)))
        own = tuple(map(F, (d0, d1)))
        bound = int(max(bill + cost)) + 2
        # All breakpoints are integral here. Half-integer offers exercise both
        # sides of each breakpoint as well as the zero-profit tie itself.
        fees = tuple(F(i, 2) for i in range(2 * bound + 1))
        fee_contracts = tuple((fee, fee) for fee in fees)
        integrated = max(F(0), *(b-c-d for b, c, d in zip(bill, cost, own)))
        observed, choices = supported_contract_optima(bill, own, cost, fee_contracts, "M")
        assert observed == integrated
        if observed > 0:
            assert choices == {k for k in range(2) if bill[k]-cost[k]-own[k] == integrated}
        counts["endogenous_model_fee_cases"] += 1
        for dv in (-2, 0, 2, 5):
            supplier_margin = F(db - dc - (d1 - d0))
            welfare_margin = F(dv - dc - (d1 - d0))
            if supplier_margin and welfare_margin:
                opposite_rankings = (supplier_margin > 0) != (welfare_margin > 0)
                assert opposite_rankings == (supplier_margin * welfare_margin < 0)
                counts["strict_supplier_planner_ranking_cases"] += 1
        if d0 or d1:
            continue

        zero_cost = (F(0), F(0))
        expected_fee = max(F(0), bill[0]-cost[0], bill[1]-max(cost[1], bill[0]))
        previous = F(0)
        for epsilon in (F(1, 4), F(1, 16), F(1, 64), F(1, 256)):
            # Shift every fee off the integral participation boundaries. In
            # particular the high-target fee is max(C_H, B_L) + epsilon,
            # equal to B_L + epsilon where the screening constraint binds.
            strict_fees = tuple((fee+epsilon, fee+epsilon) for fee in fees)
            observed, choices = supported_contract_optima(bill, zero_cost, cost, strict_fees, "C")
            profits = (bill[0]-cost[0]-epsilon,
                       bill[1]-max(cost[1], bill[0])-epsilon)
            assert observed == max(F(0), *profits)
            assert previous <= observed <= expected_fee
            assert expected_fee-observed <= epsilon
            if observed > 0:
                assert choices == {k for k in range(2) if profits[k] == observed}
            high_fee = max(cost[1], bill[0])+epsilon
            if bill[1] > high_fee:
                assert bill[0]-high_fee < 0
                assert high_fee-cost[1] > 0
                assert game(bill, (high_fee, high_fee), zero_cost, cost,
                            tuple(b+10 for b in bill), "C") == {1}
            previous = observed
            counts["cloud_fee_epsilon_profiles"] += 1
        counts["endogenous_cloud_fee_cases"] += 1

        alpha_l, alpha_c = cost[0]/bill[0], F(dc, db)
        alpha_h = max(alpha_c, cost[1]/bill[1])
        alphas = sorted({F(i, 24) for i in range(25)} |
                        {a for a in (alpha_l, alpha_c, alpha_h) if 0 <= a <= 1})
        share_contracts = tuple(tuple(a*b for b in bill) for a in alphas)
        candidates = {None: F(0)}
        if alpha_l <= min(alpha_c, F(1)):
            candidates[0] = bill[0]-cost[0]
        if alpha_h <= 1:
            candidates[1] = (1-alpha_h)*bill[1]
        expected_share = max(candidates.values())
        observed, choices = supported_contract_optima(bill, zero_cost, cost, share_contracts, "C")
        assert observed == expected_share
        if observed > 0:
            assert choices == {k for k, p in candidates.items() if p == expected_share}
        counts["endogenous_cloud_share_cases"] += 1

        if alpha_c <= 1:
            # Enumerate slopes on a grid augmented by exact indifference
            # slopes, and signed fixed components on a grid augmented by
            # participation breakpoints. This is not a formula-only check.
            contracts = set()
            for a in alphas:
                fixed_parts = {F(i, 2) for i in range(-2*bound, 2*bound+1)}
                fixed_parts.update(c-a*b for b, c in zip(bill, cost))
                contracts.update(tuple(f+a*b for b in bill) for f in fixed_parts)
            observed, choices = supported_contract_optima(bill, zero_cost, cost, contracts, "C")
            assert observed == integrated
            if observed > 0:
                assert choices == {k for k in range(2) if bill[k]-cost[k] == integrated}
            counts["endogenous_cloud_two_part_cases"] += 1
    return counts


def menu_grid_checks():
    counts = {"continuous_grid_profiles": 0, "continuous_grid_points": 0,
              "decreasing_savings_constructions": 0,
              "continuous_first_order_cases": 0,
              "alpha_monotonicity_cases": 0}
    for subdivisions in (100, 200):
        grid = tuple(F(i, subdivisions) for i in range(subdivisions+1))
        for a, b, u, v, w in product((-2, 0, 1, 3), (0, 1, 2), (0, 1), (0, 1, 2), (0, 1)):
            f0 = tuple(10 + a*k - b*k*k for k in grid)
            savings = tuple(u + v*k + w*k*k for k in grid)
            f1 = tuple(f+s for f, s in zip(f0, savings))
            old, new = maximizers(f0), maximizers(f1)
            assert monotone(savings)
            assert min(new) >= min(old) and max(new) >= max(old)
            # E is fixed across modes and makes both cost profiles positive.
            transfers = tuple(30+10*k for k in grid)
            c0 = tuple(e-f for e, f in zip(transfers, f0))
            c1 = tuple(e-f for e, f in zip(transfers, f1))
            assert all(0 <= y <= x for x, y in zip(c0, c1))
            assert tuple(x-y for x, y in zip(c0, c1)) == savings
            counts["continuous_grid_profiles"] += 1
            counts["continuous_grid_points"] += len(grid)

    # Necessity is uniform over baseline profits, not for one fixed problem.
    # Every decreasing pair in each enumerated savings vector gets its own
    # exact construction with a unique downward switch and positive costs.
    for n in range(2, 5):
        for savings in product(map(F, (0, 1, 2)), repeat=n):
            for a in range(n):
                for b in range(a+1, n):
                    if savings[a] <= savings[b]:
                        continue
                    delta = (savings[a]-savings[b])/2
                    f0 = [F(0)] * n
                    f0[a], f0[b] = F(10), F(10)+delta
                    f1 = [f+s for f, s in zip(f0, savings)]
                    c0 = [20-f for f in f0]
                    c1 = [c-s for c, s in zip(c0, savings)]
                    assert min(c0+c1) > 0
                    assert maximizers(f0) == {b} and maximizers(f1) == {a}
                    counts["decreasing_savings_constructions"] += 1

    for slope, c, d, q, v, alpha in product(
            (2, 4), (1, 2), (0, 1, 3), (0, 1), (1, 3, 5), (F(1, 4), F(3, 4))):
        cloud_k = alpha*slope/c
        planner_k = F(v, c+d+q)
        assert 0 < cloud_k < 10 and 0 < planner_k < 10
        assert alpha*slope == c*cloud_k
        assert v-q*planner_k == (c+d)*planner_k
        assert (cloud_k > planner_k) == (alpha*slope+d*cloud_k > v-q*cloud_k)
        counts["continuous_first_order_cases"] += 1

    # Alpha comparative statics use a common participating menu. Only the
    # cloud acceptance gate is asserted to expand as the revenue share rises.
    for n in range(2, 5):
        bill = tuple(F(k+2) for k in range(n))
        for cost in product(map(F, (0, 1, 3)), repeat=n):
            previous_opt, previous_admission = None, set()
            for alpha in map(lambda i: F(i, 12), range(13)):
                profit = tuple(alpha*b-c for b, c in zip(bill, cost))
                optimum = maximizers(profit)
                admission = {k for k, p in enumerate(profit) if p >= 0}
                if previous_opt is not None:
                    assert min(optimum) >= min(previous_opt) and max(optimum) >= max(previous_opt)
                assert previous_admission <= admission
                previous_opt, previous_admission = optimum, admission
            counts["alpha_monotonicity_cases"] += 1
    return counts


def extension_counterexamples():
    # Explicit counterexamples to tempting stronger claims. They are theory
    # fixtures, never empirical observations or candidate programs.
    assert F(4) != F(5) and F(4)-1 > 0 and F(5)-1 > 0
    epsilon = F(1, 100)
    assert best_supported_profit((F(4), F(10)), (F(0), F(0)), (F(1), F(2)),
                                 ((1+epsilon, 1+epsilon), (4+epsilon, 4+epsilon)), "C") == 6-epsilon
    # The incentive threshold by itself does not cover participation.
    assert F(1, 10) < F(9, 20)
    assert game((10, 20), (1, 2), (0, 0), (8, 9), (30, 30), "C") == {None}
    assert game((10, 20), (F(9, 2), 9), (0, 0), (8, 9), (30, 30), "C") == {None, 1}
    # A negative fixed component is needed to remove a positive cloud rent.
    bill, cost = (F(10), F(14)), (F(1), F(3))
    unsigned_contracts = {tuple(F(i, 2)+F(j, 24)*b for b in bill)
                          for i in range(29) for j in range(25)}
    assert best_supported_profit(bill, (0, 0), cost, unsigned_contracts, "C") == 9
    assert best_supported_profit(bill, (0, 0), cost, ((1, 3),), "C") == 11
    # Model cost matters even where the retail marginal bill is below value.
    assert F(1) < F(3, 2) and F(1)+1 > F(3, 2)
    assert F(1) > F(3, 4)  # cloud optimum exceeds welfare optimum
    # In second-price procurement, the cheap cloud receives the next cost.
    assert sorted((F(2), F(5), F(8)))[1] == 5
    return ["nonzero_bill_value_wedge_without_choice_disagreement",
            "fixed_capacity_fee_can_screen_out_low_budget",
            "incentive_threshold_can_fail_cloud_participation",
            "unsigned_two_part_fee_cannot_extract_positive_rent",
            "continuous_overprovision_requires_model_cost_derivative",
            "heterogeneous_procurement_pays_second_not_first_cost"]


def retail_pricing_checks():
    counts = {"retail_ceiling_profiles": 0, "retail_strict_epsilon_profiles": 0,
              "retail_model_control_checks": 0}
    for v0, dv, c0, dc, alpha, outside in product(
            (4, 8), (1, 2, 4), (0, 2, 4), (1, 2, 4),
            (F(1, 4), F(1, 2), F(3, 4)), (0, 1, 2)):
        value = tuple(map(F, (v0, v0+dv)))
        net_value = tuple(v-outside for v in value)
        cost = tuple(map(F, (c0, c0+dc)))
        assert net_value[1]-net_value[0] == dv
        assert not (dv < dc < alpha*(net_value[1]-net_value[0]))
        counts["retail_ceiling_profiles"] += 1
        for epsilon in (F(1, 4), F(1, 16), F(1, 64)):
            bill = tuple(b-epsilon for b in net_value)
            assert min(bill) > 0 and bill[1]-bill[0] == dv
            assert all(v-b == epsilon for v, b in zip(net_value, bill))
            transfer = tuple(alpha*b for b in bill)
            outcomes = game(bill, transfer, (0, 0), cost, net_value, "C")
            if dv < dc:
                assert 1 not in outcomes  # no cloud-controlled overprovision
            counts["retail_strict_epsilon_profiles"] += 1
            for own in ((F(0), F(0)), (F(1), F(2))):
                profit = F(0)
                chosen = {None}
                for fee in cost:
                    transfer = (fee, fee)
                    for k in game(bill, transfer, own, cost, net_value, "M")-{None}:
                        candidate = bill[k]-fee-own[k]
                        if candidate > profit:
                            profit, chosen = candidate, {k}
                        elif candidate == profit:
                            chosen.add(k)
                welfare = tuple(v-c-d for v, c, d in zip(net_value, cost, own))
                assert profit == max(F(0), *(w-epsilon for w in welfare))
                if profit > 0:
                    assert chosen == maximizers(welfare)
                counts["retail_model_control_checks"] += 1

    value, alpha = (F(10), F(11)), F(1, 2)
    c0, c1 = (F(4), F(6)), (F(17, 5), F(27, 5))
    assert c0[1] > alpha*value[1] > c1[1]
    assert (value[1]-value[0]) + (c0[0]-c1[0]) < c1[1]-c1[0]
    for epsilon in (F(1, 100), F(1, 1000)):
        bill = tuple(v-epsilon for v in value)
        transfer = tuple(alpha*b for b in bill)
        assert game(bill, transfer, (0, 0), c0, value, "M") == {0}
        assert game(bill, transfer, (0, 0), c1, value, "M") == {1}
    assert value[0]-c0[0] == 6
    assert value[1]-c1[1] == F(28, 5)

    # Posted linear token billing restores a faster-growing bill increment.
    k, base, rate = (1, 2), F(0), F(5)
    bill = tuple(base+rate*n for n in k)
    cost = (F(1), F(3))
    assert (value[1]-value[0]) < (cost[1]-cost[0]) < alpha*(bill[1]-bill[0])
    assert game(bill, tuple(alpha*b for b in bill), (0, 0), cost, value, "C") == {1}
    assert value[1]-cost[1] < value[0]-cost[0]

    # Pointwise extraction is not generally a profit-optimal menu when the
    # cloud controls k. The deviation changes an off-path price to steer it.
    epsilon = F(1, 100)
    ceiling_bill = tuple(v-epsilon for v in value)
    deviation_bill = (F(0), value[1]-epsilon)
    assert game(ceiling_bill, tuple(alpha*b for b in ceiling_bill), (0, 0), cost, value, "C") == {0}
    assert game(deviation_bill, tuple(alpha*b for b in deviation_bill), (0, 0), cost, value, "C") == {1}
    assert (1-alpha)*deviation_bill[1] > (1-alpha)*ceiling_bill[0]
    return counts, {
        "pointwise_extraction_is_conditional_not_a_menu_equilibrium": True,
        "admission_example": {"initial_choice": "L", "pooled_choice": "H",
                              "welfare_initial": "6", "welfare_pooled": "28/5"},
        "linear_tariff_restores_overprovision": True,
        "off_path_pricing_counterexample_checked": True,
        "user_ties_checked_via_common_strict_discount_limit": True
    }


def procurement_checks():
    def profit(cost, bid, rivals):
        # Bidder zero wins equal bids. A truthful tie earns exactly zero.
        return min(rivals)-cost if bid <= min(rivals) else F(0)

    count = 0
    for n in (2, 3):
        for cost in map(F, (0, 1, 3)):
            for rivals in product(map(F, (0, 1, 2, 4)), repeat=n-1):
                truthful = profit(cost, cost, rivals)
                for deviation in map(F, (0, 1, 2, 3, 4, 6)):
                    assert truthful >= profit(cost, deviation, rivals)
                    count += 1
    return {"procurement_deviation_checks": count}


def check():
    counts = {"allocation_cases": 0, "strict_controller_checks": 0,
              "fixed_share_cases": 0, "finite_cloud_cases": 0,
              "finite_admission_cases": 0, "noninterval_admission_cases": 0,
              "strict_positive_share_stability_cases": 0}
    boundaries = []

    # Both transfer rules, negative/zero/positive increments, and zero costs.
    for b0, db, d0, dd, c0, dc, alpha, fee, dv in product(
            (12, 16), (-2, 0, 2), (0, 1, 2), (-1, 0, 1, 2),
            (1, 3), (-1, 0, 1, 2), (F(1, 4), F(1, 2), F(3, 4)),
            (1, 4, 8), (-3, 0, 3)):
        if d0 + dd < 0 or c0 + dc < 0:
            continue
        bill, d, c, v = (b0, b0+db), (d0, d0+dd), (c0, c0+dc), (30, 30+dv)
        for contract, e in (("R", (fee, fee)), ("S", tuple(alpha*b for b in bill))):
            m = tuple(b-ee-dk for b, ee, dk in zip(bill, e, d))
            cloud = tuple(ee-ck for ee, ck in zip(e, c))
            user = tuple(vk-b for vk, b in zip(v, bill))
            expected_m = db-dd if contract == "R" else (1-alpha)*db-dd
            expected_c = -dc if contract == "R" else alpha*db-dc
            assert m[1]-m[0] == expected_m
            assert cloud[1]-cloud[0] == expected_c
            welfare = tuple(u+mm+cc for u, mm, cc in zip(user, m, cloud))
            assert welfare == tuple(vk-dk-ck for vk, dk, ck in zip(v, d, c))
            assert welfare[1]-welfare[0] == dv-dd-dc
            if all(x > 0 for x in m+cloud+user):
                for controller, profit in (("M", m), ("C", cloud)):
                    assert pure_outcomes(m, cloud, user, controller) == maximizers(profit)
                    counts["strict_controller_checks"] += 1
        counts["allocation_cases"] += 1

    for beta, total0, total1, db, alpha in product(
            (F(0), F(1, 4), F(1, 2), F(1)), (0, 2, 5), (0, 3, 7),
            (-2, 0, 6), (F(1, 4), F(1, 2), F(3, 4))):
        total = (F(total0), F(total1))
        d = tuple(beta*t for t in total)
        c = tuple((1-beta)*t for t in total)
        bill, value = (F(20), F(20+db)), (F(40), F(42))
        for e in ((F(8), F(8)), tuple(alpha*b for b in bill)):
            for k in range(2):
                for outside in (F(0), F(3), F(11)):
                    assert (value[k]-bill[k]-outside) + (bill[k]-e[k]-d[k]) + (e[k]-c[k]) == value[k]-total[k]-outside
        counts["fixed_share_cases"] += 1

    # Arbitrary profit vectors. Exact enumeration includes all downstream ties.
    for n in range(1, 5):
        for raw in product((-1, 0, 1), repeat=n):
            for shift in (0, 5):
                f0 = tuple(F(x+shift) for x in raw)
                if max(f0) <= 0:
                    continue
                for saving in combinations_with_replacement((F(0), F(1), F(2)), n):
                    f1 = tuple(p+s for p, s in zip(f0, saving))
                    old, new = maximizers(f0), maximizers(f1)
                    assert min(new) >= min(old) and max(new) >= max(old)
                    bill, e, value = (F(20),)*n, (F(10),)*n, (F(30),)*n
                    c0 = tuple(F(10)-p for p in f0)
                    c1 = tuple(c-s for c, s in zip(c0, saving))
                    assert game(bill, e, (F(1),)*n, c0, value, "C") == old
                    assert game(bill, e, (F(1, 2),)*n, c1, value, "C") == new
                    counts["finite_cloud_cases"] += 1

        # 0 never admitted, 1 newly admitted, 2 admitted in both modes.
        for state in product((0, 1, 2), repeat=n):
            a0 = {k for k, x in enumerate(state) if x == 2}
            a1 = {k for k, x in enumerate(state) if x in (1, 2)}
            if not a0:
                continue
            bill = tuple(F(20+4*k) for k in range(n))
            e, value = (F(10),)*n, tuple(b+5 for b in bill)
            c0 = tuple(F({0: 13, 1: 12, 2: 8}[x]) for x in state)
            c1 = tuple(F({0: 12, 1: 8, 2: 7}[x]) for x in state)
            g0 = tuple(F(k+1 if k in a0 else -k-1) for k in range(n))
            g1 = tuple(F(2*k+2 if k in a1 else -2*k-2) for k in range(n))
            d0 = tuple(b-ee-g for b, ee, g in zip(bill, e, g0))
            d1 = tuple(b-ee-g for b, ee, g in zip(bill, e, g1))
            assert all(d >= 0 for d in d0+d1)
            assert game(bill, e, d0, c0, value, "M") == {max(a0)}
            assert game(bill, e, d1, c1, value, "M") == {max(a1)}
            assert a0 <= a1 and max(a1) >= max(a0)
            counts["finite_admission_cases"] += 1
            if any(a != set(range(min(a), max(a)+1)) for a in (a0, a1)):
                counts["noninterval_admission_cases"] += 1

    def boundary(name, before, after, expected_before, expected_after):
        assert before == frozenset(expected_before), (name, before)
        assert after == frozenset(expected_after), (name, after)
        boundaries.append({"case": name, "before": displayed(before), "after": displayed(after)})

    p = lambda m, c, u, who: pure_outcomes(tuple(map(F, m)), tuple(map(F, c)), tuple(map(F, u)), who)
    boundary("arbitrary_tie_choices_can_move_down", p((4,4),(2,2),(3,3),"C"), p((4,4),(2,2),(3,3),"C"), {0,1}, {0,1})
    bill, e, value = (12,16), (6,8), (20,20)
    boundary("pointwise_savings_without_order", game(bill,e,(1,1),(5,6),value,"C"), game(bill,e,(1,1),(2,5),value,"C"), {1}, {0})
    assert monotone((5,6)) and monotone((2,5))
    boundary("bill_drift_can_reverse_order", game((20,24),(10,12),(1,1),(8,9),(30,30),"C"), game((20,16),(10,8),(1,1),(7,7),(30,30),"C"), {1}, {0})
    boundary("lost_downstream_participation", game(bill,e,(0,0),(5,6),value,"C"), game(bill,e,(0,9),(4,4),value,"C"), {1}, {0})
    boundary("admission_expands_but_firm_ranking_decreases", game((14,16),(7,8),(3,6),(8,6),(25,25),"M"), game((14,16),(7,8),(3,6),(6,5),(25,25),"M"), {1}, {0})
    boundary("cloud_zero_profit_adds_trade_outcome", game((12,14),(6,7),(0,0),(5,7),(20,22),"M"), game((12,14),(6,7),(0,0),(4,6),(20,22),"M"), {0,1}, {1})
    boundary("user_zero_surplus_adds_refusal_continuation", p((4,5),(2,2),(2,0),"M"), p((4,5),(2,2),(2,1),"M"), {0,1}, {1})
    boundary("negative_firm_profit_gives_exit", p((-2,-1),(2,2),(2,2),"M"), p((-2,-1),(3,3),(2,2),"M"), {None}, {None})
    boundary("zero_best_firm_profit_retains_exit", p((-1,0),(2,2),(2,2),"M"), p((-1,0),(3,3),(2,2),"M"), {None,1}, {None,1})
    boundary("ordered_savings_need_not_give_strict_increase", p((4,4),(5,1),(2,2),"C"), p((4,4),(5,2),(2,2),"C"), {0}, {0})
    boundary("upward_budget_can_raise_welfare", game((12,16),(6,8),(1,1),(4,7),(20,25),"C"), game((12,16),(6,8),(1,1),(3,4),(20,25),"C"), {0}, {1})
    assert (25-1-4)-(20-1-4) > 0
    boundary("third_budget_blocks_two_budget_switch", game((14,17,20),(7,F(17,2),10),(1,1,1),(2,F(5,2),6),(21,F(43,2),22),"C"), game((14,17,20),(7,F(17,2),10),(1,1,1),(F(3,2),F(3,2),F(7,2)),(21,F(43,2),22),"C"), {1}, {1})
    boundary("empty_initial_admission_gives_exit", p((2,3),(-2,-1),(2,2),"M"), p((2,3),(-1,1),(2,2),"M"), {None}, {1})
    boundary("positive_cost_share_changes_firm_contract_ranking", game((20,26),(8,8),(2,6),(2,6),(40,40),"M"), game((20,26),(10,13),(2,6),(2,6),(40,40),"M"), {1}, {0})
    boundary("all_cost_on_model_leaves_fixed_fee_cloud_tied", game((20,26),(8,8),(4,12),(0,0),(40,40),"C"), game((20,26),(8,8),(4,12),(0,0),(40,40),"C"), {0,1}, {0,1})
    boundary("firm_ranking_required_in_each_mode", game((14,16),(7,8),(6,6),(1,2),(25,25),"M"), game((14,16),(7,8),(4,6),(1,2),(25,25),"M"), {1}, {0})
    boundary("changing_transfer_can_shrink_admission", game((10,14),(5,8),(0,0),(4,7),(25,25),"M"), game((10,14),(5,5),(0,0),(3,6),(25,25),"M"), {1}, {0})
    boundary("nonpositive_cloud_maximum_retains_exit", p((4,4),(-2,-1),(2,2),"C"), p((4,4),(-1,0),(2,2),"C"), {None}, {None,1})
    boundary("ordered_total_savings_not_cloud_savings", game((12,16),(6,8),(1,4),(5,6),(20,20),"C"), game((12,16),(6,8),(3,3),(2,5),(20,20),"C"), {1}, {0})
    assert monotone(tuple(a-b for a,b in zip((6,10),(5,8))))

    # Three budgets, fixed beta=1/5, all resource-cost components positive.
    # Each original channel persists. These are algebraic witnesses, not data.
    witnesses = []
    for channel, bill, c0, c1, fee, controller, expected in (
        ("marginal", (14,18,20), (2,F(7,2),6), (F(7,4),F(13,4),4), 7, "C", (1,2)),
        ("admission", (10,12,14), (4,F(15,2),8), (2,F(11,2),6), 5, "M", (0,2))):
        value, alpha = (F(21),F(43,2),F(22)), F(1,2)
        c0, c1 = tuple(map(F,c0)), tuple(map(F,c1))
        d0, d1 = tuple(c/4 for c in c0), tuple(c/4 for c in c1)
        t0, t1 = tuple(c+d for c,d in zip(c0,d0)), tuple(c+d for c,d in zip(c1,d1))
        e = tuple(alpha*b for b in bill)
        old, new = game(bill,e,d0,c0,value,controller), game(bill,e,d1,c1,value,controller)
        assert old == {expected[0]} and new == {expected[1]}
        assert all(x > 0 for x in c0+c1+d0+d1)
        assert all(a >= b for a,b in zip(t0,t1))
        assert monotone(t0) and monotone(t1)
        delta = value[expected[1]]-t1[expected[1]]-(value[expected[0]]-t0[expected[0]])
        increment = t1[expected[1]]-t1[expected[0]]
        old_saving = t0[expected[0]]-t1[expected[0]]
        assert delta == value[expected[1]]-value[expected[0]]-increment+old_saving
        assert delta < 0
        if channel == "marginal":
            assert monotone(tuple(a-b for a,b in zip(c0,c1)))
            for d,c in ((d0,c0),(d1,c1)):
                for transfer in ((F(fee),)*3,e):
                    assert all(b-ee-dd > 0 and ee-cc > 0 and v-b > 0
                               for b,ee,dd,cc,v in zip(bill,transfer,d,c,value))
        else:
            assert len(set(a-b for a,b in zip(c0,c1))) == 1
            for d in (d0,d1):
                g = tuple(b-ee-dd for b,ee,dd in zip(bill,e,d))
                assert all(x > 0 for x in g) and all(a < b for a,b in zip(g,g[1:]))
        witnesses.append({"channel":channel,"budgets":[1,2,3],"alpha":"1/2","beta":"1/5",
                          "bill":list(map(str,bill)),"value":list(map(str,value)),
                          "cloud_cost_0":list(map(str,c0)),"cloud_cost_1":list(map(str,c1)),
                          "model_cost_0":list(map(str,d0)),"model_cost_1":list(map(str,d1)),
                          "choice_0":expected[0]+1,"choice_1":expected[1]+1,
                          "welfare_change":str(delta)})

    for bill, total0, total1, fee in (
            ((14,20),(F(2),F(6)),(F(3,2),F(7,2)),F(7)),
            ((10,14),(F(4),F(8)),(F(2),F(6)),F(5))):
        for total in (total0,total1):
            for transfer in ((fee,fee),tuple(F(b,2) for b in bill)):
                for controller in ("M","C"):
                    baseline = game(bill,transfer,(F(0),F(0)),total,(21,22),controller)
                    for beta in (F(1,1000),F(1,100),F(1,50)):
                        d = tuple(beta*t for t in total)
                        c = tuple((1-beta)*t for t in total)
                        assert game(bill,transfer,d,c,(21,22),controller) == baseline
                        assert tuple(dd+cc for dd,cc in zip(d,c)) == total
                        counts["strict_positive_share_stability_cases"] += 1

    counts.update(contract_checks())
    counts.update(menu_grid_checks())
    counts.update(procurement_checks())
    retail_counts, retail_results = retail_pricing_checks()
    counts.update(retail_counts)
    return {"status":"exact_checks_passed_not_an_analytic_proof", "counts":counts,
            "adversarial_cases":boundaries, "positive_cost_three_budget_witnesses":witnesses,
            "extension_counterexamples":extension_counterexamples(),
            "retail_pricing_checks":retail_results,
            "empirical_data_used":False,"experiments_run":False}


if __name__ == "__main__":
    print(json.dumps(check(),indent=2))
