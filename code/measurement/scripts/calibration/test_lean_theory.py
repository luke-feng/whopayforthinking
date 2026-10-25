import unittest

import lcb_ngpu_lean_theory as theory

ENERGY = {'gpu_tdp_w': {'NVIDIA H200': 700}, 'busy_fraction_of_tdp': [0.35, 0.9], 'idle_fraction_of_tdp': [0.1, 0.15]}
PRICES = {'rates': [{'id': 't', 'input_per_million': '0', 'output_per_million': '1000000'}]}
STRATUM = 'toy'


def cell(gpu_s, *, reasoning, unselected, delivered=1, span=None, hardware='NVIDIA H200'):
    return {'tasks': 10, 'hardware': hardware, 'gpu_s': gpu_s, 'cpu_s': 0.0, 'wall_s': gpu_s, 'span_s': gpu_s / 2 if span is None else span,
            'billed_input_tokens': 0.0, 'delivered_output_tokens': delivered, 'reasoning_tokens_all': reasoning,
            'unselected_final_tokens': unselected}


def replicate(cells, rep, *, serial=(100, 600), pooled=(40, 250), config='batch16', scale=1.0):
    """serial/pooled = (k1 seconds, k8 seconds); the token meters give a bill of 2 at k1 and 10 at k8 under all_non_delivered."""
    for cfg, (low, high) in (('serial', serial), (config, pooled)):
        cells[STRATUM, cfg, 1, rep] = cell(low * scale, reasoning=1, unselected=0)
        cells[STRATUM, cfg, 8, rep] = cell(high * scale, reasoning=7, unselected=2)
    return cells


def scenario(**changes):
    base = {'capacity_usd_per_gpu_hour': [360], 'electricity_usd_per_kwh': 0.0, 'cpu_usd_per_core_hour': 0.0, 'bases': ['window'],
            'hidden_billing': ['all_non_delivered'], 'response_fee_usd': [0.0], 'anchors': {STRATUM: ['t']}}
    return {**base, **changes}


def run(cells, **changes):
    return theory.rows(cells, scenario(**changes), ENERGY, PRICES)


class Estimands(unittest.TestCase):
    def test_cost_differences_follow_the_theory_definitions(self):
        # 360 USD per GPU hour is 0.1 USD per GPU second: C = seconds / 100 per request of 10 tasks
        row = run(replicate({}, 0))[0]
        for key, value in (('C0L', 1.0), ('C0H', 6.0), ('C1L', 0.4), ('C1H', 2.5)):
            self.assertAlmostEqual(row[key], value)
        self.assertAlmostEqual(row['d0'], 5.0)
        self.assertAlmostEqual(row['d1'], 2.1)
        self.assertAlmostEqual(row['s_L'], 0.6)
        self.assertAlmostEqual(row['s_H'], 3.5)
        self.assertAlmostEqual(row['H1_lo'], 2.9)
        self.assertAlmostEqual(row['H1_hi'], 2.9)
        self.assertAlmostEqual(row['d0'] - row['d1'], row['s_H'] - row['s_L'])

    def test_the_price_free_gpu_second_difference_has_the_sign_of_h1(self):
        row = run(replicate({}, 0))[0]
        self.assertAlmostEqual(row['gpu_s_H1'], ((600 - 100) - (250 - 40)) / 10)

    def test_alpha_c_and_the_admission_interval(self):
        row = run(replicate({}, 0))[0]
        self.assertEqual((row['B0L'], row['B0H'], row['B1L'], row['B1H']), (2.0, 10.0, 2.0, 10.0))
        self.assertAlmostEqual(row['bill_drift'], 0.0)
        self.assertAlmostEqual(row['alpha_C0'], 5.0 / 8)
        self.assertAlmostEqual(row['alpha_C1'], 2.1 / 8)
        # lower = max(C0L/B0L, C1H/B1H) = max(0.5, 0.25); upper = min(C0H/B0H, 1) = 0.6
        self.assertAlmostEqual(row['adm_lower'], 0.5)
        self.assertAlmostEqual(row['adm_upper'], 0.6)
        self.assertEqual(row['adm_nonempty'], 'yes')

    def test_an_interval_whose_lower_end_reaches_the_upper_end_is_empty(self):
        row = run(replicate({}, 0), capacity_usd_per_gpu_hour=[3600])[0]  # costs x10: C0L/B0L = 5 > 1
        self.assertAlmostEqual(row['adm_lower'], 5.0)
        self.assertAlmostEqual(row['adm_upper'], 1.0)
        self.assertEqual(row['adm_nonempty'], 'no')

    def test_hidden_slice_decides_which_tokens_are_billed(self):
        both = run(replicate({}, 0), hidden_billing=['all_non_delivered', 'reasoning_only'])
        self.assertEqual({r['hidden']: r['B0H'] for r in both}, {'all_non_delivered': 10.0, 'reasoning_only': 8.0})

    def test_response_fee_enters_every_bill(self):
        rows = run(replicate({}, 0), response_fee_usd=[0.0, 3.0])
        self.assertEqual({r['response_fee_usd']: (r['B0L'], r['B0H']) for r in rows}, {0.0: (2.0, 10.0), 3.0: (5.0, 13.0)})

    def test_alpha_c_is_none_when_the_bill_does_not_rise_with_k(self):
        cells = replicate({}, 0)
        for cfg in ('serial', 'batch16'):
            cells[STRATUM, cfg, 8, 0] = cell(600, reasoning=1, unselected=0)
        row = run(cells)[0]
        self.assertIsNone(row['alpha_C0'])
        self.assertIsNone(row['bill_drift'])

    def test_a_stratum_without_an_archived_tariff_has_costs_but_no_bill(self):
        row = run(replicate({}, 0), anchors={})[0]
        self.assertAlmostEqual(row['H1_lo'], 2.9)
        self.assertTrue(all(row.get(key) is None for key in ('B0L', 'alpha_C0', 'adm_lower', 'adm_nonempty', 'anchor')))


class Gaps(unittest.TestCase):
    def test_a_group_needs_all_four_cells(self):
        cells = replicate({}, 0)
        del cells[STRATUM, 'batch16', 8, 0]
        self.assertEqual(run(cells), [])

    def test_a_missing_resource_gives_no_row_not_zero(self):
        cells = replicate({}, 0)
        cells[STRATUM, 'serial', 1, 0]['gpu_s'] = None
        self.assertEqual(run(cells), [])
        unknown_gpu = replicate({}, 0)
        unknown_gpu[STRATUM, 'serial', 1, 0]['hardware'] = 'NVIDIA Unlisted'
        self.assertEqual(run(unknown_gpu), [])

    def test_replicate_groups_are_each_replicate_and_the_mean_of_complete_ones(self):
        cells = replicate(replicate({}, 0), 2, serial=(120, 640), pooled=(50, 280))
        rows = run(cells)
        self.assertEqual([(r['group'], r['windows']) for r in rows], [('r0', 1), ('r2', 1), ('all', 2)])
        self.assertAlmostEqual(rows[2]['C0L'], (1.0 + 1.2) / 2)


class Envelope(unittest.TestCase):
    def test_the_declared_envelope_needs_exactly_three_windows(self):
        two = run(replicate(replicate({}, 0), 1))
        self.assertIsNone(next(r for r in two if r['group'] == 'all')['H1_env_lo'])
        three = run(replicate(replicate(replicate({}, 0), 1), 2))
        row = next(r for r in three if r['group'] == 'all')
        self.assertAlmostEqual(row['H1_env_lo'], 0.9 * 6.0 - 1.1 * 1.0 - 1.1 * 2.5 + 0.9 * 0.4)
        self.assertIsNone(next(r for r in three if r['group'] == 'r0')['H1_env_lo'])

    def test_the_pause_rule_flags_a_window_spread_over_a_tenth_of_the_mean(self):
        steady = run(replicate(replicate(replicate({}, 0), 1), 2))
        self.assertFalse(next(r for r in steady if r['group'] == 'all')['pause_rule'])
        spread = run(replicate(replicate(replicate({}, 0), 1), 2, scale=1.5))
        self.assertTrue(next(r for r in spread if r['group'] == 'all')['pause_rule'])


class Energy(unittest.TestCase):
    def test_the_energy_envelope_gives_two_endpoints_and_a_stable_sign(self):
        rows = run(replicate({}, 0), electricity_usd_per_kwh=1.0)
        row = rows[0]
        self.assertLess(row['H1_lo'], row['H1_hi'])
        self.assertGreater(row['H1_lo'], 0)

    def test_a_basis_that_drops_the_judging_wait_uses_the_generation_span(self):
        rows = run(replicate({}, 0), bases=['window', 'generation_span'])
        window, span = rows
        self.assertAlmostEqual(span['C0L'], 0.5)  # span is half the window in this fixture
        self.assertAlmostEqual(window['C0L'], 1.0)


class Menu(unittest.TestCase):
    def test_menu_takes_the_cheaper_pooled_configuration_per_action(self):
        cells = replicate({}, 0, pooled=(40, 250))
        replicate(cells, 0, pooled=(30, 300), config='batch64')
        rows = run(cells)
        by = {r['pooled']: r for r in rows}
        self.assertEqual(set(by), {'batch16', 'batch64', 'menu'})
        # k1: batch64 (30 s) is cheaper; k8: batch16 (250 s) is cheaper
        self.assertAlmostEqual(by['menu']['C1L'], 0.3)
        self.assertAlmostEqual(by['menu']['C1H'], 2.5)


class Hardware(unittest.TestCase):
    def test_hardware_is_reported_and_matching_is_flagged(self):
        cells = replicate({}, 0)
        self.assertTrue(run(cells)[0]['hardware_matched'])
        cells[STRATUM, 'batch16', 1, 0]['hardware'] = 'NVIDIA H100 80GB HBM3'
        cells[STRATUM, 'batch16', 8, 0]['hardware'] = 'NVIDIA H100 80GB HBM3'
        ENERGY['gpu_tdp_w']['NVIDIA H100 80GB HBM3'] = 700
        try:
            row = run(cells)[0]
        finally:
            del ENERGY['gpu_tdp_w']['NVIDIA H100 80GB HBM3']
        self.assertFalse(row['hardware_matched'])
        self.assertEqual((row['hardware_serial'], row['hardware_pooled']), ('H200', 'H100 80GB HBM3'))


class HardwareGroups(unittest.TestCase):
    ENERGY = {**ENERGY, 'gpu_tdp_w': {'NVIDIA H200': 700, 'NVIDIA H100 NVL': 400, 'NVIDIA H100 80GB HBM3': 700}}

    def cells(self):
        h200, nvl = 'NVIDIA H200', 'NVIDIA H100 NVL'
        cells = {}
        for slot, rep, seconds, model in ((('serial', 1), 0, 100, h200), (('serial', 8), 0, 900, nvl), (('batch16', 1), 0, 40, h200),
                                          (('batch16', 8), 0, 250, h200), (('serial', 1), 1, 120, nvl), (('serial', 8), 1, 600, h200),
                                          (('batch16', 1), 1, 50, nvl), (('batch16', 8), 1, 300, nvl)):
            high = slot[1] == 8
            cells[STRATUM, slot[0], slot[1], rep] = cell(seconds, reasoning=7 if high else 1, unselected=2 if high else 0, hardware=model)
        return cells

    def rows(self, cells):
        return theory.rows(cells, scenario(), self.ENERGY, PRICES)

    def test_a_hardware_group_takes_each_cell_from_whichever_replicate_ran_on_that_model(self):
        rows = {r['group']: r for r in self.rows(self.cells())}
        # neither replicate has its four cells on one model, so the replicate groups are flagged as mixed
        self.assertFalse(rows['r0']['hardware_matched'])
        self.assertFalse(rows['r1']['hardware_matched'])
        h200, nvl = rows['hw:H200'], rows['hw:H100 NVL']
        self.assertTrue(h200['hardware_matched'] and nvl['hardware_matched'])
        # H200: serial k1 and pooled k1/k8 from r0, serial k8 from r1: the numbers of the plain single-replicate example
        for key, value in (('C0L', 1.0), ('C0H', 6.0), ('C1L', 0.4), ('C1H', 2.5), ('H1_lo', 2.9)):
            self.assertAlmostEqual(h200[key], value)
        # NVL: serial k1 and pooled from r1, serial k8 from r0
        for key, value in (('C0L', 1.2), ('C0H', 9.0), ('C1L', 0.5), ('C1H', 3.0), ('d0', 7.8), ('d1', 2.5), ('H1_lo', 5.3)):
            self.assertAlmostEqual(nvl[key], value)
        self.assertEqual((h200['windows'], h200['hardware_serial'], h200['hardware_pooled']), (1, 'H200', 'H200'))

    def test_a_model_that_lacks_one_of_the_four_cells_forms_no_group(self):
        cells = self.cells()
        cells[STRATUM, 'serial', 1, 2] = cell(100, reasoning=1, unselected=0, hardware='NVIDIA H100 80GB HBM3')
        self.assertNotIn('hw:H100 80GB HBM3', {r['group'] for r in self.rows(cells)})

    def test_hardware_groups_exist_for_pooled_configurations_but_not_the_menu(self):
        cells = self.cells()
        for (stratum, cfg, k, rep), c in list(cells.items()):
            if cfg == 'batch16':
                cells[stratum, 'batch64', k, rep] = dict(c)
        pooled = {(r['pooled'], r['group']) for r in self.rows(cells) if r['group'].startswith('hw:')}
        self.assertEqual(pooled, {(p, g) for p in ('batch16', 'batch64') for g in ('hw:H200', 'hw:H100 NVL')})

    def test_the_three_window_rules_need_three_cells_in_every_slot(self):
        cells = self.cells()
        row = next(r for r in self.rows(cells) if r['group'] == 'hw:H200')
        self.assertIsNone(row['H1_env_lo'])
        self.assertIsNone(row['pause_rule'])


if __name__ == '__main__':
    unittest.main()
