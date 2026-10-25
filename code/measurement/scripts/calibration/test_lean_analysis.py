import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import lcb_isolation_release_v2 as r
import lcb_ngpu_lean_analysis as analysis
import lcb_ngpu_lean_extract as extract

CELL = 'q38-thinking|H100-primary|batch16|k8|r0'


def row(task, cand, *, weak4, audit, inp=100, reasoning=0, control=0, final=10, truncated=False, partitioned=True):
    return {'task_id': task, 'candidate_id': cand, 'input_tokens': inp, 'output_tokens': reasoning + control + final,
            'reasoning_tokens': reasoning, 'control_tokens': control, 'final_tokens': final, 'partitioned': partitioned,
            'truncated': truncated, 'finish_reason': 'length' if truncated else 'stop', 'has_code': not truncated,
            'status': 'judged', 'weak4': weak4, 'audit': audit, 't_arrival_s': 0.0, 't_first_token_s': 0.1, 't_done_s': 1.0}


class Delivery(unittest.TestCase):
    def test_first_candidate_that_passes_weak4_is_delivered_and_judged_by_the_audit_fold(self):
        e = analysis.episode([row('t', 0, weak4=False, audit=False, reasoning=50, control=2, final=5),
                              row('t', 1, weak4=True, audit=True, reasoning=70, control=2, final=7),
                              row('t', 2, weak4=True, audit=False, reasoning=10, control=2, final=3)])
        self.assertEqual((e['selected_id'], e['q_correct'], e['q_wrong']), (1, 1, 0))
        self.assertEqual(e['reasoning_tokens_all'], 50 + 2 + 70 + 2 + 10 + 2)
        self.assertEqual((e['delivered_output_tokens'], e['unselected_final_tokens']), (7, 5 + 3))
        self.assertEqual((e['billed_input_tokens'], e['audit_passes']), (300, 1))
        e['selected_id'] = None  # the episode dict is plain data

    def test_a_delivered_wrong_answer_is_q_wrong_and_no_weak_pass_is_an_abstention_that_still_costs_tokens(self):
        wrong = analysis.episode([row('t', 0, weak4=True, audit=False), row('t', 1, weak4=True, audit=True)])
        self.assertEqual((wrong['selected_id'], wrong['q_correct'], wrong['q_wrong']), (0, 0, 1))
        none = analysis.episode([row('t', 0, weak4=False, audit=False, reasoning=40, final=6),
                                 row('t', 1, weak4=False, audit=False, reasoning=60, final=4)])
        self.assertEqual((none['selected_id'], none['q_correct'], none['q_wrong']), (None, 0, 0))
        self.assertEqual((none['delivered_output_tokens'], none['unselected_final_tokens'], none['reasoning_tokens_all']), (0, 10, 100))

    def test_a_truncated_candidate_is_never_delivered_but_keeps_its_tokens(self):
        e = analysis.episode([row('t', 0, weak4=True, audit=True, reasoning=24000, final=0, truncated=True),
                              row('t', 1, weak4=True, audit=False, reasoning=10, final=2)])
        self.assertEqual((e['selected_id'], e['q_correct'], e['q_wrong'], e['truncated_candidates']), (1, 0, 1, 1))
        self.assertEqual(e['reasoning_tokens_all'], 24010)

    def test_missing_labels_or_partitions_are_none_not_zero(self):
        unlabelled = analysis.episode([row('t', 0, weak4=None, audit=None)])
        self.assertEqual((unlabelled['q_correct'], unlabelled['q_wrong'], unlabelled['reasoning_tokens_all']), (None, None, None))
        unpartitioned = analysis.episode([row('t', 0, weak4=True, audit=True, partitioned=False)])
        self.assertEqual(unpartitioned['q_correct'], 1)
        self.assertIsNone(unpartitioned['reasoning_tokens_all'])


class Cells(unittest.TestCase):
    def cell(self, **changes):
        candidates = [row('a', 0, weak4=True, audit=True, reasoning=90, control=2, final=8),
                      row('a', 1, weak4=False, audit=False, reasoning=100, control=2, final=8),
                      row('b', 0, weak4=False, audit=False, reasoning=200, control=2, final=0, truncated=True),
                      row('b', 1, weak4=True, audit=False, reasoning=30, control=2, final=8)]
        value = {'attempt': 'x1', 'cell_id': CELL, 'stratum_id': 'q38-thinking', 'config_id': 'batch16', 'k': 2, 'replicate_id': 0,
                 'subset': 'main', 'missing': [], 'candidates': candidates, 'service_wall_ns': 50 * 10**9,
                 'hardware_recorded': {'model': 'NVIDIA H200'},
                 'batches': [{'batch_id': 0, 'episodes': ['a', 'b'], 'candidate_count': 4, 'dispatch_s': 0.0, 'barrier_s': 12.5}]}
        value.update(changes)
        return value

    def test_cell_metrics_average_over_tasks_and_follow_the_meter_definitions(self):
        m = analysis.cell_metrics(self.cell())
        self.assertEqual((m['status'], m['tasks'], m['candidates']), ('complete', 2, 4))
        self.assertEqual((m['q_plus'], m['q_minus'], m['abstain']), (0.5, 0.5, 0.0))
        self.assertEqual(m['audit_pass_per_candidate'], 0.25)
        self.assertEqual(m['reasoning_tokens_all'], (92 + 102 + 202 + 32) / 2)  # reasoning + control of every candidate, per task
        self.assertEqual(m['H_all_non_delivered'], m['reasoning_tokens_all'] + m['unselected_final_tokens'])
        self.assertEqual(m['unselected_final_tokens'], (8 + 0) / 2)
        self.assertAlmostEqual(m['hidden_share_of_output'], (92 + 102 + 202 + 32) / (100 + 110 + 202 + 40))
        self.assertEqual((m['generation_latency_s'], m['generation_span_s'], m['service_wall_s']), (12.5, 12.5, 50.0))
        self.assertEqual(m['truncated_candidate_share'], 0.25)

    def test_incomplete_cells_report_what_is_missing_and_no_numbers(self):
        m = analysis.cell_metrics(self.cell(missing=['generated-samples.json'], candidates=[]))
        self.assertEqual((m['status'], m['missing']), ('incomplete', ['generated-samples.json']))
        self.assertNotIn('q_plus', m)

    def test_resources_are_keyed_by_attempt_because_pilot_and_main_share_cell_ids(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            path = Path(tmp) / 'collect.jsonl'
            def batch(output, occupancy):
                return {'output': output, 'cells': [{'cell_id': CELL, 'status': 'measured_pending_pilot_review',
                        'gpu_step_occupancy_ns': occupancy * 10**9, 'cpu_point_usec': 5 * 10**6, 'gpu_step_user_usec': 2 * 10**6}]}
            path.write_text(json.dumps(batch('/s/q4-return', 10)) + '\n' + json.dumps(batch('/s/thA0-return', 99)) + '\n')
            found = analysis.collect_resources([path])
            self.assertEqual(found['q4', CELL]['gpu_step_occupancy_s'], 10.0)
            self.assertEqual(found['thA0', CELL]['gpu_step_occupancy_s'], 99.0)

    def test_command_line_prints_a_header_and_one_row_per_cell_with_resources_merged(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            tmp = Path(tmp)
            (tmp / 'c.json').write_text(json.dumps(self.cell()))
            (tmp / 'collect.json').write_text(json.dumps({'output': '/s/x1-return', 'cells': [{'cell_id': CELL,
                'status': 'measured_pending_pilot_review', 'gpu_step_occupancy_ns': 77 * 10**9, 'cpu_point_usec': 3 * 10**6,
                'gpu_step_user_usec': 10**6}]}))
            out = io.StringIO()
            with redirect_stdout(out):
                rows = analysis.main([str(tmp / 'c.json'), '--collect', str(tmp / 'collect.json')])
            lines = out.getvalue().splitlines()
            self.assertEqual(lines[0].split('\t'), list(analysis.COLUMNS))
            self.assertEqual((len(rows), rows[0]['gpu_step_occupancy_s'], rows[0]['cpu_point_s']), (1, 77.0, 3.0))


class Energy(unittest.TestCase):
    SCENARIO = {'gpu_tdp_w': {'NVIDIA H200': 700, 'NVIDIA H100 NVL': 400}, 'busy_fraction_of_tdp': [0.35, 0.9],
                'idle_fraction_of_tdp': [0.1, 0.15]}

    def test_envelope_weights_busy_and_idle_seconds_by_the_declared_fractions(self):
        low, high = analysis.energy_envelope('NVIDIA H200', 3600, 1800, self.SCENARIO)
        self.assertAlmostEqual(low, 700 * (0.35 * 1800 + 0.1 * 1800) / 3.6e6)
        self.assertAlmostEqual(high, 700 * (0.9 * 1800 + 0.15 * 1800) / 3.6e6)
        self.assertLess(low, high)

    def test_unknown_hardware_or_inconsistent_times_give_no_estimate(self):
        self.assertIsNone(analysis.energy_envelope('NVIDIA B200', 100, 50, self.SCENARIO))
        self.assertIsNone(analysis.energy_envelope('NVIDIA H200', None, 50, self.SCENARIO))
        self.assertIsNone(analysis.energy_envelope('NVIDIA H200', 100, 200, self.SCENARIO))

    def test_the_shipped_scenario_covers_every_gpu_model_the_runs_used(self):
        scenario = json.loads(analysis.ENERGY.read_text())
        self.assertEqual(scenario['status'], 'declared_assumption_not_measured')
        for model in ('NVIDIA H200', 'NVIDIA H100 NVL', 'NVIDIA H100 80GB HBM3', 'NVIDIA A100-SXM4-80GB'):
            self.assertIsNotNone(analysis.energy_envelope(model, 1000, 500, scenario), model)
        self.assertLess(scenario['idle_fraction_of_tdp'][1], scenario['busy_fraction_of_tdp'][0])


class Extraction(unittest.TestCase):
    def attempt(self, tmp, *, drop=None):
        root = Path(tmp) / 'att'
        directory = root / 'cells' / '000'
        directory.mkdir(parents=True)
        config = Path(tmp) / 'config.json'
        config.write_bytes(r.encoded({'subset': 'main'}))
        manifest = {'cells': [CELL], 'cell_inputs': {CELL: {'generation_config': {'path': str(config)}}}}
        (root / 'manifest.json').write_bytes(r.encoded(manifest))
        def sample(task, cand, arrival):
            return {'task_id': task, 'candidate_id': cand, 'input_tokens': 100, 'output_tokens': 12, 'truncated': False,
                    'finish_reason': 'stop', 'code': 'print(1)', 'token_partition': {'reasoning_ids': [1] * 8, 'control_ids': [2, 3],
                    'final_ids': [4, 5]}, 'engine_timing': {'arrival_monotonic_s': 1000.0 + arrival,
                    'first_token_monotonic_s': 1000.5 + arrival, 'generation_complete_monotonic_s': 1002.0 + arrival}}
        files = {'generated-samples.json': r.encoded({'samples': [sample('a', 0, 0), sample('a', 1, 0)]}),
                 'W1.done.json': r.encoded({'results': [{'task_id': 'a', 'candidate_id': 0, 'status': 'judged', 'weak4': True, 'audit': False},
                                                       {'task_id': 'a', 'candidate_id': 1, 'status': 'judged', 'weak4': False, 'audit': False}]}),
                 'W2.done.json': r.encoded({'results': []}),
                 'cohort-events.jsonl': b''.join(r.encoded(e) for e in (
                     {'event': 'cohort_start', 'pool_id': 1, 'concurrency': 16, 'k': 2},
                     {'event': 'dispatch', 'batch_id': 0, 'since_start_s': 0.01, 'episodes': ['a'], 'candidate_count': 2},
                     {'event': 'generation_barrier', 'batch_id': 0, 'since_start_s': 2.1})),
                 'inference-summary.json': r.encoded({'service_started_mono_ns': 10, 'service_finished_mono_ns': 10 + 5 * 10**9,
                                                      'gpu_occupancy_ns': 5 * 10**9, 'hardware_recorded': {'model': 'NVIDIA H200'}})}
        for name, raw in files.items():
            if name != drop:
                (directory / name).write_bytes(raw)
        return root, manifest

    def test_rows_carry_tokens_labels_and_times_and_nothing_is_derived(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root, manifest = self.attempt(tmp)
            value = extract.extract_cell(root, manifest, 0)
            self.assertEqual((value['subset'], value['k'], value['config_id'], value['pool_id'], value['concurrency']),
                             ('main', 8, 'batch16', 1, 16))
            self.assertEqual(value['service_wall_ns'], 5 * 10**9)
            first, second = value['candidates']
            self.assertEqual((first['reasoning_tokens'], first['control_tokens'], first['final_tokens'], first['input_tokens']), (8, 2, 2, 100))
            self.assertEqual((first['weak4'], first['audit'], second['weak4'], first['t_done_s']), (True, False, False, 2.0))
            self.assertEqual(value['batches'], [{'batch_id': 0, 'episodes': ['a'], 'candidate_count': 2, 'dispatch_s': 0.01, 'barrier_s': 2.1}])

    def test_a_cell_without_its_originals_is_written_with_the_missing_list_and_no_candidates(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root, manifest = self.attempt(tmp, drop='W2.done.json')
            value = extract.extract_cell(root, manifest, 0)
            self.assertEqual(value['missing'], ['W2.done.json'])
            self.assertNotIn('candidates', value)

    def test_command_line_writes_one_file_per_cell_and_never_overwrites(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            root, _ = self.attempt(tmp)
            out = Path(tmp) / 'out'
            with redirect_stdout(io.StringIO()):
                written = extract.main([str(out), str(root)])
            self.assertEqual([w['file'] for w in written], ['att.cell-000.candidates.json'])
            self.assertEqual(json.loads((out / written[0]['file']).read_text())['cell_id'], CELL)
            with self.assertRaises(FileExistsError), redirect_stdout(io.StringIO()):
                extract.main([str(out), str(root)])


if __name__ == '__main__':
    unittest.main()
