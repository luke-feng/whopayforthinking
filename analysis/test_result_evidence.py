"""Offline tests of the anonymous paper bundle, never of candidate execution."""
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from unittest.mock import patch

import make_result_tables as tables
import result_evidence as evidence


class Evidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(evidence.EVIDENCE, self.root / 'evidence')
        self.override = patch.multiple(evidence, ROOT=self.root, EVIDENCE=self.root / 'evidence')
        self.override.start()
        self.addCleanup(self.override.stop)

    def replace(self, name, value):
        path = self.root / 'evidence' / name
        raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
        path.write_bytes(raw)
        manifest_path = self.root / 'evidence/results-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        for row in manifest['files'] + manifest['derived_receipts']:
            if row['file'] == name:
                row['bytes'] = len(raw)
                row['sha256'] = hashlib.sha256(raw).hexdigest()
                if name.endswith('.tsv'):
                    row['rows'] = len(raw.splitlines()) - 1
        manifest_path.write_text(json.dumps(manifest))

    def test_original_bundle_passes(self):
        result = evidence.verify()
        self.assertEqual(result['restricted_menu_h1'], '-35/106')
        self.assertEqual(result['headline_admission_rows'], 1400)
        self.assertEqual(result['pilot_counts']['two_python_blocks'], 11)
        self.assertTrue(result['registered_abstract_preserved'])
        self.assertFalse(result['current_abstract_matches_registered'])
        self.assertTrue(result['current_abstract_approved'])

    def test_wrong_rounding_is_rejected_even_with_updated_hash(self):
        value = evidence.read('restricted-menu-counts.json')
        value['rounded_one_decimal'] = '-0.4'
        self.replace('restricted-menu-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'rounding'):
            evidence.verify()

    def test_rounded_window_input_is_rejected(self):
        value = evidence.read('restricted-menu-counts.json')
        row = next(r for r in value['rows'] if r['cell_alias'] == 'serial_k1')
        row['gpu_step_occupancy_ns'] = 18880 * 10**9
        self.replace('restricted-menu-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'original precision'):
            evidence.verify()

    def test_menu_exact_values_preserve_the_restricted_receipt(self):
        self.assertEqual(evidence.menu_h1()['h1'], Fraction(157, 53))
        self.assertEqual(evidence.menu_h1(False)['h1'], Fraction(-255, 106))
        self.assertEqual(evidence.menu_h1(False, 'r1')['h1'], evidence.restricted_h1())
        self.assertEqual(evidence.menu_h1()['selected'], {1: 'batch64', 8: 'batch64'})
        self.assertEqual(evidence.menu_h1(False)['selected'], {1: 'batch64', 8: 'batch16'})

    def test_menu_bound_identity_is_checked_against_the_export(self):
        value = evidence.read('menu-window-counts.json')
        row = next(r for r in value['rows'] if r['extended_bound'])
        row['extended_bound'] = False
        self.replace('menu-window-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'extended-bound identity'):
            evidence.verify()

    def test_menu_rounding_cannot_replace_exact_shared_r1_windows(self):
        value = evidence.read('menu-window-counts.json')
        row = next(r for r in value['rows'] if (r['configuration'], r['k'], r['replicate']) == ('serial', 1, 'r1'))
        row['gpu_step_occupancy_ns'] = 18880 * 10**9
        self.replace('menu-window-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'contradicts original restricted receipt'):
            evidence.verify()

    def test_duplicate_source_line_is_rejected(self):
        value = evidence.read('pilot-format-counts.json')
        value['rows'][1]['source_line'] = value['rows'][0]['source_line']
        self.replace('pilot-format-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'uniqueness'):
            evidence.verify()

    def test_changed_pilot_category_is_rejected(self):
        value = evidence.read('pilot-format-counts.json')
        row = next(r for r in value['rows'] if r['category'] == 'two_python_blocks')
        row['category'] = 'one_unlabelled_block'
        self.replace('pilot-format-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'category'):
            evidence.verify()

    def test_private_path_is_rejected_even_with_updated_hash(self):
        value = evidence.read('pilot-format-counts.json')
        value['source_path'] = '/home/private/source'
        self.replace('pilot-format-counts.json', value)
        with self.assertRaisesRegex(ValueError, 'Private identity'):
            evidence.verify()

    def test_modified_input_bytes_are_rejected(self):
        path = self.root / 'evidence/results/lean-main-resources-4-2026-10-23.tsv'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'byte count'):
            evidence.verify()

    def test_unlisted_file_is_rejected(self):
        (self.root / 'evidence/private-extra.txt').write_text('not part of the public whitelist')
        with self.assertRaisesRegex(ValueError, 'Unexpected file'):
            evidence.verify()

    def test_false_empty_band_label_is_rejected(self):
        path = self.root / 'evidence/results/lean-main-theory-5-2026-10-24.tsv'
        rows = list(csv.DictReader(io.StringIO(path.read_text()), delimiter='\t'))
        row = next(r for r in rows if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0')
        row.update(C0L='0.00000001', C1H='0.00000001', C0H='100')
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
        self.replace('results/lean-main-theory-5-2026-10-24.tsv', stream.getvalue().encode())
        with self.assertRaisesRegex(ValueError, 'admission arithmetic'):
            evidence.verify()


class ResultTables(unittest.TestCase):
    def test_readme_evidence_entrypoint_isolated_from_other_imports(self):
        with tempfile.TemporaryDirectory() as cwd:
            run = subprocess.run([sys.executable, '-I', '-B', str(evidence.ROOT / 'result_evidence.py')],
                                 cwd=cwd, text=True, capture_output=True, check=True)
        result = json.loads(run.stdout)
        self.assertEqual(result['status'], 'anonymous_paper_evidence_verified')
        self.assertEqual(result['paired_prompt_bootstrap']['fixed_configuration_financial_rows'], 588)

    def test_tables_match_published_fragments(self):
        generated = tables.render_files()
        self.assertEqual(set(generated), {p.name for p in (tables.ROOT / 'tables').glob('*.tex')})
        for name, content in generated.items():
            self.assertEqual(content, (tables.ROOT / 'tables' / name).read_text(), name)

    def test_central_rates_match_the_evidence_manifest(self):
        scenario = evidence.read('results-manifest.json')['cost_scenario']
        self.assertEqual(scenario['central_capacity_usd_per_gpu_hour']['H100-class'], float(tables.CENTRAL))
        self.assertEqual(scenario['capacity_usd_per_gpu_hour'], list(map(float, tables.GRID)))
        self.assertEqual(scenario['electricity_usd_per_kwh'], 0.15)
        self.assertEqual(scenario['cpu_usd_per_core_hour'], 0.03)

    def test_admission_scoping_keeps_half_dollar_rows(self):
        theory = tables.Theory(tables.read('theory'))
        pre = [r for r in theory.rows if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
        half = [r for r in pre if r['gpu_hour_usd'] == '0.5' and float(r['C0L']) < float(r['B0L'])]
        self.assertEqual(len(half), 42)
        self.assertEqual({r['stratum'] for r in half}, {'q38-thinking', 'q38-nonthinking'})
        self.assertTrue(all(not r['group'].startswith('hw:H100') for r in half))
        self.assertTrue(all(float(r['C0L']) > float(r['B0L']) for r in pre if r['gpu_hour_usd'] == '2.4'))

    def test_energy_box_uses_opposite_ends_for_opposite_signs(self):
        # One cell per slot, identical GPU/CPU cost and deliberately different
        # energy ranges. The constant costs cancel; the minimum is not the
        # regime-level serial-low/pooled-high corner.
        cells = type('Cells', (), {'rows': {}})()
        for (config, k), (lo, hi) in zip([('serial', 1), ('serial', 8), ('batch16', 1), ('batch16', 8)],
                                       [(1, 3), (4, 8), (2, 7), (5, 9)]):
            cells.rows[('fixture', config, k, 'r0')] = {
                'hardware': 'NVIDIA H100', 'gpu_step_occupancy_s': '10', 'cpu_point_s': '0',
                'tasks': '1', 'energy_kwh_lo': str(lo), 'energy_kwh_hi': str(hi)}
        self.assertAlmostEqual(tables.energy_box_minimum(cells, 'fixture', 'batch16', 'H100', 2.4),
                               .15 * (4 - 3 - 9 + 2))


if __name__ == '__main__':
    unittest.main()
