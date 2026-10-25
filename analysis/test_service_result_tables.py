"""Guard the identities and scopes of the follow-up paper tables."""
from pathlib import Path
import json
import shutil
import tempfile
import unittest

import service_result_tables as tables


class FollowupTables(unittest.TestCase):
    def test_five_strata_are_kept_distinct(self):
        service, a100, pipeline, _ = tables.panels()
        self.assertEqual(len(service.rows), 66)
        self.assertEqual(len(a100.rows), 15)
        self.assertEqual(len(pipeline.rows), 72)
        self.assertEqual({s: sum(k[0] == s for k in service.rows) for s in tables.STRATA},
                         dict(zip(tables.STRATA, [12, 12, 12, 18, 12])))

    def test_exact_timing_contrasts_reproduce_theory_export(self):
        service, a100, _, _ = tables.panels()
        for panel, basis in [(service, 'service'), (a100, 'window')]:
            for s in sorted({k[0] for k in panel.rows}):
                for p in panel.configs(s):
                    for rep in ['r0', 'r1', 'r2']:
                        if (s, p, 8, rep) not in panel.rows:
                            continue
                        v = panel.contrast(s, p, rep, basis)['h1']
                        expected = {r['gpu_s_H1'] for r in panel.theory if (r['stratum'], r['pooled'], r['group'], r['basis']) == (s, p, rep, basis)}
                        self.assertEqual({format(float(v), '.5g')}, expected)

    def test_all_three_a100_reruns_retain_extended_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'results').mkdir()
            for filename in tables.FILES.values():
                shutil.copyfile(tables.ROOT / 'evidence/results' / filename, root / 'results' / filename)
            value = json.loads((tables.ROOT / 'evidence/service-followup-provenance.json').read_text())
            value['a100_reruns'][0]['generation_timeout']['revised'] = False
            (root / 'service-followup-provenance.json').write_text(json.dumps(value))
            with self.assertRaises(AssertionError):
                tables.validate(root)

    def test_pipeline_bootstrap_does_not_gain_service_cells(self):
        result = json.loads((tables.ROOT / 'evidence/bootstrap-results.json').read_text())
        self.assertEqual(len(result['cells']), 72)
        self.assertTrue(all('service' not in r['id'] for r in result['cells']))

    def test_followup_validation(self):
        result = tables.validate()
        self.assertEqual(result['service_same_gpu_contrasts'], 18)
        self.assertEqual(result['service_admission_rows'], 896)
        self.assertEqual(result['a100_extended_reruns'], 3)


if __name__ == '__main__':
    unittest.main()
