"""Checks of the public retail evidence and conditional equilibrium boundaries."""
from fractions import Fraction as F
from pathlib import Path
import json
import shutil
import tempfile
import unittest

import retail_result_tables as r


class RetailEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name)/'evidence'
        shutil.copytree(r.ROOT/'evidence', self.evidence)

    def change(self, name, edit):
        p=self.evidence/name
        value=json.loads(p.read_text())
        edit(value)
        p.write_text(json.dumps(value))

    def test_saved_reference_recomputed(self):
        result=r.verify(self.evidence)
        self.assertEqual(result['reference_contract_profiles'],114)
        self.assertEqual(result['service_cells'],66)
        self.assertEqual(result['social_budget_pairs'],30)

    def test_altered_quality_changes_welfare(self):
        self.change('retail-pricing-inputs.json',lambda d:d['cells'][0].__setitem__('qplus_count',d['cells'][0]['qplus_count']+1))
        with self.assertRaisesRegex(ValueError,'threshold'):
            r.verify(self.evidence)

    def test_altered_reference_price_rejected(self):
        self.change('retail-pricing-reference.json',lambda d:d['central'][0].__setitem__('P50','1'))
        with self.assertRaisesRegex(ValueError,'Reference price match'):
            r.verify(self.evidence)

    def test_altered_budget_outcome_rejected(self):
        self.change('retail-pricing-reference.json',lambda d:d['central'][0]['outcomes_assuming_strict_user_purchase'].__setitem__('SMA',[1]))
        with self.assertRaisesRegex(ValueError,'Reference budget outcomes'):
            r.verify(self.evidence)

    def test_source_binding_rejected(self):
        self.change('retail-pricing-inputs.json',lambda d:d['cells'][0].__setitem__('source_extract_sha256','0'*64))
        with self.assertRaisesRegex(ValueError,'source binding'):
            r.verify(self.evidence)

    def test_sensitivity_count_is_recomputed(self):
        self.change('retail-pricing-reference.json',lambda d:d['full_token_sensitivity'].__setitem__('main_quote_budget_profiles',22))
        with self.assertRaisesRegex(ValueError,'Full-token sensitivity counts'):
            r.verify(self.evidence)

    def test_phase_boundaries_preserve_all_ties(self):
        d=r.Data(self.evidence);b=d.benchmark('q38-nonthinking','batch16')
        for rho in (F('1.9'),F('2.4'),F('3.4')):
            low,high=[d.cost(b['cells'][k,0],rho) for k in r.Q]
            self.assertEqual(d.outcomes(b,0,alpha=high/b['bill'][8,0],rho=rho)['SMA'],[0,8])
            self.assertEqual(d.outcomes(b,0,alpha=low/b['P'],rho=rho)['SMD'],[0,1])
            self.assertEqual(d.outcomes(b,0,alpha=high/b['P'],rho=rho)['SMD'],[1,8])

    def test_common_price_uses_all_six_cells(self):
        d=r.Data(self.evidence)
        for model in d.input['headline_anchors']:
            b=d.benchmark(model,'batch16')
            self.assertEqual(b['P'],sum(b['bill'].values())/6)
            self.assertEqual(len({d.arms(b,rep)['D'] for rep in range(3)}),1)


if __name__=='__main__':
    unittest.main()
