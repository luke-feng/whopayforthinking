"""Replay headline diagnostics with the hash-checked 43db147 numerical kernels.

Requires the repository history, not private experiment archives. Only the two
named numerical functions are compiled from the fixed source. The registered
primary pipeline is not invoked or declared completed by this check.
"""
from collections import Counter
from fractions import Fraction as F
from functools import lru_cache
from hashlib import sha256
from math import lcm
from pathlib import Path
from types import SimpleNamespace
import argparse
import ast
import json
import platform
import random
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
COMMIT = '43db14772555005af3ccb02f84b2cf8278dd337e'
SOURCE = 'scripts/calibration/theory_bootstrap.py'
SOURCE_SHA = '4900995d62276a4ec1bfdfc2b7d7272ce05a1f50184e050a6fa7141fe5e7a8cd'


def verify(repository):
    raw = subprocess.check_output(['git', '-C', str(repository), 'show', COMMIT + ':' + SOURCE])
    assert sha256(raw).hexdigest() == SOURCE_SHA
    tree = ast.parse(raw)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in ('percentile', 'paired_percentiles')]
    assert len(functions) == 2
    namespace = {'Counter': Counter, 'F': F, 'lru_cache': lru_cache, 'sha256': sha256,
                 'lcm': lcm, 'platform': platform, 'random': random, 'struct': struct,
                 'tm': SimpleNamespace(number=F)}
    exec(compile(ast.Module(body=functions, type_ignores=[]), SOURCE, 'exec'), namespace)
    engine = namespace['paired_percentiles']
    data = json.loads((ROOT / 'evidence/bootstrap-inputs.json').read_text())
    result = json.loads((ROOT / 'evidence/bootstrap-results.json').read_text())
    cells = {(c['stratum'], c['config'], c['k'], c['replicate']): c for c in data['cells']}
    def bills(cell, anchor):
        cols, price = cell['columns'], data['prices'][anchor]
        return [(F(price['input']) * a + F(price['output']) * (b + c + d)) / 10**6
                for a, b, c, d in zip(cols['billed_input_tokens'], cols['delivered_output_tokens'],
                                      cols['reasoning_tokens_all'], cols['unselected_final_tokens'])]
    def cost_delta(stratum):
        row = next(r for r in result['financial'] if r['stratum'] == stratum and r['replicate'] == 1
                   and r['policy'] == 'batch16' and r['basis'] == 'window' and r['rate'] == 2.4
                   and r['anchor'] == 'di-q38-27b-list')
        return F(row['costs_exact'][1]) - F(row['costs_exact'][0])
    columns = {}
    for s in ('q38-thinking', 'q38-nonthinking'):
        for k in (1, 8):
            cell = cells[s, 'serial', k, 1]
            columns[s, k, 'bill'] = bills(cell, 'di-q38-27b-list')
            columns[s, k, 'q_correct'] = cell['columns']['q_correct']
    on_cost, off_cost = cost_delta('q38-thinking'), cost_delta('q38-nonthinking')
    def statistic(means):
        on = means['q38-thinking', 8, 'bill'] - means['q38-thinking', 1, 'bill']
        off = means['q38-nonthinking', 8, 'bill'] - means['q38-nonthinking', 1, 'bill']
        return {'quality': means['q38-thinking', 8, 'q_correct'] - means['q38-thinking', 1, 'q_correct'],
                'bill_increment': on, 'alpha_ratio': (on_cost / on) / (off_cost / off)}
    first = engine(columns, statistic, draws=10000, seed=20261010)
    target = next(c for c in result['paired_contrasts'] if c['stratum'] == 'q38-thinking'
                  and c['replicate'] == 1 and c['contrast'] == 'budget' and c['config'] == 'serial')
    h2 = next(c for c in result['h2'] if c['replicate'] == 1 and c['config'] == 'serial' and c['basis'] == 'window')
    expected = {'quality': target['metrics']['q_correct'], 'bill_increment': target['metrics']['bill_headline_usd'],
                'alpha_ratio': h2['alpha_on_over_off']}
    checks = []
    def compare(actual, expected):
        assert actual['resample_indices_sha256'] == result['resample_indices_sha256']
        for key, value in expected.items():
            row = actual['metrics'][key]
            point, interval = str(row['point']), list(map(str, row['percentile_95']))
            assert point == value['point_exact'] and interval == value['percentile_95_exact']
            assert row['undefined_draws'] == value['undefined_draws']
            checks.append({'metric': key, 'point_exact': point, 'percentile_95_exact': interval,
                           'undefined_draws': row['undefined_draws'], 'matches': True})
    compare(first, expected)
    row = max((r for r in result['financial'] if r['policy'] != 'menu'),
              key=lambda r: r['metrics']['admission_gap']['percentile_95'][1])
    keys = [(row['stratum'], 'serial', 1, row['replicate']), (row['stratum'], 'serial', 8, row['replicate']),
            (row['stratum'], row['policy'], 1, row['replicate']), (row['stratum'], row['policy'], 8, row['replicate'])]
    columns = {i: bills(cells[key], row['anchor']) for i, key in enumerate(keys)}
    costs = list(map(F, row['costs_exact']))
    def admission(means):
        lower = max(costs[0] / means[0], costs[3] / means[3])
        upper = min(costs[1] / means[1], F(1))
        return {'admission_lower': lower, 'admission_upper': upper, 'admission_gap': upper - lower}
    compare(engine(columns, admission, draws=10000, seed=20261010),
            {k: row['metrics'][k] for k in ('admission_lower', 'admission_upper', 'admission_gap')})
    return {'schema': 'bootstrap-reference-replay-v1', 'reference_commit': COMMIT,
            'reference_source_sha256': SOURCE_SHA, 'kernels': ['percentile', 'paired_percentiles'],
            'numeric_input_adapter': 'fractions.Fraction on validated rational inputs',
            'draws': 10000, 'seed': 20261010, 'resample_indices_sha256': first['resample_indices_sha256'],
            'result_sha256': sha256((ROOT / 'evidence/bootstrap-results.json').read_bytes()).hexdigest(),
            'checks': checks, 'exact_point_or_endpoint_checks': 3 * len(checks),
            'registered_primary_pipeline_executed': False,
            'scope': 'Numerical-kernel replay only. The registered pipeline remains paused and the paper intervals are outside-gate conditional diagnostics.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=ROOT.parents[1])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    value = verify(args.repository)
    with args.out.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    print('18 exact point/endpoint checks passed, registered numerical kernels only')
