"""Paired prompt bootstrap of the frozen 72-cell paper snapshot.

Preparation reads existing compact extracts and collect receipts, never executes
candidates, and writes anonymous sufficient statistics. Inference uses the
registered random.Random index stream and exact rational percentile endpoints.
NumPy accelerates integer dot products; no floating point is used to decide ties.
These conditional diagnostics are computed outside the registered pipeline,
whose cost-spread gate withholds its entire primary bootstrap on these data.
"""
from collections import Counter
from fractions import Fraction as F
from hashlib import sha256
from math import lcm
from pathlib import Path
import argparse
import csv
import json
import platform
import random
import struct
import tarfile

ROOT = Path(__file__).resolve().parent
DRAW_COUNT = 10000
SEED = 20261010
N = 106
FIELDS = ('q_correct', 'q_wrong', 'refusal', 'billed_input_tokens',
          'delivered_output_tokens', 'reasoning_tokens_all',
          'unselected_final_tokens', 'generation_latency_s')
STRATA = ('coder-nonthinking', 'nemotron-thinking', 'q35-thinking',
          'q38-nonthinking', 'q38-thinking')
HEADLINE = {'q35-thinking': 'di-q35-9b', 'q38-nonthinking': 'di-q38-27b-list',
            'q38-thinking': 'di-q38-27b-list'}
ANCHORS = {'q35-thinking': ('di-q35-9b', 'together-q35-9b'),
           'q38-nonthinking': ('di-q38-27b-list', 'di-q38-27b-promo', 'partition-q38-27b-standard'),
           'q38-thinking': ('di-q38-27b-list', 'di-q38-27b-promo', 'partition-q38-27b-standard')}
ARCHIVES = {
    'analysis-1.tar.gz': 'b696b2cf3ec92a68e4d0fa789785a2361a159d23877b717283ac646530dd13ec',
    'analysis-2.tar.gz': '3ba75ff1bd003fadb915e8f6c48402fbd25ad9ee82301346839d45678dfba979',
    'analysis-th1.tar.gz': '275bb733365a2d10406e5ded9db01f98bdd4763bdb707671a8e6c80ed273ec16',
    'main-collect-1.tar.gz': '9bbd7b8dbc9852936e80ace9de7b88e47b36648cdf349374d97a373526a459ae',
    'main-collect-2.tar.gz': 'f6d6f899857e9d53d5e37eb1cbd08a89ec6db3fd7d666140ec897d59585f4fdf',
    'main-collect-th1.tar.gz': '29245027c550d526e7afd0df5d7128128d76a968918e2ec0c84b567fd5ef5551',
    'thC-results.tar.gz': '2b502227185255420fb0aa7f0d2083a47ee9949ff5bc4684584244779cae4c94',
}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(encoded(value))


def prompt_columns(cell, roster):
    require(not cell['missing'] and cell.get('subset') == 'main', 'Incomplete/non-main extract')
    require(cell.get('selection_mode', 'deferred') == 'deferred', 'Only frozen pipeline extracts here')
    grouped = {task: [] for task in roster}
    for row in cell['candidates']:
        require(row['task_id'] in grouped, 'Unexpected task')
        grouped[row['task_id']].append(row)
    barriers = {}
    for batch in cell['batches']:
        require(batch['barrier_s'] is not None, 'Missing batch barrier')
        for task in batch['episodes']:
            require(task not in barriers, 'Task appears in multiple scheduler batches')
            barriers[task] = batch['barrier_s']
    require(set(barriers) == set(roster), 'Incomplete latency roster')
    columns = {field: [] for field in FIELDS}
    for task in roster:
        rows = sorted(grouped[task], key=lambda r: r['candidate_id'])
        require([r['candidate_id'] for r in rows] == list(range(cell['k'])), 'Incomplete candidate block')
        require(all(type(r['weak4']) is bool and type(r['audit']) is bool and r['partitioned'] for r in rows),
                'Missing labels or token partition')
        require(all(r['output_tokens'] == r['reasoning_tokens'] + r['control_tokens'] + r['final_tokens'] for r in rows),
                'Token conservation')
        chosen = next((r for r in rows if r['weak4'] and not r['truncated']), None)
        require(chosen is None or chosen['has_code'], 'Selected candidate has no executable answer')
        correct = int(chosen is not None and chosen['audit'])
        wrong = int(chosen is not None and not chosen['audit'])
        delivered = 0 if chosen is None else chosen['final_tokens']
        values = (correct, wrong, 1 - correct - wrong,
                  sum(r['input_tokens'] for r in rows), delivered,
                  sum(r['reasoning_tokens'] + r['control_tokens'] for r in rows),
                  sum(r['final_tokens'] for r in rows) - delivered, str(barriers[task]))
        for field, value in zip(FIELDS, values):
            columns[field].append(value)
    return columns


def prepare(source):
    source = Path(source)
    extracts, collects, skipped = {}, {}, []
    for filename, expected in ARCHIVES.items():
        path = source / filename
        require(sha256(path.read_bytes()).hexdigest() == expected, 'Archive hash: ' + filename)
        with tarfile.open(path) as archive:
            for member in archive:
                if not member.isfile() or not member.name.endswith(('.candidates.json', '-collect.json')):
                    continue
                raw = archive.extractfile(member).read()
                value = json.loads(raw, parse_float=str)
                binding = {'archive_sha256': expected, 'member_sha256': sha256(raw).hexdigest()}
                if member.name.endswith('.candidates.json'):
                    key = (value['attempt'], value['cell_id'])
                    require(key not in extracts, 'Duplicate candidate extract')
                    extracts[key] = value, binding
                else:
                    attempt = Path(value['output']).name.removesuffix('-return')
                    for cell in value['cells']:
                        if cell['status'].startswith('measured'):
                            key = (attempt, cell['cell_id'])
                            require(key not in collects, 'Duplicate collected cell')
                            collects[key] = cell, binding
    roster_raw = (source / 'data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json').read_bytes()
    roster = json.loads(roster_raw)['main_task_ids']
    require(len(roster) == len(set(roster)) == N, 'Frozen 106-task roster')
    resources_raw = (ROOT / 'evidence/results/lean-main-resources-4-2026-10-23.tsv').read_bytes()
    resources = list(csv.DictReader(resources_raw.decode().splitlines(), delimiter='\t'))
    cells, used = [], set()
    for record in resources:
        if record['status'] != 'complete':
            continue
        key = record['attempt'], record['cell_id']
        require(key in extracts and key in collects, 'Missing original for complete published cell')
        extract, extract_binding = extracts[key]
        collect, collect_binding = collects[key]
        cols = prompt_columns(extract, roster)
        stratum, _, config, k, rep = record['cell_id'].split('|')
        hardware = extract['hardware_recorded']['model']
        require(hardware == record['hardware'], 'Hardware mismatch')
        for field, printed in [('q_correct', 'q_plus'), ('q_wrong', 'q_minus'), ('refusal', 'abstain'),
                               ('generation_latency_s', 'generation_latency_s')]:
            mean = sum(F(x) for x in cols[field]) / N
            require(float(format(float(mean), '.4g')) == float(record[printed]), 'Published moment mismatch: ' + field)
        for field in FIELDS[3:7]:
            require(float(format(sum(cols[field]) / N, '.4g')) == float(record[field]), 'Published token mismatch: ' + field)
        cell = {'id': '|'.join((stratum, config, k, rep)), 'stratum': stratum,
                'config': config, 'k': int(k[1:]), 'replicate': int(rep[1:]), 'hardware': hardware,
                'extended_bound': record['timeout_revised'] == 'True', 'columns': cols,
                'gpu_window_ns': collect['gpu_step_occupancy_ns'], 'cpu_usec': collect['cpu_point_usec'],
                'service_wall_ns': extract['service_wall_ns'],
                'generation_span_s': str(max(F(b['barrier_s']) for b in extract['batches'])),
                'source_extract': extract_binding, 'source_collect': collect_binding}
        require(all(type(cell[f]) is int and cell[f] >= 0 for f in ('gpu_window_ns', 'cpu_usec', 'service_wall_ns')),
                'Missing whole-window resources')
        cells.append(cell)
        used.add(key)
    require(len(cells) == len({c['id'] for c in cells}) == 72, 'Frozen 72-cell coverage')
    for key in sorted(set(extracts) - used):
        value, binding = extracts[key]
        require(value['missing'], 'Unaccounted complete extract')
        skipped.append({'source_extract': binding, 'reason': 'original_incomplete_attempt_retained',
                        'missing': value['missing']})
    prices_raw = (source / 'data/calibration/public-prices-2026-10-08.json').read_bytes()
    wanted = {x for group in ANCHORS.values() for x in group}
    prices = {r['id']: {'input': r['input_per_million'], 'output': r['output_per_million']}
              for r in json.loads(prices_raw)['rates'] if r['id'] in wanted}
    require(set(prices) == wanted, 'Missing archived tariff')
    manifest = json.loads((ROOT / 'evidence/results-manifest.json').read_text())
    method_path = source / 'scripts/calibration/theory_bootstrap.py'
    return {'schema': 'anonymous-paired-prompt-inputs-v1', 'n_prompts': N,
            'task_aliases': ['p%03d' % i for i in range(N)],
            'roster_sha256': sha256(encoded(roster)).hexdigest(), 'frozen_manifest_sha256': sha256(roster_raw).hexdigest(),
            'resource_export_sha256': sha256(resources_raw).hexdigest(), 'price_source_sha256': sha256(prices_raw).hexdigest(),
            'method_source_sha256': sha256(method_path.read_bytes()).hexdigest(),
            'cost_scenario': manifest['cost_scenario'], 'energy': manifest['energy_assumption'],
            'prices': prices, 'cells': sorted(cells, key=lambda c: c['id']), 'excluded_originals': skipped,
            'scope': '72 main pipeline cells only, including two separately marked extended-bound completions. '
                     'Each anonymous index is the same frozen task across every cell. Aggregation retains all candidate tokens '
                     'and the fixed selector result before resampling. Raw generated text and host identities are excluded.'}


def indices(n, draws=DRAW_COUNT, seed=SEED):
    import numpy as np
    rng = random.Random(seed)
    counts = np.zeros((draws + 1, n), dtype=np.int64)
    counts[0] = 1
    digest = sha256()
    for d in range(1, draws + 1):
        sample = [rng.randrange(n) for _ in range(n)]
        digest.update(struct.pack('<%dI' % n, *sample))
        for i, count in Counter(sample).items():
            counts[d, i] = count
    return counts, digest.hexdigest()


class Series:
    """Rational values at point index zero and each bootstrap index thereafter."""
    def __init__(self, numerator, denominator=1, invalid=None):
        import numpy as np
        self.n = np.asarray(numerator, dtype=object)
        self.d = np.broadcast_to(np.asarray(denominator, dtype=object), self.n.shape)
        self.invalid = np.zeros(self.n.shape, dtype=bool) if invalid is None else np.asarray(invalid, dtype=bool)

    def value(self, index):
        return None if self.invalid[index] else F(int(self.n[index]), int(self.d[index]))

    def __add__(self, other):
        return Series(self.n * other.d + other.n * self.d, self.d * other.d, self.invalid | other.invalid)

    def __sub__(self, other):
        return Series(self.n * other.d - other.n * self.d, self.d * other.d, self.invalid | other.invalid)

    def ratio(self, other):
        import numpy as np
        invalid = self.invalid | other.invalid | (other.n <= 0)
        # Invalid draws retain their position and are never silently discarded.
        den = np.where(invalid, 1, self.d * other.n)
        return Series(self.n * other.d, den, invalid)

    def extremum(self, other, maximum):
        import numpy as np
        take_self = self.n * other.d >= other.n * self.d
        if not maximum:
            take_self = ~take_self
        return Series(np.where(take_self, self.n, other.n), np.where(take_self, self.d, other.d),
                      self.invalid | other.invalid)

    def summary(self):
        import numpy as np
        invalid = int(self.invalid[1:].sum())
        point = self.value(0)
        lo = hi = None
        if not invalid:
            ns, ds = self.n[1:], self.d[1:]
            order = np.argsort(ns.astype(float) / ds.astype(float), kind='stable')
            # Verify the entire proposed order with exact cross products.
            # Rare floating ties fall back to exact Fraction sorting.
            sn, sd = ns[order], ds[order]
            if np.any(sn[1:] * sd[:-1] < sn[:-1] * sd[1:]):
                order = sorted(range(len(ns)), key=lambda i: F(int(ns[i]), int(ds[i])))
            def at(probability):
                position = (len(ns) - 1) * probability
                left = position.numerator // position.denominator
                weight = position - left
                a, b = order[left], order[min(left + 1, len(order) - 1)]
                return F(int(ns[a]), int(ds[a])) * (1 - weight) + F(int(ns[b]), int(ds[b])) * weight
            lo, hi = at(F(1, 40)), at(F(39, 40))
        return {'point': None if point is None else float(point),
                'percentile_95': None if invalid else [float(lo), float(hi)],
                'point_exact': None if point is None else str(point),
                'percentile_95_exact': None if invalid else [str(lo), str(hi)],
                'undefined_draws': invalid, 'draws': len(self.n) - 1,
                'positive_draws': int(((self.n[1:] > 0) & ~self.invalid[1:]).sum()),
                'zero_draws': int(((self.n[1:] == 0) & ~self.invalid[1:]).sum()),
                'status': 'unidentified_in_resamples' if invalid else 'conditional_percentile_pointwise'}


def constant(value, length):
    import numpy as np
    value = F(value)
    return Series(np.full(length, value.numerator, dtype=object), value.denominator)


def linear(series, coefficient):
    value = F(coefficient)
    return Series(series.n * value.numerator, series.d * value.denominator, series.invalid)


def sample_columns(data, counts):
    import numpy as np
    out = {}
    for cell in data['cells']:
        for field in FIELDS:
            values = [F(v) for v in cell['columns'][field]]
            require(len(values) == data['n_prompts'], 'Incomplete paired column')
            scale = lcm(*(v.denominator for v in values))
            numerators = [int(v * scale) for v in values]
            # Int64 only where a complete N-term sum cannot overflow.
            dtype = np.int64 if max(abs(x) for x in numerators) * data['n_prompts'] < 2**63 else object
            sums = counts @ np.array(numerators, dtype=dtype)
            out[cell['id'], field] = Series(sums, data['n_prompts'] * scale)
    return out


def cost(cell, data, rate, basis='window'):
    span = F(cell['generation_span_s'])
    gpu = F(cell['gpu_window_ns'], 10**9) if basis == 'window' else span
    wall = F(cell['service_wall_ns'], 10**9) if basis == 'window' else span
    require(wall >= span, 'Generation span exceeds wall')
    energy = data['energy']
    busy = sum(F(str(v)) for v in energy['busy_fraction_of_tdp']) / 2
    idle = sum(F(str(v)) for v in energy['idle_fraction_of_tdp']) / 2
    kwh = F(energy['gpu_tdp_w'][cell['hardware']]) * (busy * span + idle * (wall - span)) / 3600000
    cpu = F(cell['cpu_usec'], 10**6)
    return (F(str(rate)) * gpu / 3600 + F('0.15') * kwh + F('0.03') * cpu / 3600) / data['n_prompts']


def bill(sampled, cell_id, price):
    return linear(sampled[cell_id, 'billed_input_tokens'], F(price['input']) / 10**6) + linear(
        sampled[cell_id, 'delivered_output_tokens'] + sampled[cell_id, 'reasoning_tokens_all']
        + sampled[cell_id, 'unselected_final_tokens'], F(price['output']) / 10**6)


def diagnostic_scope():
    """Describe the diagnostic analysis separately from its numerical payload."""
    return {
        'analysis_role': 'conditional_diagnostics_outside_paused_registered_pipeline',
        'registered_primary_inference_completed': False,
        'coverage': 'Asymptotic pointwise percentile interpretation under prompt-block sampling and regularity assumptions, conditional on the observed schedule, generation seed and measured cost on the stated basis. No simultaneous or finite-sample coverage guarantee.',
        'cost_scope': 'Costs on each row\'s window or generation-span basis stay fixed in every prompt draw. H1 has no prompt-bootstrap interval. The registered cost-spread gate withholds its entire primary bootstrap. These intervals are computed outside that gate.',
        'menu_scope': 'Selected once from three-replicate mean costs on the row\'s cost basis, including serial fallback. Same choice in every draw and seed. All intervals here are separate conditional diagnostics, not registered primary inference.',
        'financial_scope': 'Archived tariffs, no response fee, all non-delivered tokens billed, per-seed fixed configurations and the declared mean-cost menu rule. No bootstrap over hardware composites or merged seed observations.',
        'welfare_scope': 'No welfare interval: end-to-end delivery latency and user-value scenarios are not identified by these pipeline extracts.'}


def run(data, draws=DRAW_COUNT):
    import numpy as np
    require(data['schema'] == 'anonymous-paired-prompt-inputs-v1' and data['n_prompts'] == N, 'Input schema/cohort')
    require(draws == DRAW_COUNT, 'Production analysis uses the frozen 10000 draws')
    counts, digest = indices(N, draws)
    sampled = sample_columns(data, counts)
    cells = {(c['stratum'], c['config'], c['k'], c['replicate']): c for c in data['cells']}
    bills = {(c['id'], anchor): bill(sampled, c['id'], data['prices'][anchor])
             for c in data['cells'] for anchor in ANCHORS.get(c['stratum'], ())}
    point_metrics, contrasts, financial, h2, pauses = [], [], [], [], []
    def value(c, field):
        return sampled[c['id'], field]
    for c in data['cells']:
        metrics = {f: value(c, f).summary() for f in FIELDS}
        if c['stratum'] in HEADLINE:
            metrics['bill_headline_usd'] = bills[c['id'], HEADLINE[c['stratum']]].summary()
        point_metrics.append({**{k: c[k] for k in ('id', 'stratum', 'config', 'k', 'replicate', 'hardware', 'extended_bound')},
                              'metrics': metrics})
    for s in STRATA:
        configs = sorted({key[1] for key in cells if key[0] == s})
        for rep in range(3):
            pairs = [('budget', config, cells[s, config, 1, rep], cells[s, config, 8, rep]) for config in configs]
            pairs += [('pooling_k%d' % k, config, cells[s, 'serial', k, rep], cells[s, config, k, rep])
                      for config in configs if config != 'serial' for k in (1, 8)]
            for kind, config, a, b in pairs:
                metrics = {f: (value(b, f) - value(a, f)).summary() for f in FIELDS}
                if s in HEADLINE:
                    metrics['bill_headline_usd'] = (bills[b['id'], HEADLINE[s]] - bills[a['id'], HEADLINE[s]]).summary()
                contrasts.append({'stratum': s, 'replicate': rep, 'contrast': kind, 'config': config,
                                  'cells': [a['id'], b['id']], 'hardware_matched': a['hardware'] == b['hardware'],
                                  'extended_bound': a['extended_bound'] or b['extended_bound'], 'metrics': metrics})
        # The predeclared menu choice is frozen from three-window mean costs,
        # including serial as a feasible fallback. The cost-spread flag stays on.
        if s not in ANCHORS:
            continue
        for basis in ('window', 'generation_span'):
            for rate in data['cost_scenario']['capacity_usd_per_gpu_hour']:
                costs = {key: cost(c, data, rate, basis) for key, c in cells.items() if key[0] == s}
                choice = {k: min(configs, key=lambda cfg: (sum(costs[s, cfg, k, rep] for rep in range(3)),
                                                          ('serial', 'batch16', 'batch64').index(cfg))) for k in (1, 8)}
                spread = []
                for cfg in configs:
                    for k in (1, 8):
                        xs = [costs[s, cfg, k, rep] for rep in range(3)]
                        if max(xs) - min(xs) > sum(xs) / 30:
                            spread.append('%s/k%d' % (cfg, k))
                pauses.append({'stratum': s, 'basis': basis, 'rate': rate, 'cost_pause': bool(spread),
                               'flagged_slots': spread, 'menu_selected': {str(k): c for k, c in choice.items()},
                               'status': 'conditional_diagnostics_only' if spread else 'cost_spread_not_triggered'})
                for rep in range(3):
                    for policy in [c for c in configs if c != 'serial'] + ['menu']:
                        selected = choice if policy == 'menu' else {1: policy, 8: policy}
                        keys = [(s, 'serial', 1, rep), (s, 'serial', 8, rep),
                                (s, selected[1], 1, rep), (s, selected[8], 8, rep)]
                        cc = [cells[k] for k in keys]
                        cs = [costs[k] for k in keys]
                        for anchor in ANCHORS[s]:
                            bs = [bills[c['id'], anchor] for c in cc]
                            db0, db1 = bs[1] - bs[0], bs[3] - bs[2]
                            const = lambda x: constant(x, draws + 1)
                            lower = const(cs[0]).ratio(bs[0]).extremum(const(cs[3]).ratio(bs[3]), True)
                            upper = const(cs[1]).ratio(bs[1]).extremum(const(1), False)
                            metrics = {
                                'alpha_C0': const(cs[1] - cs[0]).ratio(db0).summary(),
                                'alpha_C1': const(cs[3] - cs[2]).ratio(db1).summary(),
                                'admission_lower': lower.summary(), 'admission_upper': upper.summary(),
                                'admission_gap': (upper - lower).summary(),
                                'bill_increment_drift': (db1 - db0).summary(),
                                'bill_increment_relative_drift': (db1 - db0).ratio(db0).summary()}
                            financial.append({'stratum': s, 'replicate': rep, 'policy': policy,
                                              'anchor': anchor, 'basis': basis, 'rate': rate,
                                              'hardware_matched': len({c['hardware'] for c in cc}) == 1,
                                              'hardware': [c['hardware'] for c in cc],
                                              'extended_bound': any(c['extended_bound'] for c in cc),
                                              'menu_candidate_extended_bound': policy == 'menu' and any(c['extended_bound'] for c in data['cells'] if c['stratum'] == s),
                                              'cost_pause': bool(spread), 'selected': {str(k): c for k, c in selected.items()},
                                              'costs_exact': list(map(str, cs)), 'H1_fixed': str(cs[1] - cs[0] - cs[3] + cs[2]),
                                              'metrics': metrics})
                print(json.dumps({'completed': s, 'basis': basis, 'rate': rate, 'financial_rows': len(financial)}), flush=True)
    # Native on/off deployment comparison, paired by question within each seed.
    for rep in range(3):
        for cfg in ('serial', 'batch16', 'batch64'):
            for basis in ('window', 'generation_span'):
                cs = [cells[s, cfg, k, rep] for s in ('q38-thinking', 'q38-nonthinking') for k in (1, 8)]
                bs = [bills[c['id'], 'di-q38-27b-list'] for c in cs]
                on = constant(cost(cs[1], data, '2.4', basis) - cost(cs[0], data, '2.4', basis), draws + 1).ratio(bs[1] - bs[0])
                off = constant(cost(cs[3], data, '2.4', basis) - cost(cs[2], data, '2.4', basis), draws + 1).ratio(bs[3] - bs[2])
                h2.append({'replicate': rep, 'config': cfg, 'basis': basis, 'rate': '2.4',
                           'hardware_matched': len({c['hardware'] for c in cs}) == 1,
                           'hardware': [c['hardware'] for c in cs], 'extended_bound': any(c['extended_bound'] for c in cs),
                           'alpha_on_minus_off': (on - off).summary(), 'alpha_on_over_off': on.ratio(off).summary()})
    return {'schema': 'paired-prompt-bootstrap-v1', 'input_sha256': sha256(encoded(data)).hexdigest(),
            'draws': draws, 'seed': SEED, 'n_prompts': N, 'resample_indices_sha256': digest,
            'python_version': platform.python_version(), 'numpy_version': np.__version__,
            'resampling': 'One shared vector of 106 prompt indices per draw across all cells. Seed groups are reported separately.',
            'percentile': 'Exact linear interpolation at (B-1)*p, p=1/40 and 39/40. Float-suggested sort orders are verified by exact cross products.',
            **diagnostic_scope(),
            'cells': point_metrics, 'paired_contrasts': contrasts, 'financial': financial, 'h2': h2, 'cost_pause_audit': pauses,
            'experiments_run': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-from', type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    require(bool(args.prepare_from) != bool(args.inputs), 'Choose prepare or inference')
    if args.prepare_from:
        write_new(args.out, prepare(args.prepare_from))
    else:
        write_new(args.out, run(json.loads(args.inputs.read_text())))


if __name__ == '__main__':
    main()
