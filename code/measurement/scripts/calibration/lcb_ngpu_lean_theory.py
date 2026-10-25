"""Named theory estimands of H1, H2 and H3 from measured lean cells (descriptive floats, not the frozen exact-rational estimator).

  python3 -I -B scripts/calibration/lcb_ngpu_lean_theory.py CANDIDATES.json [...] --collect COLLECT_OUTPUT.json [...] [--scenario PATH]

One row per stratum x pooled configuration x replicate group x anchor x capacity rate x cost basis x hidden slice x response fee.
A replicate group is one replicate (the four cells serial/pooled x k1/k8 of that replicate) or the mean over all replicates that
have all four cells. A hardware group ('hw:MODEL', batch16 and batch64 only) takes, for each of the four cells, the replicates whose
cell ran on that GPU model, even when they come from different replicates. This stratifies by GPU model (hardware_matched is True: all four cells ran on one model) but does not match seeds or replicates: a descriptive hardware-stratified estimate, not a paired test. pi=0 is serial, pi=1 the pooled configuration (batch16, batch64, or per action the cheaper of the two: 'menu');
L is k=1, H is k=8.

Cost per request (theory_estimands.accounting): C = (capacity rate x GPU seconds + electricity rate x kWh + CPU rate x CPU seconds) / n.
GPU seconds are the allocated G step wall of the cell ('window', the declared scope) or the generation span alone ('generation_span',
a sensitivity that drops the wait for deferred judging). The lean runs measured no power: kWh is the declared envelope of
energy-scenario-v1.json, so every cost carries two endpoints (low and high draw, applied to all cells together) and the estimands are
reported at both. Bill per request: B = base fee + (input rate x billed input + output rate x (delivered output + hidden)) / 1e6 with
hidden = reasoning (+ unselected final tokens under all_non_delivered); the hidden-token rate equals the output rate (scenario
assumption). A stratum without an archived tariff has no bill, hence no alpha_C or admission interval, never a stand-in price.

--mode service reads the cells run on the service path instead (online weak4 selection, audit after the window). Their bases are
'service' (steady-state service: GPU seconds of the cohort window, CPU of the service roles between the bracketing snapshots; cold
start and audit excluded) and 'service_startup' (the same plus the cold start: the whole G step, which stops when the window ends,
and the cumulative service-role CPU at the end snapshot; the audit is still excluded). The paper must say which one it studies.
For the evaluation-pipeline cells 'generation_span' still prices whole-cell CPU, which includes the audit and the judging of every
candidate.

Estimands (theory_estimands.estimate_profiles): d_pi = C(pi,H)-C(pi,L); s_L = C(0,L)-C(1,L); s_H = C(0,H)-C(1,H);
H1 = s_H-s_L = d0-d1; alpha_C,pi = d_pi / (B(pi,H)-B(pi,L)) when that denominator is positive (H2); admission interval
[max(C0L/B0L, C1H/B1H), min(C0H/B0H, 1)] (H3). The declared 3-window envelope [0.9 min, 1.1 max] of each of the four costs gives
the H1 lower bound only for a group of exactly three replicates; otherwise it is None. Nothing is filled in: a missing input gives None.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_ngpu_lean_analysis as analysis

ROOT = analysis.ROOT
SCENARIO = ROOT / 'experiments/calibration/lean-theory-scenario-v1.json'
PRICES = ROOT / 'data/calibration/public-prices-2026-10-08.json'
NEEDED_TOKENS = ('billed_input_tokens', 'delivered_output_tokens', 'reasoning_tokens_all', 'unselected_final_tokens')
COLUMNS = ('stratum', 'pooled', 'group', 'windows', 'hardware_serial', 'hardware_pooled', 'hardware_matched', 'anchor', 'gpu_hour_usd',
           'basis', 'hidden', 'response_fee_usd', 'gpu_s_H1', 'C0L', 'C0H', 'C1L', 'C1H', 'd0', 'd1', 's_L', 's_H',
           'H1_lo', 'H1_hi', 'H1_env_lo', 'pause_rule', 'B0L', 'B0H', 'B1L', 'B1H', 'bill_drift', 'alpha_C0', 'alpha_C1',
           'adm_lower', 'adm_upper', 'adm_nonempty')


def load_cells(candidate_paths, collect_paths, mode='pipeline'):
    """(stratum, config, k, replicate) -> inputs of one measured cell; unmeasured resources stay None. mode 'pipeline' takes
    the cells of the evaluation pipeline (deferred judging), 'service' the cells of the service path (online weak4 selection)."""
    resources = analysis.collect_resources(collect_paths)
    cells = {}
    for path in candidate_paths:
        m = analysis.cell_metrics(json.loads(Path(path).read_text()))
        if m['status'] == 'incomplete' or (m.get('mode') == 'service') != (mode == 'service'):
            continue
        res = resources.get((m['attempt'], m['cell_id']), {})
        key = (m['stratum'], m['config'], m['k'], m['replicate'])
        if key in cells:
            raise ValueError('Two cells for the same stratum/config/k/replicate in one run (pilot and main, or two attempts): ' + str(key))
        cells[key] = {
            'tasks': m['tasks'], 'hardware': m['hardware'], 'timeout_s': m.get('timeout_s'), 'timeout_revised': m.get('timeout_revised'), 'gpu_s': res.get('gpu_step_occupancy_s'),
            'cpu_s': res.get('cpu_point_s'), 'wall_s': m['service_wall_s'], 'span_s': m['generation_span_s'],
            'service_s': m.get('service_window_s'), 'service_cpu_s': m.get('service_cpu_s'),
            'service_cpu_startup_s': m.get('service_cpu_startup_s'),
            **{key: m[key] for key in NEEDED_TOKENS}}
    return cells


def usd_per_request(cell, basis, rates, energy):
    """(low, high) USD per request at the low and high end of the declared energy envelope, or None when an input is missing."""
    gpu_s = gpu_seconds(cell, basis)
    wall_s = (cell['wall_s'] if basis in ('window', 'service_startup') else cell.get('service_s') if basis == 'service'
              else cell['span_s'])
    # service: CPU of the service roles inside the window; service_startup: the same plus the cold start before it (G step
    # occupancy, the audit excluded because the G role stops when the window ends)
    cpu_s = (cell.get('service_cpu_s') if basis == 'service' else cell.get('service_cpu_startup_s') if basis == 'service_startup'
             else cell['cpu_s'])
    kwh = None if wall_s is None or cell['span_s'] is None else analysis.energy_envelope(cell['hardware'], wall_s, cell['span_s'], energy)
    if gpu_s is None or cpu_s is None or kwh is None or not cell['tasks']:
        return None
    fixed = rates['gpu_hour'] / 3600 * gpu_s + rates['cpu_hour'] / 3600 * cpu_s
    return tuple((fixed + rates['kwh'] * e) / cell['tasks'] for e in kwh)


def bill(cell, price, hidden, fee):
    if price is None or any(cell[key] is None for key in NEEDED_TOKENS):
        return None
    hidden_tokens = cell['reasoning_tokens_all'] + (cell['unselected_final_tokens'] if hidden == 'all_non_delivered' else 0)
    return fee + (price['in'] * cell['billed_input_tokens'] + price['out'] * (cell['delivered_output_tokens'] + hidden_tokens)) / 1e6


def mean(values):
    return sum(values) / len(values)


def gpu_seconds(cell, basis):
    if basis in ('window', 'service_startup'):
        return cell['gpu_s']
    return cell.get('service_s') if basis == 'service' else cell['span_s']


def groups(cells, stratum, pooled):
    """[(label, replicates)]: every replicate with the four cells, plus 'all' when at least two have them."""
    ready = [r for r in sorted({key[3] for key in cells if key[0] == stratum})
             if all((stratum, cfg, k, r) in cells for cfg in ('serial', pooled) for k in (1, 8))]
    found = [('r%d' % r, [r]) for r in ready]
    return found + ([('all', ready)] if len(ready) > 1 else [])


def hardware_groups(cells, stratum, pooled):
    """[(label, slots)]: one group per GPU model. slots maps each of the four cells (serial/pooled x k1/k8) to the replicates whose
    cell of that slot ran on the model; a model needs all four slots. Replicates may differ between slots (the serial k1 of r0 with
    the serial k8 of r1), so hardware is held fixed, as it is in a replicate group only when the four cells of one replicate happened
    to land on the same model. The replicate (seed group) composition of the four cells is not held fixed: this is a descriptive
    hardware-stratified estimate, not a paired test."""
    slot_cell = {(pi, a): ('serial' if pi == 0 else pooled, 1 if a == 'L' else 8) for pi in (0, 1) for a in 'LH'}
    models = sorted({c['hardware'] for key, c in cells.items() if key[0] == stratum and c['hardware']})
    found = []
    for model in models:
        slots = {slot: sorted(key[3] for key, c in cells.items() if key[:3] == (stratum, config, k) and c['hardware'] == model)
                 for slot, (config, k) in slot_cell.items()}
        if all(slots.values()):
            found.append(('hw:' + model.replace('NVIDIA ', ''), slots))
    return found


def endpoints(windows):
    """windows[(pi, a)] = per-replicate (low, high) costs -> two cost vectors (low draw, high draw), mean over the windows."""
    return [{key: mean([w[side] for w in ws]) for key, ws in windows.items()} for side in (0, 1)]


def solve(c, b):
    """Estimands of one cost vector c[(pi, a)] and bill vector b[(pi, a)] (b may be None)."""
    out = {'d0': c[0, 'H'] - c[0, 'L'], 'd1': c[1, 'H'] - c[1, 'L'], 's_L': c[0, 'L'] - c[1, 'L'], 's_H': c[0, 'H'] - c[1, 'H']}
    out['H1'] = out['s_H'] - out['s_L']
    if b is not None:
        db = [b[pi, 'H'] - b[pi, 'L'] for pi in (0, 1)]
        out['bill_drift'] = (db[1] - db[0]) / db[0] if db[0] > 0 else None
        out['alpha_C0'] = out['d0'] / db[0] if db[0] > 0 else None
        out['alpha_C1'] = out['d1'] / db[1] if db[1] > 0 else None
        if min(b[0, 'L'], b[0, 'H'], b[1, 'H']) > 0:
            out['adm_lower'] = max(c[0, 'L'] / b[0, 'L'], c[1, 'H'] / b[1, 'H'])
            out['adm_upper'] = min(c[0, 'H'] / b[0, 'H'], 1.0)
    return out


def envelope_lower(windows):
    """Lower bound of s_H-s_L over the declared envelope [0.9 min, 1.1 max] of the four costs; only for exactly three windows."""
    if any(len(ws) != 3 for ws in windows.values()):
        return None
    lo = {key: 0.9 * min(w[0] for w in ws) for key, ws in windows.items()}
    hi = {key: 1.1 * max(w[1] for w in ws) for key, ws in windows.items()}
    return lo[0, 'H'] - hi[0, 'L'] - hi[1, 'H'] + lo[1, 'L']


def pause_rule(windows):
    """Preregistered pause: the spread of three window costs exceeds a tenth of their mean (any of the four costs)."""
    if any(len(ws) != 3 for ws in windows.values()):
        return None
    mids = [[0.5 * (w[0] + w[1]) for w in ws] for ws in windows.values()]
    return any(max(v) - min(v) > mean(v) / 10 for v in mids)


def menu_choice(cells, stratum, reps, basis, rates, energy):
    """Per action the pooled configuration with the lower mean cost (batch16 on a tie); None unless both are measured."""
    choice = {}
    for a, k in (('L', 1), ('H', 8)):
        means = {}
        for cfg in ('batch16', 'batch64'):
            ws = [usd_per_request(cells[stratum, cfg, k, r], basis, rates, energy) for r in reps if (stratum, cfg, k, r) in cells]
            if len(ws) != len(reps) or any(w is None for w in ws):
                return None
            means[cfg] = mean([0.5 * (w[0] + w[1]) for w in ws])
        choice[a] = min(('batch16', 'batch64'), key=lambda cfg: means[cfg])
    return choice


def tariffs(scenario, stratum, archived):
    """[(anchor, price, hidden, fee)]: one entry without a bill for a stratum that has no archived tariff."""
    ids = scenario['anchors'].get(stratum)
    if not ids:
        return [(None, None, None, None)]
    return [(i, {'in': float(archived[i]['input_per_million']), 'out': float(archived[i]['output_per_million'])}, hidden, fee)
            for i in ids for hidden in scenario['hidden_billing'] for fee in scenario['response_fee_usd']]


def group_timeout(cells, compared=()):
    """timeout_s of a row: the largest per-call generation timeout among its cells; 'unknown' if one of them is unknown, 'partial' when
    only some of them were recorded (extracts from before it was recorded), blank when none was. timeout_revised: some cell of the
    row, or of the cells a menu row chose between (compared), ran under the owner-approved extension."""
    seconds = [c.get('timeout_s') for c in cells]
    known = [v for v in seconds if isinstance(v, int)]
    value = ('unknown' if 'unknown' in seconds else None if not known else 'partial' if None in seconds else max(known))
    return {'timeout_s': value, 'timeout_revised': any(c.get('timeout_revised') is True for c in list(cells) + list(compared))}


def group_rows(cells, scenario, energy, archived, stratum, pooled, label, reps, mode='pipeline'):
    """reps: the replicates of a replicate group (the same for all four cells), or, for a hardware group, the slot -> replicates map."""
    slots = reps if isinstance(reps, dict) else {(pi, a): reps for pi in (0, 1) for a in 'LH'}
    output = []
    bases = scenario['bases'] if mode == 'pipeline' else scenario.get('bases_service', ['service', 'service_startup'])
    for basis in bases:
        for gpu_hour in scenario['capacity_usd_per_gpu_hour']:
            rates = {'gpu_hour': gpu_hour, 'kwh': scenario['electricity_usd_per_kwh'], 'cpu_hour': scenario['cpu_usd_per_core_hour']}
            picks = menu_choice(cells, stratum, reps, basis, rates, energy) if pooled == 'menu' else None
            if pooled == 'menu' and picks is None:
                continue
            config = lambda pi, a: 'serial' if pi == 0 else (picks[a] if picks else pooled)
            members = {(pi, a): [cells[stratum, config(pi, a), k, r] for r in slots[pi, a]] for pi in (0, 1) for a, k in (('L', 1), ('H', 8))}
            windows = {key: [usd_per_request(c, basis, rates, energy) for c in cs] for key, cs in members.items()}
            if any(w is None for ws in windows.values() for w in ws):
                continue
            low, high = endpoints(windows)
            seconds = {key: [gpu_seconds(c, basis) for c in cs] for key, cs in members.items()}
            tasks = {key: [c['tasks'] for c in cs] for key, cs in members.items()}
            gpu = None if any(v is None for vs in seconds.values() for v in vs) else {
                key: mean([s / n for s, n in zip(seconds[key], tasks[key])]) for key in members}
            hardware = [sorted({(c['hardware'] or '?').replace('NVIDIA ', '') for a in 'LH' for c in members[pi, a]}) for pi in (0, 1)]
            for anchor, price, hidden, fee in tariffs(scenario, stratum, archived):
                bills = {key: [bill(c, price, hidden, fee) for c in cs] for key, cs in members.items()}
                b = None if price is None or any(v is None for vs in bills.values() for v in vs) else {key: mean(vs) for key, vs in bills.items()}
                lo, hi = solve(low, b), solve(high, b)
                mid = lambda key: None if lo.get(key) is None else 0.5 * (lo[key] + hi[key])
                row = {'stratum': stratum, 'pooled': pooled, 'group': label, 'windows': min(len(v) for v in slots.values()), 'mode': mode,
                       **group_timeout([c for cs in members.values() for c in cs],
                                       [cells[stratum, cfg, k, r] for cfg in ('batch16', 'batch64') for k in (1, 8) for r in slots[1, 'L']
                                        if (stratum, cfg, k, r) in cells] if picks else ()),
                       'hardware_serial': '/'.join(hardware[0]), 'hardware_pooled': '/'.join(hardware[1]),
                       'hardware_matched': hardware[0] == hardware[1] and len(hardware[0]) == 1,
                       'anchor': anchor, 'gpu_hour_usd': gpu_hour, 'basis': basis, 'hidden': hidden, 'response_fee_usd': fee,
                       'gpu_s_H1': None if gpu is None else (gpu[0, 'H'] - gpu[0, 'L']) - (gpu[1, 'H'] - gpu[1, 'L']),
                       **{name + level: 0.5 * (low[pi, level] + high[pi, level]) for name, pi in (('C0', 0), ('C1', 1)) for level in 'LH'},
                       **{key: mid(key) for key in ('d0', 'd1', 's_L', 's_H')},
                       'H1_lo': min(lo['H1'], hi['H1']), 'H1_hi': max(lo['H1'], hi['H1']),
                       'H1_env_lo': envelope_lower(windows), 'pause_rule': pause_rule(windows)}
                if b is not None:
                    row.update(B0L=b[0, 'L'], B0H=b[0, 'H'], B1L=b[1, 'L'], B1H=b[1, 'H'], bill_drift=lo['bill_drift'],
                               alpha_C0=mid('alpha_C0'), alpha_C1=mid('alpha_C1'))
                    if 'adm_lower' in lo:
                        row.update(adm_lower=mid('adm_lower'), adm_upper=mid('adm_upper'))
                        states = {lo['adm_lower'] < lo['adm_upper'], hi['adm_lower'] < hi['adm_upper']}
                        row['adm_nonempty'] = 'yes' if states == {True} else 'no' if states == {False} else 'depends_on_energy'
                output.append(row)
    return output


def rows(cells, scenario, energy, prices, mode='pipeline'):
    archived = {row['id']: row for row in prices['rates']}
    output = []
    for stratum in sorted({key[0] for key in cells}):
        pooled_options = ['batch16', 'batch64'] + (['menu'] if any(key[:2] == (stratum, 'batch64') for key in cells) else [])
        for pooled in pooled_options:
            replicate_groups = groups(cells, stratum, 'batch16' if pooled == 'menu' else pooled)
            for label, reps in replicate_groups:
                output += group_rows(cells, scenario, energy, archived, stratum, pooled, label, reps, mode)
            if pooled != 'menu':
                same = {tuple(reps) for _, reps in replicate_groups}
                for label, slots in hardware_groups(cells, stratum, pooled):
                    if len({tuple(v) for v in slots.values()}) == 1 and tuple(next(iter(slots.values()))) in same:
                        continue  # the four cells of these replicates all ran on this model: the replicate group is the same group
                    output += group_rows(cells, scenario, energy, archived, stratum, pooled, label, slots, mode)
    return output


def fmt(value):
    return '' if value is None else '%.5g' % value if isinstance(value, float) else str(value)


def table_columns(table, mode='pipeline'):
    columns = COLUMNS + (('mode',) if mode == 'service' else ())  # pipeline tables keep their format
    # the largest per-call generation timeout among the cells of a row; a column only when some row has a cell under the extension or an unknown one
    return columns + (('timeout_s', 'timeout_revised') if any(r['timeout_revised'] or r['timeout_s'] in ('unknown', 'partial') for r in table) else ())


def main(argv):
    scenario_path = SCENARIO
    if '--scenario' in argv:
        i = argv.index('--scenario')
        scenario_path = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    mode = 'pipeline'
    if '--mode' in argv:
        i = argv.index('--mode')
        mode = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
        if mode not in ('pipeline', 'service'):
            raise SystemExit('--mode is pipeline or service')
    split = argv.index('--collect') if '--collect' in argv else len(argv)
    cells = load_cells(argv[:split], argv[split + 1:], mode)
    table = rows(cells, json.loads(scenario_path.read_text()), json.loads(analysis.ENERGY.read_text()), json.loads(PRICES.read_text()), mode)
    columns = table_columns(table, mode)
    print('\t'.join(columns))
    for r in table:
        print('\t'.join(fmt(r.get(c)) for c in columns))
    return table


if __name__ == '__main__':
    main(sys.argv[1:])
