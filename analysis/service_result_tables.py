"""Paper-only rendering of the reviewed 2026-10-25 service/A100 follow-up.

The original pipeline snapshot stays separate. No model, candidate, or
bootstrap is run by this module.
"""
from fractions import Fraction as F
from pathlib import Path
import csv
import hashlib
import json
import itertools

ROOT = Path(__file__).resolve().parent
FILES = {
    'service': 'lean-service-resources-2-2026-10-25.tsv',
    'service_theory': 'lean-service-theory-3-2026-10-25.tsv',
    'a100': 'lean-a100-resources-2-2026-10-25.tsv',
    'a100_theory': 'lean-a100-theory-3-2026-10-25.tsv',
    'pipeline': 'lean-main-resources-4-2026-10-23.tsv',
    'pipeline_theory': 'lean-main-theory-5-2026-10-24.tsv'}
STRATA = ['coder-nonthinking', 'nemotron-thinking', 'q35-thinking', 'q38-nonthinking', 'q38-thinking']
NAMES = dict(zip(STRATA, ['Coder', 'Nemotron', 'Qwen3.5 thinking', 'Qwen3.8 non-thinking', 'Qwen3.8 thinking']))
TAGS = dict(zip(STRATA, ['Cod', 'Nem', 'QFive', 'QOff', 'QOn']))
HW = {'NVIDIA H100 80GB HBM3': 'H100', 'NVIDIA H100 NVL': 'NVL', 'NVIDIA H200': 'H200', 'NVIDIA A100-SXM4-80GB': 'A100'}
LETTERS = {'NVIDIA H100 80GB HBM3': 'H', 'NVIDIA H100 NVL': 'N', 'NVIDIA H200': 'E', 'NVIDIA A100-SXM4-80GB': 'A'}
ANCHOR = {'q35-thinking': 'di-q35-9b', 'q38-nonthinking': 'di-q38-27b-list', 'q38-thinking': 'di-q38-27b-list'}
RATES = ['0.25', '0.5', '1', '2', '2.4', '3', '4']


def read(name, evidence=None):
    evidence = ROOT / 'evidence' if evidence is None else evidence
    with (evidence / 'results' / FILES[name]).open() as stream:
        return list(csv.DictReader(stream, delimiter='\t'))


def key(row):
    s, _, c, k, rep = row['cell_id'].split('|')
    return s, c, int(k[1:]), rep


def fmt(x, digits=1):
    return ('%.*f' % (digits, float(x))).replace('-', '$-$')


def header():
    paths = [ROOT / 'evidence/results' / FILES[n] for n in ('service', 'service_theory', 'a100', 'a100_theory')]
    paths.append(ROOT / 'evidence/service-followup-provenance.json')
    return '% Follow-up inputs: ' + ' '.join(p.name + '=' + hashlib.sha256(p.read_bytes()).hexdigest()[:12] for p in paths) + '\n'


class Panel:
    def __init__(self, rows, theory, exact=()):
        self.rows = {}
        self.theory = theory
        self.exact = {(r['stratum'], r['config'], r['k'], r['replicate']): r for r in exact}
        for r in rows:
            if r['status'] != 'complete':
                continue
            k = key(r)
            if k in self.rows:
                raise ValueError('Duplicate complete follow-up cell')
            self.rows[k] = r

    def configs(self, s):
        return sorted({k[1] for k in self.rows if k[0] == s and k[1] != 'serial'})

    def seconds(self, k, basis):
        r, e = self.rows[k], self.exact.get(k, {})
        if basis == 'service':
            return F(e['service_window_s_exact']) if e else F(r['service_window_s'])
        if basis in ('window', 'service_startup'):
            return F(e['gpu_step_occupancy_ns'], 10**9) if e else F(r['gpu_step_occupancy_s'])
        return F(e['generation_span_s_exact']) if e else F(r['generation_span_s'])

    def contrast(self, s, p, rep, basis):
        keys = [(s, 'serial', 1, rep), (s, 'serial', 8, rep), (s, p, 1, rep), (s, p, 8, rep)]
        times = [self.seconds(k, basis) / 106 for k in keys]
        d0 = times[1] - times[0]
        raw = d0 - times[3] + times[2]
        recorded = {r['gpu_s_H1'] for r in self.theory if (r['stratum'], r['pooled'], r['group'], r['basis']) == (s, p, rep, basis)}
        if recorded:
            assert len(recorded) == 1
            h = F(recorded.pop())
            assert abs(float(h - raw)) < .15
            if not self.exact:
                raw = h
        return {'d0': d0, 'd1': d0 - raw, 'h1': raw, 'share': raw / d0,
                'hardware': [self.rows[k]['hardware'] for k in keys]}

    def financial(self, s, p, rep, basis='service', rate='2.4'):
        rows = [r for r in self.theory if (r['stratum'], r['pooled'], r['group'], r['basis'], r['gpu_hour_usd'],
                r['anchor'], r['hidden'], r['response_fee_usd']) == (s, p, rep, basis, rate, ANCHOR[s], 'all_non_delivered', '0')]
        assert len(rows) == 1
        return rows[0]

    def cost(self, k, rate, endpoint=0):
        e = self.exact[k]
        energy = json.loads((ROOT / 'evidence/results-manifest.json').read_text())['energy_assumption']
        span = F(e['generation_span_s_exact'])
        service = 'service_window_s_exact' in e
        wall = F(e['service_window_s_exact']) if service else F(e['lifetime_service_wall_ns'], 10**9)
        gpu = wall if service else F(e['gpu_step_occupancy_ns'], 10**9)
        cpu = F(e['service_cpu_usec'] if service else e['cpu_point_usec'], 10**6)
        kwh = F(energy['gpu_tdp_w'][e['gpu_model']]) * (span * F(str(energy['busy_fraction_of_tdp'][endpoint]))
                    + (wall - span) * F(str(energy['idle_fraction_of_tdp'][endpoint]))) / 3600000
        return (F(rate) * gpu / 3600 + F('.15') * kwh + F('.03') * cpu / 3600) / 106

    def energy_minimum(self, s, p, rep, rate):
        # H1 = high serial - low serial - high pooled + low pooled.
        return (self.cost((s, 'serial', 8, rep), rate, 0) - self.cost((s, 'serial', 1, rep), rate, 1)
                - self.cost((s, p, 8, rep), rate, 1) + self.cost((s, p, 1, rep), rate, 0))


def panels(evidence=None):
    ev = ROOT / 'evidence' if evidence is None else evidence
    provenance = json.loads((ev / 'service-followup-provenance.json').read_text())
    return (Panel(read('service', ev), read('service_theory', ev), provenance['service_cells']),
            Panel(read('a100', ev), read('a100_theory', ev), provenance['a100_cells']),
            Panel(read('pipeline', ev), read('pipeline_theory', ev)), provenance)


def validate(evidence=None):
    service, a100, _, prov = panels(evidence)
    assert len(service.rows) == 66 and len(a100.rows) == 15
    assert {k[0] for k in service.rows} == set(STRATA)
    assert len(service.exact) == 66 and len(a100.exact) == 15
    for k, row in service.rows.items():
        e = service.exact[k]
        limit = 1800 if k[0] == 'coder-nonthinking' else 3600
        assert e['generation_timeout'] == {'seconds': limit, 'revised': False}
        assert e['max_call_seconds'] <= limit
        assert row['mode'] == 'service' and int(row['tasks']) == 106
        assert float(format(float(F(e['service_window_s_exact'])), '.4g')) == float(row['service_window_s'])
    comparisons = 0
    for s in STRATA:
        for p in service.configs(s):
            for rep in ('r0', 'r1', 'r2'):
                ids = {service.exact[s, c, k, rep]['gpu_identity_sha256'] for c in ('serial', p) for k in (1, 8)}
                assert len(ids) == 1
                assert service.contrast(s, p, rep, 'service')['h1'] > 0
                comparisons += 1
    assert comparisons == 18
    for row in prov['a100_reruns']:
        assert row['generation_timeout'] == {'seconds': 7200, 'revised': True}
        k = row['stratum'], row['config'], row['k'], row['replicate']
        assert a100.rows[k]['timeout_revised'] == 'True'
    assert len(prov['a100_reruns']) == 3
    pre = [r for r in service.theory if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
    assert len(pre) == 896 and all(r['adm_nonempty'] == 'no' for r in pre)
    assert all(float(r['C0H']) / float(r['C0L']) < float(r['B0H']) / float(r['B0L']) for r in pre)
    return {'service_cells': 66, 'service_same_gpu_contrasts': comparisons,
            'service_admission_rows': len(pre), 'a100_measured_cells': 15,
            'a100_extended_reruns': 3, 'new_bootstrap_performed': False}


def table_quality(service):
    lines = [header(), r'\begin{table*}[t]',
             r'\caption{Online service outcomes, descriptive means of three generation seeds on 106 tasks. $q^+$ and $q^-$ are correct and incorrect delivery rates. Hidden tokens are reasoning plus unselected output per request, and Share is their fraction of all output tokens. Bills use the headline tariff, in USD per 1,000 requests. A dash denotes no archived tariff. Seed groups use different hardware, as shown in Table~\ref{tab:service-h1}.}',
             r'\label{tab:service-quality}', r'\centering\small\setlength{\tabcolsep}{4pt}', r'\begin{tabular}{lrrrrrrrrrr}',
             r'\toprule', r' & \multicolumn{5}{c}{$k=1$, serial} & \multicolumn{5}{c}{$k=8$, serial} \\',
             r'\cmidrule(lr){2-6}\cmidrule(lr){7-11}',
             r'Stratum & $q^+$ & $q^-$ & Hidden & Share & Bill & $q^+$ & $q^-$ & Hidden & Share & Bill \\', r'\midrule']
    for s in STRATA:
        out = []
        for k in (1, 8):
            rr = [service.rows[s, 'serial', k, rep] for rep in ('r0', 'r1', 'r2')]
            avg = lambda field: sum(float(r[field]) for r in rr) / 3
            h, v = avg('reasoning_tokens_all') + avg('unselected_final_tokens'), avg('delivered_output_tokens')
            b = '--' if s not in ANCHOR else fmt(1000 * sum(float(service.financial(s, 'batch16', rep)['B0L' if k == 1 else 'B0H']) for rep in ('r0', 'r1', 'r2')) / 3)
            out += [fmt(avg('q_plus'), 3), fmt(avg('q_minus'), 3), format(round(h), ','), fmt(100 * h / (h + v)) + r'\%', b]
        lines.append(NAMES[s] + ' & ' + ' & '.join(out) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table*}']) + '\n'


def table_h1(service):
    lines = [header(), r'\begin{table*}[t]',
             r'\caption{Follow-up online service cost contrasts. Each row uses four cells from one allocation on the same GPU. $d_0$ and $d_1$ are increases from one to eight candidates under serial and pooled processing, in GPU seconds per request. H1 is $d_0-d_1$. These are descriptive point values. H100 denotes H100 80GB HBM3 and NVL denotes H100 NVL.}',
             r'\label{tab:service-h1}', r'\centering\small', r'\begin{tabular}{lllrrrrr}', r'\toprule',
             r'Stratum & Pooled & Seed & GPU & $d_0$ & $d_1$ & H1 & H1/$d_0$ \\', r'\midrule']
    for s in STRATA:
        for p in service.configs(s):
            for rep in ('r0', 'r1', 'r2'):
                c = service.contrast(s, p, rep, 'service')
                lines.append(' & '.join([NAMES[s], p, rep, HW[c['hardware'][0]],
                             fmt(c['d0']), fmt(c['d1']), fmt(c['h1'], 2),
                             fmt(100 * c['share']) + r'\%']) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table*}']) + '\n'


def table_compare(service, pipeline):
    lines = [header(), r'\begin{table*}[t]',
             r'\caption{Service and evaluation-pipeline H1, in GPU seconds per request with H1/$d_0$ in parentheses. Each service contrast is from one GPU. Pipeline hardware codes give serial low/high and pooled low/high cells in order: H is H100 HBM3, N is H100 NVL, E is H200. Different hardware or seed compositions prevent attributing between-run differences solely to accounting scope.}',
             r'\label{tab:service}', r'\centering\small\setlength{\tabcolsep}{3pt}', r'\begin{tabular}{lllllrrr}',
             r'\toprule', r'Stratum & Pooled & Seed & Service GPU & Pipeline GPUs & Service & Pipeline window & Pipeline span \\', r'\midrule']
    for s in STRATA:
        for p in service.configs(s):
            for rep in ('r0', 'r1', 'r2'):
                v = service.contrast(s, p, rep, 'service')
                w = pipeline.contrast(s, p, rep, 'window'); sp = pipeline.contrast(s, p, rep, 'generation_span')
                val = lambda z: fmt(z['h1'], 2) + ' (' + fmt(100 * z['share']) + r'\%)'
                lines.append(' & '.join([NAMES[s], p, rep, HW[v['hardware'][0]], ''.join(LETTERS[h] for h in w['hardware']), val(v), val(w), val(sp)]) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table*}']) + '\n'


def table_financial(service):
    lines = [header(), r'\begin{table*}[t]',
             r'\caption{Follow-up service financial conditions, batch16 versus serial, headline tariff and 2.4 USD per GPU hour. $L$ and $H$ denote one and eight candidates. Ratios above one in $C_0(L)/B_0(L)$ preclude low-budget serial cost coverage from a revenue share below one. The admission band is empty in every row.}',
             r'\label{tab:service-financial}', r'\centering\small', r'\begin{tabular}{llcrrrrrr}', r'\toprule',
             r'Stratum & Seed & GPU & $\alpha_{C,0}$ & $\alpha_{C,1}$ & $C_0(L)/B_0(L)$ & $C_1(H)/B_1(H)$ & $B_0(H)/B_0(L)$ & $C_0(H)/C_0(L)$ \\', r'\midrule']
    for s in ANCHOR:
        for rep in ('r0', 'r1', 'r2'):
            r = service.financial(s, 'batch16', rep)
            vals = [float(r['alpha_C0']), float(r['alpha_C1'])] + [float(r[a]) / float(r[b]) for a, b in [('C0L', 'B0L'), ('C1H', 'B1H'), ('B0H', 'B0L'), ('C0H', 'C0L')]]
            lines.append(' & '.join([NAMES[s], rep, HW[service.rows[s, 'serial', 1, rep]['hardware']]] + [fmt(v, 2) for v in vals]) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table*}']) + '\n'


def table_h2(service):
    lines = [header(), r'\begin{table}[t]',
             r'\caption{Service thinking/non-thinking ratio of $\alpha_C$ at the headline tariff and 2.4 USD per GPU hour, without cold start. Each arm uses one GPU. H200 versus H100 in r2 is an unmatched comparison.}',
             r'\label{tab:service-h2}', r'\centering\small', r'\begin{tabular}{lllrr}', r'\toprule',
             r'Seed & Thinking GPU & Off GPU & Serial ratio & Batch16 ratio \\', r'\midrule']
    for rep in ('r0', 'r1', 'r2'):
        on = service.financial('q38-thinking', 'batch16', rep);off = service.financial('q38-nonthinking', 'batch16', rep)
        hws = [HW[service.rows[s, 'serial', 1, rep]['hardware']] for s in ('q38-thinking', 'q38-nonthinking')]
        lines.append(' & '.join([rep, *hws, *[fmt(float(on[k]) / float(off[k]), 2) for k in ('alpha_C0', 'alpha_C1')]]) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table}']) + '\n'


def table_energy(service):
    lines = [header(), r'\begin{table*}[t]',
             r'\caption{Service H1 under independently varying energy endpoints. Each entry is the minimum over the three observed seed-specific contrasts and all 16 energy corners, in USD per 1,000 requests. Columns give capacity rates in USD per GPU hour. This is a sensitivity calculation, not a confidence bound.}',
             r'\label{tab:service-energy}', r'\centering\small', r'\begin{tabular}{lrrrrrrr}', r'\toprule',
             r'Stratum, pooled & 0.25 & 0.5 & 1 & 2 & 2.4 & 3 & 4 \\', r'\midrule']
    for s in STRATA:
        for p in service.configs(s):
            vals = [min(service.energy_minimum(s, p, rep, rate) for rep in ('r0', 'r1', 'r2')) * 1000 for rate in RATES]
            lines.append(' & '.join([NAMES[s] + ', ' + p] + [fmt(v, 2) for v in vals]) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table*}']) + '\n'


def table_a100(a100, prov):
    lines = [header(), r'\begin{table}[t]',
             r'\caption{A100 batch16 exploratory contrasts. All three high-budget reruns used the 7,200 s protocol ($\dagger$). Longest call is for that rerun. H1 is in GPU seconds per request.}',
             r'\label{tab:a100-followup}', r'\centering\small\setlength{\tabcolsep}{4pt}', r'\begin{tabular}{lrrrrr}', r'\toprule',
             r'Seed & Window H1 & Share & Span H1 & Share & Longest call (s) \\', r'\midrule']
    for rep in ('r0', 'r1', 'r2'):
        w = a100.contrast('q38-thinking', 'batch16', rep, 'window');s = a100.contrast('q38-thinking', 'batch16', rep, 'generation_span')
        t = next(r['max_call_seconds'] for r in prov['a100_reruns'] if r['replicate'] == rep)
        lines.append(' & '.join([rep + r'$^\dagger$', fmt(w['h1']), fmt(100 * w['share']) + r'\%', fmt(s['h1']), fmt(100 * s['share']) + r'\%', fmt(t, 0)]) + r' \\')
    return '\n'.join(lines + [r'\bottomrule', r'\end{tabular}', r'\end{table}']) + '\n'


def numbers():
    service, a100, _, prov = panels(); n = {}
    for s in STRATA:
        for p in service.configs(s):
            tag = TAGS[s] + ('Sixteen' if p == 'batch16' else 'SixtyFour')
            values = [100 * service.contrast(s, p, rep, 'service')['share'] for rep in ('r0', 'r1', 'r2')]
            n['svNewShare' + tag + 'Lo'], n['svNewShare' + tag + 'Hi'] = fmt(min(values)), fmt(max(values))
    n.update(svNewCells='66', svNewAddedCells='54', svNewContrasts='18', svNewRows=format(len(service.theory), ','))
    ratios = {s: [service.seconds(k, 'service') / service.seconds(k, 'generation_span') for k in service.rows if k[0] == s] for s in STRATA}
    n['svNewCoderSpanLo'], n['svNewCoderSpanHi'] = fmt(min(ratios['coder-nonthinking'])), fmt(max(ratios['coder-nonthinking']))
    other = [v for s, vs in ratios.items() if s != 'coder-nonthinking' for v in vs]
    n['svNewOtherSpanLo'], n['svNewOtherSpanHi'] = fmt(min(other), 3), fmt(max(other), 3)
    pre = [r for r in service.theory if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
    n['svNewPreRows'] = str(len(pre));n['svNewPreOpen'] = str(sum(r['adm_nonempty'] != 'no' for r in pre))
    n['svNewReasonFeeOpen'] = str(sum(r['hidden'] == 'reasoning_only' and r['response_fee_usd'] == '0.04'
                                        and r['adm_nonempty'] != 'no' for r in service.theory))
    n['svNewCostGrowthLo'], n['svNewCostGrowthHi'] = [fmt(f([float(r['C0H']) / float(r['C0L']) for r in pre]), 2) for f in (min, max)]
    n['svNewBillGrowthLo'], n['svNewBillGrowthHi'] = [fmt(f([float(r['B0H']) / float(r['B0L']) for r in pre]), 2) for f in (min, max)]
    allr = [r for r in service.theory if r['group'] == 'all']
    n['svNewPauseRows'] = str(len(allr));n['svNewPauseFires'] = str(sum(r['pause_rule'] == 'True' for r in allr))
    n['svNewSpreadNonpositive'] = str(sum(float(r['H1_env_lo']) <= 0 for r in allr))
    for rep, tag in [('r0', 'Zero'), ('r1', 'One'), ('r2', 'Two')]:
        on, off = service.financial('q38-thinking', 'batch16', rep), service.financial('q38-nonthinking', 'batch16', rep)
        for k, kt in [('alpha_C0', 'Serial'), ('alpha_C1', 'Pooled')]:
            n['svNewHtwo' + kt + tag] = fmt(float(on[k]) / float(off[k]), 2)
    financial = [service.financial(s, 'batch16', rep) for s in ANCHOR for rep in ('r0', 'r1', 'r2')]
    low = [100 * float(r['B0L']) / float(r['C0L']) for r in financial]
    high = [float(r['B1H']) / float(r['C1H']) for r in financial if r['stratum'].startswith('q38-')]
    n['svNewLowCoverageLo'], n['svNewLowCoverageHi'] = fmt(min(low)), fmt(max(low))
    n['svNewHighCoverageLo'], n['svNewHighCoverageHi'] = fmt(min(high)), fmt(max(high))
    n['svNewLongestCall'] = fmt(max(r['max_call_seconds'] for r in prov['service_cells']), 0)
    drifts = [100 * float(r['bill_drift']) for r in pre if r['anchor'] == ANCHOR[r['stratum']]]
    n['svNewBillDriftLo'], n['svNewBillDriftHi'] = fmt(min(drifts)), fmt(max(drifts))
    vals = [100 * a100.contrast('q38-thinking', 'batch16', rep, 'window')['share'] for rep in ('r0', 'r1', 'r2')]
    n['aNewShareLo'], n['aNewShareHi'] = fmt(min(vals)), fmt(max(vals))
    crossed = []
    for reps in itertools.product(('r0', 'r1', 'r2'), repeat=4):
        keys = [('q38-thinking', c, k, rep) for (c, k), rep in zip([('serial', 1), ('serial', 8), ('batch16', 1), ('batch16', 8)], reps)]
        t = [a100.seconds(k, 'window') / 106 for k in keys];crossed.append(t[1] - t[0] - t[3] + t[2])
    n['aNewCrossLo'], n['aNewCrossHi'] = fmt(min(crossed), 2), fmt(max(crossed), 2)
    n['aNewCrossNonpositive'] = str(sum(v <= 0 for v in crossed))
    n['aNewRows'] = str(len(a100.theory))
    return n


def render():
    service, a100, pipeline, prov = panels()
    return {'service-quality.tex': table_quality(service), 'service-h1.tex': table_h1(service),
            'service-financial.tex': table_financial(service), 'service-h2.tex': table_h2(service),
            'service-energy.tex': table_energy(service), 'service.tex': table_compare(service, pipeline),
            'a100-followup.tex': table_a100(a100, prov)}
