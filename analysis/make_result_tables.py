"""Result tables and number macros of the manuscript, made from the committed records only.

  python3 -I -B paper/www27/make_result_tables.py [--out paper/www27/tables]

Reads anonymous lean-run exports under evidence/results (72-cell resources and theory, service path, A100 arm), writes LaTeX fragments
and number macros under paper/www27/tables. Nothing is estimated here beyond the arithmetic of those tables: composites average
the cells of one GPU model, shares are ratios of the recorded increments, and every number in the prose comes through a macro in
numbers.tex. The first line of every output file names the inputs and their sha256 prefixes.
"""
import csv
from decimal import Decimal
import hashlib
from itertools import product
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import result_evidence
import bootstrap_tables
import service_result_tables
import retail_result_tables

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'evidence/results'
INPUTS = {
    'resources': 'lean-main-resources-4-2026-10-23.tsv',
    'theory': 'lean-main-theory-5-2026-10-24.tsv',
    'service_resources': 'lean-service-resources-1-2026-10-24.tsv',
    'service_theory': 'lean-service-theory-2-2026-10-24.tsv',
    'a100_resources': 'lean-a100-resources-1-2026-10-24.tsv',
    'a100_theory': 'lean-a100-theory-2-2026-10-24.tsv',
}
CENTRAL = '2.4'
GRID = ['0.25', '0.5', '1', '2', '2.4', '3', '4']
STRATA = ['coder-nonthinking', 'nemotron-thinking', 'q35-thinking', 'q38-nonthinking', 'q38-thinking']
LABEL = {'coder-nonthinking': 'Qwen2.5-Coder-7B', 'nemotron-thinking': 'Nemotron-3-Nano-30B', 'q35-thinking': 'Qwen3.5-9B thinking',
         'q38-nonthinking': 'Qwen3.8-27B non-thinking', 'q38-thinking': 'Qwen3.8-27B thinking'}
# the GPU model whose cells form the hardware-stratified composite shown in the main text, one per stratum
PRIMARY_HW = {'coder-nonthinking': 'H100 80GB HBM3', 'nemotron-thinking': 'H100 80GB HBM3', 'q35-thinking': 'H200',
              'q38-nonthinking': 'H100 80GB HBM3', 'q38-thinking': 'H100 80GB HBM3'}
HW_SHORT = {'H100 80GB HBM3': 'H100', 'H200': 'H200', 'H100 NVL': 'NVL', 'A100-SXM4-80GB': 'A100'}
HEADLINE = {'q35-thinking': 'di-q35-9b', 'q38-nonthinking': 'di-q38-27b-list', 'q38-thinking': 'di-q38-27b-list'}
POOLED = {'coder-nonthinking': ['batch16'], 'nemotron-thinking': ['batch16'], 'q35-thinking': ['batch16'],
          'q38-nonthinking': ['batch16', 'batch64'], 'q38-thinking': ['batch16', 'batch64']}
EXTENDED = {('q38-thinking', 'batch64')}     # cells that exist only under the owner-approved 7,200 s per-call bound
NAMES = {'serial': 'serial', 'batch16': 'batch16', 'batch64': 'batch64'}


def read(name):
    path = DATA / INPUTS[name]
    with open(path, newline='') as handle:
        return list(csv.DictReader(handle, delimiter='\t'))


def digest():
    return ' '.join('%s=%s' % (INPUTS[k], hashlib.sha256((DATA / INPUTS[k]).read_bytes()).hexdigest()[:12]) for k in INPUTS)


def num(x):
    return float(x) if x not in ('', None) else None


def hw_name(row):
    return (row.get('hardware') or '').replace('NVIDIA ', '')


class Cells:
    """Complete cells of a resources table, keyed by stratum, configuration, k and replicate."""

    def __init__(self, rows):
        self.rows = {}
        for r in rows:
            if r['status'] != 'complete':
                continue
            stratum, _, config, k, rep = r['cell_id'].split('|')
            key = (stratum, config, int(k[1:]), rep)
            assert key not in self.rows, 'a complete cell appears twice: %s' % '|'.join(map(str, key))
            self.rows[key] = r

    def slot(self, stratum, config, k, hw=None, basis='window'):
        """Mean GPU seconds per request over the cells of this slot (those on GPU model hw, or all) and their count."""
        values = []
        for (s, c, kk, rep), r in self.rows.items():
            if (s, c, kk) == (stratum, config, k) and (hw is None or hw_name(r) == hw):
                total = num(r['gpu_step_occupancy_s'] if basis == 'window' else r['generation_span_s'])
                values.append(total / num(r['tasks']))
        return (sum(values) / len(values), len(values)) if values else (None, 0)

    def mean(self, stratum, config, k, column):
        values = [num(r[column]) for (s, c, kk, rep), r in self.rows.items() if (s, c, kk) == (stratum, config, k)]
        return sum(values) / len(values), len(values)

    def hidden(self, stratum, config, k):
        values = [(num(r['reasoning_tokens_all']) + num(r['unselected_final_tokens']), num(r['delivered_output_tokens']))
                  for (s, c, kk, rep), r in self.rows.items() if (s, c, kk) == (stratum, config, k)]
        n = len(values)
        return sum(v[0] for v in values) / n, sum(v[1] for v in values) / n


def exact_h1(theory, stratum, pooled, group, basis):
    """Recorded rate-free gpu_s_H1, at higher precision than the resource export."""
    values = {r['gpu_s_H1'] for r in theory.rows if r['stratum'] == stratum and r['pooled'] == pooled and r['group'] == group
              and r['basis'] == basis}
    assert len(values) == 1, (stratum, pooled, group, basis, values)
    return float(values.pop())


def with_exact(result, h1):
    """Keep the higher-precision recorded H1 and resource d0, then derive d1."""
    assert abs(result['h1'] - h1) <= 0.15, 'rounded cells and exact H1 disagree by more than rounding: %s %s' % (result['h1'], h1)
    d0 = result['d0']
    return {**result, 'h1': h1, 'd1': d0 - h1, 'share': h1 / d0}


def composite(cells, stratum, pooled, hw, basis='window', theory=None):
    """The four slots of the pooling contrast on one GPU model, and H1 = d0 - d1 in GPU seconds per request."""
    a, na = cells.slot(stratum, 'serial', 1, hw, basis)
    b, nb = cells.slot(stratum, 'serial', 8, hw, basis)
    c, nc = cells.slot(stratum, pooled, 1, hw, basis)
    d, nd = cells.slot(stratum, pooled, 8, hw, basis)
    if None in (a, b, c, d):
        return None
    d0, d1 = b - a, d - c
    result = {'a': a, 'b': b, 'c': c, 'd': d, 'd0': d0, 'd1': d1, 'h1': d0 - d1, 'share': (d0 - d1) / d0, 'n': min(na, nb, nc, nd)}
    if theory is not None:
        result = with_exact(result, exact_h1(theory, stratum, pooled, 'hw:' + hw, {'window': 'window', 'span': 'generation_span'}[basis]))
    return result


def replicate_composite(cells, stratum, pooled, rep, basis='window', theory=None):
    slots = []
    hws = []
    for config, k in (('serial', 1), ('serial', 8), (pooled, 1), (pooled, 8)):
        r = cells.rows.get((stratum, config, k, rep))
        if r is None:
            return None
        total = num(r['gpu_step_occupancy_s'] if basis == 'window' else r['generation_span_s'])
        slots.append(total / num(r['tasks']))
        hws.append(hw_name(r))
    a, b, c, d = slots
    d0, d1 = b - a, d - c
    result = {'a': a, 'b': b, 'c': c, 'd': d, 'd0': d0, 'd1': d1, 'h1': d0 - d1, 'share': (d0 - d1) / d0, 'hw': hws}
    if theory is not None:
        result = with_exact(result, exact_h1(theory, stratum, pooled, rep, {'window': 'window', 'span': 'generation_span'}[basis]))
    return result


class Theory:
    def __init__(self, rows):
        self.rows = rows

    def pick(self, stratum, pooled, group, rate, basis='window', anchor=None, hidden=None, fee=None):
        found = [r for r in self.rows if r['stratum'] == stratum and r['pooled'] == pooled and r['group'] == group
                 and r['gpu_hour_usd'] == rate and r['basis'] == basis and (anchor is None or r['anchor'] == anchor)
                 and (hidden is None or r['hidden'] == hidden) and (fee is None or r['response_fee_usd'] == fee)]
        return found


def one(rows):
    assert len(rows) == 1, 'expected one row, got %d' % len(rows)
    return rows[0]


def f(x, digits=3):
    return ('%.' + str(digits) + 'g') % x


def signed(text):
    return '$-$' + text[1:] if text.startswith('-') else text


def pct(x, digits=0):
    return signed(('%.' + str(digits) + 'f') % (100 * x))


def gp(x):
    return signed('%.1f' % x)


def header(title):
    return '%% %s. Made by paper/www27/make_result_tables.py from: %s\n' % (title, digest())


def compute():
    cells = Cells(read('resources'))
    theory = Theory(read('theory'))
    out = {'cells': cells, 'theory': theory}
    return out


# ---------------------------------------------------------------------------------------------------------------- tables


def table_quality(cells, theory):
    lines = [header('Delivered quality, hidden tokens and bills'),
             r'\begin{table*}[t]',
             r'\caption{Initial evaluation-pipeline delivered quality and billed tokens of the serial configuration, mean of three replicates over 106 tasks. '
             r'$q^+$ and $q^-$ are the shares of requests with a correct or an incorrect delivery, and the rest abstain. Hidden tokens are '
             r'reasoning plus unselected final tokens per request, billed at the output rate, and Share is hidden over hidden plus delivered tokens. Token entries summarize the rounded per-cell exports. Bills (USD per 1,000 requests) use the list tariff of the model family and exist for Qwen3.5 and Qwen3.8 only.}',
             r'\label{tab:quality}', r'\centering\small\setlength{\tabcolsep}{4pt}',
             r'\begin{tabular}{lrrrrrrrrrr}', r'\toprule',
             r' & \multicolumn{5}{c}{$k=1$} & \multicolumn{5}{c}{$k=8$} \\',
             r'\cmidrule(lr){2-6}\cmidrule(lr){7-11}',
             r'Stratum & $q^+$ & $q^-$ & Hidden & Share & Bill & $q^+$ & $q^-$ & Hidden & Share & Bill \\', r'\midrule']
    for stratum in STRATA:
        cols = []
        for k in (1, 8):
            qp, _ = cells.mean(stratum, 'serial', k, 'q_plus')
            qm, _ = cells.mean(stratum, 'serial', k, 'q_minus')
            hid, deliv = cells.hidden(stratum, 'serial', k)
            if stratum in HEADLINE:
                row = one(theory.pick(stratum, 'batch16', 'all', CENTRAL, 'window', HEADLINE[stratum], 'all_non_delivered', '0'))
                bill = '%.1f' % (1000 * num(row['B0L' if k == 1 else 'B0H']))
            else:
                bill = '--'
            cols += ['%.3f' % qp, '%.3f' % qm, format(round(hid), ','), pct(hid / (hid + deliv), 1) + r'\%', bill]
        lines.append('%s & %s \\\\' % (LABEL[stratum], ' & '.join(cols)))
    lines += [r'\bottomrule', r'\end{tabular}', r'\end{table*}']
    return '\n'.join(lines) + '\n'


def h1_rows(cells, theory):
    rows = []
    for stratum in STRATA:
        hw = PRIMARY_HW[stratum]
        for pooled in POOLED[stratum]:
            win = composite(cells, stratum, pooled, hw, 'window', theory)
            span = composite(cells, stratum, pooled, hw, 'span', theory)
            group = 'hw:' + hw
            trow = [r for r in theory.pick(stratum, pooled, group, CENTRAL, 'window', fee=None) if r['hidden'] in ('', 'all_non_delivered') and r['response_fee_usd'] in ('', '0')]
            trow = trow[0]
            rows.append({'stratum': stratum, 'pooled': pooled, 'hw': hw, 'win': win, 'span': span, 'theory': trow,
                         'ext': (stratum, pooled) in EXTENDED})
    return rows


def table_h1(cells, theory):
    h200 = {p: composite(cells, 'q38-nonthinking', p, 'H200', 'window', theory)['share'] for p in ('batch16', 'batch64')}
    lines = [header('Pooling contrast'),
             r'\begin{table*}[t]',
             r'\caption{Initial evaluation-pipeline cost of extra attempts in one hardware-stratified composite per stratum, the GPU model with the most cells (H100 is the 80GB HBM3 model, $n$ the fewest cells in any slot). '
             r'$d_0$ and $d_1$ are the increases in GPU seconds per request from $k=1$ to $k=8$ under serial and pooled execution, and H1 $=d_0-d_1$. Window counts the GPU step of the evaluation pipeline, span the generation calls only. '
             r'USD columns are per 1,000 requests at 2.4 USD per GPU hour, 0.15 USD per kWh, and 0.03 USD per core hour, with $d_0$ and $d_1$ at the midpoint of the energy envelope and H1 at the common low endpoint. $\dagger$: extended-bound cell. The two H200 composites of Qwen3.8 non-thinking give ' + pct(h200['batch16']) + r'\% (batch16) and ' + pct(h200['batch64']) + r'\% (batch64).}',
             r'\label{tab:h1}', r'\centering\small',
             r'\begin{tabular}{llcrrrrrrrr}', r'\toprule',
             r' & & & \multicolumn{3}{c}{GPU s per request, window} & \multicolumn{2}{c}{H1/$d_0$} & \multicolumn{3}{c}{USD per 1,000 requests, window} \\',
             r'\cmidrule(lr){4-6}\cmidrule(lr){7-8}\cmidrule(lr){9-11}',
             r'Stratum, pooled & GPU & $n$ & $d_0$ & $d_1$ & H1 & window & span & $d_0$ & $d_1$ & H1, common low \\', r'\midrule']
    for row in h1_rows(cells, theory):
        w, s, t = row['win'], row['span'], row['theory']
        name = '%s, %s%s' % (LABEL[row['stratum']], row['pooled'], r'$^\dagger$' if row['ext'] else '')
        lines.append('%s & %s & %d & %s & %s & %s & %s\\%% & %s\\%% & %.1f & %.1f & %.1f \\\\' % (
            name, HW_SHORT[row['hw']], w['n'], gp(w['d0']), gp(w['d1']), gp(w['h1']), pct(w['share']), pct(s['share']),
            1000 * num(t['d0']), 1000 * num(t['d1']), 1000 * num(t['H1_lo'])))
    lines += [r'\bottomrule', r'\end{tabular}', r'\end{table*}']
    return '\n'.join(lines) + '\n'


def threshold_rows(theory):
    rows = []
    for stratum, pooled in (('q38-nonthinking', 'batch16'), ('q38-thinking', 'batch16'), ('q35-thinking', 'batch16')):
        hw = PRIMARY_HW[stratum]
        anchor = HEADLINE[stratum]
        group = 'hw:' + hw
        r0 = one(theory.pick(stratum, pooled, group, CENTRAL, 'window', anchor, 'all_non_delivered', '0'))
        r4 = one(theory.pick(stratum, pooled, group, CENTRAL, 'window', anchor, 'all_non_delivered', '0.04'))
        rows.append({'stratum': stratum, 'pooled': pooled, 'hw': hw, 'fee0': r0, 'fee4': r4})
    return rows


def table_h3(theory):
    short = {'q38-nonthinking': 'Qwen3.8 non-thinking', 'q38-thinking': 'Qwen3.8 thinking', 'q35-thinking': 'Qwen3.5 thinking'}
    lines = [header('Pass-through and admission inputs'),
             r'\begin{table*}[t]',
             r'\caption{Initial evaluation-pipeline indifference shares and admission inputs at 2.4 USD per GPU hour, hardware-stratified composites with batch16 (H100 for Qwen3.8, H200 for Qwen3.5), window basis, all non-delivered tokens billed, list tariff (Appendix~\ref{app:tariffs}). '
             r'$k_L=1$ and $k_H=8$. Shares $\alpha_{C,\pi}=d_\pi/\Delta B_\pi$ compare the cloud\textquotesingle s budget preferences, conditional on participation. The cost/bill ratios describe coverage at each indicated configuration. The admission band is empty in every row.}',
             r'\label{tab:h3}', r'\centering\small\setlength{\tabcolsep}{6pt}',
             r'\begin{tabular}{lrrrrrr}', r'\toprule',
             r' & \multicolumn{2}{c}{Indifference share} & \multicolumn{2}{c}{Cost/bill} & \multicolumn{2}{c}{Serial growth} \\',
             r'\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}',
             r'Stratum & $\alpha_{C,0}$ & $\alpha_{C,1}$ & $\frac{C_0(k_L)}{B_0(k_L)}$ & $\frac{C_1(k_H)}{B_1(k_H)}$ & $\frac{B_0(k_H)}{B_0(k_L)}$ & $\frac{C_0(k_H)}{C_0(k_L)}$ \\', r'\midrule']
    for r in threshold_rows(theory):
        a, b = r['fee0'], r['fee4']
        assert a['adm_nonempty'] == 'no' and b['adm_nonempty'] == 'no', 'the table caption says the band is empty in every row'
        lines.append('%s & %.2f & %.2f & %.1f & %.2f & %.1f & %.2f \\\\' % (
            short[r['stratum']], num(a['alpha_C0']), num(a['alpha_C1']), num(a['C0L']) / num(a['B0L']),
            num(a['C1H']) / num(a['B1H']), num(a['B0H']) / num(a['B0L']),
            num(a['C0H']) / num(a['C0L'])))
    lines += [r'\bottomrule', r'\end{tabular}', r'\end{table*}']
    return '\n'.join(lines) + '\n'

def break_even_rate(theory, row):
    """Capacity rate at which the serial k=1 cost equals the serial k=1 bill (cost is linear in the rate)."""
    base = dict(stratum=row['stratum'], pooled=row['pooled'], group=row['group'], basis=row['basis'], anchor=row['anchor'],
                hidden=row['hidden'], fee=row['response_fee_usd'])
    lo = one(theory.pick(rate='2', **base))
    hi = one(theory.pick(rate='4', **base))
    slope = (num(hi['C0L']) - num(lo['C0L'])) / 2.0
    intercept = num(lo['C0L']) - 2.0 * slope
    return (num(row['B0L']) - intercept) / slope


class Service:
    """Complete cells of the service-path resources table (Qwen3.5), window of the online-selection service."""

    def __init__(self, rows):
        self.rows = {}
        for r in rows:
            if r['status'] != 'complete':
                continue
            _, _, config, k, rep = r['cell_id'].split('|')
            self.rows[(config, int(k[1:]), rep)] = r

    def per_request(self, config, k, rep, column='service_window_s'):
        r = self.rows[(config, k, rep)]
        return num(r[column]) / num(r['tasks'])

    def h1(self, rep, column='service_window_s', theory=None):
        d0 = self.per_request('serial', 8, rep, column) - self.per_request('serial', 1, rep, column)
        d1 = self.per_request('batch16', 8, rep, column) - self.per_request('batch16', 1, rep, column)
        if theory is not None:
            h1 = exact_h1(theory, 'q35-thinking', 'batch16', rep, 'service')
            assert abs((d0 - d1) - h1) <= 0.15, 'rounded cells and exact H1 disagree by more than rounding'
            return d0, d0 - h1, h1, h1 / d0
        return d0, d1, d0 - d1, (d0 - d1) / d0

    def hardware(self, rep):
        return {hw_name(r) for (c, k, rr), r in self.rows.items() if rr == rep}


def table_replicates(cells, theory):
    lines = [header('Replicate-level pooling contrasts'),
             r'\begin{table*}[t]',
             r'\caption{Replicate-level pooling contrasts of every pooled row, window basis. GPU models of the four cells (serial $k=1$, serial $k=8$, pooled $k=1$, pooled $k=8$): '
             r'H is H100 80GB HBM3, E is H200, N is H100 NVL. A replicate whose four cells ran on one model is a matched contrast. $\dagger$: extended-bound cell in the pooled $k=8$ slot.}',
             r'\label{tab:replicates}', r'\centering\small',
             r'\begin{tabular}{llcclrrr}', r'\toprule',
             r'Stratum & Pooled & Replicate & GPUs & Matched & H1 (GPU s) & H1/$d_0$ window & H1/$d_0$ span \\', r'\midrule']
    letters = {'H100 80GB HBM3': 'H', 'H200': 'E', 'H100 NVL': 'N'}
    for stratum in STRATA:
        for pooled in POOLED[stratum]:
            for rep in ('r0', 'r1', 'r2'):
                w = replicate_composite(cells, stratum, pooled, rep, 'window', theory)
                s = replicate_composite(cells, stratum, pooled, rep, 'span', theory)
                gpus = ''.join(letters[h] for h in w['hw'])
                matched = 'yes' if len(set(w['hw'])) == 1 else 'no'
                ext = (stratum, pooled) in EXTENDED and rep in ('r0', 'r1')
                name = '%s%s' % (LABEL[stratum], '') if (pooled == POOLED[stratum][0] and rep == 'r0') else ''
                lines.append('%s & %s%s & %s & %s & %s & %s & %s\\%% & %s\\%% \\\\' % (
                    name, pooled, r'$^\dagger$' if ext else '', rep, gpus, matched, gp(w['h1']), pct(w['share']), pct(s['share'])))
        lines.append(r'\addlinespace')
    lines[-1] = r'\bottomrule'
    lines += [r'\end{tabular}', r'\end{table*}']
    return '\n'.join(lines) + '\n'


def table_service(cells, theory, service, service_theory):
    lines = [header('Service path against the evaluation pipeline, Qwen3.5-9B thinking'),
             r'\begin{table*}[t]',
             r'\caption{H1 for Qwen3.5-9B thinking in GPU seconds per request (batch16 against serial) under three cost windows. The service window runs online selection '
             r'and ends when the last delivered answer leaves, the pipeline window holds the GPU while every candidate is judged, and the span counts the generation calls only. '
             r'Matched replicates are those whose four cells ran on one GPU model, H100 NVL for $r_1$ in both runs. In $r_0$ and $r_2$ the pipeline cells ran on H200 and the service cells on H100 80GB HBM3.}',
             r'\label{tab:service}', r'\centering\small',
             r'\begin{tabular}{lllrrrr}', r'\toprule',
             r'Replicate & Pipeline GPU & Service GPU & Service & Pipeline window & Pipeline span & Service/pipeline GPU matched \\', r'\midrule']
    for rep in ('r0', 'r1', 'r2'):
        w = replicate_composite(cells, 'q35-thinking', 'batch16', rep, 'window', theory)
        s = replicate_composite(cells, 'q35-thinking', 'batch16', rep, 'span', theory)
        sv = service.h1(rep, theory=service_theory)
        pgpu = '/'.join(sorted({HW_SHORT[h] for h in w['hw']}))
        sgpu = '/'.join(sorted({HW_SHORT[h] for h in service.hardware(rep)}))
        lines.append('%s & %s & %s & %s (%s\\%%) & %s (%s\\%%) & %s (%s\\%%) & %s \\\\' % (
            rep, pgpu, sgpu, gp(sv[2]), pct(sv[3]), gp(w['h1']), pct(w['share']), gp(s['h1']), pct(s['share']), 'yes' if pgpu == sgpu else 'no'))
    lines += [r'\bottomrule', r'\end{tabular}', r'\end{table*}']
    return '\n'.join(lines) + '\n'


def numbers(cells, theory, service, a100):
    n = {}
    rows = cells.rows
    n['nCellsTotal'] = str(len(rows))
    n['nCellsCoder'] = str(sum(1 for key in rows if key[0] == 'coder-nonthinking'))
    n['nCellsExtended'] = str(sum(1 for r in rows.values() if r.get('timeout_revised') == 'True'))
    n['nCellsBound'] = str(len(rows) - int(n['nCellsCoder']) - int(n['nCellsExtended']))
    hw = {}
    for r in rows.values():
        hw[hw_name(r)] = hw.get(hw_name(r), 0) + 1
    n['nCellsHBM'], n['nCellsHTwo'], n['nCellsNVL'] = str(hw['H100 80GB HBM3']), str(hw['H200']), str(hw['H100 NVL'])
    # quality
    drops, rises, hid1, hid8 = [], [], [], []
    qdiff = 0
    for stratum in STRATA:
        a1 = cells.mean(stratum, 'serial', 1, 'abstain')[0]
        a8 = cells.mean(stratum, 'serial', 8, 'abstain')[0]
        m1 = cells.mean(stratum, 'serial', 1, 'q_minus')[0]
        m8 = cells.mean(stratum, 'serial', 8, 'q_minus')[0]
        drops.append(a1 - a8)
        rises.append(m8 - m1)
        if stratum in ('nemotron-thinking', 'q35-thinking', 'q38-thinking'):
            for k, bucket in ((1, hid1), (8, hid8)):
                h, d = cells.hidden(stratum, 'serial', k)
                bucket.append(h / (h + d))
        for pooled in POOLED[stratum]:
            for k in (1, 8):
                qdiff = max(qdiff, abs(cells.mean(stratum, 'serial', k, 'q_plus')[0] - cells.mean(stratum, pooled, k, 'q_plus')[0]))
    n['qAbstainDropLo'], n['qAbstainDropHi'] = pct(min(drops)), pct(max(drops))
    n['qWrongRiseLo'], n['qWrongRiseHi'] = pct(min(rises)), pct(max(rises))
    n['qHiddenKOneLo'], n['qHiddenKOneHi'] = pct(min(hid1)), pct(max(hid1))
    n['qHiddenKEightLo'], n['qHiddenKEightHi'] = pct(min(hid8), 1), pct(max(hid8), 1)
    n['qPooledDiffMax'] = pct(qdiff, 1)
    code = {'coder-nonthinking': 'Cod', 'nemotron-thinking': 'Nem', 'q35-thinking': 'QFive', 'q38-nonthinking': 'QOff', 'q38-thinking': 'QOn'}
    pcode = {'batch16': 'Sixteen', 'batch64': 'SixtyFour'}
    for row in h1_rows(cells, theory):
        tag = code[row['stratum']] + pcode[row['pooled']]
        n['shWin' + tag] = pct(row['win']['share'])
        n['shSpan' + tag] = pct(row['span']['share'])
    # H1 sign over the grid, every hardware-stratified row of the theory table
    hw_rows = [r for r in theory.rows if r['group'].startswith('hw:')]
    n['nHwRows'] = format(len(hw_rows), ',')
    n['nHwRowsPositive'] = format(sum(1 for r in hw_rows if num(r['H1_lo']) > 0), ',')
    shift = max(abs(num(r[k]) - (num(r['d0']) - num(r['d1']))) / num(r['d0']) for r in hw_rows if r['basis'] == 'window' for k in ('H1_lo', 'H1_hi'))
    n['enShiftMax'] = pct(shift)
    # H2 and H3 inputs at the central rate
    trs = {r['stratum']: r for r in threshold_rows(theory)}
    for stratum, tag in (('q38-nonthinking', 'QOff'), ('q38-thinking', 'QOn'), ('q35-thinking', 'QFive')):
        r0 = trs[stratum]['fee0']
        n['aZero' + tag], n['aOne' + tag] = '%.2f' % num(r0['alpha_C0']), '%.2f' % num(r0['alpha_C1'])
        n['costRatio' + tag] = '%.1f' % (num(r0['C0H']) / num(r0['C0L']))
        n['billRatio' + tag] = '%.1f' % (num(r0['B0H']) / num(r0['B0L']))
        n['lowRatio' + tag] = '%.1f' % (num(r0['C0L']) / num(r0['B0L']))
        n['breakEven' + tag] = '%.2f' % break_even_rate(theory, r0)
    n['aZeroRatio'] = '%.2f' % (num(trs['q38-thinking']['fee0']['alpha_C0']) / num(trs['q38-nonthinking']['fee0']['alpha_C0']))
    pre = [r for r in theory.rows if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
    n['admPreRows'], n['admPreOpen'] = format(len(pre), ','), str(sum(r['adm_nonempty'] != 'no' for r in pre))
    zero = [r for r in theory.rows if r['response_fee_usd'] == '0']
    n['admZeroOpen'] = str(sum(r['adm_nonempty'] != 'no' for r in zero))
    four = [r for r in theory.rows if r['response_fee_usd'] == '0.04' and r['hidden'] == 'all_non_delivered']
    n['admFourRows'] = format(len(four), ',')
    n['admFourOpen'] = str(sum(r['adm_nonempty'] != 'no' for r in four))
    n['admFourOpenSpan'] = str(sum(r['adm_nonempty'] != 'no' for r in four if r['basis'] == 'generation_span'))
    # batch64 against batch16 for Qwen3.8 thinking on H100 80GB HBM3
    c16 = composite(cells, 'q38-thinking', 'batch16', 'H100 80GB HBM3', 'window', theory)
    c64 = composite(cells, 'q38-thinking', 'batch64', 'H100 80GB HBM3', 'window', theory)
    n['bSixtyFourKOneDrop'] = pct(1 - c64['c'] / c16['c'])
    n['bSixtyFourKEightDrop'] = pct(1 - c64['d'] / c16['d'])
    # replicates whose four cells ran on one GPU model: H1 must be positive in all of them
    matched = []
    for stratum in STRATA:
        for pooled in POOLED[stratum]:
            for rep in ('r0', 'r1', 'r2'):
                w = replicate_composite(cells, stratum, pooled, rep, 'window', theory)
                if len(set(w['hw'])) == 1:
                    matched.append(w['h1'])
    n['nMatchedReps'] = str(len(matched))
    n['nMatchedPositive'] = str(sum(v > 0 for v in matched))
    for k, tag in ((1, 'KOne'), (8, 'KEight')):
        h, d = cells.hidden('q38-nonthinking', 'serial', k)
        n['qOffHidden' + tag] = pct(h / (h + d))
    # service path (Qwen3.5-9B thinking, three replicates)
    ratios = [num(r['service_window_s']) / num(r['generation_span_s']) for r in service.rows.values()]
    n['svWinSpanLo'], n['svWinSpanHi'] = '%.3f' % min(ratios), '%.3f' % max(ratios)
    for rep, tag in (('r0', 'RZero'), ('r1', 'ROne'), ('r2', 'RTwo')):
        sv = service.h1(rep, theory=Theory(read('service_theory')))
        n['svShare' + tag] = pct(sv[3])
        n['svGpuS' + tag] = gp(sv[2])
        w = replicate_composite(cells, 'q35-thinking', 'batch16', rep, 'window', theory)
        n['plShare' + tag] = pct(w['share'])
        sp = replicate_composite(cells, 'q35-thinking', 'batch16', rep, 'span', theory)
        n['spShare' + tag] = pct(sp['share'])
    comp = one(Theory(read('service_theory')).pick('q35-thinking', 'batch16', 'hw:H100 80GB HBM3', CENTRAL, 'service', 'di-q35-9b', 'all_non_delivered', '0'))
    svt = Theory(read('service_theory'))
    n['svRows'] = format(len(svt.rows), ',')
    n['svRowsPositive'] = format(sum(1 for r in svt.rows if num(r['H1_lo']) > 0), ',')
    n['svShareHw'] = pct((num(comp['d0']) - num(comp['d1'])) / num(comp['d0']))
    # A100 arm
    hwa = 'A100-SXM4-80GB'
    a100_theory = Theory(read('a100_theory'))
    comp_a = composite(a100, 'q38-thinking', 'batch16', hwa, 'window', a100_theory)
    n['aHOneComp'], n['aShareComp'] = gp(comp_a['h1']), pct(comp_a['share'])
    r0a = replicate_composite(a100, 'q38-thinking', 'batch16', 'r0', 'window', a100_theory)
    n['aHOneRZero'], n['aShareRZero'] = gp(r0a['h1']), pct(r0a['share'])
    values = []
    for i in ('r0', 'r1', 'r2'):
        for j in ('r0', 'r1', 'r2'):
            for k in ('r0', 'r1', 'r2'):
                d0 = a100.rows[('q38-thinking', 'serial', 8, k)]
                a = a100.rows[('q38-thinking', 'serial', 1, i)]
                c = a100.rows[('q38-thinking', 'batch16', 1, j)]
                dd = a100.rows[('q38-thinking', 'batch16', 8, 'r0')]
                g = lambda r: num(r['gpu_step_occupancy_s']) / num(r['tasks'])
                values.append((g(d0) - g(a)) - (g(dd) - g(c)))
    n['aPairLo'], n['aPairHi'], n['aPairNonPos'] = signed('%.0f' % min(values)), '%.0f' % max(values), str(sum(v <= 0 for v in values))
    more_numbers(cells, theory, service, n)
    review_numbers(cells, theory, n)
    n['restrictedMenuHOne'] = gp(float(result_evidence.restricted_h1()))
    return n


def cell_cost(row, rate, endpoint, window_column='gpu_step_occupancy_s', cpu_column='cpu_point_s'):
    """Cost per request of one cell at a capacity rate and an energy endpoint (lo, hi or mid), the formula of the theory tool."""
    lo, hi = num(row['energy_kwh_lo']), num(row['energy_kwh_hi'])
    kwh = {'lo': lo, 'hi': hi, 'mid': (lo + hi) / 2}[endpoint]
    return (rate * num(row[window_column]) / 3600 + 0.15 * kwh + 0.03 * num(row[cpu_column]) / 3600) / num(row['tasks'])


def mixed_corner_share(cells, stratum, pooled, hw, rate, serial_end, pooled_end):
    def slot(config, k, end):
        values = [cell_cost(r, rate, end) for (s, c, kk, rep), r in cells.rows.items() if (s, c, kk) == (stratum, config, k) and hw_name(r) == hw]
        return sum(values) / len(values)
    d0 = slot('serial', 8, serial_end) - slot('serial', 1, serial_end)
    d1 = slot(pooled, 8, pooled_end) - slot(pooled, 1, pooled_end)
    return (d0 - d1) / d0


def margin_rows(cells, theory):
    """The two terms of the margin decomposition under each headline tariff."""
    out = []
    for r in h1_rows(cells, theory):
        if r['stratum'] not in HEADLINE:
            continue
        t = one(theory.pick(r['stratum'], r['pooled'], 'hw:' + r['hw'], CENTRAL,
                            'window', HEADLINE[r['stratum']], 'all_non_delivered', '0'))
        delta_zero = Decimal(t['B0H']) - Decimal(t['B0L'])
        drift = float(Decimal(t['B1H']) - Decimal(t['B1L']) - delta_zero)
        out.append({**r, 'bill_drift': drift, 'relative_drift': drift / float(delta_zero),
                    'cost_term': float(Decimal(t['s_H']) - Decimal(t['s_L']))})
    return out


def table_margin(cells, theory):
    lines = [header('Cost and bill terms of the cloud margin'), r'\begin{table}[t]',
             r'\caption{Terms in~\eqref{eq:margin-decomp} for the Table~\ref{tab:h1} composites with a headline tariff, at the central cost scenario on the window basis. Monetary terms are USD per 1,000 requests. The bill term is multiplied by $\alpha$ in the cloud\textquotesingle s margin. $\dagger$: extended-bound cells.}',
             r'\label{tab:margin}', r'\centering\small\setlength{\tabcolsep}{3pt}',
             r'\begin{tabular}{lrrr}', r'\toprule',
             r' & Cost term & Bill term & Relative bill \\',
             r'Stratum, pooled & $s_H-s_L$ & $\Delta B_1-\Delta B_0$ & change \\', r'\midrule']
    short = {'q35-thinking': 'Qwen3.5', 'q38-nonthinking': 'Qwen3.8 off', 'q38-thinking': 'Qwen3.8 on'}
    for r in margin_rows(cells, theory):
        name = short[r['stratum']] + ', ' + r['pooled'] + (r'$^\dagger$' if r['ext'] else '')
        lines.append('%s & %.2f & %s & %s\\%% \\\\' %
                     (name, 1000 * r['cost_term'], signed('%.2f' % (1000 * r['bill_drift'])), pct(r['relative_drift'], 1)))
    lines += [r'\bottomrule', r'\end{tabular}', r'\end{table}']
    return '\n'.join(lines) + '\n'


def energy_box_minimum(cells, stratum, pooled, hw, rate):
    """Exact vertex minimum of the affine cost contrast for four energy intervals."""
    slots = [('serial', 1), ('serial', 8), (pooled, 1), (pooled, 8)]
    def at(endpoints):
        means = []
        for (config, k), endpoint in zip(slots, endpoints):
            values = [cell_cost(r, rate, endpoint) for (s, c, kk, rep), r in cells.rows.items()
                      if (s, c, kk) == (stratum, config, k) and hw_name(r) == hw]
            assert values, 'missing energy-box slot'
            means.append(sum(values) / len(values))
        return means[1] - means[0] - means[3] + means[2]
    value, endpoints = min((at(e), e) for e in product(('lo', 'hi'), repeat=4))
    assert endpoints == ('hi', 'lo', 'lo', 'hi')
    return value


def table_energy(cells, theory):
    groups = sorted({(r['stratum'], r['pooled'], r['group'][3:]) for r in theory.rows
                     if r['group'].startswith('hw:') and r['pooled'] != 'menu'},
                    key=lambda x: (STRATA.index(x[0]), x[1], x[2]))
    lines = [header('Independent energy endpoint sensitivity'), r'\begin{table*}[t]',
             r'\caption{Minimum window-basis H1 in USD per 1,000 requests when all four cells independently range over their declared energy endpoints. Only energy varies within each column. Columns show capacity rates in USD per GPU hour, with CPU at 0.03 USD per core hour. These are scenario-box minima, not sampling bounds. $\dagger$: extended-bound cells.}',
             r'\label{tab:energy-box}', r'\centering\small', r'\begin{tabular}{llrrrrrrr}',
             r'\toprule', r'Stratum, pooled & GPU & 0.25 & 0.5 & 1 & 2 & 2.4 & 3 & 4 \\', r'\midrule']
    for s, p, hw in groups:
        name = LABEL[s] + ', ' + p + (r'$^\dagger$' if (s, p) in EXTENDED else '')
        values = [signed('%.2f' % (1000 * energy_box_minimum(cells, s, p, hw, float(rate)))) for rate in GRID]
        lines.append(name + ' & ' + HW_SHORT[hw] + ' & ' + ' & '.join(values) + r' \\')
    lines += [r'\bottomrule', r'\end{tabular}', r'\end{table*}']
    return '\n'.join(lines) + '\n'


def review_numbers(cells, theory, n):
    """Scoped arithmetic added after the independent manuscript review."""
    pre = [r for r in theory.rows if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
    feasible = [r for r in pre if num(r['C0L']) < num(r['B0L'])]
    half = [r for r in feasible if r['gpu_hour_usd'] == '0.5']
    assert len(half) == 42 and {r['gpu_hour_usd'] for r in feasible} == {'0.25', '0.5'}
    n['participationHalfRows'] = str(len(half))
    n['participationHalfLo'] = '%.2f' % min(num(r['C0L']) / num(r['B0L']) for r in half)
    n['participationHalfHi'] = '%.2f' % max(num(r['C0L']) / num(r['B0L']) for r in half)
    n['admQFiveRows'] = str(sum(r['stratum'] == 'q35-thinking' for r in pre))
    r = margin_rows(cells, theory)
    n['billDriftLo'], n['billDriftHi'] = pct(min(x['relative_drift'] for x in r), 1), pct(max(x['relative_drift'] for x in r), 1)
    n['billDriftAbsMax'] = '%.1f' % (1000 * max(abs(x['bill_drift']) for x in r))
    ordinary = [x['cost_term'] for x in r if not x['ext']]
    n['billCostLo'], n['billCostHi'] = '%.1f' % (1000 * min(ordinary)), '%.1f' % (1000 * max(ordinary))
    extended = next(x for x in r if x['ext'])
    n['billDriftExt'], n['billCostExt'] = '%.1f' % (1000 * extended['bill_drift']), '%.1f' % (1000 * extended['cost_term'])
    high = [num(x['fee0']['B1H']) / num(x['fee0']['C1H']) for x in threshold_rows(theory) if x['stratum'].startswith('q38-')]
    n['highBillCostQEightLo'], n['highBillCostQEightHi'] = '%.1f' % min(high), '%.1f' % max(high)
    q5 = next(x['fee0'] for x in threshold_rows(theory) if x['stratum'] == 'q35-thinking')
    n['highBillCostQFive'] = '%.1f' % (num(q5['B1H']) / num(q5['C1H']))
    three = [r for r in theory.rows if r['windows'] == '3']
    n['pauseExtRows'] = str(sum(r['timeout_revised'] == 'True' for r in three))
    plain = [r for r in three if r['timeout_revised'] != 'True']
    n['pausePlainRows'] = str(len(plain))
    n['pausePlainFires'] = str(sum(r['pause_rule'] == 'True' for r in plain))
    for s, tag in [('q35-thinking', 'QFive'), ('q38-thinking', 'QOn')]:
        bad = [rate for rate in GRID if energy_box_minimum(cells, s, 'batch16', PRIMARY_HW[s], float(rate)) < 0]
        assert bad == ['0.25', '0.5']
    n['boxExtCentral'] = signed('%.2f' % (1000 * energy_box_minimum(cells, 'q38-thinking', 'batch64', PRIMARY_HW['q38-thinking'], 2.4)))
    for replicate, tag in [(None, 'Composite'), ('r1', 'ROne')]:
        for include, suffix in [(True, 'Full'), (False, 'Restricted')]:
            result = result_evidence.menu_h1(include, replicate)
            n['menu' + tag + suffix] = gp(float(result['h1']))
            # Verify that minimizing GPU time selects the same implementation
            # as the declared cost over every rate and both common endpoints.
            for k, selected in result['selected'].items():
                for rate, end in product(GRID, ('lo', 'mid', 'hi')):
                    means = {}
                    for config in ['serial'] + POOLED['q38-thinking']:
                        values = [cell_cost(r, float(rate), end) for (s, c, kk, rep), r in cells.rows.items()
                                  if (s, c, kk) == ('q38-thinking', config, k)
                                  and hw_name(r) == PRIMARY_HW[s] and (replicate is None or rep == replicate)
                                  and (include or r['timeout_revised'] != 'True')]
                        if values:
                            means[config] = sum(values) / len(values)
                    assert selected == min(means, key=means.get), 'Window menu and resource-cost menu differ'
    non_generation = [1 - num(r['generation_span_s']) / num(r['gpu_step_occupancy_s'])
                      for (s, c, k, rep), r in cells.rows.items()
                      if s in ('nemotron-thinking', 'q38-thinking', 'q38-nonthinking') and c != 'serial' and k == 8]
    n['nonGenerationLo'], n['nonGenerationHi'] = pct(min(non_generation)), pct(max(non_generation))
    cpu = [0.03 * num(r['cpu_point_s']) / 3600 / num(r['tasks']) / cell_cost(r, 2.4, 'mid') for r in cells.rows.values()]
    n['cpuPotentialOverlapHi'] = pct(max(cpu), 1)
    # Same non-server hosting uplift in all three bottom-up corners. The
    # archived low case omitted it; this only corrects the contextual anchors.
    def capacity(price, overhead, life, interest, operations, kw, colo, utilisation):
        capital = price / 8 * (1 + overhead)
        recovery = 1 / life if interest == 0 else interest / (1 - (1 + interest) ** -life)
        return (capital * (recovery + operations) + kw / 8 * 1.1 * colo * 12) / 8760 / utilisation
    for tag, low, mid, high, kw in [('Hopper', 249000, 285000, 302999, 10.2),
                                   ('AOneHundred', 95200, 118567, 199000, 6.5)]:
        for label, value in [('Low', capacity(low, .10, 6, 0, .015, kw, 80, .9)),
                             ('Mid', capacity(mid, .18, 5, .0933, .035, kw, 150, .7)),
                             ('High', capacity(high, .23, 4, .13, .06, kw, 196, .5))]:
            n['capacity' + tag + label] = '%.2f' % value


def more_numbers(cells, theory, service, n):
    # fee rows outside the preregistered reading
    reasoning = [r for r in theory.rows if r['response_fee_usd'] == '0.04' and r['hidden'] == 'reasoning_only' and r['adm_nonempty'] != 'no']
    n['admReasonOpen'] = str(len(reasoning))
    n['admReasonOffOpen'] = str(sum(r['stratum'] == 'q38-nonthinking' for r in reasoning))
    n['admReasonFiveOpen'] = str(sum(r['stratum'] == 'q35-thinking' for r in reasoning))
    assert len(reasoning) == int(n['admReasonOffOpen']) + int(n['admReasonFiveOpen']), 'another stratum has open reasoning-only rows'
    assert max(float(r['gpu_hour_usd']) for r in reasoning if r['stratum'] == 'q38-nonthinking') == 2.0
    assert max(float(r['gpu_hour_usd']) for r in reasoning if r['stratum'] == 'q35-thinking') == 1.0
    # cost and bill ratios over every preregistered row
    pre = [r for r in theory.rows if r['hidden'] == 'all_non_delivered' and r['response_fee_usd'] == '0']
    cost = [num(r['C0H']) / num(r['C0L']) for r in pre]
    bill = [num(r['B0H']) / num(r['B0L']) for r in pre]
    assert all(c < b for c, b in zip(cost, bill)), 'the cost ratio exceeds the bill ratio in a preregistered row'
    n['costRowsLo'], n['costRowsHi'] = '%.1f' % min(cost), '%.1f' % max(cost)
    n['billRowsLo'], n['billRowsHi'] = '%.1f' % min(bill), '%.1f' % max(bill)
    lowc = [num(r['fee0']['C0L']) / num(r['fee0']['B0L']) for r in threshold_rows(theory)]
    n['billCoversHi'], n['billCoversLo'] = pct(1 / min(lowc)), pct(1 / max(lowc))
    # pooled against serial quality, single cells
    worst = 0
    for stratum in STRATA:
        for pooled in POOLED[stratum]:
            for k in (1, 8):
                for rep in ('r0', 'r1', 'r2'):
                    a, b = cells.rows.get((stratum, 'serial', k, rep)), cells.rows.get((stratum, pooled, k, rep))
                    if a and b:
                        worst = max(worst, abs(num(a['q_plus']) - num(b['q_plus'])))
    n['qPooledDiffCellMax'] = pct(worst)
    # truncation at the 24,576-token cap in the main cells
    for stratum, tag in (('q35-thinking', 'QFive'), ('nemotron-thinking', 'Nem'), ('q38-thinking', 'QOn')):
        values = [num(r['truncated_candidate_share']) for (s, c, k, rep), r in cells.rows.items() if s == stratum]
        n['trunc' + tag + 'Lo'], n['trunc' + tag + 'Hi'] = pct(min(values)), pct(max(values))
    # the preregistered three-replicate mean
    three = [r for r in theory.rows if r['windows'] == '3']
    n['pauseRows'], n['pauseFires'] = format(len(three), ','), format(sum(r['pause_rule'] == 'True' for r in three), ',')
    n['envNonPositive'] = format(sum(r['H1_env_lo'] != '' and num(r['H1_env_lo']) <= 0 for r in three), ',')
    # the mixed corner of the energy envelope: serial cells at the low end and pooled cells at the high end
    shares, extended = [], []
    for stratum in STRATA:
        for pooled in POOLED[stratum]:
            for rate in (0.25, 0.5, 1, 2, 2.4, 3, 4):
                v = mixed_corner_share(cells, stratum, pooled, PRIMARY_HW[stratum], rate, 'lo', 'hi')
                (extended if (stratum, pooled) in EXTENDED else shares).append((rate, v))
    n['mixedMinShare'] = pct(min(v for r, v in shares))
    negative = [r for r, v in extended if v <= 0]
    n['mixedExtMaxNegRate'] = '%g' % max(negative)
    assert min(v for r, v in extended) < 0 and all(v > 0 for r, v in shares)
    # H2 on both bases and per replicate, Qwen3.8 thinking against non-thinking, list tariff
    def alpha(stratum, group, basis, key):
        return num(one(theory.pick(stratum, 'batch16', group, CENTRAL, basis, 'di-q38-27b-list', 'all_non_delivered', '0'))[key])
    for g, tag in (('r0', 'RZero'), ('r1', 'ROne'), ('r2', 'RTwo')):
        for basis, btag in (('window', 'Win'), ('generation_span', 'Span')):
            n['aRatio' + tag + btag] = '%.2f' % (alpha('q38-thinking', g, basis, 'alpha_C0') / alpha('q38-nonthinking', g, basis, 'alpha_C0'))
    n['aOneSpanOn'] = '%.2f' % alpha('q38-thinking', 'hw:H100 80GB HBM3', 'generation_span', 'alpha_C1')
    n['aOneSpanOff'] = '%.2f' % alpha('q38-nonthinking', 'hw:H100 80GB HBM3', 'generation_span', 'alpha_C1')
    # the other hardware-stratified composites of Qwen3.8 non-thinking, on H200
    for pooled, tag in (('batch16', 'Sixteen'), ('batch64', 'SixtyFour')):
        w = composite(cells, 'q38-nonthinking', pooled, 'H200', 'window', theory)
        n['shWinQOff' + tag + 'HTwo'] = pct(w['share'])
    groups = {(r['stratum'], r['pooled'], r['group']) for r in theory.rows if r['group'].startswith('hw:') and r['pooled'] != 'menu'}
    n['nComposites'] = str(len(groups))
    # extended-bound rows among the preregistered admission rows
    n['admPreExt'] = str(sum(r['timeout_revised'] == 'True' for r in pre))
    # throughput of serial k=1 against pooled k=8, generated tokens per GPU second on the window basis, Qwen3.8
    def tokens_per_gpu_second(stratum, config, k):
        values = []
        for (s_, c_, kk, rep_), r in cells.rows.items():
            if (s_, c_, kk) == (stratum, config, k):
                generated = num(r['reasoning_tokens_all']) + num(r['unselected_final_tokens']) + num(r['delivered_output_tokens'])
                values.append(generated / (num(r['gpu_step_occupancy_s']) / num(r['tasks'])))
        return sum(values) / len(values)
    serial = [tokens_per_gpu_second(s_, 'serial', 1) for s_ in ('q38-nonthinking', 'q38-thinking')]
    pooled = [tokens_per_gpu_second(s_, c_, 8) for s_ in ('q38-nonthinking', 'q38-thinking') for c_ in ('batch16', 'batch64')]
    n['tokSerialQEightLo'], n['tokSerialQEightHi'] = '%.0f' % min(serial), '%.0f' % max(serial)
    n['tokPooledQEightLo'], n['tokPooledQEightHi'] = '%.0f' % min(pooled), '%.0f' % max(pooled)
    nem = composite(cells, 'nemotron-thinking', 'batch16', 'H100 80GB HBM3', 'window', theory)
    n['costRatioNem'] = '%.1f' % (nem['b'] / nem['a'])
    quarter = []
    for s_ in ('q38-nonthinking', 'q38-thinking'):
        r_ = one(theory.pick(s_, 'batch16', 'hw:H100 80GB HBM3', '0.25', 'window', 'di-q38-27b-list', 'all_non_delivered', '0'))
        quarter.append(num(r_['C0L']) / num(r_['B0L']))
    assert max(quarter) < 1
    n['lowRatioQuarter'] = '%.2f' % max(quarter)
    # capacity share of cost at the central rate, and CPU share of the service windows
    cap = []
    for r in cells.rows.values():
        for end in ('lo', 'hi'):
            cap.append(2.4 * num(r['gpu_step_occupancy_s']) / 3600 / num(r['tasks']) / cell_cost(r, 2.4, end))
    n['capShareLo'], n['capShareHi'] = pct(min(cap)), pct(max(cap))
    shares_cpu = []
    for r in service.rows.values():
        total = cell_cost(r, 2.4, 'mid', 'service_window_s', 'service_cpu_s')
        shares_cpu.append(0.03 * num(r['service_cpu_s']) / 3600 / num(r['tasks']) / total)
    n['cpuShareLo'], n['cpuShareHi'] = pct(min(shares_cpu), 1), pct(max(shares_cpu), 1)
    n['shRepQOnSixteenRZero'] = pct(replicate_composite(cells, 'q38-thinking', 'batch16', 'r0', 'window', theory)['share'])
    # service window against the generation span of the service run itself
    for rep, tag in (('r0', 'RZero'), ('r1', 'ROne'), ('r2', 'RTwo')):
        n['svSpShare' + tag] = pct(service.h1(rep, column='generation_span_s')[3])


def numbers_tex(n):
    lines = [header('Number macros used in the prose')]
    for name in sorted(n):
        assert name.isalpha(), name
        lines.append('\\newcommand{\\%s}{%s}' % (name, n[name]))
    return '\n'.join(lines) + '\n'


COMPACT_CAPTIONS = {
    'quality.tex': 'Initial pipeline quality and token use.',
    'h1.tex': 'Hardware-stratified pipeline cost contrasts.',
    'h3.tex': 'Pipeline indifference shares and participation conditions.',
    'replicates.tex': 'Pipeline contrasts by repetition.',
    'service.tex': 'Service and pipeline cost contrasts.',
    'margin.tex': 'Cost and bill contributions (USD/1,000 requests).',
    'energy.tex': 'Pipeline energy-corner H1 (USD/1,000 requests).',
    'bootstrap-budget.tex': 'Conditional paired budget changes in the pipeline.',
    'bootstrap-h2.tex': 'Conditional thinking/non-thinking share ratios.',
    'service-quality.tex': 'Serial online-service quality and token use.',
    'service-h1.tex': 'Online-service cost contrasts (GPU s/request).',
    'service-financial.tex': 'Batch16 versus serial financial conditions.',
    'service-h2.tex': 'Online-service thinking/non-thinking share ratios.',
    'service-energy.tex': 'Service energy-corner H1 (USD/1,000 requests).',
    'a100-followup.tex': 'Exploratory A100 batch16 H1 (GPU s/request).',
}


def compact_captions(files):
    """Layout-only captions; definitions and scope are kept in adjacent prose."""
    for name, caption in COMPACT_CAPTIONS.items():
        text=files[name]
        start=text.index(r'\caption{')+len(r'\caption{')
        depth=1;end=start
        while depth:
            if text[end]=='{':depth+=1
            elif text[end]=='}':depth-=1
            end+=1
        files[name]=text[:start]+caption+text[end-1:]
    return files


def render_files():
    """Build fragments in memory; no source or result files are changed."""
    result_evidence.verify()
    data = compute()
    cells, theory = data['cells'], data['theory']
    service = Service(read('service_resources'))
    a100 = Cells(read('a100_resources'))
    n = numbers(cells, theory, service, a100)
    n.update(bootstrap_tables.numbers())
    n.update(service_result_tables.numbers())
    n.update(retail_result_tables.numbers())
    return compact_captions({'quality.tex': table_quality(cells, theory), 'h1.tex': table_h1(cells, theory), 'h3.tex': table_h3(theory),
            'replicates.tex': table_replicates(cells, theory), 'service.tex': table_service(cells, theory, service, Theory(read('service_theory'))),
            'margin.tex': table_margin(cells, theory), 'energy.tex': table_energy(cells, theory), 'numbers.tex': numbers_tex(n),
            **bootstrap_tables.render(), **service_result_tables.render(), **retail_result_tables.render()})


def main(argv):
    out_dir = ROOT / 'tables'
    if '--out' in argv:
        out_dir = Path(argv[argv.index('--out') + 1])
    files = render_files()
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out_dir / name).write_text(text)
    print('wrote', ' '.join(sorted(files)), 'to', out_dir)


if __name__ == '__main__':
    main(sys.argv[1:])
