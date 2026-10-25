"""Per-cell delivery quality, token meters and generation latency from extracted lean cells (read-only).

  python3 -I -B scripts/calibration/lcb_ngpu_lean_analysis.py CANDIDATES.json [...] [--collect COLLECT_OUTPUT.json ...]

Delivery rule of the frozen design (policy generate_all_first_accept_weak4): every candidate of an episode is generated, the
first candidate (lowest id) that passes the weak4 fold is delivered, and none is delivered when no candidate passes. A truncated
candidate cannot be delivered but keeps its generated tokens. Per task: q_correct = a candidate was delivered and passes the
audit fold, q_wrong = one was delivered and fails it. Token meters follow lcb_metering.episode_meters: reasoning_tokens_all counts
reasoning and control tokens of all candidates, unselected_final_tokens the visible tokens of the candidates not delivered,
delivered_output_tokens those of the delivered one. Latency is the generation latency only: the time from the cohort start (all
episodes arrive at 0) to the barrier of the scheduler batch that generated the episode; verification time is not part of it.
Nothing is filled in: a quantity whose inputs are missing is None.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
ENERGY = ROOT / 'experiments/calibration/energy-scenario-v1.json'


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else None


def episode(rows):
    """Meters and labels of one task from its candidate rows."""
    rows = sorted(rows, key=lambda r: r['candidate_id'])
    labelled = all(r['weak4'] is not None and r['audit'] is not None for r in rows)
    selected = next((r for r in rows if r['weak4'] is True and not r['truncated']), None) if labelled else None
    out = {'task_id': rows[0]['task_id'], 'candidates': len(rows), 'labels_complete': labelled,
           'billed_input_tokens': sum(r['input_tokens'] for r in rows),
           'total_output_tokens': sum(r['output_tokens'] for r in rows),
           'truncated_candidates': sum(r['truncated'] for r in rows),
           'selected_id': None if selected is None else selected['candidate_id']}
    if labelled:
        out['q_correct'] = int(selected is not None and selected['audit'] is True)
        out['q_wrong'] = int(selected is not None and selected['audit'] is not True)
        out['audit_passes'] = sum(r['audit'] is True for r in rows)
    else:
        out['q_correct'] = out['q_wrong'] = out['audit_passes'] = None
    if all(r['partitioned'] for r in rows) and labelled:
        out['reasoning_tokens_all'] = sum(r['reasoning_tokens'] + r['control_tokens'] for r in rows)
        out['delivered_output_tokens'] = 0 if selected is None else selected['final_tokens']
        out['unselected_final_tokens'] = sum(r['final_tokens'] for r in rows) - out['delivered_output_tokens']
    else:
        out['reasoning_tokens_all'] = out['delivered_output_tokens'] = out['unselected_final_tokens'] = None
    return out


def service_episode(rows, online):
    """One episode of the service path: the delivered candidate is the one the online weak4 selector chose; its audit label
    (measured after the service window) decides q_correct/q_wrong. Meters come from the scheduler's episode record."""
    rows = sorted(rows, key=lambda r: r['candidate_id'])
    selected = online['selected_id']
    audit = None if selected is None else next(r for r in rows if r['candidate_id'] == selected)['audit']
    meters = online.get('meters') or {}
    complete = meters.get('metering_status') == 'complete'
    labelled = selected is None or audit is not None
    return {'task_id': rows[0]['task_id'], 'candidates': len(rows), 'selected_id': selected, 'labels_complete': labelled,
            'billed_input_tokens': sum(r['input_tokens'] for r in rows), 'total_output_tokens': sum(r['output_tokens'] for r in rows),
            'truncated_candidates': sum(r['truncated'] for r in rows),
            'q_correct': int(selected is not None and audit is True) if labelled else None,
            'q_wrong': int(selected is not None and audit is not True) if labelled else None,
            'reasoning_tokens_all': meters.get('reasoning_tokens_all') if complete else None,
            'delivered_output_tokens': meters.get('delivered_output_tokens') if complete else None,
            'unselected_final_tokens': meters.get('unselected_final_tokens') if complete else None,
            'delivery_latency_s': online.get('delivery_latency_s'), 'verification_wall_s': online.get('verification_wall_s'),
            'weak_tests_run': online.get('weak_tests_run')}


def service_metrics(cell, base, by_task):
    """Metrics of a cell run on the service path (online weak4 selection, audit of delivered answers after the window)."""
    online = {e['task_id']: e for e in cell.get('episodes') or ()}
    if set(online) != set(by_task):
        return {**base, 'status': 'incomplete', 'missing': ['episodes']}
    episodes = [service_episode(rows, online[task]) for task, rows in by_task.items()]
    metered = all(e['reasoning_tokens_all'] is not None for e in episodes)
    complete = metered and all(e['labels_complete'] for e in episodes)  # labels: the delivered candidates' audit

    def avg(key):
        values = [e[key] for e in episodes]
        return None if any(v is None for v in values) else mean(values)
    total_out = sum(e['total_output_tokens'] for e in episodes)
    hidden = None if not metered else sum(e['reasoning_tokens_all'] for e in episodes)
    unselected = avg('unselected_final_tokens')
    h_mean = avg('reasoning_tokens_all')
    # On the service path the scheduler selects after every barrier, so the barrier offset (generation_span_s of the evaluation
    # pipeline) contains the selection time. Busy generation is the sum of the generation calls; delivery time is tau_delivery_s.
    busy = [b['barrier_s'] - b['dispatch_s'] for b in cell['batches'] if b['barrier_s'] is not None]
    window = cell.get('service_window') or {}
    # G ends the window: when collect would not accept G (or the extractor did not judge it), the window quantities are not
    # recovered here; the labels and token meters of the cell do not depend on it
    g_error = window.get('g_error', 'G was not judged by the extractor')
    valid = g_error is None
    cpu = (window.get('cpu') or {}).get('total_usec') if valid else None
    cpu_startup = (window.get('cpu') or {}).get('total_with_startup_usec') if valid else None
    in_window = lambda value: value if valid else None
    return {**base, 'status': 'complete' if complete else 'labels_or_partition_incomplete', 'tasks': len(episodes),
            'candidates': len(cell['candidates']), 'mode': 'service',
            'q_plus': avg('q_correct'), 'q_minus': avg('q_wrong'),
            'abstain': None if avg('q_correct') is None else 1 - avg('q_correct') - avg('q_wrong'),
            'audit_pass_per_candidate': None,
            'billed_input_tokens': avg('billed_input_tokens'), 'delivered_output_tokens': avg('delivered_output_tokens'),
            'reasoning_tokens_all': h_mean, 'unselected_final_tokens': unselected,
            'H_reasoning_only': h_mean, 'H_all_non_delivered': None if h_mean is None else h_mean + unselected,
            'hidden_share_of_output': None if hidden is None or not total_out else hidden / total_out,
            'truncated_candidate_share': sum(e['truncated_candidates'] for e in episodes) / len(cell['candidates']),
            'generation_latency_s': None,
            'generation_span_s': in_window(sum(busy) if len(busy) == len(cell['batches']) else None),  # sum of the generation calls
            'service_wall_s': None if not valid or cell.get('service_wall_ns') is None else cell['service_wall_ns'] / 1e9,
            'tau_delivery_s': in_window(avg('delivery_latency_s')), 'selection_s': in_window(avg('verification_wall_s')),
            'weak_tests_run': sum(e['weak_tests_run'] for e in episodes),
            'service_window_s': in_window(window.get('cohort_elapsed_s')), 'startup_s': in_window(window.get('startup_s')),
            'window_error': None if valid else ' '.join(str(g_error).split()),
            'service_cpu_s': None if cpu is None else cpu / 1e6,
            'service_cpu_startup_s': None if cpu_startup is None else cpu_startup / 1e6,
            'startup_cpu_s': None if cpu is None or cpu_startup is None else (cpu_startup - cpu) / 1e6,
            **{'cpu_%s_s' % rid: None if v is None or not valid else v / 1e6
               for rid, v in ((window.get('cpu') or {}).get('by_role_usec') or {}).items()},
            'hardware': None if not cell.get('hardware_recorded') else cell['hardware_recorded'].get('model')}


def cell_metrics(cell):
    base = {'cell_id': cell['cell_id'], 'stratum': cell['stratum_id'], 'config': cell['config_id'], 'k': cell['k'],
            'replicate': cell['replicate_id'], 'subset': cell.get('subset'), 'attempt': cell['attempt'],
            **timeout_fields(cell)}
    if cell['missing'] or not cell.get('candidates'):
        return {**base, 'status': 'incomplete', 'missing': cell['missing']}
    by_task = {}
    for row in cell['candidates']:
        by_task.setdefault(row['task_id'], []).append(row)
    if cell.get('selection_mode') == 'online':
        return service_metrics(cell, base, by_task)
    episodes = [episode(rows) for rows in by_task.values()]
    complete = all(e['labels_complete'] for e in episodes) and all(e['reasoning_tokens_all'] is not None for e in episodes)
    barrier = {}
    for batch in cell['batches']:
        for task in batch['episodes']:
            barrier[task] = batch['barrier_s']
    latencies = [barrier.get(e['task_id']) for e in episodes]

    def avg(key):
        values = [e[key] for e in episodes]
        return None if any(v is None for v in values) else mean(values)
    total_out = sum(e['total_output_tokens'] for e in episodes)
    hidden = None if not complete else sum(e['reasoning_tokens_all'] for e in episodes)
    h_mean = avg('reasoning_tokens_all')
    unselected = avg('unselected_final_tokens')
    return {**base, 'status': 'complete' if complete else 'labels_or_partition_incomplete', 'tasks': len(episodes),
            'candidates': len(cell['candidates']),
            'q_plus': avg('q_correct'), 'q_minus': avg('q_wrong'),
            'abstain': None if avg('q_correct') is None else 1 - avg('q_correct') - avg('q_wrong'),
            'audit_pass_per_candidate': None if not complete else sum(e['audit_passes'] for e in episodes) / len(cell['candidates']),
            'billed_input_tokens': avg('billed_input_tokens'), 'delivered_output_tokens': avg('delivered_output_tokens'),
            'reasoning_tokens_all': h_mean, 'unselected_final_tokens': unselected,
            'H_reasoning_only': h_mean, 'H_all_non_delivered': None if h_mean is None else h_mean + unselected,
            'hidden_share_of_output': None if hidden is None or not total_out else hidden / total_out,
            'truncated_candidate_share': sum(e['truncated_candidates'] for e in episodes) / len(cell['candidates']),
            'generation_latency_s': None if any(v is None for v in latencies) else mean(latencies),
            'generation_span_s': max((b['barrier_s'] for b in cell['batches'] if b['barrier_s'] is not None), default=None),
            'service_wall_s': None if cell.get('service_wall_ns') is None else cell['service_wall_ns'] / 1e9,
            'hardware': None if not cell.get('hardware_recorded') else cell['hardware_recorded'].get('model')}


def energy_envelope(model, service_wall_s, busy_s, scenario):
    """[low, high] kWh of one cell from the declared envelope (experiments/calibration/energy-scenario-v1.json), or None.

    Busy seconds (the generation span) draw busy_fraction of the GPU's TDP, the remaining service seconds the idle fraction. The lean
    runs measured no power, so this is a declared assumption, never a point value."""
    tdp = scenario['gpu_tdp_w'].get(model)
    if tdp is None or service_wall_s is None or busy_s is None or busy_s > service_wall_s:
        return None
    idle_s = service_wall_s - busy_s
    low = tdp * (scenario['busy_fraction_of_tdp'][0] * busy_s + scenario['idle_fraction_of_tdp'][0] * idle_s)
    high = tdp * (scenario['busy_fraction_of_tdp'][1] * busy_s + scenario['idle_fraction_of_tdp'][1] * idle_s)
    return [low / 3.6e6, high / 3.6e6]


def collect_resources(paths):
    """(attempt, cell_id) -> resource fields of the collect outputs; the attempt is the output directory minus '-return',
    because pilot and main attempts contain cells with the same id."""
    found = {}
    for path in paths:
        text = Path(path).read_text()
        try:
            batches = [json.loads(text)]
        except ValueError:
            batches = [json.loads(line) for line in text.splitlines() if line.strip()]
        if not batches or any(not isinstance(b, dict) or not b.get('cells') for b in batches):
            # an empty or cell-less collect output would otherwise drop its measured cells without a word
            raise ValueError('Empty or cell-less collect output: ' + str(path))
        for batch in batches:
            attempt = Path(batch['output']).name.removesuffix('-return')
            for cell in batch['cells']:
                if cell['status'].startswith('measured'):
                    scale = lambda value, unit: None if value is None else value / unit  # a partial service cell has no whole-cell CPU
                    found[attempt, cell['cell_id']] = {'gpu_step_occupancy_s': scale(cell['gpu_step_occupancy_ns'], 1e9),
                                              'cpu_point_s': scale(cell['cpu_point_usec'], 1e6),
                                              'G_step_cpu_s': scale(cell['gpu_step_user_usec'], 1e6)}
    return found


COLUMNS = ('cell_id', 'status', 'tasks', 'q_plus', 'q_minus', 'abstain', 'audit_pass_per_candidate', 'billed_input_tokens',
           'delivered_output_tokens', 'reasoning_tokens_all', 'unselected_final_tokens', 'hidden_share_of_output',
           'truncated_candidate_share', 'generation_latency_s', 'generation_span_s', 'gpu_step_occupancy_s', 'cpu_point_s',
           'energy_kwh_lo', 'energy_kwh_hi', 'hardware')


def timeout_fields(cell):
    """The per-call generation timeout a cell ran under, from the extract: timeout_s is its seconds, 'unknown' when the extract could
    not establish it, blank for an extract made before it was recorded; timeout_revised is True for the owner-approved extension."""
    record = cell.get('generation_timeout')
    if record is None:
        return {'timeout_s': None, 'timeout_revised': None}
    return {'timeout_s': 'unknown' if record.get('seconds') is None else record['seconds'], 'timeout_revised': record.get('revised')}


SERVICE_COLUMNS = ('mode', 'tau_delivery_s', 'selection_s', 'weak_tests_run', 'service_window_s', 'startup_s', 'step_other_s', 'service_cpu_s',
                   'service_cpu_startup_s', 'startup_cpu_s', 'cpu_G_s', 'cpu_W1_s', 'cpu_E1_s', 'window_error')


def table_columns(rows):
    columns = COLUMNS + (SERVICE_COLUMNS if any(r.get('mode') == 'service' for r in rows) else ())  # pipeline-only tables keep their format
    # the per-call generation timeout is a column only when some cell ran under the owner-approved extension or its timeout is unknown
    columns += ('timeout_s', 'timeout_revised') if any(r.get('timeout_revised') is True or r.get('timeout_s') == 'unknown' for r in rows) else ()
    # a cell that was run twice (an unidentified attempt and its re-run) appears twice: say which attempt each row is
    ids = [r.get('cell_id') for r in rows]
    return columns + (('attempt',) if len(set(ids)) != len(ids) else ())


def main(argv):
    split = argv.index('--collect') if '--collect' in argv else len(argv)
    candidates, collects = argv[:split], argv[split + 1:]
    resources = collect_resources(collects)
    scenario = json.loads(ENERGY.read_text())
    rows = []
    for path in candidates:
        metrics = cell_metrics(json.loads(Path(path).read_text()))
        metrics.update(resources.get((metrics['attempt'], metrics['cell_id']), {}))
        if metrics['status'] != 'incomplete':
            service = metrics.get('mode') == 'service'
            # service cells: the steady-state window (busy = the generation calls, idle = the selection waits between them);
            # evaluation cells: the whole inference service wall (busy = generation span, idle = the wait for judging)
            wall = metrics['service_window_s'] if service else metrics['service_wall_s']
            envelope = None if wall is None else energy_envelope(metrics['hardware'], wall, metrics['generation_span_s'], scenario)
            metrics['energy_kwh_lo'], metrics['energy_kwh_hi'] = (None, None) if envelope is None else envelope
            if service and None not in (metrics.get('gpu_step_occupancy_s'), metrics.get('startup_s'), metrics['service_window_s']):
                metrics['step_other_s'] = metrics['gpu_step_occupancy_s'] - metrics['startup_s'] - metrics['service_window_s']
        rows.append(metrics)
    if len({r.get('mode') == 'service' for r in rows if r['status'] != 'incomplete'}) > 1:
        raise SystemExit('Service-path cells and evaluation-pipeline cells must not be mixed in one table; run them separately')
    columns = table_columns(rows)
    print('\t'.join(columns))
    for r in rows:
        print('\t'.join('' if r.get(c) is None else ('%.4g' % r[c] if isinstance(r[c], float) else str(r[c])) for c in columns))
    return rows


if __name__ == '__main__':
    main(sys.argv[1:])
