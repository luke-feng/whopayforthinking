"""Compact per-candidate data of finished lean attempts (read-only), the input of the analysis.

  python3 -I -B scripts/calibration/lcb_ngpu_lean_extract.py OUTPUT_DIR ATTEMPT_ROOT [ATTEMPT_ROOT ...]

For every cell of an attempt it writes OUTPUT_DIR/<attempt>.cell-NNN.candidates.json: one row per candidate with its token
counts (input, output, hidden reasoning with control tokens, visible final), whether it was truncated, the weak4/audit labels of
the worker roles, and its generation timestamps; plus one row per scheduler batch (dispatch and barrier time). The multi-hundred-MB
sample files stay where they are; these files are small enough to copy around. Nothing is derived or filled in: a file that a cell
does not have is listed under "missing" and the cell is written without candidates.
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_batch_v2 as batch
import lcb_isolation_release_v2 as release
import lcb_ngpu_v3 as ngpu

NEEDED = ('generated-samples.json', 'W1.done.json', 'W2.done.json', 'cohort-events.jsonl', 'inference-summary.json')
SERVICE_NEEDED = ('service-window.json', 'generation-episodes.json')  # only cells run on the service path


def read_json(path):
    return release.strict(Path(path).read_bytes())


def read_lines(path):
    return [release.strict(line) for line in Path(path).read_bytes().splitlines() if line.strip()]


def candidate_rows(samples, results):
    labels = {(r['task_id'], r['candidate_id']): r for r in results}
    arrivals = [s['engine_timing']['arrival_monotonic_s'] for s in samples if s.get('engine_timing')]
    origin = min(arrivals) if arrivals else 0
    rows = []
    for s in samples:
        part = s.get('token_partition') or {}
        label = labels.get((s['task_id'], s['candidate_id']), {})
        timing = s.get('engine_timing') or {}

        def at(key):
            return None if key not in timing else round(timing[key] - origin, 6)
        rows.append({'task_id': s['task_id'], 'candidate_id': s['candidate_id'], 'input_tokens': s['input_tokens'],
                     'output_tokens': s['output_tokens'], 'reasoning_tokens': len(part.get('reasoning_ids', ())),
                     'control_tokens': len(part.get('control_ids', ())), 'final_tokens': len(part.get('final_ids', ())),
                     'partitioned': s.get('token_partition') is not None,
                     'truncated': bool(s.get('truncated')), 'finish_reason': s.get('finish_reason'),
                     'has_code': bool(s.get('code')), 'status': label.get('status'), 'weak4': label.get('weak4'),
                     'audit': label.get('audit'), 't_arrival_s': at('arrival_monotonic_s'),
                     't_first_token_s': at('first_token_monotonic_s'), 't_done_s': at('generation_complete_monotonic_s')})
    return sorted(rows, key=lambda r: (r['task_id'], r['candidate_id']))


def batch_rows(events):
    dispatch = {e['batch_id']: e for e in events if e.get('event') == 'dispatch'}
    barrier = {e['batch_id']: e for e in events if e.get('event') == 'generation_barrier'}
    return [{'batch_id': b, 'episodes': dispatch[b]['episodes'], 'candidate_count': dispatch[b]['candidate_count'],
             'dispatch_s': dispatch[b]['since_start_s'], 'barrier_s': barrier[b]['since_start_s'] if b in barrier else None}
            for b in sorted(dispatch)]


def episode_rows(episodes):
    """Online delivery of every episode: which candidate was delivered, when, and what the selector cost."""
    rows = []
    for ep in episodes:
        checks = ep.get('online_checks') or []
        rows.append({'task_id': ep['task_id'], 'selected_id': ep['selected_id'], 'delivery_latency_s': ep.get('delivery_latency_s'),
                     'complete_offset_s': ep.get('complete_offset_s'), 'selection_elapsed_s': ep.get('selection_elapsed_s'),
                     'verification_wall_s': ep.get('verification_wall_s'), 'meters': ep.get('meters'),
                     'weak_tests_run': sum(len(c['result']['cases']) for c in checks if 'result' in c),
                     'candidates_checked': sum(1 for c in checks if 'result' in c)})
    return rows


def service_summary(directory, summary, events):
    """Service window of a service-path cell: cohort span from the scheduler events, startup before it, CPU of the service
    roles between the bracketing snapshots (service-window.json). Anything unreadable stays None; g_error is why G does not
    qualify as the end of the window (None when it does)."""
    window = read_json(directory / 'service-window.json')
    joins_error = bundle = None
    try:
        bundle = read_json(directory / '8-joins.json')
        joins = {j['role_id']: j['user_cgroup']['path'] for j in bundle['joins']}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # The snapshot domain cannot be tied to the role's bound cgroup: the CPU values that depend on that stay None
        bundle, joins, joins_error = None, {}, type(exc).__name__ + ': ' + str(exc)
    start = next((e for e in events if e.get('event') == 'cohort_start'), {})
    end = next((e for e in events if e.get('event') == 'cohort_end'), {})
    cohort_start = start.get('cohort_start_monotonic_s')
    begun = summary.get('service_started_mono_ns')
    return {'cohort_elapsed_s': end.get('elapsed_s'),
            'startup_s': None if cohort_start is None or begun is None else cohort_start - begun / 1e9,
            'cpu': ngpu.service_cpu(window, joins), 'weak_size': window.get('weak_size'), 'joins_error': joins_error,
            # collect's judgement of G (clean exit, captured endpoint): an unclean G ended no valid window, and the analysis then
            # keeps the labels and token meters of the cell but none of its window quantities
            'g_error': ngpu.service_g_error(directory, bundle)}


def extract_cell(root, manifest, index):
    cell_id = manifest['cells'][index]
    cell = batch.panel_cell(cell_id)
    directory = Path(root) / 'cells' / ('%03d' % index)
    service_cell = (directory / 'service-window.json').exists()
    required = (tuple(n for n in NEEDED if n not in ('W1.done.json', 'W2.done.json')) + SERVICE_NEEDED) if service_cell else NEEDED
    out = {'schema': 'lean-cell-candidates-v1', 'attempt': Path(root).name, 'cell_id': cell_id, 'index': index,
           'stratum_id': cell['stratum_id'], 'hardware_label': cell['hardware'], 'config_id': cell['config_id'],
           'k': cell['k'], 'replicate_id': cell['replicate_id'], 'subset': ngpu.cell_subset(manifest, cell_id),
           'generation_timeout': ngpu.cell_timeout_record(manifest, cell_id),
           'missing': [name for name in required if not (directory / name).exists()]}
    if out['missing']:
        return out
    mode = 'online' if service_cell else read_json(directory / 'W1.done.json').get('selection_mode', 'deferred')
    out['selection_mode'] = mode
    if mode == 'online' and not service_cell:
        out['missing'] = [name for name in SERVICE_NEEDED if not (directory / name).exists()]
        return out
    summary = read_json(directory / 'inference-summary.json')
    events = read_lines(directory / 'cohort-events.jsonl')
    start = next((e for e in events if e.get('event') == 'cohort_start'), {})
    if service_cell:
        # What the window measured does not depend on how the audit phase ended. A missing W1.done.json leaves the audit labels
        # unmeasured (None); the delivery and the online weak4 decisions come from the episodes.
        episodes = read_json(directory / 'generation-episodes.json')['episodes']
        if (directory / 'W1.done.json').exists():
            done = read_json(directory / 'W1.done.json')
            results, out['audit_error'] = done['results'], done.get('audit_error')
        else:
            results, out['audit_error'] = ngpu.service_results(episodes, {}), 'W1.done.json missing: the audit phase did not finish'
    else:
        results = [r for name in ('W1.done.json', 'W2.done.json') for r in read_json(directory / name)['results']]
    out.update(pool_id=start.get('pool_id'), concurrency=start.get('concurrency'),
               hardware_recorded=summary.get('hardware_recorded'),
               service_wall_ns=summary['service_finished_mono_ns'] - summary['service_started_mono_ns'],
               gpu_occupancy_ns=summary.get('gpu_occupancy_ns'), batches=batch_rows(events),
               candidates=candidate_rows(read_json(directory / 'generated-samples.json')['samples'], results))
    if service_cell:
        out.update(service_window=service_summary(directory, summary, events), episodes=episode_rows(episodes))
    return out


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    output = Path(argv[0])
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    written = []
    for root in map(Path, argv[1:]):
        manifest = read_json(root / 'manifest.json')
        for index in range(len(manifest['cells'])):
            value = extract_cell(root, manifest, index)
            path = output / ('%s.cell-%03d.candidates.json' % (root.name, index))
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(release.encoded(value))
            written.append({'file': path.name, 'cell': value['cell_id'], 'candidates': len(value.get('candidates', ())),
                            'missing': value['missing']})
    for row in written:
        print(json.dumps(row, sort_keys=True))
    return written


if __name__ == '__main__':
    main(sys.argv[1:])
