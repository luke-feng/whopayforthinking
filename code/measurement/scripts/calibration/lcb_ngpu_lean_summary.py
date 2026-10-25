"""One line per cell from the JSON that `collect` prints (read-only; no cluster access).

  python3 -I -B scripts/calibration/lcb_ngpu_lean_summary.py COLLECT_OUTPUT.json [...]

Columns: cell, status, candidates by outcome, weak4/audit passes, tokens (in, out, hidden, final), the hidden share of the
output, the G step occupancy and the inference service wall in seconds, CPU seconds (G step, all role steps, cpu point) and GPU.
"""
import json
import sys
from pathlib import Path

COLUMNS = ('cell', 'status', 'cases', 'delivered', 'weak4', 'audit', 'in', 'out', 'hidden', 'final', 'hidden%', 'occupancy_s',
           'service_s', 'G_cpu_s', 'role_cpu_s', 'cpu_point_s', 'gpu')


def batches(path):
    text = Path(path).read_text()
    try:
        return [json.loads(text)]
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def row(cell):
    cases = cell.get('case_results') or []
    out, hidden = cell.get('tokens_out'), cell.get('hidden_reasoning_tokens')
    hardware = cell.get('hardware_recorded') or {}

    def seconds(value, scale=10**9):
        return None if value is None else round(value / scale, 1)
    return {'cell': cell['cell_id'].replace('|H100-primary|', '|'), 'status': cell['status'].replace('_pending_pilot_review', ''),
            'cases': len(cases), 'delivered': sum(c['status'] not in ('no_deliverable',) for c in cases),
            'weak4': sum(bool(c['weak4']) for c in cases), 'audit': sum(bool(c['audit']) for c in cases),
            'in': cell.get('tokens_in'), 'out': out, 'hidden': hidden, 'final': cell.get('final_tokens'),
            'hidden%': None if not out or hidden is None else round(100 * hidden / out, 1),
            'occupancy_s': seconds(cell.get('gpu_step_occupancy_ns')), 'service_s': seconds(cell.get('inference_service_wall_ns')),
            'G_cpu_s': seconds(cell.get('gpu_step_user_usec'), 10**6), 'role_cpu_s': seconds(cell.get('user_step_total_usec'), 10**6),
            'cpu_point_s': seconds(cell.get('cpu_point_usec'), 10**6),
            'gpu': ' '.join(str(hardware.get(k, '')) for k in ('model', 'node')).strip()}


def main(paths):
    cells = [cell for path in paths for batch in batches(path) for cell in batch['cells']]
    skipped = [c['cell_id'] for c in cells if c.get('selection_mode') == 'online']
    if skipped:  # their weak4/audit columns are partial by design (online selection, delivered-only audit)
        print('skipped %d service-path cells: use lcb_ngpu_lean_analysis.py for them' % len(skipped), file=sys.stderr)
    rows = [row(cell) for cell in cells if cell.get('selection_mode') != 'online']
    print('\t'.join(COLUMNS))
    for r in rows:
        print('\t'.join('' if r[c] is None else str(r[c]) for c in COLUMNS))
    return rows


if __name__ == '__main__':
    main(sys.argv[1:])
