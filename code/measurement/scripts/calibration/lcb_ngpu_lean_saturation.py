"""Pre-registered saturation stop rule from the returned lean cells (read-only; no cluster access).

Definition (data/calibration/model-panel-decision-2026-10-09.json, workload.saturation_metric): for each prompt, average the
audit-fold pass indicators over the eight candidates of every eligible k=8 pilot cell of one model (serial and pooled cells with
the same replicate and generation parameters are combined); then average the 16 prompt means. The model is stopped when the value
is strictly greater than 0.9. A candidate without an executable output counts as a failure. Infrastructure failures are reported
separately, and with incomplete judge coverage the rule is not applied.

  python3 -I -B scripts/calibration/lcb_ngpu_lean_saturation.py COLLECT_OUTPUT.json [...]

A COLLECT_OUTPUT is the JSON the `collect` command prints (or batch.json); one file may hold one or several lines.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

THRESHOLD = 0.9
PILOT_TASKS = 16
CANDIDATES = 8
CASE_STATUS = {'judged', 'failed', 'no_deliverable', 'candidate_rejected_prefilter'}  # everything else is infrastructure


def read_batches(path):
    text = Path(path).read_text()
    try:
        return [json.loads(text)]
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def groups(batches):
    """(stratum, replicate) -> {cell_id: case_results} over measured k=8 pilot cells (16 tasks x 8 candidates)."""
    found = defaultdict(dict)
    for batch in batches:
        for cell in batch['cells']:
            if cell.get('selection_mode') == 'online':
                continue  # service-path cells audit only the delivered candidate: no all-candidate pass rate
            stratum, hardware, config, k, replicate = cell['cell_id'].split('|')
            rows = cell.get('case_results') or []
            if k != 'k8' or not cell['status'].startswith('measured') or len({r['task_id'] for r in rows}) != PILOT_TASKS:
                continue
            found[(stratum, replicate)][cell['cell_id']] = rows
    return found


def evaluate(cells):
    """One model's rule value from its eligible cells, or None when the rule cannot be applied."""
    per_task = defaultdict(list)
    infrastructure = 0
    complete = True
    for rows in cells.values():
        keys = {(r['task_id'], r['candidate_id']) for r in rows}
        complete = complete and len(rows) == len(keys) == PILOT_TASKS * CANDIDATES
        for row in rows:
            infrastructure += row['status'] not in CASE_STATUS
            per_task[row['task_id']].append(1.0 if row['audit'] is True else 0.0)
    value = None
    if complete and len(per_task) == PILOT_TASKS:
        value = sum(sum(v) / len(v) for v in per_task.values()) / PILOT_TASKS
    return {'cells': sorted(cells), 'audit_pass_at_1': value, 'infrastructure_failures': infrastructure,
            'complete_judge_coverage': complete,
            'stop': None if value is None else value > THRESHOLD,
            'rule': 'not applied: incomplete judge coverage' if value is None else
                    ('SATURATED: stop, value strictly greater than %s' % THRESHOLD if value > THRESHOLD else
                     'not saturated: main cells may proceed')}


def main(paths):
    batches = [b for path in paths for b in read_batches(path)]
    result = {'%s|%s' % key: evaluate(cells) for key, cells in sorted(groups(batches).items())}
    print(json.dumps(result, indent=1, sort_keys=True))
    return result


if __name__ == '__main__':
    main(sys.argv[1:])
