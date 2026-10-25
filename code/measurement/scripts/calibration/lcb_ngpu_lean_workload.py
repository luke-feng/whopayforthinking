"""Base workload of the pilot or main cohort from the prepared frozen inputs (tasks plus k=1, replicate 0 jobs).

The same construction as the pilot workload of the first Coder cell: the full private row of every frozen task, joined with its
prompt, in the frozen roster order; one job per task with the frozen hash seed. The prompt and private-test files are checked
against the frozen manifest first. Cells with another k or replicate derive their own workload from this file
(lcb_ngpu_lean_config.derive_workload), so this is run once per cohort.

  python3 -I -B scripts/calibration/lcb_ngpu_lean_workload.py --subset main \
      --prepared /data/site/www27-lcb-release-v6.Dw36FT/prepared-semantic-v2 --output /data/experiment-inputs/main/main-workload.json
"""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_release_v2 as release
import lcb_seeds as seeds

FROZEN = 'data/calibration/owner-lcb-manifest-semantic-v2-2026-10-09.json'


def rows_by_id(raw):
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    result = {row['task_id']: row for row in rows}
    release.check(len(rows) == len(result), 'Duplicate task_id in frozen input')
    return result


def make_workload(frozen, prompts_raw, tests_raw, subset):
    release.check(subset in ('pilot', 'main'), 'Subset must be pilot or main')
    release.check(release.sha(prompts_raw) == frozen['prompts_sha256'], 'Frozen prompts SHA mismatch')
    release.check(release.sha(tests_raw) == frozen['private_tests_sha256'], 'Frozen private-tests SHA mismatch')
    ids = frozen['pilot_task_ids'] if subset == 'pilot' else frozen['main_task_ids']
    prompts, tests = rows_by_id(prompts_raw), rows_by_id(tests_raw)
    tasks, jobs = [], []
    for task_id in ids:
        task = deepcopy(tests[task_id])  # the full original private row; only its paired prompt is added
        task['prompt'] = prompts[task_id]['prompt']
        tasks.append(task)
        jobs.append({'task_id': task_id, 'candidate_id': 0, 'prompt': task['prompt'],
                     'seed': seeds.candidate_seed(frozen['seed'], 0, task_id, 0)})
    release.check(len(tasks) == len(jobs) == len(ids), 'Workload coverage')
    return {'tasks': tasks, 'jobs': jobs}


def write(path, workload):
    """Canonical JSON streamed to a new file (same bytes as release.encoded, without a second full copy in memory)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(workload, stream, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--subset', choices=('pilot', 'main'), required=True)
    parser.add_argument('--prepared', required=True, help='directory with prompts.jsonl and tests.private.jsonl')
    parser.add_argument('--output', required=True, help='new file; never overwritten')
    args = parser.parse_args()
    frozen = release.strict((release.ROOT / FROZEN).read_bytes())
    prepared = Path(args.prepared)
    workload = make_workload(frozen, (prepared / 'prompts.jsonl').read_bytes(), (prepared / 'tests.private.jsonl').read_bytes(),
                             args.subset)
    write(args.output, workload)
    raw = Path(args.output).read_bytes()
    print(release.encoded({'output': args.output, 'subset': args.subset, 'tasks': len(workload['tasks']),
                           'jobs': len(workload['jobs']), 'tests': sum(len(t['tests']) for t in workload['tasks']),
                           'bytes': len(raw), 'sha256': release.sha(raw)}).decode(), end='')


if __name__ == '__main__':
    main()
