"""Wiring check of service-path cells from their originals (read-only; run on the cluster or on a copy of the attempt).

  python3 -I -B scripts/calibration/lcb_ngpu_lean_service_check.py ATTEMPT_ROOT [ATTEMPT_ROOT ...]

Every cell the attempt's manifest lists must have run on the service path and must pass every check, otherwise the exit
code is 1 (a missing root, a missing manifest, a cell without service-window.json all count as failures; nothing is skipped):

  snapshots    start and end CPU snapshots of G, W1 and E1 are complete, in one counter domain that equals the role's bound
               user cgroup in 8-joins.json, non-negative, and the usage equals the raw cpu.stat text saved with it
  times        every start snapshot precedes the cohort start and every end snapshot follows the cohort end (monotonic clock),
               and each role's end follows its start
  decisions    the weak4 requests E1 received are exactly the tests the recorded online decisions list, in order
  short        within a candidate the tests stop at the first failing test, no candidate after the delivered one was checked,
               and every delivered candidate passed all of its weak tests
  audit_after  every weak4 request finished before E1's end snapshot and every audit request started after it (E1 serves one
               request at a time, so the snapshot sits between the two phases)
  audit_only   the audited candidates are exactly the delivered ones, each with the number of tests its row reports (a cell whose
               audit phase failed is reported with audit_error and fails this check)

It prints one JSON object per cell. It checks the wiring of the run; it does not judge the scientific result.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_release_v2 as release
import lcb_ngpu_v3 as ngpu

CHECKS = ('snapshots', 'times', 'decisions', 'short', 'audit_after', 'audit_only')


def read(path):
    return release.strict(Path(path).read_bytes())


def usage_from(raw):
    for line in (raw or '').splitlines():
        if line.startswith('usage_usec '):
            return int(line.split()[1])
    return None


def snapshots_ok(window, joins):
    for when in ('start', 'end'):
        for rid in ngpu.SERVICE_ROLES:
            s = (window.get(when) or {}).get(rid) or {}
            if s.get('status') != 'captured' or type(s.get('usage_usec')) is not int or usage_from(s.get('cpu_stat')) != s['usage_usec']:
                return False
    return ngpu.service_cpu(window, joins)['total_usec'] is not None


def times_ok(window, events):
    start = next((e for e in events if e.get('event') == 'cohort_start'), None)
    end = next((e for e in events if e.get('event') == 'cohort_end'), None)
    if start is None or end is None:
        return False
    began = start['cohort_start_monotonic_s'] * 1e9
    ended = (start['cohort_start_monotonic_s'] + end['elapsed_s']) * 1e9
    for rid in ngpu.SERVICE_ROLES:
        a, b = window['start'][rid].get('mono_ns'), window['end'][rid].get('mono_ns')
        if a is None or b is None or not (a <= began and b >= ended and a <= b):
            return False
    return True


def check_cell(directory):
    d = Path(directory)
    window = read(d / 'service-window.json')
    episodes = read(d / 'generation-episodes.json')['episodes']
    done = read(d / 'W1.done.json')
    events = [read_line for read_line in (release.strict(l) for l in (d / 'cohort-events.jsonl').read_bytes().splitlines() if l.strip())]
    joins = {j['role_id']: j['user_cgroup']['path'] for j in read(d / '8-joins.json')['joins']}
    decided = [(ep['task_id'], c['candidate_id'], case['test_id']) for ep in episodes for c in ep['online_checks']
               if 'result' in c for case in c['result']['cases']]
    delivered = {(ep['task_id'], ep['selected_id']) for ep in episodes if ep['selected_id'] is not None}
    receipts_path = d / 'E1-candidate-receipts.jsonl'
    if receipts_path.exists():
        receipts = [json.loads(line) for line in receipts_path.read_bytes().splitlines() if line.strip()]
    elif not decided and not delivered:
        receipts = []  # every candidate was ineligible: no test ran, so E1 never created its receipts file
    else:
        raise FileNotFoundError(str(receipts_path) + ' (the decisions list tests that must have been requested)')
    requests = [r['request'] for r in receipts]
    weak = [(r['task_id'], r['candidate_id'], r['test_id']) for r in requests if r['role'] == 'weak4']
    audit = [(r['task_id'], r['candidate_id'], r['test_id']) for r in requests if r['role'] == 'audit']
    short = True
    for ep in episodes:
        reached = {c['candidate_id'] for c in ep['online_checks']}
        if ep['selected_id'] is not None and any(j > ep['selected_id'] for j in reached):
            short = False
        for c in ep['online_checks']:
            cases = c.get('result', {}).get('cases', [])
            if any(not case['pass'] for case in cases[:-1]):
                short = False
            if c['candidate_id'] == ep['selected_id'] and not (cases and all(case['pass'] for case in cases)
                                                               and len(cases) == window.get('weak_size')):
                short = False
    end_wall = window['end']['E1'].get('wall_ns')
    weak_done = [r.get('finished_wall_ns') for r in receipts if r['request']['role'] == 'weak4']
    audit_start = [r.get('started_wall_ns') for r in receipts if r['request']['role'] == 'audit']
    roles = [r['role'] for r in requests]
    in_order = max((i for i, role in enumerate(roles) if role == 'weak4'), default=-1) < next(
        (i for i, role in enumerate(roles) if role == 'audit'), len(roles))
    stamped = None not in weak_done + audit_start and end_wall is not None
    audit_after = in_order and stamped and all(t <= end_wall for t in weak_done) and all(t >= end_wall for t in audit_start)
    rows = {(x['task_id'], x['candidate_id']): x for x in done['results']}
    audited = {(t, j) for t, j, _ in audit}
    tests_run = sum(rows[key].get('audit_tests_run', 0) for key in delivered if key in rows)
    return {'cell': d.name, 'snapshots': snapshots_ok(window, joins), 'times': times_ok(window, events),
            'decisions': weak == decided, 'short': short, 'audit_after': bool(audit_after),
            'audit_only': audited == delivered and len(audit) == tests_run and not done.get('audit_error'),
            'audit_error': done.get('audit_error'),
            'episodes': len(episodes), 'delivered': len(delivered), 'weak_requests': len(weak), 'audit_requests': len(audit),
            'service_cpu_usec': ngpu.service_cpu(window, joins)['total_usec']}


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    failed = False
    for root in map(Path, argv):
        try:
            cells = read(root / 'manifest.json')['cells']
        except (OSError, ValueError, KeyError) as exc:
            print(json.dumps({'attempt': root.name, 'error': 'manifest: ' + type(exc).__name__ + ': ' + str(exc)}, sort_keys=True))
            failed = True
            continue
        failed |= not cells  # nothing to check is not a pass
        for index, cell_id in enumerate(cells):
            directory = root / 'cells' / ('%03d' % index)
            try:
                report = check_cell(directory)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                report = {'cell': directory.name, 'error': type(exc).__name__ + ': ' + str(exc)}
            report.update(attempt=root.name, cell_id=cell_id)
            failed |= 'error' in report or not all(report[k] for k in CHECKS)
            print(json.dumps(report, sort_keys=True))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
