"""Progress of lean attempts under the run root, read-only (run on the cluster login node).

  WWW27_PATTERN='^(aD[12]|sv[cnot][0-9])$' WWW27_ONLY=1 python3 -I -B scripts/calibration/lcb_ngpu_lean_progress.py

Prints, per attempt root whose name matches WWW27_PATTERN (default ^thC[0-9]+$), the Slurm state of its job and, per cell, the phase,
the generation calls done against the expected number, the seconds of each pooled call so far and the age of the call in flight.
Without WWW27_ONLY it also lists every attempt whose manifest has an A100 cell. WWW27_ROOT overrides /data/experiment.
It only reads files and calls sacct, it changes nothing and cancels nothing.
"""
import glob, json, math, os, re, subprocess, time

ROOT = os.environ.get('WWW27_ROOT', '/data/experiment')
PATTERN = re.compile(os.environ.get('WWW27_PATTERN', r'^thC\d+$'))


def read_json(path):
    try:
        with open(path, 'rb') as f:
            return json.loads(f.read())
    except (OSError, ValueError):
        return None


def job_line(job):
    try:
        out = subprocess.run(['sacct', '-j', str(job), '-X', '-n', '-P', '--format=State,Elapsed,Timelimit,NodeList'],
                             capture_output=True, text=True, timeout=60).stdout.strip().splitlines()
        return out[0].replace('|', '  ') if out else '(no sacct row)'
    except Exception as exc:
        return '(sacct unavailable: %s)' % type(exc).__name__


def cell_state(directory, now):
    exists = lambda name: os.path.exists(os.path.join(directory, name))
    if not os.path.isdir(directory):
        return 'queued'
    if exists('W1.done.json'):
        return 'DONE'
    failed = exists('D-failure.json') or exists('batch.stop.json')
    events_path = os.path.join(directory, 'cohort-events.jsonl')
    detail = ''
    if os.path.exists(events_path):
        dispatched, spans, expected, concurrency, last, call_failed = {}, {}, 0, 1, None, False
        try:
            with open(events_path, 'rb') as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    kind = e.get('event')
                    if kind == 'cohort_start':
                        concurrency = max(1, e.get('concurrency') or 1)
                        expected = math.ceil(len(e.get('arrivals', {})) / concurrency)
                    elif kind == 'dispatch':
                        dispatched[e['batch_id']] = e['since_start_s']
                    elif kind == 'generation_barrier' and e.get('batch_id') in dispatched:
                        spans[e['batch_id']] = e['since_start_s'] - dispatched[e['batch_id']]
                    elif kind == 'generation_batch_failure':
                        call_failed = True
                    last = kind
        except OSError:
            pass
        age = int(now - os.path.getmtime(events_path))
        detail = ' generation calls %d/%d done (%d dispatched)' % (len(spans), expected, len(dispatched))
        if concurrency > 1:  # pooled cell: a few long calls, each one worth reading against the per-call bound
            detail += '; call seconds so far %s' % [int(spans[k]) for k in sorted(spans)]
            if last == 'dispatch':
                detail += '; the call in flight has run %s' % fmt(age)
            if call_failed:
                detail += '; a call FAILED'
        else:
            detail += ', last event %s ago' % fmt(age)
    phase = 'running'
    if exists('service-window.json'):
        phase = 'audit (service window finished)'
    elif not os.path.exists(events_path):
        phase = 'starting (model load)' if exists('G.started.json') else 'queued'
    return ('FAILED ' if failed else '') + phase + detail


def fmt(seconds):
    return '%dh%02dm' % (seconds // 3600, seconds % 3600 // 60) if seconds >= 3600 else '%dm%02ds' % (seconds // 60, seconds % 60)


def wanted(path):
    """the re-run attempts by name (thC0, thC1), the A100 arm by its cells (any cell id with A100 in it: aA, aB, aC, aD)"""
    if not os.path.isdir(path) or not os.path.exists(os.path.join(path, 'manifest.json')):
        return False
    if PATTERN.match(os.path.basename(path)):
        return True
    if os.environ.get('WWW27_ONLY'):
        return False
    return any('A100' in c for c in (read_json(os.path.join(path, 'manifest.json')) or {}).get('cells', []))


now = time.time()
roots = sorted(p for p in glob.glob(os.path.join(ROOT, '*')) if wanted(p))
if not roots:
    print('no attempt root matched', PATTERN.pattern, 'or an A100 manifest under', ROOT)
for root in roots:
    manifest = read_json(os.path.join(root, 'manifest.json')) or {}
    sub = read_json(os.path.join(root, 'submission.json')) or read_json(os.path.join(root, 'allocation.json')) or {}
    job = sub.get('job_id')
    print('%s  job %s  %s' % (os.path.basename(root), job, job_line(job) if job else '(not submitted)'))
    complete = os.path.exists(os.path.join(root, 'cells-complete.json'))
    for index, cell in enumerate(manifest.get('cells', [])):
        short = '|'.join(cell.split('|')[2:])
        print('   %03d %-28s %s' % (index, short, cell_state(os.path.join(root, 'cells', '%03d' % index), now)))
    if complete:
        print('   (cells-complete.json present: the dispatcher finished the attempt)')
