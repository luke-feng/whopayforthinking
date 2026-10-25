"""Gather the results of finished lean attempts in one go (run on the cluster login node, from the newest source directory).

  python3 -I -B scripts/calibration/lcb_ngpu_lean_gather.py [--run] [--tag TAG] [--originals] [--src DIR] ATTEMPT [ATTEMPT ...]

ATTEMPT is the name of a directory under /data/experiment (svq0, aA1, thC0, ...). Without --run it only prints the plan and
changes nothing. With --run, for every attempt whose Slurm job has ended:

  collect   lcb_isolation_owner_v2.py collect --root R/ATTEMPT --output R/ATTEMPT-return, its stdout kept in R/ATTEMPT-collect.json,
            with the source directory whose HEAD is the manifest's source_head (override: --src DIR). An attempt that already has
            its -return directory and -collect.json is not collected again; one with only a -return directory is reported and skipped.
  extract   lcb_ngpu_lean_extract.py R/analysis-TAG ROOT ... over all ended attempts of this call (a new directory)
  check     lcb_ngpu_lean_service_check.py on the attempts that ran on the service path (R/check-TAG.jsonl)
  tar       R/results-TAG.tar.gz with the collect outputs, the return directories, the extract and the check
            (--originals adds the attempt roots without runtime-cache)

An attempt whose job is still pending or running is skipped and named. Nothing is overwritten: every output path must be new, and no
step retries or cancels anything. The collect and extract tools are the ones that read the originals; this script only calls them.
"""
import argparse
import glob
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time

ROOT = os.environ.get('WWW27_ROOT', '/data/experiment')
TERMINAL = {'COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT', 'NODE_FAIL', 'OUT_OF_MEMORY', 'BOOT_FAIL', 'PREEMPTED', 'DEADLINE'}
HERE = Path(__file__).resolve().parent


def read_json(path):
    try:
        return json.loads(Path(path).read_bytes())
    except (OSError, ValueError):
        return None


def sacct_state(job):
    """First word of the job's State, or None when sacct cannot tell."""
    try:
        out = subprocess.run(['sacct', '-j', str(job), '-X', '-n', '-P', '--format=State'], capture_output=True, text=True,
                             timeout=60).stdout.strip().splitlines()
        return out[0].split()[0].split('|')[0] if out else None
    except Exception:
        return None


def git_head(directory):
    try:
        return subprocess.run(['git', '-C', str(directory), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                              timeout=60, check=True).stdout.strip()
    except Exception:
        return None


def find_src(head, root=ROOT):
    """The source directory (ROOT-src*) whose checkout is at the commit the manifest names, or None."""
    for directory in sorted(glob.glob(root + '-src*')):
        if git_head(directory) == head:
            return directory
    return None


def plan_attempt(name, root=ROOT, state=sacct_state, src_override=None):
    """One attempt's plan: {'attempt', 'state', 'action', ...}; action is collect, collected, running, no-manifest, no-source or
    half-collected."""
    path = Path(root) / name
    item = {'attempt': name, 'root': str(path), 'job': None, 'state': None, 'src': None, 'service': False}
    manifest = read_json(path / 'manifest.json') if re.fullmatch(r'[A-Za-z0-9_-]+', name) else None
    if not manifest:
        return {**item, 'action': 'no-manifest'}
    submission = read_json(path / 'submission.json') or read_json(path / 'allocation.json') or {}
    item['job'] = submission.get('job_id')
    item['state'] = None if item['job'] is None else state(item['job'])
    item['service'] = any((path / 'cells' / ('%03d' % i) / 'service-window.json').exists() for i in range(len(manifest.get('cells', []))))
    if item['state'] not in TERMINAL:
        return {**item, 'action': 'running'}
    returned, collected_json = Path(root) / (name + '-return'), Path(root) / (name + '-collect.json')
    stdout_ok = collected_json.exists() and collected_json.stat().st_size > 0  # an empty file is a collect that did not finish
    if returned.exists() and stdout_ok:
        return {**item, 'action': 'collected'}
    if returned.exists() or collected_json.exists():  # an earlier collect that did not finish: look at it, never overwrite it
        present = '-return' if returned.exists() and not collected_json.exists() else '-collect.json (empty)' if returned.exists() else '-collect.json'
        return {**item, 'action': 'half-collected', 'present': present}
    item['src'] = src_override or find_src(manifest.get('source_head'), root)
    return {**item, 'action': 'collect' if item['src'] else 'no-source'}


def default_run(command, stdout_path=None):
    out = open(stdout_path, 'xb') if stdout_path else None
    try:
        return subprocess.run(command, stdout=out, check=False).returncode
    finally:
        if out:
            out.close()


def describe(item):
    text = {'no-manifest': 'no manifest.json (not an attempt root)', 'running': 'job not ended: skipped',
            'collected': 'already collected', 'collect': 'will be collected with ' + str(item['src']),
            'half-collected': '%s exists without the other of -return/-collect.json: skipped (a collect started before and did not finish; '
                              'look at it, move it aside, then run again)' % item.get('present'),
            'no-source': 'no source directory at the manifest\'s source_head: pass --src DIR'}[item['action']]
    return '%-8s job %-9s %-10s %s%s' % (item['attempt'], item['job'], item['state'], text, '  [service path]' if item['service'] else '')


def gather(names, *, run=False, tag=None, originals=False, src=None, root=ROOT, state=sacct_state, runner=default_run, out=print):
    plans = [plan_attempt(n, root, state, src) for n in names]
    for item in plans:
        out(describe(item))
    ended = [p for p in plans if p['action'] in ('collect', 'collected')]
    if not run:
        out('dry run: nothing executed (add --run); would extract %d attempt(s): %s' % (len(ended), ' '.join(p['attempt'] for p in ended)))
        return 0
    tag = tag or time.strftime('%m%d-%H%M')
    taken = [p for p in (Path(root) / ('analysis-' + tag), Path(root) / ('check-' + tag + '.jsonl'), Path(root) / ('results-' + tag + '.tar.gz'))
             if p.exists()]
    if taken:  # judged before anything runs: no step is started and nothing is overwritten
        out('refusing: %s already exist(s); use another --tag' % ', '.join(str(p) for p in taken))
        return 2
    py = sys.executable
    failed = False
    for item in plans:
        if item['action'] != 'collect':
            continue
        command = [py, '-I', '-B', str(Path(item['src']) / 'scripts/calibration/lcb_isolation_owner_v2.py'), 'collect', '--root', item['root'],
                   '--output', item['root'] + '-return']
        try:
            code = runner(command, item['root'] + '-collect.json')
        except Exception as exc:  # one attempt's failure does not stop the others
            code = '%s: %s' % (type(exc).__name__, exc)
        out('collect %s: exit %s' % (item['attempt'], code))
        failed |= code != 0
    ready = [p for p in ended if (Path(root) / (p['attempt'] + '-return')).exists() and (Path(root) / (p['attempt'] + '-collect.json')).exists()]
    if not ready:
        out('nothing to extract')
        return 1 if failed else 0
    analysis = Path(root) / ('analysis-' + tag)
    code = runner([py, '-I', '-B', str(HERE / 'lcb_ngpu_lean_extract.py'), str(analysis)] + [p['root'] for p in ready])
    out('extract: exit %s -> %s' % (code, analysis))
    failed |= code != 0
    service = [p for p in ready if p['service']]
    check = Path(root) / ('check-' + tag + '.jsonl')
    if service:
        code = runner([py, '-I', '-B', str(HERE / 'lcb_ngpu_lean_service_check.py')] + [p['root'] for p in service], str(check))
        out('service check: exit %s -> %s (exit 1 means some cell failed a check; read the lines)' % (code, check))
    tarball = Path(root) / ('results-' + tag + '.tar.gz')
    with tarfile.open(tarball, 'x:gz') as tar:
        for p in ready:
            tar.add(Path(root) / (p['attempt'] + '-collect.json'), arcname=p['attempt'] + '-collect.json')
            tar.add(Path(root) / (p['attempt'] + '-return'), arcname=p['attempt'] + '-return')
            if originals:
                tar.add(p['root'], arcname=p['attempt'], filter=lambda i: None if 'runtime-cache' in Path(i.name).parts else i)
        if analysis.exists():
            tar.add(analysis, arcname=analysis.name)
        if check.exists():
            tar.add(check, arcname=check.name)
    out('tarball: %s' % tarball)
    return 1 if failed else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('attempts', nargs='+')
    parser.add_argument('--run', action='store_true', help='execute; the default only prints the plan')
    parser.add_argument('--tag', help='name of the outputs (default: month-day-hourminute)')
    parser.add_argument('--originals', action='store_true', help='also put the attempt roots (without runtime-cache) into the tarball')
    parser.add_argument('--src', help='source directory to collect with, for every attempt (default: the one at the manifest\'s source_head)')
    args = parser.parse_args(argv)
    return gather(args.attempts, run=args.run, tag=args.tag, originals=args.originals, src=args.src)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
