"""Build the manifest request for a lean GPU attempt.

Run on the cluster login node from a checkout of this repository:

  python3 -I -B scripts/calibration/lcb_ngpu_lean_request.py \
      --attempt-root /data/experiment/p1 --candidates \
      --cell 'coder-nonthinking|H100-primary|serial|k1|r0' CONFIG.json WORKLOAD.json \
      --output /data/experiment/p1-request.json

A cell given by id alone gets its generation configuration generated (lcb_ngpu_lean_config); its workload is the
base --workload when that already is the cell's (k=1, replicate 0), otherwise one derived from it (same tasks, the
cell's k candidates per task with the frozen hash seeds). Any cell of the panel works:

  python3 -I -B scripts/calibration/lcb_ngpu_lean_request.py \
      --attempt-root /data/experiment/q1 --candidates --workload WORKLOAD.json \
      --cell 'q38-thinking|H100-primary|serial|k1|r0' --cell 'q38-nonthinking|H100-primary|serial|k1|r0' \
      --output /data/experiment/q1-request.json

Main cohort (106 tasks): build the base workload once with lcb_ngpu_lean_workload.py --subset main, then add --main-matrix
(and one allocation per long cell: the QOS allows 24 h).

then prepare and submit it (see experiments/calibration/ngpu-lean-run.md):

  python3 -I -B scripts/calibration/lcb_isolation_owner_v2.py prepare --lean --root ROOT --request REQUEST
  python3 -I -B scripts/calibration/lcb_isolation_owner_v2.py submit --execute --root ROOT

The request names WHICH experiment is measured: cells, their generation config and workload files (path, hash,
size), the asset contract and the inference assets (model weights, image, candidate runner). It states the
resources it asks Slurm for; actual CPU/memory/GPU/node are recorded at run time, not matched.
Candidate execution is off unless --candidates is given; the main matrix, retries and cancellation cannot be
enabled from here.
"""
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lcb_isolation_batch_v2 as batch
import lcb_isolation_release_v2 as release
import lcb_ngpu_lean_config as cellconfig
import lcb_ngpu_v3 as ngpu
import lcb_timeout_revision as timeout_revision

HOPPER_NODES = ('node-6c6c500fa02f', 'node-e4d0aaa459d6', 'node-ce182d22c3ce', 'node-9a0121767b0e',
                'node-ed1b8fac9837', 'node-0d1ccf508722', 'node-f66e22f03809', 'node-2a8d0df195c3')
ACCEPTANCE = 'experiments/calibration/isolation-endpoint-site-v2.acceptance.json'


def require_clean_tracked_tree(root):
    """The manifest records HEAD as source_head; the code that runs is the tree. Refuse to describe a changed tree as HEAD."""
    # Only what can change a run: code, contracts and frozen inputs (the rest, e.g. a tracked .DS_Store, is not execution)
    result = subprocess.run(['/usr/bin/git', '-C', str(root), 'diff', '--quiet', 'HEAD', '--', 'scripts', 'experiments', 'data'],
                            capture_output=True)
    if result.returncode != 0:
        raise SystemExit('Tracked files differ from HEAD (or this is not a git checkout): commit them before syncing the tree, '
                         'so that source_head names the code that runs. Check: git -C ' + str(root) + ' diff --stat HEAD')


def file_ref(path):
    raw = Path(path).read_bytes()
    return {'path': str(Path(path).resolve()), 'sha256': release.sha(raw), 'bytes': len(raw)}


def validate_cells(cells, main_authorized=False):
    """The attempt checks every cell's inputs again at prepare time; do it here so a mismatch shows up before sbatch."""
    workload = (None, None)  # one workload at a time: cells often share a file, main-cohort files are ~150 MB each
    for cell, config, work in cells:
        if workload[0] != work:
            workload = (work, None)  # drop the previous one before reading the next
            workload = (work, release.strict(Path(work).read_bytes()))
        try:
            ngpu.validate_inputs(release.strict(Path(config).read_bytes()), workload[1], batch.panel_cell(cell),
                                 main_authorized=main_authorized)
        except ValueError as exc:
            raise ValueError(cell + ': ' + str(exc)) from None


def build(cells, *, attempt_root, candidates, cpus, memory_gib, walltime_h, queue_days, nodes, now_ns=None,
          check_inputs=True, worker_memory_gib=4, main_matrix=False):
    root = release.ROOT
    if check_inputs:
        validate_cells(cells, main_authorized=main_matrix)
    head = subprocess.run(['/usr/bin/git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True,
                          text=True, check=True).stdout.strip()
    contract_raw = (root / release.ASSETS).read_bytes()
    contract = release.strict(contract_raw)
    acceptance = (root / ACCEPTANCE).read_bytes()
    hardware = {batch.panel_cell(cell)['hardware'] for cell, _, _ in cells}
    if len(hardware) != 1:
        raise SystemExit('All cells of one allocation must belong to one hardware stratum: ' + ', '.join(sorted(hardware)))
    hardware = hardware.pop()
    inference = release.lean_inference(contract, [cell for cell, _, _ in cells])
    family, constraint = ('Hopper', 'H100|H200') if hardware == 'H100-primary' else ('A100', 'A100')
    tag = secrets.token_hex(6)
    now = time.time_ns() if now_ns is None else now_ns
    walltime_s = int(walltime_h * 3600) // 60 * 60
    qos = 'normal' if walltime_s <= 24 * 3600 else 'medium'  # the frozen envelope: normal up to 24 h, medium up to 48 h
    start_by = now + int(queue_days * 86400) * batch.NS
    memory = int(memory_gib) * batch.GIB
    # The two worker roles hold the workload and the generated samples (the samples of a k=8 thinking cell are tens of MB
    # of JSON, several times that as Python objects); every other role keeps 1 GiB. The inference role gets what remains,
    # less 1 GiB of slack, so the steps always fit the job's memory.
    worker = int(worker_memory_gib) * batch.GIB
    inference_memory = memory - (1 + 4 + 1) * batch.GIB - 2 * worker  # D + E1,E2,O1,O2 + slack, and W1,W2
    if inference_memory < 16 * batch.GIB:
        raise SystemExit('Allocation memory too small for the worker roles: raise --memory-gib or lower --worker-memory-gib')
    roles = []
    for rid in batch.GPU_ROLE_IDS:
        roles.append({'role_id': rid, 'kind': 'inference' if rid == 'G' else batch.ROLE_KIND[rid[0]],
                      'worker_id': None if rid in ('D', 'G') else batch.WORKERS[int(rid[1]) - 1],
                      'nonce': secrets.token_hex(32), 'cpus': 8 if rid == 'G' else 1,
                      'memory_bytes': inference_memory if rid == 'G' else worker if rid[0] == 'W' else batch.GIB,
                      'cases': [] if rid in ('D', 'G') else ['candidate']})
    manifest = {
        'schema': batch.GPU_SCHEMA, 'purpose': batch.GPU_PURPOSE, 'batch_id': 'lean-' + tag, 'attempt_id': 'attempt-' + tag,
        'attempt_root': attempt_root, 'nonce': secrets.token_hex(32), 'source_head': head,
        'assets_sha256': release.sha(contract_raw), 'endpoint_site_acceptance_sha256': release.sha(acceptance),
        'inference_assets_sha256': release.object_sha(inference), 'owner_uid': os.getuid(),
        'node_pool': list(nodes) if hardware == 'H100-primary' or tuple(nodes) != HOPPER_NODES else ['a100-nodes-not-listed'],
        'constraint': constraint, 'cpu_model': 'recorded_at_runtime',
        # submit_by is not enforced in lean attempts; the schema only wants it before start_by
        'submit_by_ns': now + 3600 * batch.NS, 'start_by_ns': start_by, 'max_run_s': walltime_s,
        'absolute_end_by_ns': start_by + walltime_s * batch.NS, 'bootstrap_receipt_s': batch.BOOTSTRAP_RECEIPT_S,
        'allocation': {'nodes': 1, 'cpus': cpus, 'memory_bytes': memory, 'partition': 'standard', 'qos': qos,
                       'gpus': 1, 'no_requeue': True},
        'roles': roles, 'private_nproc': 32,
        'cells': [cell for cell, _, _ in cells],
        'cell_inputs': {cell: {'generation_config': file_ref(config), 'workload': file_ref(work)}
                        for cell, config, work in cells},
        'gpu': {'family': family, 'walltime_s': walltime_s, 'partitions': 'standard', 'qos': qos},
        'candidate_limits': dict(batch.CANDIDATE_LIMITS),
        'candidate_execution_authorized': bool(candidates), 'main_matrix_authorized': bool(main_matrix),
        'automatic_retry_authorized': False, 'scancel_authorized': False,
    }
    return batch.validate_manifest(manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--attempt-root', required=True, help='new directory, at most 70 bytes (Unix socket limit)')
    parser.add_argument('--cell', nargs='+', action='append', metavar='ARG', required=True,
                        help='CELL_ID [CONFIG WORKLOAD]: by id alone the configuration is generated and --workload is '
                             'used; with all three the files are used as given. Repeat for paired cells of one model')
    parser.add_argument('--workload', help='base workload (the k=1, replicate 0 file) for cells given by id alone; '
                                           'cells with another k or replicate get a derived workload next to their configuration')
    parser.add_argument('--config-dir', help='where generated configurations go (default: OUTPUT.configs)')
    parser.add_argument('--output', required=True)
    parser.add_argument('--candidates', action='store_true', help='allow candidate execution in this attempt')
    parser.add_argument('--service', action='store_true',
                        help='service path for cells given by id: the weak4 selector runs online (first passing candidate is '
                             'delivered, the first failing test ends a fold), service CPU is snapshotted at the window start and '
                             'end, the GPU role stops when the window ends, and only the delivered candidates are audited after it')
    parser.add_argument('--extend-timeout', action='store_true',
                        help='owner-approved revision (lcb_timeout_revision): 7200 s instead of the frozen 3600 s per pooled generation '
                             'call, with its marker in the configuration, for cells given by id that it covers (q38-thinking, k=8, '
                             'batch16 or batch64); every other cell is refused, and so is --service. Run it as a new attempt of its own')
    parser.add_argument('--main-matrix', action='store_true',
                        help='main cohort: cells given by id use the main configuration (106 tasks) and --workload must be the '
                             'main base workload; sets main_matrix_authorized in the manifest. Defaults change to 160 GiB, '
                             '8 GiB per worker role and 24 h (the QOS maximum)')
    parser.add_argument('--cpus', type=int, default=26,
                        help='CPUs requested. The 7 one-CPU role steps are rounded up to whole cores (2 threads each '
                             'on SMT nodes) and the inference role takes 8 threads: 22 in all; the default adds two spare cores')
    parser.add_argument('--memory-gib', type=int, default=None, help='default 96 (160 with --main-matrix)')
    parser.add_argument('--worker-memory-gib', type=int, default=None,
                        help='memory of each of the two worker roles (workload + generated samples); the inference role '
                             'gets the rest of --memory-gib. Default 4 (8 with --main-matrix)')
    parser.add_argument('--walltime-h', type=float, default=None, help='default 6 (24 with --main-matrix)')
    parser.add_argument('--queue-days', type=float, default=7, help='how long the job may wait in the queue')
    parser.add_argument('--nodes', nargs='+', default=list(HOPPER_NODES), help='recorded node pool (not matched)')
    args = parser.parse_args()
    for path in (args.attempt_root, args.output):
        if str(path).startswith('/home/'):
            print('warning: '+str(path)+' is under /home, whose quota is small (vLLM caches and journals live in the attempt root); use /data/site', file=sys.stderr)
    if args.extend_timeout and args.service:
        parser.error('--extend-timeout is for the evaluation-pipeline cells that aborted; no service configuration is approved with it')
    subset = 'main' if args.main_matrix else 'pilot'
    require_clean_tracked_tree(release.ROOT)
    if args.memory_gib is None:
        args.memory_gib = 160 if args.main_matrix else 96
    if args.worker_memory_gib is None:
        args.worker_memory_gib = 8 if args.main_matrix else 4
    if args.walltime_h is None:
        args.walltime_h = 24 if args.main_matrix else 6
    if args.extend_timeout:  # judge every cell before anything is written
        for spec in args.cell:
            if len(spec) == 1:
                try:
                    in_scope = timeout_revision.in_scope(batch.panel_cell(spec[0]))
                except ValueError as exc:
                    parser.error(str(exc))
                if not in_scope:
                    parser.error('--extend-timeout covers only q38-thinking k=8 pooled cells (batch16, batch64): ' + spec[0])
    cells = []
    for spec in args.cell:
        if len(spec) == 3:
            if args.service:
                parser.error('--service applies to cells given by id alone; a given configuration is used as is, so it must '
                             'already be a service configuration (selection_mode online)')
            if args.extend_timeout:
                parser.error('--extend-timeout applies to cells given by id alone; a given configuration is used as is and '
                             'must already carry the revision marker')
            cells.append(tuple(spec))
        elif len(spec) == 1:
            if not args.workload:
                parser.error('--workload is required for a cell given by id alone')
            directory = args.config_dir or args.output + '.configs'
            config = cellconfig.write(spec[0], directory, subset, args.service, args.extend_timeout)
            cells.append((spec[0], str(config), str(cellconfig.workload_for(spec[0], args.workload, directory, subset))))
        else:
            parser.error('--cell takes CELL_ID or CELL_ID CONFIG WORKLOAD')
    manifest = build(cells, attempt_root=args.attempt_root, candidates=args.candidates,
                     cpus=args.cpus, memory_gib=args.memory_gib, walltime_h=args.walltime_h,
                     queue_days=args.queue_days, nodes=args.nodes, worker_memory_gib=args.worker_memory_gib,
                     main_matrix=args.main_matrix)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(release.encoded(manifest))
    print(release.encoded({'request': args.output, 'manifest_sha256': release.object_sha(manifest),
                           'attempt_root': args.attempt_root, 'cells': manifest['cells'],
                           'model': batch.panel_cell(manifest['cells'][0])['model_id'],
                           'generation_configs': {cell: manifest['cell_inputs'][cell]['generation_config']['path']
                                                  for cell in manifest['cells']},
                           'generation_timeouts_s': {cell: release.strict(Path(manifest['cell_inputs'][cell]['generation_config']['path'])
                                                                          .read_bytes()).get('generation_timeout_s')
                                                     for cell in manifest['cells']},
                           'selection_modes': {cell: release.strict(Path(manifest['cell_inputs'][cell]['generation_config']['path'])
                                                                    .read_bytes()).get('selection_mode', 'deferred')
                                               for cell in manifest['cells']},
                           'candidate_execution_authorized': manifest['candidate_execution_authorized'],
                           'main_matrix_authorized': manifest['main_matrix_authorized'], 'walltime_h': manifest['max_run_s'] / 3600,
                           'worker_memory_gib': args.worker_memory_gib,
                           'allocation': manifest['allocation'], 'source_head': manifest['source_head']}).decode(), end='')


if __name__ == '__main__':
    main()
