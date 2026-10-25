# Lean GPU run (owner commands)

A lean attempt takes the manifest as the approval: no registry, reviewed-release or owner-approval files.
What still stops a run is only what decides which experiment is measured or how a number is computed
(model weights, image, candidate runner, sandbox helper hashes; the cell's generation config and workload;
endpoint capture rules) plus the four scope switches, which live in the manifest: candidate execution is
on only with `--candidates`; the main matrix, automatic retry and cancellation cannot be enabled here.
CPU, memory, GPU model, node, driver, client hashes and clock offsets are recorded, not matched.

All commands run on the login node from a copy of this repository (call it `$SRC`) with `/usr/bin/python3.12`,
the interpreter the Slurm job itself uses. The copy must not change while the job is queued or running.

Getting the code there without a git push (from your Mac; replace the host):

```bash
rsync -a --delete --exclude work --exclude .DS_Store --exclude 'review/*.pdf' \
  /workspace/researcher/workspace/git/www27/ researcher@<cluster-login-host>:/data/experiment-src/
```

then `SRC=/data/experiment-src` on the cluster. (A `git pull` of the branch works too.)

Where things live: everything below goes under `/data/site`, not `/home` (small quota). The attempt root also
holds the vLLM compile caches and all journals, so it is the part that can get large. Use a new root name
(`p2`, `p3`, ...) for every attempt; a root is never reused.

Optional 10-second check that `/scratch` supports what an attempt root needs (a Unix socket in the root, directory fsync):

```bash
python3 -c "import socket,os;d='/data/experiment';os.makedirs(d,exist_ok=True);p=d+'/.sock-test';s=socket.socket(socket.AF_UNIX);s.bind(p);s.listen(1);c=socket.socket(socket.AF_UNIX);c.connect(p);print('unix socket ok');os.unlink(p);fd=os.open(d,os.O_RDONLY);os.fsync(fd);print('dir fsync ok')"
```

## 1. One request per allocation

```bash
mkdir -p /data/experiment /data/experiment-inputs
# one-time: the pilot inputs live in /home; keep a copy in scratch and use that from now on
cp -a /home/researcher/www27-coder-pilot-nv.rpag1jj6/inputs /data/experiment-inputs/coder-pilot
cd $SRC
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py \
  --attempt-root /data/experiment/p2 --candidates \
  --cell 'coder-nonthinking|H100-primary|serial|k1|r0' \
      /data/experiment-inputs/coder-pilot/generation-config.json \
      /data/experiment-inputs/coder-pilot/pilot-workload.json \
  --output /data/experiment/p2-request.json
```

(`seed_appendix` inside the config still names the old /home path; it is only a label, nothing reads that file
at run time, and the copied file next to it has the same bytes.)

Paired comparison cells of one model go in one allocation: repeat `--cell ID CONFIG WORKLOAD`.
`--cpus` (default 26) is the CPU count asked from Slurm: the 7 one-CPU role steps are rounded up to whole cores
on SMT nodes (2 threads each) and the inference role takes 8 threads, 22 in all; the default leaves two spare
cores. Slurm may give more; that is recorded.

### Other models (Qwen3.8-27B, Qwen3.5-9B, Nemotron-3-Nano-30B)

One allocation serves one model: its weights are hashed once and bound into the manifest. The weights come from
`experiments/calibration/inference-models-v1.json`, which pins each model's owner asset lock (`assets.lock.json`,
sha256 recorded in the repo); the lock's file hashes are the inventory that `submit` re-verifies on disk. The SIF,
candidate runner and nvidia-smi are the same for every model (the contract's SIF). A cell given by id alone gets its
generation configuration generated (native sampling and template settings, frozen cap, memory fraction, text-only flag,
as the admission chain sets them) and uses one shared workload. At k=1, replicate 0 the 16 pilot tasks and their seeds are
the same for every model, so the Coder pilot workload is reused:

```bash
cd $SRC
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py \
  --attempt-root /data/experiment/q1 --candidates \
  --workload /data/experiment-inputs/coder-pilot/pilot-workload.json \
  --cell 'q38-thinking|H100-primary|serial|k1|r0' --cell 'q38-nonthinking|H100-primary|serial|k1|r0' \
  --output /data/experiment/q1-request.json
```

Other allocations: `q35-thinking|H100-primary|serial|k1|r0` and `nemotron-thinking|H100-primary|serial|k1|r0`
(one `--cell` each, own attempt root such as `/data/experiment/q2`, `.../n1`). The command stops before
writing a request if the weight lock does not match the pinned sha, a cell's configuration disagrees with the
workload, or the cells belong to different models or hardware strata. Prepare and submit exactly as below; for the
50-60 GB models `submit` takes several minutes longer because every weight file is hashed once.

### Main cohort (106 tasks)

Before a model's main cells: its 16-task k=8 pooled pilot (`<stratum>|H100-primary|batch16|k8|r0`) must be collected, and the
pre-registered saturation rule must not stop it (`audit_pass_at_1` over the pilot, stop when strictly above 0.9):

```bash
python3 -I -B scripts/calibration/lcb_ngpu_lean_saturation.py COLLECT_OUTPUT.json [...]
```

The main base workload (all 106 main tasks, k=1, replicate 0; about 150 MB) is built once from the prepared inputs, which are
checked against the frozen manifest first:

```bash
mkdir -p /data/experiment-inputs/main && /usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_workload.py \
  --subset main --prepared /data/site/www27-lcb-release-v6.Dw36FT/prepared-semantic-v2 \
  --output /data/experiment-inputs/main/main-workload.json
```

Then the same request command with `--main-matrix` and that file as `--workload`. `--main-matrix` sets `main_matrix_authorized` in the
manifest (a main-cohort cell is refused without it), builds main configurations (106 arrival offsets of 0, as the frozen main
plan has them) and derives one workload per (k, replicate) next to the configuration (about 150 MB each). Its defaults are 160 GiB,
8 GiB for each of the two worker roles and 24 h, the QOS maximum; every value can be overridden. Give each long cell its own
allocation: a cell that fails after 20 hours is lost, there is no resume inside a cell.

Never synchronise new code into a source directory that a queued or running attempt uses: every role step starts a fresh Python
process from it. Use a new directory per code version (`www27-lean-src2`, ...) and keep the old one until its attempts have ended.

## Service path (C0): online weak4 selection, audit after the window

The evaluation pipeline above generates every candidate first and judges all of them (weak4 and audit, no short circuit) while the
GPU role waits. That is the cost of the evaluation, not of the service the theory prices. `--service` runs the service instead:

- W1 generates and then selects per episode through E1: candidates in id order, an ineligible (truncated or code-free) candidate is
  skipped, a candidate runs the weak4 fold test by test and stops at its first failing test, the first candidate that passes the whole
  fold is delivered, none passing is a refusal. The delivery time of every episode is recorded (`generation-episodes.json`).
- W1 snapshots the cumulative CPU of the service roles (G, W1, E1: the cgroup `user` domain of each role's step, which holds vLLM,
  Apptainer and the candidate processes) right before the cohort starts and right after the last selection returns. Both snapshots are
  saved with their raw `cpu.stat` text and read times in `service-window.json`. Service CPU is end minus start per role; a missing or
  inconsistent snapshot makes that role and the total unidentified, never a partial sum. The cold start is before the start snapshot and
  is kept separately (`startup_s`, `service_cpu_startup_s`).
- Writing `service-window.json` stops the G role. Its step also holds time outside the recorded cold-start interval and the window:
  the bootstrap before inference starts and a short teardown after the window (backend close and a GPU probe, about 14 s in the
  pilots); the analysis reports the sum as `step_other_s`. Only afterwards W1 audits the *delivered*
  candidates (so quality is measured on the same samples as the cost). Audit time and CPU are outside the window. The audit never
  changes the delivery. These cells have no all-candidate audit pass rate.
- W2 and E2 only follow W1; selection is sequential, so no second worker evaluates candidates that are not needed.

All four cells of a replicate go into one allocation, so every serial/pooled comparison is made on one GPU without pinning a node.
The cell order is fixed in advance and rotated across the replicates so that a first-cell effect (cold page cache, first JIT) is
not always carried by the same cell: r0 serial k1, serial k8, batch16 k1, batch16 k8; r1 batch16 k1, batch16 k8, serial k1,
serial k8; r2 serial k8, serial k1, batch16 k8, batch16 k1 (the order is the order of the `--cell` arguments and is recorded in the manifest). Different replicates may land on different GPU models; read the
three-window envelope as seed and hardware together, and use one stated GPU-hour rate for all models.

Code and provenance. Commit first, then sync into a NEW source directory (never into one that a queued or running attempt uses);
the manifest records `git rev-parse HEAD` of the checkout as `source_head`, and the request generator refuses to build when tracked
files under `scripts`, `experiments` or `data` differ from HEAD:

```bash
rsync -a --delete --exclude work --exclude .DS_Store --exclude 'review/*.pdf' --exclude '/*.tar.gz' --exclude '/*.zip' \
  /workspace/researcher/workspace/git/www27/ researcher@<cluster-login-host>:/data/experiment-src8/
ssh researcher@<cluster-login-host> 'git -C /data/experiment-src8 rev-parse HEAD; git -C /data/experiment-src8 diff --stat HEAD -- scripts experiments data'
```

(the anchored `/*.tar.gz` and `/*.zip` skip only the untracked archives in the repository root; tracked archives live under `data/`.) The
second command must print the commit and then nothing. Use `SRC=/data/experiment-src8` below and do not edit that tree afterwards. (The wiring smoke ran from `www27-lean-src7`
at b97ab7b; src8 is the commit that adds the collect-side status fixes and the shared judgement of G. The functions the roles run are unchanged
(`git diff b97ab7b -- scripts/calibration/lcb_ngpu_v3.py` touches only `cell_report`, `read_service_cell`, `collect_gpu` and two helpers they
use), so the smoke covers it: the differences are in what collect, the extractor and the analysis read back from the originals.)

What the numbers contain (state this in the paper):
- `service` is the steady state: GPU seconds of the cohort window (generation calls plus the online selections between them), CPU of G, W1
  and E1 between the two snapshots. `service_startup` adds the cold start: the G step (which also holds `step_other_s`) and the
  cumulative service-role CPU at the end snapshot. Neither contains the audit.
- Service CPU is the component covered by G, W1 and E1 (not the whole C0 CPU): G + W1 + E1 only. The idle harness roles (W2, E2, O1, O2), the dispatcher D and the shared coordination cost
  (`shared-cost.json`, counted once per allocation) are not in it; they stay in the lifecycle endpoints. It includes vLLM host CPU and the
  evidence bookkeeping W1 and E1 do inside the window (request digests, receipts, journals); task digests are computed before the window.
- Energy of a service cell uses busy = the sum of the generation calls and idle = the rest of the window (the selection waits). The
  evaluation-pipeline energy scenario defines idle as the wait for judging; the declared fractions are the same.
- No warm-up request precedes the window: first-use JIT inside it counts, as the preregistration says.
- Failures after the window keep the window, and never make a cell complete. Collect marks a service cell `measured_pending_pilot_review`
  only when every role ended cleanly (lifecycle endpoint captured, step waited with exit code 0), W1 and W2 published their done files,
  the audit phase has no `audit_error`, and every delivered answer has its audit label. Anything else that leaves the window intact
  (E1 exits during the audit, a follower or observer stops, the audit fails) is `measured_service_partial` with `lifecycle_failures`
  and `audit_error` in the cell record: window, delivery, tokens and service CPU stay, the unaudited delivered answers have no audit
  label (None, so q is None), the whole-cell lifecycle CPU is absent, and the batch is `partial_pending_pilot_review`.
- G ends the window. If G did not exit cleanly or its endpoint is not captured, collect marks the cell unidentified and the extractor
  records the same judgement (`service_window.g_error`, one shared function); the analysis then keeps the labels and token meters of
  the cell but none of its window quantities (window, startup, CPU, delivery times), so no service cost is recovered from a cell
  that collect rejected. An extract that carries no judgement of G is treated the same way.
- If `8-joins.json` is missing, collect and the extractor keep the window time, and the CPU values that need the bound cgroup path are
  None; collect cannot verify the roles then and lists the cell as unidentified (the window stays in its record).

Wiring smoke (Coder, the frozen 16-task pilot, four cells; wiring check only, not a result):

```bash
cd $SRC   # /data/experiment-src7 for the smoke that was run
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py \
  --attempt-root /data/experiment/sv0 --candidates --service \
  --workload /data/experiment-inputs/coder-pilot/pilot-workload.json \
  --cell 'coder-nonthinking|H100-primary|serial|k1|r0' --cell 'coder-nonthinking|H100-primary|serial|k8|r0' \
  --cell 'coder-nonthinking|H100-primary|batch16|k1|r0' --cell 'coder-nonthinking|H100-primary|batch16|k8|r0' \
  --walltime-h 3 --output /data/experiment/sv0-request.json
```

Then prepare, submit and, after the job, collect as in sections 2 and 3 and run the wiring check on the attempt root:

```bash
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_service_check.py /data/experiment/sv0
```

Every cell of the manifest must report `snapshots`, `times`, `decisions`, `short`, `audit_after`, `audit_only` all true (exit code 0;
a missing root, manifest or window file is a failure, not a skip).

Qwen3.5-9B service cells (main cohort, one allocation per replicate, attempt roots `svq0`, `svq1`, `svq2`, submitted together; the
`--cell` order below is the rotated order of the replicate):

```bash
W=/data/experiment-inputs/main/main-workload.json; P='q35-thinking|H100-primary'
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py --candidates --service --main-matrix --workload $W \
  --attempt-root /data/experiment/svq0 --output /data/experiment/svq0-request.json \
  --cell "$P|serial|k1|r0" --cell "$P|serial|k8|r0" --cell "$P|batch16|k1|r0" --cell "$P|batch16|k8|r0"
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py --candidates --service --main-matrix --workload $W \
  --attempt-root /data/experiment/svq1 --output /data/experiment/svq1-request.json \
  --cell "$P|batch16|k1|r1" --cell "$P|batch16|k8|r1" --cell "$P|serial|k1|r1" --cell "$P|serial|k8|r1"
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py --candidates --service --main-matrix --workload $W \
  --attempt-root /data/experiment/svq2 --output /data/experiment/svq2-request.json \
  --cell "$P|serial|k8|r2" --cell "$P|serial|k1|r2" --cell "$P|batch16|k8|r2" --cell "$P|batch16|k1|r2"
```

The defaults (24 h, 160 GiB, 8 GiB per worker role) leave a wide margin over the roughly 9 h estimated for the four cells of one
replicate (an estimate: it assumes similar GPU speed and no long queueing; the pooled generate calls last about 10 minutes, far below the
frozen 3600 s per-call limit).

Analysis of service cells: `lcb_ngpu_lean_extract.py` and `lcb_ngpu_lean_analysis.py` handle them automatically (extra columns
`tau_delivery_s`, `selection_s`, `service_window_s`, `startup_s`, `service_cpu_s`, `service_cpu_startup_s`);
`lcb_ngpu_lean_theory.py --mode service` prices them on two bases: `service` (steady state) and `service_startup` (with the cold
start). The paper has to say which one it studies. Do not mix service cells with evaluation-pipeline cells in one table.

## Revision of the per-call generation timeout (2026-10-23, owner-approved; evaluation-pipeline cells)

Decision record: `experiments/calibration/generation-timeout-revision-2026-10-23.md` (what was approved, the evidence, what is not
decided). The frozen cap path gives the Qwen3.8 thinking stratum 3,600 s for one pooled generation call and records the old 7,200 s
contingency as withdrawn; that file is not edited and its note stays as written. The revision supersedes the note only for the scope
below, by the owner's approval of 2026-10-23.

Why: `q38-thinking|H100-primary|batch64|k8` (r0 in thA0, r1 in thA1) aborted at that bound: W1 failed 3,600.6 s after the first
512-candidate dispatch with `Incomplete inference/execute response` (G closed the connection), the Slurm limit was 24 h, and the same
cell on an H200 (r2) completed (first call 2,497 s). The A100 `batch16|k8` attempts (aB0-aB2) completed 3/7, 3/7 and 0/7 calls and
their `batch64|k8` cells 0/2 before aborting, as listed by the owner on 2026-10-23 (originals not archived yet).

The timeout is the longest a client waits for one pooled call. The decoder never reads it (`lcb_vllm_worker.py`) and no seed or sampling
parameter depends on it (`lcb_seeds.candidate_seed(seed, replicate, task, candidate)`), so the sampling parameters and
per-candidate seeds of a cell that completes under 7,200 s are exactly those it would have had under 3,600 s (a draw of the same estimand;
batched vLLM decoding is not bitwise reproducible, so identical tokens on a rerun are not promised); cells that already completed need no re-run. The revision is therefore
narrow and explicit (`scripts/calibration/lcb_timeout_revision.py`):

- scope: `q38-thinking` cells with k=8 and a pooled configuration (batch16 or batch64), on either hardware stratum, of the evaluation
  pipeline; every other cell, every other value and any service configuration (`selection_mode` online) are refused by the validator;
- the gate is the marker: a generation configuration may use 7,200 s only with the exact marker `timeout_revision` (compared as encoded
  bytes: schema, from 3,600 to 7,200, date, scope, reason, owner, path of the decision record) and must use it. `lcb_ngpu_v3.validate_inputs`
  checks it in the request, in prepare, in the inference role and in the worker roles (the other roles never read the generation
  configuration). `lcb_ngpu_lean_request.py --extend-timeout` is the convenient way to build such a configuration for cells given by id
  (its file is named `...t7200...`); a configuration given as a file passes the same checks, flag or not;
- the original 3,600 s failures and the cells that passed under 3,600 s stay as they are, and an attempt of extended cells is an attempt
  of its own (a new root, whole cells, no continuation of an aborted cell, no retry);
- every extract records the timeout the cell ran under, read from the configuration the manifest pins (sha256 and bytes checked; run
  the extract where the `...configs/` directory still exists): `generation_timeout` = seconds and whether the marker is present, or
  unknown. The analysis and theory tables get a `timeout_s` column whenever some cell used the extension or its timeout is unknown (never
  a defaulted 3,600; Coder's frozen 1,800 is not a revision); a theory row whose cells were only partly recorded shows `partial`, and a menu row is flagged when any of the cells it chose between ran under the extension. These cells are reported as extended-bound, exploratory results next to
  the preregistered outcome (unidentified under 3,600 s), never in place of it.

The single call is bounded by 7,200 s, the cell by the allocation: a batch16 k8 cell has 7 calls, so size the walltime for the worst case
(7 x 7,200 s = 14 h of generation plus start-up, judging and teardown: ask 24 h; the H100 batch64 k8 cell has 2 calls, about 4 h in
the estimate, ask 8 h).

What was observed and what to expect. H100: the first batch16 k8 call took 1,741-1,861 s on H100 80GB and 882 s on the H200 of r2, and the
first batch64 k8 call 2,497 s on that H200; the forecast for the first batch64 k8 call on H100 80GB was 4,900-5,300 s, the two extended
cells (thC0, thC1) took 5,885 s and 5,728 s (8.7-11.7% above the forecast, inside 7,200 s; thC1's second call, 3,627 s, also exceeded
3,600 s). The batch64/batch16 first-call ratio is therefore 2.83 on the H200 and 3.16-3.29 on H100 HBM3. A100: from the owner's listing (not archived), aB0 and aB1 completed
three batch16 k8 calls, each under 3,600 s, and a later call exceeded it; aB2's first call did. The A100 first-call time of batch16 k8 is
therefore not recorded, and the first batch64 k8 call is about 2.8 times the first batch16 call on the H200 (2,497 s / 882 s; a
ratio measured on that card and only assumed to carry over to the A100; the H100 ratio would give 3.2-3.3): an
A100 batch64 k8 first call fits 7,200 s only if the A100 batch16 first call took at most about 2,200 s (H100 ratio) to 2,500 s (H200 ratio),
that is 37-42 min. Run one A100
`batch16|k8` cell first, read its first-call time (batch 0, dispatch to barrier, in `cohort-events.jsonl`), and submit A100 `batch64|k8` only
if it is at most about 2,200 s; otherwise that cell stays unidentified and no further extension is implied. (aD0's first call took
3,291 s, so the A100 batch64 k8 cells are not submitted.)

```bash
cd $SRC   # a source directory made at the commit that holds this revision (not one a running attempt uses)
W=/data/experiment-inputs/main/main-workload.json
/usr/bin/python3.12 -I -B scripts/calibration/lcb_ngpu_lean_request.py --candidates --main-matrix --extend-timeout --walltime-h 8 \
  --workload $W --attempt-root /data/experiment/thC0 --output /data/experiment/thC0-request.json \
  --cell 'q38-thinking|H100-primary|batch64|k8|r0'
```

(thC1 the same with r1; an A100 batch16 k8 cell uses its A100 cell id and `--walltime-h 24`.) The summary printed by the request lists
`generation_timeouts_s`: check that it says 7200 for these cells and nothing else.

## 2. Prepare and submit (one sbatch, then you may log out)

```bash
/usr/bin/python3.12 -I -B scripts/calibration/lcb_isolation_owner_v2.py prepare --lean \
  --root /data/experiment/p2 --request /data/experiment/p2-request.json
/usr/bin/python3.12 -I -B scripts/calibration/lcb_isolation_owner_v2.py submit --execute \
  --root /data/experiment/p2
```

`submit` checks the image, the model files and the candidate runner, then calls sbatch once. A frozen asset is hashed in full only
the first time: the verified digest is remembered in `.www27-hash-cache.json` next to the model directory (and next to the image),
keyed by size, mtime, ctime and inode, so later submits of the same files take seconds. Any change to a file, or an unreadable cache,
means a full hash again; delete that cache file to force one. The first submit per model still reads all of its weights, so submit
one allocation per model first and the others afterwards (submits made at the same moment all hash). The candidate runner is a small
repository file and is always hashed.
It never resubmits: a failed or unclear sbatch leaves `submission.consumed.json` and you start a new attempt root.

## 3. After the job ends

```bash
/usr/bin/python3.12 -I -B scripts/calibration/lcb_isolation_owner_v2.py collect \
  --root /data/experiment/p2 --output /data/experiment/p2-return
tar -czf /data/experiment/p2-originals.tar.gz -C /data/experiment p2 p2-return
```

Send the tarball (or paste `p2-return/batch.json` and `p2/*.stderr` if it is small). Anything missing stays
missing in the result: a missing endpoint makes that quantity `unidentified`, never a substituted number.
