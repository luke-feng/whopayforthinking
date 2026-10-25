"""Owner-approved revision of the per-call generation timeout for the pooled k=8 cells of the Qwen3.8 thinking stratum.

The frozen cap path (experiments/calibration/admission-cap-path-v3.json) gives the stratum a deadline of 3,600 s for one
pooled generation call and records the old 7,200 s contingency as withdrawn. In the lean main run the first call of
q38-thinking batch64 k8 on H100 80GB HBM3 did not return within it (thA0 and thA1: the call was still running when W1
failed 3,600.6 s after dispatch), and the cell aborted without a measurement.

The deadline is the longest a client waits for one pooled call. It is not read by the decoder (lcb_vllm_worker.py never sees
it) and enters no seed or sampling parameter, so the sampling parameters and per-candidate seeds of a cell that completes under
7,200 s are exactly those it would have had under 3,600 s (a draw of the same estimand; batched vLLM decoding is not bitwise
reproducible, so identical tokens on a rerun are not promised). The owner approved extending it to 7,200 s for exactly the cells that need it, as an explicit,
recorded revision:

- only a generation configuration that carries MARKER may use 7,200 s, and it must use it; any other 7,200 s, any altered marker
  (compared as canonical JSON) and any cell outside the scope are refused by lcb_ngpu_v3.validate_inputs, which the request, prepare,
  the inference role and the worker roles call (the other roles never read the generation configuration);
- the scope is the q38-thinking cells with k=8 and a pooled configuration (concurrency 16 or 64, either hardware stratum) of the
  evaluation pipeline (a service configuration with the marker is refused);
- the frozen cap file is not edited, every other cell keeps 3,600 s, and the original 3,600 s failures stay in their records.
"""
import lcb_isolation_release_v2 as release

BASE_S = 3600
EXTENDED_S = 7200
MARKER = {
    'schema': 'generation-timeout-revision-v1', 'from_s': BASE_S, 'to_s': EXTENDED_S, 'date': '2026-10-23',
    'scope': 'q38-thinking, k=8, pooled configuration (concurrency >= 16)',
    'reason': 'the first pooled call of q38-thinking batch64 k8 exceeded the frozen 3600 s on H100 80GB HBM3 (attempts thA0, '
              'thA1); the timeout is a client wait bound that the decoder never reads and no seed or sampling parameter depends on',
    'approved_by': 'owner',
    'record': 'experiments/calibration/generation-timeout-revision-2026-10-23.md',
}


def in_scope(cell):
    """cell: a panel cell (lcb_isolation_batch_v2.panel_cell)."""
    return cell['stratum_id'] == 'q38-thinking' and cell['k'] == 8 and cell['concurrency'] >= 16


def marker():
    return dict(MARKER)


def expected_timeout(config, cell, frozen_s):
    """The timeout this configuration may carry: the frozen one, or EXTENDED_S for an in-scope cell with the exact marker."""
    if 'timeout_revision' not in config:
        return frozen_s
    # exact: the marker must equal MARKER as canonical JSON (key order is not significant; no 3600.0 for 3600, no extra or missing
    # key, not null), the timeout is an int, and the evaluation-pipeline configuration is the only one approved (not the service path)
    release.check(release.encoded(config['timeout_revision']) == release.encoded(MARKER) and frozen_s == BASE_S and in_scope(cell)
                  and type(config.get('generation_timeout_s')) is int and config.get('selection_mode', 'deferred') == 'deferred',
                  'Generation timeout revision marker differs, the cell is outside its scope or the configuration is a service one')
    return EXTENDED_S
