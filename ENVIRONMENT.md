# Environments

## Offline replay

Tested with CPython 3.12.14. The default record and table replay and exact theory
checks use the Python standard library. NumPy 2.3.5 is needed only to recompute
the stored bootstrap diagnostics or run tests that directly exercise that engine.
`requirements-offline.txt` records this tested optional dependency.

The manuscript itself is not part of this repository. The analysis scripts in
`analysis/` regenerate the numerical tables and the plot data files without TeX.

## Inference and measurement

The final pilot `backend.json` records report vLLM 0.30.0, PyTorch
2.13.0+cu130, and CUDA 13.0. These are direct pilot observations. The compact
main/service returns do not supply a full per-run backend installation snapshot,
so those pilot versions are not represented as a separately verified inventory
for every later run.

Source includes Slurm/Apptainer orchestration, GPU identity checks, native helpers,
server requests, extraction, accounting, and analysis. The released record tree
contains hardware models and consistent pseudonyms for site identities. A new
GPU run requires the original model revisions and container, prepared task/test
inputs, compilation of helpers, and site-specific deployment settings. These
large or site-specific assets are not bundled. The offline analysis entrypoint
runs none of these execution paths.

Original and normalized source hashes are listed in
`manifests/source-code-provenance.json`. Site paths in the exported code are
placeholders. Runtime admission hashes refer to the historical release and are
not regenerated or bypassed by this material package.
