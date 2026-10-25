# Who Pays for Thinking? Code and data

Code, returned measurement records, and analysis scripts for *Who Pays for
Thinking? Billing Hidden Reasoning Tokens in Model–Cloud Contracts*. The
manuscript itself is not included. Everything here runs offline, without a
cluster, model downloads, or execution of generated candidate code.

## Start here

From the repository root:

```sh
python3 -I -B reproduce.py
python3 -I -B reproduce.py --theory
```

The first command verifies the file manifest, replays the returned records for
all 153 completed cells, and regenerates the numerical tables and plot data in
`analysis/`, comparing them with the saved copies. The second also runs the exact
synthetic theory checks. Both print JSON and leave the records unchanged. The
replay uses only the Python standard library and was tested with CPython 3.12.14
and 3.9.6.

Unit tests:

```sh
cd analysis && python3 -B -m unittest test_result_evidence test_retail_result_tables test_service_result_tables test_bootstrap_pairs
cd code/measurement/scripts/calibration && python3 -B -m unittest test_lean_analysis test_lean_theory
```

## Contents

| Path | Content |
| --- | --- |
| `code/measurement/` | Measurement, scheduling, extraction, collection, accounting, and analysis source, native helper sources, selected tests, and scientific configurations |
| `analysis/` | Scripts that turn the records into the reported numbers: result tables, plot data, the retail-pricing counterfactual, the paired bootstrap, and exact theory checks |
| `analysis/evidence/` | Anonymous sufficient statistics, resource and theory tables, and saved results read by the analysis scripts |
| `analysis/tables/`, `analysis/figures/src/` | Saved outputs of the analysis scripts, used as references by `reproduce.py` |
| `data/experiment-records/` | Returned main-pipeline, online-service, and A100 records, retaining incomplete attempts and duplicate source copies |
| `data/pilot-records/` | Five final generation-admission pilots, including samples, episodes, schedules, backend metadata, and metering records |
| `manifests/` | Source and export hashes, cell coverage, anonymization provenance, environment observations, and missing-data disclosure |
| `licenses/` | The LiveCodeBench MIT notice |
| `DATA_COVERAGE.md` | What is present, what was never returned in these archives, and what can be reproduced |
| `ENVIRONMENT.md` | Dependencies and the distinction between offline replay and a fresh GPU run |

## Result coverage

- Initial evaluation pipeline: 72 completed cells.
- Online service: 66 completed cells across five deployments.
- A100 extension: 15 completed cells.
- Five final generation-admission pilots.

The 153 completed cells contain 71,868 candidate rows. Replay checks 61,056
pipeline per-task values exactly and performs 1,119 additional metric checks.
All 114 reference retail-contract profiles and the saved result tables are
recomputed from the supplied inputs. User values and energy and cost conversion
rates remain declared inputs.

The record tree contains 163 candidate-extract files representing 161 distinct
source files. Eight are incomplete original extracts. Duplicate byte-identical
copies are retained for provenance and are not additional observations. The
analyzed 153 cells are selected by the source hashes in
`manifests/raw-coverage.json`.

## Records and anonymization

The records retain all JSON fields, numerical values, labels, token counts,
timing values, and missingness. Site paths, account names, node names, and GPU
UUID strings are replaced consistently. The original member SHA-256 and the
exported-file SHA-256 are both recorded in `manifests/`. The exported copies are
not byte-identical to the original receipts.

The quantitative analysis and theory engines are byte-identical to the versions
used in the archived analysis records. Other site-specific source strings are
normalized, with original and exported hashes recorded separately. Two analysis
files were edited when the manuscript was removed, and a site name was removed
from one measurement docstring. These edits are recorded in
`manifests/source-code-provenance.json`. A fresh GPU deployment requires a new
site's assets and configuration.

## Bootstrap diagnostics

The registered pipeline withheld its primary bootstrap after the cost-spread
pause. The stored bootstrap intervals are conditional diagnostics produced
outside that gate for the original pipeline. They are not uncertainty intervals
for the later service measurements. To replay them, install NumPy from
`requirements-offline.txt` and write to a new path:

```sh
mkdir -p reproduced
python3 -I -B analysis/bootstrap_pairs.py --inputs analysis/evidence/bootstrap-inputs.json --out reproduced/bootstrap-results.json
```

Complete generated text for the main and service study, prepared prompts and
private tests, model weights, and some full timing and event originals are not
present in the compact return archives. See `DATA_COVERAGE.md`.

## License

The code in this repository is released under the MIT License (see `LICENSE`).
The LiveCodeBench notice in `licenses/` applies to material derived from
LiveCodeBench.
