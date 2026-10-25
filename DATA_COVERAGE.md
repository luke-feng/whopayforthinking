# Data coverage and provenance

## Included records

The nine returned archives are expanded under `data/experiment-records/`, one
subdirectory per source archive. Their members are field-preserving exports with
site identifiers normalized. `manifests/record-provenance.json` records each
original archive/member hash and exported hash. The original tarballs themselves
are retained separately by the owner.

`manifests/raw-coverage.json` matches both the candidate-extract and collect-file
source hashes for every completed cell cited by the analysis inputs:

| Cohort | Completed cells | Scope |
| --- | ---: | --- |
| Pipeline | 72 | Deferred all-candidate judging, with original timeout-extension labels retained |
| Service | 66 | Online selection, offline audit of delivery, and service-window counters |
| A100 | 15 | Completed exploratory cells, retaining extended-bound identities |

The eight incomplete original extracts and duplicate copies remain in the tree.
Missing fields and empty files remain missing or empty. They are not filled from
later runs. Pipeline, service, and A100 records are selected as separate cohorts,
including when their model/configuration/repetition identifiers coincide.

The five final pilot directories include 45 original record files. These pilot
samples include generated text and token information where present in the
returned samples. They are calibration data, not a substitute for main-run
sample originals. Backend, episode, schedule, tokenization, completion, and GPU
records retain their original field content with identifier substitutions.

## What was not returned for the main/service study

The compact extraction tool deliberately leaves the much larger sample files on
the cluster. In particular, this folder does not contain a complete copy of:

- `generated-samples.json` with generated text for every main/service candidate;
- the original prepared `main-workload.json`, `prompts.jsonl`, and
  `tests.private.jsonl`;
- all original per-request, online-check, `service-window.json`, and runtime
  event files needed to rerun every service wiring check from scratch;
- model weights, model/tokenizer installations, or the inference container.

Their absence is recorded in `manifests/missing-originals.json`. No reconstructed
text or synthetic timing records have been added. The frozen 106-task roster,
input hashes, generation settings, per-candidate measurements, and exact
sufficient statistics used by the analysis are included.

## Reproduction claims

The default replay reconstructs candidate selection, quality, token meters, and
latency from the returned candidate/episode records. It compares the original
pipeline's per-task sufficient statistics exactly and checks service quantities
against the recorded CPU/GPU counters and analysis inputs. It then regenerates the
numerical tables and plot data files in `analysis/` and compares them with the
saved copies.

This is a replay of the supplied measurements. It does not repeat GPU generation,
rejudge generated programs, prove that each site control passed in the field,
or recover the absent raw event streams. Source commitments and the owner's
untouched originals preserve that audit boundary.

The manuscript and its LaTeX sources are not part of this repository. The
analysis scripts, their inputs, and the saved numerical outputs are in
`analysis/`.
