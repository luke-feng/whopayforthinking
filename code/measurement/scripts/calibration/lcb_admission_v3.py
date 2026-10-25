"""CPU-only native-chain proposals and receipts rebuilt from complete originals.

No legacy loader, recursive prerequisite traversal, label selection or execution.
Report audits each bounded prefix receipt by equality to already loaded records.
Off-mode can inherit only an on-mode report (one bounded additional chain).
"""
import argparse
import json
from pathlib import Path
import re

from pilot import read_json, write_new
from lcb_sandbox import file_sha
from lcb_cap_policy_v3 import POLICY, envelope, select
import lcb_native_generation as native

SCHEMA = 'lcb-model-cap-recommendation-v3'
PROTOCOL = 'native-admission-chain-v3'
PAIR_KEYS = ('model_id', 'model_revision', 'system_prompt', 'inference_sif_sha256',
             'gpu_memory_utilization', 'max_num_seqs', 'cache_mode', 'seed', 'replicate_id',
             'workload_manifest_sha256', 'seed_appendix_sha256', 'expected_gpu_name',
             'expected_vllm_version', 'engine_metrics_schema', 'engine_metrics_source_reference',
             'inference_text_only', 'sampling_seed_policy', 'k', 'pool_id', 'concurrency',
             'arrival_offsets_s')


def initial(name, effort, cap):
    return ((name == 'q38-thinking' and effort == 'medium' and cap == 12288)
            or (name in ('q35-thinking', 'nemotron-thinking') and effort is None and cap == 12288)
            or (name == 'coder-nonthinking' and effort is None and cap == 4096))


def validate_shape(cfg):
    native.validate(cfg)
    if cfg.get('cap_chain_protocol') != PROTOCOL or cfg.get('cap_policy') != POLICY:
        raise ValueError('New native chain marker required; legacy is diagnostic only')
    context, deadline = envelope(cfg['stratum_id'], cfg['max_tokens'])
    if cfg.get('max_model_len') != context or cfg.get('generation_timeout_s') != deadline:
        raise ValueError('Native stage context/deadline changed')
    if cfg.get('replicate_id') != 0 or type(cfg.get('replicate_id')) is not int:
        raise ValueError('Cap chain uses paired replicate 0 only')
    first = initial(cfg['stratum_id'], cfg['reasoning_effort'], cfg['max_tokens'])
    path, digest = cfg.get('cap_prerequisite_receipt'), cfg.get('cap_prerequisite_receipt_sha256')
    if first:
        if path is not None or digest is not None:
            raise ValueError('Initial stage must start a new chain')
    elif not isinstance(path, str) or not Path(path).is_absolute() or not re.fullmatch('[0-9a-f]{64}', str(digest)):
        raise ValueError('Non-initial stage requires a hashed native prerequisite receipt')
    if cfg.get('cap_legacy_source') is not None:
        raise ValueError('No legacy source may enter the new chain')


def _samples(record):
    rows = record['samples']; cfg = record['cfg']; cap = cfg['max_tokens']
    keys = [(r['task_id'], r['candidate_id'], r['seed']) for r in rows]
    tasks = list(dict.fromkeys(r['task_id'] for r in rows))
    if (len(rows) != 128 or len(set(keys)) != 128 or len(tasks) != 16
            or any(type(r['candidate_id']) is not int or type(r['seed']) is not int or not 0 <= r['seed'] < 2**63 for r in rows)
            or any([r['candidate_id'] for r in rows if r['task_id'] == t] != list(range(8)) for t in tasks)):
        raise ValueError('Full ordered 16 by 8 paired seed coverage required')
    if any(type(r.get('truncated')) is not bool or type(r.get('output_tokens')) is not int
           or not 0 <= r['output_tokens'] <= cap for r in rows):
        raise ValueError('Actual cap-bounded completions required')
    return keys, sum(r['truncated'] for r in rows)


def choose(records):
    if not records or len(records) > 4:
        raise ValueError('One complete ordered native chain, at most four stages')
    first = records[0]; name = first['cfg']['stratum_id']; observations = []
    keys0 = None; per_effort = {}
    for record in records:
        cfg = record['cfg']; validate_shape(cfg)
        if cfg['stratum_id'] != name or any(cfg.get(k) != first['cfg'].get(k) for k in PAIR_KEYS):
            raise ValueError('Keep model, workload, seeds and non-stage settings paired')
        keys, cuts = _samples(record)
        if keys0 is not None and keys != keys0:
            raise ValueError('Task/candidate seeds and order differ across native stages')
        keys0 = keys
        # Across effort changes only prompt content/length may differ, not roster.
        roster = [r['task_id'] for r in record['tokenization_rows']]
        if (roster != [r['task_id'] for r in first['tokenization_rows']]
                or len(roster) != 122 or len(set(roster)) != 122 or set(record['lengths']) != set(roster)
                or any(type(n) is not int or n < 1 for n in record['lengths'].values())
                or max(record['lengths'].values()) + cfg['max_tokens'] > cfg['max_model_len']):
            raise ValueError('Entire native workload must fit without filtering')
        effort = cfg['reasoning_effort']
        if effort in per_effort and (record['tokenization_rows'] != per_effort[effort]['tokenization_rows']
                                    or record['lengths'] != per_effort[effort]['lengths']):
            raise ValueError('Same-effort stages must have identical full tokenization')
        per_effort[effort] = record
        observations.append((effort, cfg['max_tokens'], cuts))
    if name == 'q38-nonthinking':
        if len(records) != 1:
            raise ValueError('Off-mode inherits one cap, never optimizes its own truncation')
        cfg = first['cfg']; cuts = observations[0][2]
        return {'status': 'cap_recommended', 'max_tokens': cfg['max_tokens'],
                'max_model_len': cfg['max_model_len'], 'generation_timeout_s': cfg['generation_timeout_s'],
                'recommended_effort': None, 'paired_on_effort': cfg.get('paired_on_effort'),
                'threshold_met': cuts <= 6, 'residual_truncation_report_required': cuts > 6,
                'observed_stages': [{'reasoning_effort': None, 'max_tokens': cfg['max_tokens'],
                    'max_model_len': cfg['max_model_len'], 'generation_timeout_s': cfg['generation_timeout_s'],
                    'truncated': cuts, 'candidates': 128}], 'next_stage': None,
                'control_rule': 'inherit_native_on_cap_context_deadline'}
    return select(name, observations)


def _result(records):
    decision = choose(records)
    cfg = records[0]['cfg']
    return {'schema': SCHEMA, 'cap_policy': POLICY, **decision, 'stratum_id': cfg['stratum_id'],
            'frozen_workload_sha256': cfg['workload_manifest_sha256'],
            'source_runs': [r['path'] for r in records],
            'sources': [{'run': r['path'], 'hashes': r['original_hashes'],
                         'submission': r['concurrency'], 'generation_settings': native.profile_settings(r['cfg']),
                         'max_tokens': r['cfg']['max_tokens'], 'max_model_len': r['cfg']['max_model_len']} for r in records],
            'recommended_is_not_frozen': True, 'reviewer_frozen': False, 'execution_authorized': False,
            'main_matrix_authorized': False, 'candidate_execution': False, 'inference_calls': 0,
            'quality_admission': 'pending_isolated_audit_labels_and_saturation_review',
            'budget_contrast': 'cap and context jointly change; not a pure output-budget effect'}


def _dependency(cfg):
    path = Path(cfg['cap_prerequisite_receipt'])
    if file_sha(path) != cfg['cap_prerequisite_receipt_sha256']:
        raise ValueError('Native prerequisite receipt bytes changed')
    value = read_json(path)
    if value.get('schema') != SCHEMA or value.get('cap_policy') != POLICY:
        raise ValueError('Only v3 receipts are accepted; old diagnostics cannot seed a new chain')
    return value


def _target(cfg, value):
    if cfg['stratum_id'] == 'q38-nonthinking':
        if (value['stratum_id'] != 'q38-thinking' or value['status'] != 'cap_recommended'
                or cfg.get('paired_on_effort') != value['recommended_effort']
                or any(cfg[k] != value[k] for k in ('max_tokens', 'max_model_len', 'generation_timeout_s'))):
            raise ValueError('Off-mode must inherit actual final on-mode effort/cap/context/deadline')
    else:
        wanted = value.get('next_stage')
        if (value['stratum_id'] != cfg['stratum_id'] or not wanted
                or any(cfg[k] != wanted[k] for k in wanted)):
            raise ValueError('Requested stage is not the next native transition')


def report(paths, *, on_only=False):
    from lcb_admission_report import load_run
    # Inspect ALL headers before loading any dependency; no recursive cfg check.
    paths = [str(Path(p).resolve(strict=True)) for p in paths]
    if not 1 <= len(paths) <= 4 or len(set(paths)) != len(paths):
        raise ValueError('Unique bounded ordered source runs required')
    configs = [read_json(Path(p)/'run.json')['config'] for p in paths]
    if any(not native.active(c) or c.get('cap_chain_protocol') != PROTOCOL for c in configs):
        raise ValueError('Legacy run is diagnostic only, not new-chain evidence')
    if on_only and any(c.get('stratum_id') == 'q38-nonthinking' for c in configs):
        raise ValueError('Inheritance accepts only an on-mode chain; recursive off references rejected')
    records = [load_run(p) for p in paths]
    value = _result(records)  # Also rejects skipped/extra/reordered stages first.
    for i, record in enumerate(records):
        cfg = record['cfg']
        if cfg['stratum_id'] == 'q38-nonthinking':
            parent = verified_receipt(cfg['cap_prerequisite_receipt'], on_only=True)
            if _dependency(cfg) != parent:
                raise ValueError('Inherited receipt changed')
            _target(cfg, parent)
            last = read_json(Path(parent['source_runs'][-1])/'run.json')['config']
            if any(cfg.get(k) != last.get(k) for k in PAIR_KEYS):
                raise ValueError('Off-mode changes non-mode paired settings')
        elif i:
            if _dependency(cfg) != _result(records[:i]):
                raise ValueError('Prerequisite must equal this exact audited prefix; no cycles or foreign chains')
            _target(cfg, _result(records[:i]))
    return value


def verified_receipt(path, *, on_only=True):
    value = read_json(path)
    if value.get('schema') != SCHEMA or value.get('cap_policy') != POLICY:
        raise ValueError('New native v3 receipt required')
    rebuilt = report(value['source_runs'], on_only=on_only)
    if rebuilt != value:
        raise ValueError('Native receipt does not reproduce from original records')
    return value


def prepare_proposal(name, cap, effort=None, receipt=None):
    from lcb_admission import native_proposal
    if name == 'q38-thinking' and effort is None:
        effort = 'medium'
    cfg = native_proposal(name, cap, effort)
    cfg.update(cap_chain_protocol=PROTOCOL, cap_prerequisite_receipt=None,
               cap_prerequisite_receipt_sha256=None, inherited_cap_receipt=None,
               inherited_cap_receipt_sha256=None, paired_on_effort=None,
               note='Native v3 chain proposal only; fresh core, extended and wrapper review required.')
    if initial(name, effort, cap):
        if receipt is not None:
            raise ValueError('Initial native stage cannot inherit old or other evidence')
    else:
        if not receipt:
            raise ValueError('Non-initial stage requires a reproducible native receipt')
        value = verified_receipt(receipt)
        if name == 'q38-nonthinking':
            cfg['paired_on_effort'] = value.get('recommended_effort')
        _target(cfg, value)
        prior = read_json(Path(value['source_runs'][-1])/'run.json')['config']
        # Retain actual assets for pairing, owner wrapper independently rebinds
        # paths and verifies their byte hashes; never copy approval booleans.
        for k in ('weights_dir', 'weights_manifest', 'inference_sif', 'inference_sif_sha256', 'seed_appendix'):
            cfg[k] = prior[k]
        cfg.update(cap_prerequisite_receipt=str(Path(receipt).resolve(strict=True)),
                   cap_prerequisite_receipt_sha256=file_sha(receipt))
        if name == 'q38-nonthinking':
            cfg.update(inherited_cap_receipt=cfg['cap_prerequisite_receipt'],
                       inherited_cap_receipt_sha256=cfg['cap_prerequisite_receipt_sha256'])
    validate_shape(cfg)
    return cfg


def verify_for_execution(cfg):
    """Lineage check, not approval. Called BEFORE the still-closed release gate."""
    validate_shape(cfg)
    value = None
    if not initial(cfg['stratum_id'], cfg['reasoning_effort'], cfg['max_tokens']):
        value = verified_receipt(cfg['cap_prerequisite_receipt'])
        if _dependency(cfg) != value:
            raise ValueError('Prerequisite changed during verification')
        _target(cfg, value)
        parent = read_json(Path(value['source_runs'][-1])/'run.json')['config']
        if any(cfg.get(k) != parent.get(k) for k in PAIR_KEYS):
            raise ValueError('Non-stage parent settings changed before execution')
    return value


def verify_tokenization_pair(cfg, tokenized):
    """Before dispatch: same effort preserves inputs, cross effort preserves IDs."""
    validate_shape(cfg)
    if initial(cfg['stratum_id'], cfg['reasoning_effort'], cfg['max_tokens']):
        return
    value = _dependency(cfg)  # Full receipt was rederived before GPU startup.
    parent = Path(value['source_runs'][-1])
    previous_cfg = read_json(parent/'run.json')['config']
    previous = read_json(parent/'tokenization.json')['rows']
    current = tokenized['rows']
    if [r['task_id'] for r in current] != [r['task_id'] for r in previous]:
        raise ValueError('Native chain workload roster changed before dispatch')
    if (cfg['stratum_id'] == previous_cfg['stratum_id']
            and cfg['reasoning_effort'] == previous_cfg['reasoning_effort'] and current != previous):
        raise ValueError('Same-effort tokenization changed before dispatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    r = sub.add_parser('report'); r.add_argument('--runs', nargs='+', required=True)
    p = sub.add_parser('proposal'); p.add_argument('--stratum', required=True)
    p.add_argument('--cap', type=int, required=True); p.add_argument('--reasoning-effort', choices=('medium', 'low'))
    p.add_argument('--receipt')
    for s in (r, p): s.add_argument('--output', required=True)
    args = parser.parse_args()
    result = report(args.runs) if args.action == 'report' else prepare_proposal(args.stratum, args.cap, args.reasoning_effort, args.receipt)
    write_new(args.output, result)
    print(json.dumps({'output': args.output, 'status': result.get('status', 'proposal_only'), 'execution_authorized': False}))


if __name__ == '__main__': main()
