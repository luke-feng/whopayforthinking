"""Frozen pilot quality: byte-bound inputs, isolated-label protocol, read-only reports.

No process, model, container or scheduler entry point. The only callable adapter
is a synthetic lookup, guarded against use with measured candidates.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Literal, Protocol

from lcb_delivery import eligible
from lcb_manifest import validate_manifest
from lcb_metering import extract_code
import lcb_native_generation as native
from lcb_output_compare import project_compare
from lcb_seeds import BASE_SEED, POLICY, verify_appendix

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'experiments/calibration/pilot-quality-v1.contract.json'
STRATA = ('q38-thinking', 'q35-thinking', 'nemotron-thinking',
          'coder-nonthinking', 'q38-nonthinking')
FILES = ('cell/run.json', 'cell/completion.json', 'cell/samples.jsonl',
         'cell/episodes.jsonl', 'cap-recommendation.json')
FOLDS = ('weak2', 'weak4', 'audit')
Status = Literal['ok', 'runtime_error', 'time_limit', 'infrastructure_error', 'pending']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def object_sha(value) -> str:
    return sha(canonical(value))


def strict_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result

    def bad(value):
        raise ValueError('Nonfinite JSON: ' + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def json_rows(raw):
    return [strict_json(line) for line in raw.splitlines() if line.strip()]


def read_bytes(path: Path) -> bytes:
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symlink input')
    require(path.is_file() and path.stat().st_size <= 64 * 1024**2,
            'Missing, nonregular or oversized input: ' + str(path))
    return path.read_bytes()


def relative_file(base: Path, name: str) -> Path:
    p = Path(name)
    require(not p.is_absolute() and '..' not in p.parts and str(p) == name,
            'Noncanonical relative path')
    return Path(base) / p


@dataclass(frozen=True)
class PilotRun:
    stratum_id: str
    task_ids: tuple[str, ...]
    samples: tuple[dict, ...]
    episodes: tuple[dict, ...]
    binding: dict
    evidence: Literal['measured', 'synthetic']
    weak_size: int


def decode_run(blobs: dict[str, bytes], entry: dict, manifest_raw: bytes,
               appendix_raw: bytes, *, synthetic=False) -> PilotRun:
    """Pure original-bytes to roster path, shared by production and fixtures."""
    require(set(blobs) == set(FILES) == set(entry['files']), 'Original file coverage')
    require(all(sha(blobs[n]) == entry['files'][n] for n in FILES), 'Original hash mismatch')
    manifest = strict_json(manifest_raw)
    validate_manifest(manifest)
    seeds = verify_appendix(strict_json(appendix_raw), manifest_raw)
    tasks = manifest['pilot_task_ids']
    meta, done = (strict_json(blobs[n]) for n in FILES[:2])
    cfg = meta['config']
    native.validate(cfg)
    name = entry['stratum_id']
    require(name in STRATA and cfg['stratum_id'] == name, 'Wrong stratum')
    expected = {k: entry[k] for k in ('reasoning_effort', 'paired_on_effort',
                                     'max_tokens', 'max_model_len', 'generation_timeout_s')}
    expected.update(subset='pilot', k=8, pool_id=1, concurrency=16, replicate_id=0,
                    sampling_seed_policy=POLICY, seed=BASE_SEED)
    require(all(canonical(cfg.get(k)) == canonical(v) for k, v in expected.items()),
            'Off-spec or nonfinal generation settings')
    require(meta['task_ids'] == tasks and cfg['workload_manifest_sha256'] == sha(manifest_raw)
            and meta['preparation_sha256'] == sha(manifest_raw)
            and cfg['seed_appendix_sha256'] == sha(appendix_raw)
            and meta['private_tests_sha256'] == manifest['private_tests_sha256'],
            'Manifest, seed appendix or task binding mismatch')
    require(meta['evidence'] == ('fixture' if synthetic else 'measured'), 'Evidence class mismatch')
    require(done['status'] == 'collected_not_audited' and done.get('error') is None
            and done['samples_sha256'] == sha(blobs['cell/samples.jsonl']), 'Incomplete source run')
    if not synthetic:
        require(meta.get('judge_mode') == cfg.get('judge') == done.get('judge_mode') == 'deferred'
                and meta.get('candidate_execution') is False, 'Frozen pilot must remain deferred')
    receipt = strict_json(blobs['cap-recommendation.json'])
    require(receipt['stratum_id'] == name and receipt['status'] == 'cap_recommended'
            and receipt['sources'][-1]['run'] == entry['remote_run'], 'Wrong final receipt')
    for key in ('max_tokens', 'max_model_len', 'generation_timeout_s'):
        require(receipt[key] == entry[key], 'Final receipt envelope mismatch')
    for n in FILES[:4]:
        require(receipt['sources'][-1]['hashes'][Path(n).name] == sha(blobs[n]),
                'Final receipt original binding mismatch')
    samples = json_rows(blobs['cell/samples.jsonl'])
    lookup = {}
    for row in samples:
        t, j = row['task_id'], row['candidate_id']
        require(type(j) is int and t in tasks and 0 <= j < 8, 'Task leak or invalid candidate')
        require((t, j) not in lookup, 'Duplicate candidate')
        lookup[t, j] = row
        require(type(row.get('seed')) is int and row['seed'] == seeds[0, t, j]
                and row.get('replicate_id') == 0 and type(row.get('replicate_id')) is int
                and row.get('sampling_seed_policy') == POLICY, 'Candidate seed binding mismatch')
        native.validate_sample(row, cfg)
        for field in ('input', 'output'):
            ids = row[field + '_token_ids']
            require(isinstance(ids, list) and all(type(x) is int and x >= 0 for x in ids)
                    and type(row[field + '_tokens']) is int and row[field + '_tokens'] == len(ids),
                    'Token IDs/count mismatch')
        require(row['output_tokens'] <= cfg['max_tokens'], 'Candidate exceeds cap')
        require(isinstance(row.get('final_text'), str), 'Extraction provenance unavailable')
        extracted = extract_code(row['final_text'])
        require(all(row.get(k) == v for k, v in extracted.items()), 'Extraction mismatch')
        eligible(row, strict=True)
    require(set(lookup) == {(t, j) for t in tasks for j in range(8)}, 'Missing candidates')
    episodes = json_rows(blobs['cell/episodes.jsonl'])
    require([e['task_id'] for e in episodes] == tasks, 'Episode coverage/order mismatch')
    for ep in episodes:
        require(ep['samples'] == [lookup[ep['task_id'], j] for j in range(8)], 'Episode samples mismatch')
        if not synthetic or ep.get('selection_status') == 'deferred':
            # Archived deferred collectors emit JSON null; some versions emit
            # an empty list. Neither records an online check or a refusal.
            require(ep.get('selection_status') == 'deferred' and ep.get('selected_id') is None
                    and ep.get('refusal') is None and 'online_checks' in ep
                    and (ep['online_checks'] is None or ep['online_checks'] == []),
                    'Deferred generation is not an observed refusal or selection')
    binding = {'stratum_id': name, 'manifest_sha256': sha(manifest_raw),
               'seed_appendix_sha256': sha(appendix_raw),
               'task_ids_sha256': object_sha(tasks), 'private_tests_sha256': manifest['private_tests_sha256'],
               'originals_sha256': dict(entry['files'])}
    return PilotRun(name, tuple(tasks), tuple(samples), tuple(episodes), binding,
                    'synthetic' if synthetic else 'measured', cfg['weak_size'])


def load_frozen_roster(base=ROOT) -> tuple[PilotRun, ...]:
    base = Path(base)
    contract = strict_json(read_bytes(base / CONTRACT))
    require(contract['schema'] == 'lcb-pilot-quality-contract-v1', 'Contract schema')
    require(contract['pilot_tasks'] == 16 and contract['candidates_per_task'] == 8
            and contract['saturation'] == {'denominator': 128, 'operator': '>', 'threshold': 0.9,
                'minimum_passes': 116, 'requires_complete_audit_labels': True}, 'Frozen saturation definition')
    require(all(contract[k] is False for k in ('candidate_execution_authorized',
                'main_matrix_authorized', 'backend_execution_implemented')), 'Execution gates must stay closed')
    require([e['stratum_id'] for e in contract['strata']] == list(STRATA), 'Exactly five final strata required')
    for path, digest in contract['references'].items():
        require(sha(read_bytes(relative_file(base, path))) == digest, 'Frozen dependency changed: ' + path)
    originals = []
    for key in ('manifest', 'seed_appendix'):
        ref = contract[key]
        raw = read_bytes(relative_file(base, ref['path']))
        require(sha(raw) == ref['sha256'], 'Frozen ' + key + ' changed')
        originals.append(raw)
    require(strict_json(originals[0])['pilot_task_ids'] == contract['task_ids'], 'Frozen roster changed')
    result = []
    for entry in contract['strata']:
        root = relative_file(base, entry['originals'])
        run = decode_run({n: read_bytes(root / n) for n in FILES}, entry, *originals)
        require(run.binding['private_tests_sha256'] == contract['private_tests_sha256'], 'Private task binding')
        result.append(run)
    return tuple(result)


def validate_tasks(run: PilotRun, raw: bytes) -> dict[str, dict]:
    require(sha(raw) == run.binding['private_tests_sha256'], 'Private tasks hash mismatch')
    rows = json_rows(raw)
    tasks = {}
    for row in rows:
        t = row['task_id']
        require(t not in tasks, 'Duplicate private task')
        tasks[t] = row
        tests = row['tests']
        ids = [x['test_id'] for x in tests]
        require(len(set(ids)) == len(ids), 'Duplicate test')
        folds = row['folds']
        require(set(folds) == set(FOLDS), 'Fold declarations required')
        w2, w4, audit = (folds[f] for f in FOLDS)
        require(all(isinstance(v, list) and len(v) == len(set(v)) for v in (w2, w4, audit))
                and len(w2) == 2 and len(w4) == 4 and len(audit) >= 10
                and set(w2) < set(w4) and not set(w4) & set(audit)
                and set(w4 + audit) == set(ids), 'Weak/audit split leaked or incomplete')
        kind = row['test_type']
        require(kind in ('stdin', 'functional') and row['comparison'] ==
                ('whitespace_tokens_exact' if kind == 'stdin' else 'json_exact'), 'Comparison contract')
        require(kind != 'functional' or (isinstance(row.get('entry_point'), str)
                and row['entry_point'].isidentifier() and not row['entry_point'].startswith('__')),
                'Invalid functional entry point')
        for case in tests:
            require(isinstance(case['input'], str) and isinstance(case['output'], str)
                    and case['testtype'] == kind
                    and case['test_id'] == sha((kind + '\0' + case['input']).encode()), 'Test identity mismatch')
    # Main tasks may be present in the original file but never enter requests.
    require(set(run.task_ids) <= set(tasks), 'Missing pilot task')
    return {t: tasks[t] for t in run.task_ids}


@dataclass(frozen=True)
class CaseRequest:
    binding_sha256: str
    stratum_id: str
    task_id: str
    candidate_id: int
    seed: int
    sample_sha256: str
    code_sha256: str
    task_sha256: str
    role: Literal['weak4', 'audit']
    test_id: str
    code: str
    stdin: str
    test_type: str
    entry_point: str | None

    @property
    def request_sha256(self):
        return object_sha(asdict(self))


@dataclass(frozen=True)
class CaseResult:
    request_sha256: str
    status: Status
    stdout: str | None = None
    error: str | None = None


class IsolatedLabelAdapter(Protocol):
    """Future approved adapter contract; one outstanding case per worker.

    Multiple independent workers may consume disjoint requests. Implementations
    must bind P/N/I/F acceptance and preserve errors and exact request receipts.
    This protocol grants no authority and has no production implementation here.
    Expected outputs never enter the candidate-facing request.
    """
    def evaluate(self, request: CaseRequest) -> CaseResult: ...


class SyntheticAdapter:
    """Lookup of explicitly supplied results, never evaluates request.code."""
    def __init__(self, results: dict[str, CaseResult]):
        self.results = dict(results)

    def evaluate(self, request: CaseRequest) -> CaseResult:
        return self.results.get(request.request_sha256,
                                CaseResult(request.request_sha256, 'pending'))


def requests(run: PilotRun, tasks: dict) -> tuple[CaseRequest, ...]:
    result = []
    for sample in run.samples:
        if not eligible(sample, strict=True):
            continue
        task = tasks[sample['task_id']]
        tests = {x['test_id']: x for x in task['tests']}
        for role in ('weak4', 'audit'):
            for tid in task['folds'][role]:
                result.append(CaseRequest(object_sha(run.binding), run.stratum_id, task['task_id'],
                    sample['candidate_id'], sample['seed'], object_sha(sample), sha(sample['code'].encode()),
                    object_sha(task), role, tid, sample['code'], tests[tid]['input'],
                    task['test_type'], task.get('entry_point')))
    return tuple(result)


def synthetic_labels(run: PilotRun, tasks_raw: bytes, adapter: SyntheticAdapter) -> dict:
    require(run.evidence == 'synthetic' and type(adapter) is SyntheticAdapter,
            'Only synthetic runs and the lookup adapter may be dispatched')
    tasks = validate_tasks(run, tasks_raw)
    return {'schema': 'lcb-isolated-labels-v1', 'evidence': 'synthetic', 'binding': run.binding,
            'backend_identity': {'kind': 'synthetic_lookup'},
            'folds': {t: tasks[t]['folds'] for t in run.task_ids},
            'cases': [asdict(adapter.evaluate(r)) for r in requests(run, tasks)]}


def reduce_labels(run: PilotRun, tasks: dict | None, bundle: dict | None):
    """Every executable candidate starts pending; no bool default for missing data."""
    outcomes = {(s['task_id'], s['candidate_id']): {
        f: {'state': 'pending', 'pass': None} if eligible(s, strict=True)
        else {'state': 'structural_unavailable', 'pass': False} for f in FOLDS} for s in run.samples}
    if bundle is None:
        return outcomes, {}, 0
    require(tasks is not None, 'Original private tasks required with labels')
    require(bundle.get('schema') == 'lcb-isolated-labels-v1' and bundle.get('binding') == run.binding,
            'Label replay binding mismatch')
    require(bundle.get('evidence') == ('synthetic' if run.evidence == 'synthetic'
            else 'isolated_backend_records'), 'Synthetic labels cannot label measured candidates')
    identity = bundle.get('backend_identity', {})
    if run.evidence == 'measured':
        for key in ('adapter_sha256', 'execution_receipt_sha256'):
            require(isinstance(identity.get(key), str) and len(identity[key]) == 64
                    and all(c in '0123456789abcdef' for c in identity[key]), 'Missing backend provenance')
    require(bundle.get('folds') == {t: tasks[t]['folds'] for t in run.task_ids},
            'Label fold declarations differ; weak cannot substitute for audit')
    reqs = {r.request_sha256: r for r in requests(run, tasks)}
    labels = {}
    for row in bundle['cases']:
        require(set(row) == {'request_sha256', 'status', 'stdout', 'error'}, 'Case result fields')
        rid = row['request_sha256']
        require(rid in reqs and rid not in labels, 'Duplicate, leaked or replay-mismatched case result')
        status = row['status']
        require(status in ('ok', 'runtime_error', 'time_limit', 'infrastructure_error', 'pending'),
                'Unknown result status')
        require(row['error'] is None or isinstance(row['error'], str), 'Invalid error detail')
        require((status == 'ok' and isinstance(row['stdout'], str)) or
                (status != 'ok' and row['stdout'] is None), 'Result stdout/status mismatch')
        require(status not in ('runtime_error', 'time_limit', 'infrastructure_error') or bool(row['error']),
                'Failure provenance required')
        req = reqs[rid]
        test = next(t for t in tasks[req.task_id]['tests'] if t['test_id'] == req.test_id)
        passed = (project_compare(row['stdout'], test['output'], tasks[req.task_id]['comparison'])
                  if status == 'ok' else False if status in ('runtime_error', 'time_limit') else None)
        labels[rid] = {'state': 'error' if status == 'infrastructure_error' else
                       'pending' if status == 'pending' else 'judged', 'pass': passed}
    case_map = {(r.task_id, r.candidate_id, r.role, r.test_id):
                labels.get(rid, {'state': 'pending', 'pass': None}) for rid, r in reqs.items()}
    for sample in run.samples:
        t, j = sample['task_id'], sample['candidate_id']
        if not eligible(sample, strict=True):
            continue
        for fold in FOLDS:
            role = 'audit' if fold == 'audit' else 'weak4'
            cases = [case_map[t, j, role, i] for i in tasks[t]['folds'][fold]]
            state = ('error' if any(c['state'] == 'error' for c in cases) else
                     'pending' if any(c['pass'] is None for c in cases) else 'judged')
            outcomes[t, j][fold] = {'state': state,
                                   'pass': all(c['pass'] for c in cases) if state == 'judged' else None}
    return outcomes, case_map, sum(v['state'] == 'error' for v in labels.values())


def replay_report(run, outcomes, fold):
    counts = Counter({k: 0 for k in ('TP', 'FP', 'FN', 'TN')})
    executable = Counter(counts)
    eligible_keys = {(s['task_id'], s['candidate_id']) for s in run.samples if eligible(s, strict=True)}
    complete = 0
    selections = []
    for t in run.task_ids:
        candidates = [outcomes[t, j] for j in range(8)]
        for j, c in enumerate(candidates):
            w, a = c[fold]['pass'], c['audit']['pass']
            if w is not None and a is not None:
                key = 'TP' if w and a else 'FP' if w else 'FN' if a else 'TN'
                counts[key] += 1
                if (t, j) in eligible_keys:
                    executable[key] += 1
                complete += 1
        # Missing later labels do not alter an already known first accept.
        selected, resolved = None, True
        for j, c in enumerate(candidates):
            if c[fold]['pass'] is None:
                resolved = False
                break
            if c[fold]['pass']:
                selected = j
                break
        selections.append({'task_id': t, 'status': 'complete' if resolved else 'pending',
                           'selected_id': selected if resolved else None,
                           'refusal': selected is None if resolved else None})
    tp, fp, fn, tn = (counts[k] for k in ('TP', 'FP', 'FN', 'TN'))
    ratio = lambda n, d: n / d if d else None
    return {'scope': 'offline_counterfactual_not_actual_delivery', 'complete_pairs': complete,
            'confusion': dict(counts), 'confusion_includes_structural_negatives': True,
            'executable_only_confusion': dict(executable),
            'TPR': ratio(tp, tp + fn), 'FPR': ratio(fp, fp + tn),
            'precision': ratio(tp, tp + fp), 'selections': selections}


def online_report(run, outcomes, tasks, case_map):
    lookup = {(s['task_id'], s['candidate_id']): s for s in run.samples}
    counts = Counter({k: 0 for k in ('correct', 'wrong', 'refused', 'pending_quality', 'unobserved')})
    mismatches = []
    compared = evaluated = 0
    for ep in run.episodes:
        t = ep['task_id']
        if ep.get('selection_status') == 'deferred':
            counts['unobserved'] += 1
            continue
        require(tasks is not None and run.weak_size in (2, 4), 'Online declarations required')
        selected, cursor = None, 0
        checks = ep['online_checks']
        for j in range(8):
            require(cursor < len(checks), 'Incomplete online checks')
            check = checks[cursor]
            cursor += 1
            require(type(check['candidate_id']) is int and check['candidate_id'] == j,
                    'Online check order mismatch')
            if not eligible(lookup[t, j], strict=True):
                require(check['status'] == 'no_executable_final' and 'result' not in check,
                        'Online checked structurally unavailable candidate')
                continue
            require(check['status'] == 'evaluated', 'Missing actual online check')
            evaluated += 1
            result = check['result']
            cases = result['cases']
            declared = tasks[t]['folds']['weak' + str(run.weak_size)]
            require(0 < len(cases) <= len(declared)
                    and [c['test_id'] for c in cases] == declared[:len(cases)], 'Online fold leak/order mismatch')
            require(all(type(c.get('pass')) is bool for c in cases)
                    and type(result.get('pass')) is bool
                    and result['pass'] == all(c['pass'] for c in cases)
                    and all(c['pass'] for c in cases[:-1])
                    and (not cases[-1]['pass'] or len(cases) == run.weak_size),
                    'Online short-circuit/decision mismatch')
            offline = [case_map.get((t, j, 'weak4', c['test_id'])) for c in cases]
            fold_label = outcomes[t, j]['weak' + str(run.weak_size)]['pass']
            if fold_label is not None and all(c is not None and c['pass'] is not None for c in offline):
                compared += 1
                if result['pass'] != fold_label or any(c['pass'] != d['pass'] for c, d in zip(cases, offline)):
                    mismatches.append({'task_id': t, 'candidate_id': j, 'online_pass': result['pass'],
                                       'offline_pass': fold_label})
            if result['pass']:
                selected = j
                break
        require(cursor == len(checks) and type(ep.get('selected_id')) in (int, type(None))
                and ep['selected_id'] == selected and ep.get('refusal') is (selected is None),
                'Actual online selection mismatch')
        if selected is None:
            counts['refused'] += 1
        else:
            audit = outcomes[t, selected]['audit']['pass']
            counts['pending_quality' if audit is None else 'correct' if audit else 'wrong'] += 1
    complete = counts['unobserved'] == counts['pending_quality'] == 0
    comparison_status = ('unobserved' if counts['unobserved'] == 16 else
                         'pending_observations' if counts['unobserved'] else
                         'complete' if compared == evaluated else 'pending_labels')
    return {'scope': 'actual_online_delivery_offline_audit_quality', 'counts': dict(counts),
            'q_plus': counts['correct'] / 16 if complete else None,
            'q_minus': counts['wrong'] / 16 if complete else None,
            'denominator': 16, 'status': 'complete' if complete else 'pending',
            'offline_replay_comparison': {'evaluated_online_checks': evaluated,
                'compared_checks': compared, 'mismatched_checks': len(mismatches),
                'status': comparison_status,
                'mismatch_rate': len(mismatches) / compared if compared else None,
                'pause_review': None if counts['unobserved'] else
                                True if len(mismatches) * 100 > evaluated else
                                False if compared == evaluated else None,
                'threshold': 'strictly_greater_than_1_percent_of_evaluated_candidate_folds',
                'details': mismatches}}


def case_status_counts(run, tasks, bundle, case_map):
    """Diagnostic case counts only, after the unchanged label validation/reduction.

    Weak2 reuses its subset of weak4 records. Missing records count as pending;
    without a validated task inventory the case denominator is unknown.
    """
    if tasks is None:
        return None
    counts = {fold: dict.fromkeys(('passed', 'incorrect', 'runtime_error', 'time_limit',
                                  'pending', 'infrastructure_error'), 0) for fold in FOLDS}
    rows = {row['request_sha256']: row for row in bundle['cases']} if bundle is not None else {}
    for request in requests(run, tasks):
        key = (request.task_id, request.candidate_id, request.role, request.test_id)
        row = rows.get(request.request_sha256)
        status = row['status'] if row is not None else 'pending'
        if status == 'ok':
            status = 'passed' if case_map[key]['pass'] else 'incorrect'
        counts[request.role][status] += 1
        if request.role == 'weak4' and request.test_id in tasks[request.task_id]['folds']['weak2']:
            counts['weak2'][status] += 1
    return counts


def report(run: PilotRun, *, tasks_raw: bytes | None = None, labels_raw: bytes | None = None) -> dict:
    tasks = validate_tasks(run, tasks_raw) if tasks_raw is not None else None
    bundle = strict_json(labels_raw) if labels_raw is not None else None
    outcomes, cases, errors = reduce_labels(run, tasks, bundle)
    audits = [o['audit'] for o in outcomes.values()]
    known = sum(o['pass'] is not None for o in audits)
    passes = sum(o['pass'] is True for o in audits)
    complete = known == 128
    structural = Counter('length_truncated' if s['truncated'] else 'no_executable_final'
                         for s in run.samples if not eligible(s, strict=True))
    return {'schema': 'lcb-pilot-quality-report-v1', 'evidence': run.evidence,
        'binding': run.binding, 'labels_sha256': sha(labels_raw) if labels_raw is not None else None,
        'candidate_execution_authorized': False, 'main_matrix_authorized': False,
        'candidate_executions_performed': 0, 'inference_calls': 0,
        'quality_acceptance': 'not_granted_readonly_report', 'structural_unavailability': dict(structural),
        'generated_tokens_all_128': sum(s['output_tokens'] for s in run.samples),
        'infrastructure_error_cases': errors,
        'case_status_counts': case_status_counts(run, tasks, bundle, cases),
        'candidate_outcomes': [{'task_id': t, 'candidate_id': j, **outcomes[t, j]}
                               for t in run.task_ids for j in range(8)],
        'saturation': {'status': 'complete' if complete else 'pending_labels', 'denominator': 128,
            'audit_passes': passes, 'known_outcomes': known, 'pending_or_error': 128 - known,
            'S_s': passes / 128 if complete else None, 'strictly_greater_than_point9': passes >= 116 if complete else None,
            'minimum_passes': 116, 'audit_state_counts': dict(Counter(o['state'] for o in audits))},
        'online': online_report(run, outcomes, tasks, cases),
        'selectors': {f: replay_report(run, outcomes, f) for f in ('weak2', 'weak4')}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-tasks', type=Path)
    parser.add_argument('--labels', type=Path, help='Directory of <stratum_id>.json captured label bundles')
    args = parser.parse_args()
    require(args.labels is None or args.private_tasks is not None, 'Labels need original private tasks')
    runs = load_frozen_roster()
    private = read_bytes(args.private_tasks) if args.private_tasks is not None else None
    reports = []
    for run in runs:
        path = args.labels / (run.stratum_id + '.json') if args.labels is not None else None
        raw = read_bytes(path) if path is not None and path.exists() else None
        reports.append(report(run, tasks_raw=private, labels_raw=raw))
    print(json.dumps({'schema': 'lcb-pilot-quality-roster-report-v1', 'strata': reports,
        'execution_authorized': False, 'candidate_executions_performed': 0}, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
