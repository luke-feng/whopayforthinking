"""Pure 63-bit generation seeds and collision appendix; never inference."""
import argparse
import hashlib
import json
from pathlib import Path

from lcb_manifest import validate_manifest

POLICY = 'sha256-prefix63-v1'
LEGACY = 'legacy-offset-v1'
BASE_SEED = 20261006
REPLICATES = (0, 1, 2)
MAX_CANDIDATES = 8


def candidate_seed(base_seed, replicate_id, task_id, candidate_id):
    if type(base_seed) is not int or not 0 <= base_seed < 2**63:
        raise ValueError('Nonnegative signed-63-bit base seed required')
    if type(replicate_id) is not int or replicate_id not in REPLICATES:
        raise ValueError('replicate_id must be 0, 1 or 2')
    if not isinstance(task_id, str) or not task_id or '|' in task_id:
        raise ValueError('Exact manifest task ID without separator required')
    if type(candidate_id) is not int or not 0 <= candidate_id < MAX_CANDIDATES:
        raise ValueError('candidate_id must be 0 through 7')
    digest = hashlib.sha256(f'www27|{base_seed}|{replicate_id}|{task_id}|{candidate_id}'.encode('utf-8')).digest()
    return int.from_bytes(digest[:8], 'big') >> 1


def build_appendix(manifest_raw, base_seed=BASE_SEED):
    manifest = json.loads(manifest_raw)
    validate_manifest(manifest)
    if base_seed != BASE_SEED or type(base_seed) is not int:
        raise ValueError('This design fixes base_seed=20261006')
    tasks = sorted(row['task_id'] for row in manifest['eligible_tasks'])
    records, seen = [], set()
    for replicate in REPLICATES:
        for task in tasks:
            seeds = [candidate_seed(base_seed, replicate, task, j) for j in range(MAX_CANDIDATES)]
            for seed in seeds:
                if seed in seen:
                    raise ValueError('Generation seed collision; refuse appendix')
                seen.add(seed)
            records.append({'replicate_id': replicate, 'task_id': task, 'candidate_seeds': seeds})
    return {'schema': 'lcb-generation-seeds-v1', 'policy': POLICY,
            'workload_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
            'base_seed': base_seed, 'replicate_ids': list(REPLICATES), 'candidate_ids': list(range(MAX_CANDIDATES)),
            'encoding': 'UTF-8 www27|decimal_base_seed|decimal_replicate_id|exact_task_id|decimal_candidate_id',
            'digest_rule': "int.from_bytes(sha256(message).digest()[:8], 'big') >> 1",
            'task_count': len(tasks), 'seed_count': len(seen), 'collision_count': 0,
            'records': records, 'scope': 'Generation seed appendix only; not an execution approval; workload bytes unchanged.'}


def verify_appendix(appendix, manifest_raw, base_seed=BASE_SEED):
    expected = build_appendix(manifest_raw, base_seed)
    # Re-derive the entire finite map, not just a reported collision counter.
    if type(appendix) is not dict or json.dumps(appendix, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError('Seed appendix differs from the full rederived map')
    return {(r['replicate_id'], r['task_id'], j): value
            for r in appendix['records'] for j, value in enumerate(r['candidate_seeds'])}


def validate_policy(cfg):
    policy = cfg.get('sampling_seed_policy')
    if policy == LEGACY:
        if cfg.get('subset') != 'pilot' or cfg.get('replicate_id') is not None:
            raise ValueError('Legacy offset seed permitted only for historical pilot/lifecycle acceptance')
    elif policy == POLICY:
        candidate_seed(cfg['seed'], cfg.get('replicate_id'), 'validation/task', 0)
        if not cfg.get('seed_appendix') or not cfg.get('seed_appendix_sha256'):
            raise ValueError('Reviewed seed appendix and digest required')
        if cfg['seed'] != BASE_SEED or cfg['k'] > MAX_CANDIDATES:
            raise ValueError('Hash-seed policy supports frozen base and k<=8')
    else:
        raise ValueError('Explicit reviewed sampling_seed_policy required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    raw = Path(args.manifest).read_bytes()
    appendix = build_appendix(raw)
    with Path(args.output).open('x') as stream:
        json.dump(appendix, stream, indent=2, ensure_ascii=False, allow_nan=False)
    print(json.dumps({k: appendix[k] for k in ('policy', 'task_count', 'seed_count', 'collision_count', 'workload_manifest_sha256')}))


if __name__ == '__main__':
    main()
