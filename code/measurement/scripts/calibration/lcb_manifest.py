"""Pure frozen-cohort metadata validation shared by collection and budgeting."""
from collections import Counter
import hashlib
import re

PILOT_COUNT=16
MIN_MAIN_COUNT=80
SELECTION_RULE='seed_sha256_all_remaining_v1'
CONFLICT_RULE='declared_comparator_keep_first_v1'
PREPARATION_SCHEMA='lcb-preparation-v2'


def ordered_ids(ids,seed):
    if type(seed) is not int:raise ValueError('Integer selection seed required')
    if any(not isinstance(x,str) or not x for x in ids) or len(set(ids))!=len(ids):
        raise ValueError('Unique nonempty task IDs required')
    return sorted(ids,key=lambda x:(hashlib.sha256(f'{seed}|selection|{x}'.encode()).hexdigest(),x))


def composition(roster):
    return {key+'_counts':dict(sorted(Counter(r[key] for r in roster).items())) for key in ('platform','difficulty')}


def validate_manifest(manifest,prompts=None):
    """No private tests read, no old-manifest promotion, no execution permission."""
    if not isinstance(manifest,dict):raise ValueError('Manifest object required')
    if manifest.get('schema')!=PREPARATION_SCHEMA or manifest.get('status')!='prepared_not_executed':
        raise ValueError('Complete v2 preparation manifest required; reprepare legacy data')
    if manifest.get('selection_rule')!=SELECTION_RULE or manifest.get('conflict_rule')!=CONFLICT_RULE:
        raise ValueError('Unreviewed selection/conflict policy')
    policy=manifest.get('sample_policy',{})
    if (type(policy.get('pilot_count')) is not int or policy['pilot_count']!=PILOT_COUNT
        or type(policy.get('minimum_main_count')) is not int or policy['minimum_main_count']!=MIN_MAIN_COUNT
        or policy.get('main_count_rule')!='all_remaining'):
        raise ValueError('Require pilot=16 and all remaining main>=80')
    if type(manifest.get('seed')) is not int or manifest['seed']!=20261006:
        raise ValueError('Frozen preparation seed mismatch')
    if (manifest.get('start_date'),manifest.get('end_date'))!=('2025-02-01','2025-04-30'):
        raise ValueError('Frozen contest-date window mismatch')
    for name in ('dataset_sha256','prompts_sha256','private_tests_sha256'):
        if not re.fullmatch('[0-9a-f]{64}',str(manifest.get(name,''))):raise ValueError('Missing source hash: '+name)
    lists=[]
    for key in ('pilot_task_ids','main_task_ids'):
        ids=manifest.get(key)
        if not isinstance(ids,list):raise ValueError('Explicit frozen task lists required')
        ordered_ids(ids,manifest['seed']);lists.append(ids)
    pilot,main=lists
    if len(pilot)!=PILOT_COUNT or len(main)<MIN_MAIN_COUNT or set(pilot)&set(main):
        raise ValueError('Pilot/main size or disjointness violated')
    for key,expected in (('pilot_count',len(pilot)),('main_count',len(main)),('eligible',len(pilot)+len(main))):
        if type(manifest.get(key)) is not int or manifest[key]!=expected:
            raise ValueError('Actual count differs from frozen lists: '+key)
    roster=manifest.get('eligible_tasks')
    if not isinstance(roster,list) or len(roster)!=manifest['eligible']:
        raise ValueError('Complete eligible task roster required')
    for row in roster:
        if not isinstance(row,dict) or set(row)!={'task_id','platform','difficulty'}:
            raise ValueError('Roster must contain only task_id/platform/difficulty')
        if any(not isinstance(row[k],str) or not row[k] for k in row):raise ValueError('Invalid roster category')
        if not row['task_id'].startswith(row['platform']+'/'):raise ValueError('Roster platform/ID mismatch')
    order=ordered_ids([r['task_id'] for r in roster],manifest['seed'])
    if pilot!=order[:PILOT_COUNT] or main!=order[PILOT_COUNT:]:
        raise ValueError('All eligible tasks must follow the frozen seed-only split')
    if manifest.get('eligible_composition')!=composition(roster):raise ValueError('Composition totals mismatch')
    for counts in manifest['eligible_composition'].values():
        if any(type(x) is not int for x in counts.values()):raise ValueError('Integer composition counts required')
    stats=manifest.get('input_record_statistics',{})
    excluded=manifest.get('excluded')
    if not isinstance(excluded,list):raise ValueError('Exclusion ledger required')
    excluded_ids=[]
    for item in excluded:
        if (not isinstance(item,dict) or not isinstance(item.get('task_id'),str) or not item['task_id']
            or not isinstance(item.get('reason'),str) or not item['reason']):
            raise ValueError('Invalid exclusion record')
        excluded_ids.append(item['task_id'])
    if len(set(excluded_ids))!=len(excluded_ids) or set(excluded_ids)&set(order):
        raise ValueError('Exclusion and eligibility coverage overlap or repeat')
    if type(stats.get('nonblank_records')) is not int or stats['nonblank_records']!=manifest['eligible']+len(excluded):
        raise ValueError('Input coverage differs from eligible plus excluded')
    if prompts is not None:
        if not isinstance(prompts,list):raise ValueError('Public prompt roster required')
        ids=[p.get('task_id') for p in prompts];ordered_ids(ids,manifest['seed'])
        if ids!=pilot+main:raise ValueError('Prompt coverage/order differs from full frozen cohort')
        indexed={r['task_id']:r for r in roster}
        for row in prompts:
            if any(row.get(k)!=indexed[row['task_id']][k] for k in ('platform','difficulty')):
                raise ValueError('Prompt metadata differs from eligible roster')
    return {'pilot_count':len(pilot),'main_count':len(main),'eligible':len(roster)}
