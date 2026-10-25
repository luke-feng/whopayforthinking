"""Pure single-allocation I-v2 manifest/resource/deadline policy.

No Slurm client, wait loop, process creation, or cancellation API lives here.
The owner submits once; submission_receipt() returns without waiting for RUNNING.
All timestamps ending in _ns are Unix wall-clock nanoseconds.
"""
from copy import deepcopy
from pathlib import PurePosixPath
import re

import lcb_isolation_release_v2 as release

NS = 10**9
GIB = 1024**3
SCHEMA = 'isolation-batch-manifest-v2'
PURPOSE = 'trusted_isolation_fixed_v2'
WORKERS = ('worker-01', 'worker-02')
CASES = ('controls', 'cpu', 'reuse')
ROLE_IDS = ('D', 'W1', 'O1', 'E1', 'W2', 'O2', 'E2')
ROLES = ROLE_IDS
roles = ROLE_IDS
NODE_POOL = tuple('site-cpu-' + f'{n:03d}' for n in
                  (*range(1, 11), *range(101, 131), *range(201, 210)))
node_pool = NODE_POOL
CPU_MODEL = 'AMD EPYC 9554 64-Core Processor'
CONSTRAINT = '9554'
MAX_RUN_S = 3600
BOOTSTRAP_RECEIPT_S = 120
ALLOCATION = {'nodes': 1, 'cpus': 7, 'memory_bytes': 8 * GIB,
              'partition': 'standard', 'qos': 'normal', 'gpus': 0, 'no_requeue': True}
FALSE_GATES = ('candidate_execution_authorized', 'main_matrix_authorized',
               'automatic_retry_authorized', 'scancel_authorized')
ROLE_KIND = {'D': 'dispatcher', 'W': 'worker', 'O': 'observer', 'E': 'execution'}
GPU_SCHEMA = 'isolation-batch-manifest-v3'
GPU_PURPOSE = 'candidate_cell_v3'
GPU_ROLE_IDS = (*ROLE_IDS, 'G')
PANEL = 'data/calibration/model-panel-theory-aligned-v2.json'
# Real bounds of the frozen C helper: payload 5 s CPU and 5 s wall, judge wait 7 s, namespace init 10 s.
CANDIDATE_LIMITS = {'cpu_s': 5, 'wall_s': 5, 'judge_wall_s': 7, 'init_wall_s': 10, 'address_space_bytes': 268435456,
                    'file_size_bytes': 4096, 'open_files': 64, 'private_nproc': 32,
                    'threads_allowed': False}


def is_gpu(value):
    return value.get('schema') == GPU_SCHEMA


def role_ids(value):
    return GPU_ROLE_IDS if is_gpu(value) else ROLE_IDS


def panel_cell(cell_id):
    from theory_panel import enumerate_cells
    cells = {c['cell_id']: c for c in enumerate_cells(release.strict(release.read(release.ROOT/PANEL)))}
    release.check(cell_id in cells, 'Cell outside frozen 90-cell panel')
    return cells[cell_id]


def cell_root(root, manifest, index=None):
    from pathlib import Path
    if index is None:return Path(root)
    release.check(is_gpu(manifest) and type(index) is int and 0<=index<len(manifest['cells']), 'Cell index outside finite list')
    return Path(root)/'cells'/f'{index:03d}'


def _gpu_manifest(value):
    from lcb_isolation_batch_v1 import gpu_policy
    common={'schema','purpose','batch_id','attempt_id','attempt_root','nonce','source_head','assets_sha256',
            'endpoint_site_acceptance_sha256','owner_uid','node_pool','constraint','cpu_model','submit_by_ns',
            'start_by_ns','max_run_s','absolute_end_by_ns','bootstrap_receipt_s','allocation','roles','private_nproc',*FALSE_GATES}
    release.check(set(value)==common|{'cells','cell_inputs','gpu','inference_assets_sha256','candidate_limits'},'Exact v3 manifest fields')
    limits=value['candidate_limits']
    release.check(type(limits) is dict and set(limits)==set(CANDIDATE_LIMITS) and
                  all(type(limits[k]) is type(v) and limits[k]==v for k,v in CANDIDATE_LIMITS.items()),
                  'Frozen candidate measurement limits differ')
    release.check(value['purpose']==GPU_PURPOSE,'GPU purpose differs')
    for k in ('batch_id','attempt_id'):release.token(value[k])
    attempt_path(value['attempt_root']);release.digest(value['nonce'])
    release.check(type(value['source_head']) is str and re.fullmatch('[0-9a-f]{40}',value['source_head']),'Source SHA')
    for k in ('assets_sha256','endpoint_site_acceptance_sha256','inference_assets_sha256'):release.digest(value[k])
    release.integer(value['owner_uid'],1)
    pool=value['node_pool'];release.check(type(pool) is list and 0<len(pool)<=128 and len(set(pool))==len(pool),'GPU node pool')
    for node in pool:release.token(node)
    release.check(type(value['cpu_model']) is str,'Recorded CPU model label')
    cells=value['cells']
    release.check(type(cells) is list and 0<len(cells)<=90 and len(set(cells))==len(cells), 'Finite unique cells required')
    hardware={panel_cell(c)['hardware'] for c in cells}
    release.check(len(hardware)==1,'Mixed hardware strata in one allocation')
    hardware=next(iter(hardware));gpu=value['gpu']
    release.check(type(gpu) is dict and set(gpu)=={'family','walltime_s','partitions','qos'},'GPU fields')
    release.check(gpu['family']==('Hopper' if hardware=='H100-primary' else 'A100')
                  and value['constraint']==('H100|H200' if hardware=='H100-primary' else 'A100'),'GPU family/constraint differs')
    gpu_policy(hardware,gpu['partitions'],gpu['qos'],gpu['walltime_s'])
    inputs=value['cell_inputs']
    release.check(type(inputs) is dict and set(inputs)==set(cells),'One input pair per cell')
    for pair in inputs.values():
        release.check(type(pair) is dict and set(pair)=={'generation_config','workload'},'Cell input fields')
        for row in pair.values():
            release.check(type(row) is dict and set(row)=={'path','sha256','bytes'} and
                          PurePosixPath(row['path']).is_absolute(),'Input file reference')
            release.digest(row['sha256']);release.integer(row['bytes'],1)
    release.check(value['max_run_s']==gpu['walltime_s'] and value['max_run_s']%60==0,'Whole-minute GPU walltime')
    for k in ('submit_by_ns','start_by_ns','absolute_end_by_ns'):release.integer(value[k],1)
    release.check(value['submit_by_ns']<value['start_by_ns'] and
                  value['absolute_end_by_ns']==value['start_by_ns']+value['max_run_s']*NS,'GPU time windows')
    release.check(value['bootstrap_receipt_s']==120 and value['private_nproc']==32,'Existing bootstrap/private limits')
    # Candidate execution and the main cohort are explicit choices of the manifest (a main-cohort cell is refused unless
    # main_matrix_authorized is true); automatic retry and cancellation can never be enabled.
    release.check(type(value['candidate_execution_authorized']) is bool and type(value['main_matrix_authorized']) is bool and
                  all(value[k] is False for k in ('automatic_retry_authorized','scancel_authorized')),'GPU gates')
    alloc=value['allocation']
    release.check(set(alloc)==set(ALLOCATION) and all(type(alloc[k]) is int for k in ('nodes','cpus','memory_bytes','gpus'))
                  and alloc['nodes']==1 and alloc['cpus']>=15 and
                  alloc['memory_bytes']>=96*GIB and
                  alloc['partition']==gpu['partitions'] and alloc['qos']==gpu['qos'] and
                  alloc['gpus']==1 and alloc['no_requeue'] is True,'GPU allocation')
    release.check([r.get('role_id') for r in value['roles']]==list(GPU_ROLE_IDS),'Eight GPU roles')
    nonces={value['nonce']}
    for row in value['roles']:
        release.check(set(row)=={'role_id','kind','worker_id','nonce','cpus','memory_bytes','cases'},'Role fields')
        rid=row['role_id'];release.digest(row['nonce'])
        release.check(row['nonce'] not in nonces,'Duplicate role nonce');nonces.add(row['nonce'])
        release.check(row['kind']==('inference' if rid=='G' else ROLE_KIND[rid[0]]) and
                      row['worker_id']==(None if rid in ('D','G') else WORKERS[int(rid[1])-1]),'Role mapping')
        release.check(type(row['cpus']) is int and type(row['memory_bytes']) is int and row['cpus']>=(8 if rid=='G' else 1)
                      and row['memory_bytes']>=GIB,'Role resources')  # lower bounds; actual cpusets are recorded, not matched
        release.check(row['cases']==([] if rid in ('D','G') else ['candidate']),'Candidate role purpose')
    return deepcopy(value)


def attempt_path(value):
    release.check(type(value) is str and value.startswith('/')
                  and str(PurePosixPath(value)) == value
                  and '..' not in PurePosixPath(value).parts
                  and len(value.encode()) <= 70 and value != '/'
                  and not any(c in value for c in ('\0', '\n', '\r', ':', ',')),
                  'Short canonical absolute attempt_root required')
    return value


def validate_manifest(value):
    if type(value) is dict and is_gpu(value):return _gpu_manifest(value)
    keys = {'schema', 'purpose', 'batch_id', 'attempt_id', 'attempt_root', 'nonce',
            'source_head', 'assets_sha256', 'endpoint_site_acceptance_sha256', 'owner_uid',
            'node_pool', 'constraint', 'cpu_model', 'submit_by_ns', 'start_by_ns',
            'max_run_s', 'absolute_end_by_ns', 'bootstrap_receipt_s', 'allocation',
            'roles', 'private_nproc', *FALSE_GATES}
    release.check(type(value) is dict and set(value) == keys, 'Exact I-v2 manifest keys required')
    release.check(value['schema'] == SCHEMA and value['purpose'] == PURPOSE, 'I-v2 manifest required')
    for key in ('batch_id', 'attempt_id'):
        release.token(value[key])
    attempt_path(value['attempt_root'])
    release.digest(value['nonce'])
    release.check(type(value['source_head']) is str
                  and re.fullmatch('[0-9a-f]{40}', value['source_head']), 'Fixed source B required')
    for key in ('assets_sha256', 'endpoint_site_acceptance_sha256'):
        release.digest(value[key])
    release.integer(value['owner_uid'], 1)
    release.check(value['node_pool'] == list(NODE_POOL) and value['constraint'] == CONSTRAINT
                  and value['cpu_model'] == CPU_MODEL, 'Exact 49-node 9554 pool/model required')
    for key in ('submit_by_ns', 'start_by_ns', 'absolute_end_by_ns'):
        release.integer(value[key], 1)
    release.integer(value['max_run_s'], 1, MAX_RUN_S)
    release.check(value['max_run_s'] % 60 == 0, 'I-v2 max_run_s must be whole Slurm minutes')
    release.check(value['submit_by_ns'] < value['start_by_ns']
                  and value['absolute_end_by_ns'] == value['start_by_ns'] + value['max_run_s'] * NS,
                  'Queue/start/run absolute bounds differ')
    release.check(type(value['bootstrap_receipt_s']) is int
                  and value['bootstrap_receipt_s'] == BOOTSTRAP_RECEIPT_S,
                  'Fixed 120s bootstrap receipt window required')
    release.check(type(value['private_nproc']) is int and value['private_nproc'] == 32,
                  'Private I/J/payload nproc32 required')
    release.check(type(value['allocation']) is dict and value['allocation'] == ALLOCATION
                  and all(type(value['allocation'][k]) is int for k in ('nodes', 'cpus', 'memory_bytes', 'gpus'))
                  and value['allocation']['no_requeue'] is True, 'Exact 7CPU/8GiB allocation required')
    release.check(all(value[k] is False for k in FALSE_GATES), 'No candidate/main/retry/cancel authority')
    table = value['roles']
    release.check(type(table) is list and len(table) == 7
                  and all(type(row) is dict for row in table)
                  and [row.get('role_id') for row in table] == list(ROLE_IDS), 'Exact ordered seven-role table required')
    nonces = {value['nonce']}
    for row in table:
        release.check(set(row) == {'role_id', 'kind', 'worker_id', 'nonce', 'cpus', 'memory_bytes', 'cases'},
                      'Exact role schema required')
        rid = row['role_id']
        release.check(row['kind'] == ROLE_KIND[rid[0]]
                      and row['worker_id'] == (None if rid == 'D' else WORKERS[int(rid[1]) - 1]),
                      'Role kind/worker mapping differs')
        release.digest(row['nonce'])
        release.check(row['nonce'] not in nonces, 'Fresh distinct batch/role nonces required')
        nonces.add(row['nonce'])
        release.check(type(row['cpus']) is int and row['cpus'] == 1
                      and type(row['memory_bytes']) is int and row['memory_bytes'] == GIB,
                      'Each role requires 1CPU/1GiB')
        release.check(row['cases'] == ([] if rid == 'D' else list(CASES)), 'Fixed three cases per worker')
    return deepcopy(value)


def role_for(manifest, role_id):
    value = validate_manifest(manifest)
    release.check(role_id in role_ids(manifest), 'Unknown I-v2/v3 role')
    return next(row for row in value['roles'] if row['role_id'] == role_id)


def run_end_ns(manifest, actual_start_ns):
    value = validate_manifest(manifest)
    release.integer(actual_start_ns, 1)
    if is_gpu(value):  # the job's own --time is the bound; start_by/absolute_end_by only limited the queue
        return actual_start_ns + value['max_run_s'] * NS
    release.check(actual_start_ns <= value['start_by_ns'], 'Allocation started after start_by_ns')
    return min(actual_start_ns + value['max_run_s'] * NS, value['absolute_end_by_ns'])


def bootstrap_deadline_ns(manifest, actual_start_ns):
    return min(run_end_ns(manifest, actual_start_ns), actual_start_ns + BOOTSTRAP_RECEIPT_S * NS)


def clip_deadline_ns(manifest, actual_start_ns, proposed_ns, *, previous_ns=None):
    release.integer(proposed_ns, 1)
    bound = min(run_end_ns(manifest, actual_start_ns), proposed_ns)
    if previous_ns is not None:
        release.integer(previous_ns, 1)
        bound = min(bound, previous_ns)
    return bound


def allocation_cpu_count(manifest, actual):
    """Keep requested role capacity separate from scheduler-rounded capacity."""
    requested=manifest['allocation']['cpus']
    release.check(type(actual) is int and (actual >= requested if is_gpu(manifest) else actual == requested),
                  'Allocation has fewer CPUs than the manifest needs ('+str(actual)+' < '+str(requested)+')')
    return actual


def validate_runtime_receipt(manifest, value):
    """Validate scheduler facts supplied by the independently checking owner/D."""
    m = validate_manifest(manifest)
    release.check(type(value) is dict and set(value) == {
        'schema', 'job_id', 'manifest_sha256', 'nonce', 'source_head', 'actual_start_ns',
        'node', 'boot_id', 'cpu_model', 'cpus', 'memory_bytes', 'gpus'}, 'Exact runtime allocation receipt required')
    release.check(value['schema'] == 'isolation-allocation-runtime-v2', 'Runtime receipt v2 required')
    release.number(value['job_id'])
    release.check(value['manifest_sha256'] == release.object_sha(m) and value['nonce'] == m['nonce']
                  and value['source_head'] == m['source_head'], 'Runtime receipt manifest/source binding differs')
    release.check(is_gpu(m) or (value['node'] in m['node_pool'] and value['cpu_model'] == CPU_MODEL),
                  'Actual node/model outside approved pool')  # GPU: node and model are recorded, not gated
    release.check(type(value['boot_id']) is str
                  and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']), 'Actual boot identity required')
    allocation_cpu_count(m,value['cpus'])
    release.check(all(type(value[k]) is int for k in ('memory_bytes', 'gpus'))
                  and (value['memory_bytes'], value['gpus']) ==
                  (m['allocation']['memory_bytes'],m['allocation']['gpus']),
                  'Actual allocation resources differ')
    run_end_ns(m, value['actual_start_ns'])
    return deepcopy(value)


def live_join(manifest, role_id, receipt, *, step_id, pid, pid_start_ticks, uid,
              node, boot_id, cgroup_path, cgroup_device, cgroup_inode, user_cgroup,
              cpu_ids, memory_max_bytes, role_nonce):
    """Bind actual proc task_0 and separately opened user-ancestor identities."""
    m = validate_manifest(manifest)
    actual = validate_runtime_receipt(m, receipt)
    role = role_for(m, role_id)
    release.number(step_id, zero=True)
    release.integer(pid, 1); release.integer(pid_start_ticks, 1); release.integer(uid, 1)
    release.integer(cgroup_device, 0); release.integer(cgroup_inode, 1)
    release.check(uid == m['owner_uid'] and role_nonce == role['nonce'], 'Role uid/nonce differs')
    release.check(node == actual['node'] and boot_id == actual['boot_id'], 'Observed role node/boot differs')
    expected = '/system.slice/slurmstepd.scope/job_' + actual['job_id'] + '/step_' + step_id + '/user'
    release.check(cgroup_path == expected + '/task_0', 'Actual numeric role/task_0 proc cgroup required')
    release.check(type(user_cgroup) is dict and set(user_cgroup) == {'path', 'device', 'inode'},
                  'Separately opened user-ancestor identity required')
    release.integer(user_cgroup['device'], 0); release.integer(user_cgroup['inode'], 1)
    release.check(user_cgroup['path'] == '/sys/fs/cgroup' + expected
                  and user_cgroup['device'] == cgroup_device and user_cgroup['inode'] != cgroup_inode,
                  'User ancestor path/filesystem/identity differs from task_0')
    release.check(type(cpu_ids) is list and len(cpu_ids) >= role['cpus']
                  and all(type(c) is int and c>=0 for c in cpu_ids)
                  and (memory_max_bytes is None or (type(memory_max_bytes) is int and memory_max_bytes >= role['memory_bytes'])),
                  'Role step got fewer CPUs or less memory than requested')  # SMT nodes round steps up to whole cores
    return {'schema': 'isolation-role-live-join-v2', 'role_id': role_id, 'kind': role['kind'],
            'worker_id': role['worker_id'], 'nonce': role_nonce, 'job_id': actual['job_id'],
            'step_id': step_id, 'pid': pid, 'pid_start_ticks': pid_start_ticks,
            'uid': uid, 'node': node, 'boot_id': boot_id,
            'cgroup_path': cgroup_path, 'cgroup_device': cgroup_device, 'cgroup_inode': cgroup_inode,
            'user_cgroup': deepcopy(user_cgroup),
            'cpu_ids': list(cpu_ids), 'memory_max_bytes': memory_max_bytes,
            'manifest_sha256': release.object_sha(m)}


def validate_joins(manifest, joins, *, runtime_receipt):
    """Require all seven distinct roles/steps/CPUs before releasing work."""
    m = validate_manifest(manifest)
    actual = validate_runtime_receipt(m, runtime_receipt)
    keys = {'schema', 'role_id', 'kind', 'worker_id', 'nonce', 'job_id', 'step_id',
            'pid', 'pid_start_ticks', 'uid', 'node', 'boot_id', 'cgroup_path', 'cgroup_device', 'cgroup_inode', 'user_cgroup',
            'cpu_ids', 'memory_max_bytes', 'manifest_sha256'}
    ids=role_ids(m)
    release.check(type(joins) is list and len(joins) == len(ids)
                  and all(type(j) is dict and set(j) == keys for j in joins)
                  and {j['role_id'] for j in joins} == set(ids), 'Complete live role set required')
    for j in joins:
        rebuilt = live_join(m, j['role_id'], actual, step_id=j['step_id'], pid=j['pid'],
                            pid_start_ticks=j['pid_start_ticks'], uid=j['uid'], node=j['node'], boot_id=j['boot_id'],
                            cgroup_path=j['cgroup_path'], cgroup_device=j['cgroup_device'],
                            cgroup_inode=j['cgroup_inode'], user_cgroup=j['user_cgroup'], cpu_ids=j['cpu_ids'],
                            memory_max_bytes=j['memory_max_bytes'], role_nonce=j['nonce'])
        release.check(j == rebuilt, 'Role join differs from independently bound allocation facts')
    release.check(len({(j['job_id'], j['node'], j['boot_id']) for j in joins}) == 1
                  and (is_gpu(m) or joins[0]['node'] in m['node_pool']), 'Roles must share one allocation/node/boot')
    count=len(ids)
    release.check(len({j['step_id'] for j in joins}) == count
                  and len({j['pid'] for j in joins}) == count
                  and len({(j['pid'], j['pid_start_ticks']) for j in joins}) == count
                  and len({(j['cgroup_device'], j['cgroup_inode']) for j in joins}) == count
                  and len({(j['user_cgroup']['device'], j['user_cgroup']['inode']) for j in joins}) == count
                  and len({cpu for j in joins for cpu in j['cpu_ids']})==sum(len(j['cpu_ids']) for j in joins), 'Role step/PID/cgroup/CPU overlap')
    all_groups = {(j['cgroup_device'], j['cgroup_inode']) for j in joins}
    all_groups.update((j['user_cgroup']['device'], j['user_cgroup']['inode']) for j in joins)
    release.check(len(all_groups) == 2*count, 'Task leaf and user-ancestor identities overlap')
    for join in joins:
        role = role_for(m, join['role_id'])
        release.check(join['schema'] == 'isolation-role-live-join-v2'
                      and join['manifest_sha256'] == release.object_sha(m)
                      and join['nonce'] == role['nonce'] and join['uid'] == m['owner_uid']
                      and join['kind'] == role['kind'] and join['worker_id'] == role['worker_id']
                      and (join['memory_max_bytes'] is None or join['memory_max_bytes'] >= role['memory_bytes'])
                      and len(join['cpu_ids']) >= role['cpus'],
                      'Live join binding differs')
    return deepcopy(joins)


def submission_receipt(authority, job_id, *, submitted_ns=None):
    """Return immediately; submitted_ns means ack time, never RPC begin time."""
    release.require(authority, phase='queue')
    release.number(job_id)
    now = release.time.time_ns()
    ack = now if submitted_ns is None else submitted_ns
    release.integer(ack, 1, now if getattr(authority,'snapshot',{}).get('lean') else min(now, authority.manifest['submit_by_ns']))
    return {'schema': 'isolation-submission-v2', 'status': 'submitted_once', 'job_id': job_id,
            'manifest_sha256': release.object_sha(authority.manifest), 'nonce': authority.manifest['nonce'],
            'owner_sha256': authority.owner_sha, 'review_sha256': authority.review_sha, 'submitted_ns': ack}
