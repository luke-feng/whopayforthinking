"""Finite I manifests, single-cell GPU allocations, and exact live identity joins."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

import lcb_isolation_release_v1 as release

CASES = ('controls', 'cpu', 'reuse')
WORKERS = ('worker-01', 'worker-02')
CPU_WALL = {'worker': 1200, 'observer': 2700}
WAIT_FLOORS = {'bind_wait_s': 600, 'observer_wait_running_s': 1200,
               'ready_wait_s': 600, 'barrier_wait_s': 10, 'native_accept_wait_s': 10}
MAX_SLOTS = 94  # two W/O pairs plus at most the frozen 90 GPU cells
PANEL = 'data/calibration/model-panel-theory-aligned-v2.json'


def gpu_policy(hardware, partitions, qos, walltime_s):
    release.check(hardware in ('H100-primary', 'A100-80GB-conditional'), 'Frozen GPU hardware only')
    release.integer(walltime_s, 1, 48*3600)
    release.check(qos == ('normal' if walltime_s <= 24*3600 else 'medium'), 'Explicit normal/medium time envelope')
    allowed = ('standard', 'standard,lowprio') if hardware == 'H100-primary' and qos == 'normal' else ('standard',)
    release.check(partitions in allowed, 'H100 normal alone may use one multi-partition job; medium is standard only')
    return {'partitions': partitions, 'qos': qos, 'walltime_s': walltime_s, 'no_requeue': True,
            'gpu_count': 1, 'gpu_jobs_per_cell': 1}


def validate_manifest(value):
    release.check(set(value) == {'schema', 'purpose', 'batch_id', 'attempt_id', 'attempt_root', 'nonce',
                  'source_head', 'assets_sha256', 'owner_uid', 'not_before_ns', 'expires_ns', 'queue_poll_s',
                  *WAIT_FLOORS, 'cpu_node', 'cpu_model', 'slots',
                  'candidate_execution_authorized', 'main_matrix_authorized', 'automatic_retry_authorized'},
                  'Exact finite manifest schema keys')
    release.check(value.get('schema') == 'isolation-batch-manifest-v1'
                  and value.get('purpose') == 'trusted_isolation_fixed_v1', 'Trusted I manifest only')
    for name in ('batch_id', 'attempt_id'):
        release.token(value[name])
    release.check(type(value['attempt_root']) is str and Path(value['attempt_root']).is_absolute()
                  and str(Path(value['attempt_root'])) == value['attempt_root']
                  and '..' not in Path(value['attempt_root']).parts, 'Literal attempt root required')
    release.check(re.fullmatch('[0-9a-f]{64}', value['nonce']), '64-hex batch nonce')
    release.check(re.fullmatch('[0-9a-f]{40}', value['source_head']), 'Exact tool/source B head')
    release.digest(value['assets_sha256'])
    release.integer(value['owner_uid'], 1)
    release.token(value['cpu_node'])
    release.check(type(value['cpu_model']) is str and 0 < len(value['cpu_model']) <= 256
                  and '\n' not in value['cpu_model'], 'Owner exact CPU model required')
    release.integer(value['not_before_ns'], 1); release.integer(value['expires_ns'], 1)
    release.check(value['not_before_ns'] < value['expires_ns'], 'Finite approval must cover queue and run')
    release.integer(value['queue_poll_s'], 1, 60)
    window_s = (value['expires_ns']-value['not_before_ns'])//10**9
    for key, floor in WAIT_FLOORS.items():
        release.integer(value[key], floor, window_s)
    release.check(all(value[k] is False for k in ('candidate_execution_authorized',
                  'main_matrix_authorized', 'automatic_retry_authorized')), 'Manifest cannot grant candidate/main/retry authority')
    slots = value['slots']; release.check(4 <= len(slots) <= MAX_SLOTS, 'Finite exact slot roster')
    ids, roles, gpu_cells = set(), set(), set()
    frozen_cells = None
    nonces = set()
    for s in slots:
        release.token(s['slot_id']); release.check(s['slot_id'] not in ids, 'Duplicate slot')
        common = {'slot_id', 'role', 'worker_id', 'nonce', 'cluster', 'partitions', 'qos', 'walltime_s',
                  'cpus', 'memory_bytes', 'gpus', 'no_requeue', 'cell_id', 'chunk_id'}
        release.check(set(s) == common | ({'hardware', 'operation', 'expected_gpu_name'} if s['role'] == 'gpu' else {'cases'}),
                      'Exact slot schema keys')
        release.token(s['chunk_id']); release.check(type(s['cell_id']) is str and s['cell_id'], 'Cell/chunk binding')
        ids.add(s['slot_id'])
        release.check(s['no_requeue'] is True and s['cluster'] == 'cluster', 'No requeue; one frozen cluster')
        release.check(re.fullmatch('[0-9a-f]{64}', s['nonce']) and s['nonce'] not in nonces, 'Fresh per-slot nonce')
        nonces.add(s['nonce'])
        release.check(s['role'] in ('worker', 'observer', 'gpu'), 'Fixed role only')
        if s['role'] in CPU_WALL:
            release.check(s['worker_id'] in WORKERS and (s['worker_id'], s['role']) not in roles, 'Exact independent W/O')
            roles.add((s['worker_id'], s['role']))
            release.check(s['partitions'] == 'standard' and s['qos'] == 'normal'
                          and s['walltime_s'] == CPU_WALL[s['role']] and s['cpus'] == 1
                          and s['memory_bytes'] == 1073741824 and s['gpus'] == 0, 'Dedicated CPU worker resources')
            release.check(s['cases'] == list(CASES), 'Exactly three fixed trusted cases')
        else:
            if frozen_cells is None:
                from theory_panel import enumerate_cells
                frozen_cells = {c['cell_id']: c for c in enumerate_cells(release.strict(release.read(release.ROOT/PANEL)))}
            release.check(s['cell_id'] in frozen_cells and frozen_cells[s['cell_id']]['hardware'] == s['hardware'],
                          'GPU slot must retain an exact frozen cell/hardware axis')
            release.check(s['cell_id'] not in gpu_cells, 'One cell one GPU job; no racing duplicate')
            gpu_cells.add(s['cell_id'])
            gpu_policy(s['hardware'], s['partitions'], s['qos'], s['walltime_s'])
            release.check(s['gpus'] == 1 and s['cpus'] >= 1 and s['memory_bytes'] > 0, 'GPU host resources separate')
            release.check(s['operation'] == 'identity_only', 'I GPU template does not release inference or candidates')
        release.check(value['expires_ns']-value['not_before_ns'] >= s['walltime_s']*10**9,
                      'Batch window too short even before queueing')
    release.check(roles == {(w, role) for w in WORKERS for role in CPU_WALL}, 'Two workers and independent observers required')
    return deepcopy(value)


def labels(manifest, slot):
    return ('www27-i-' + slot['nonce'][:12],
            'www27-isolation:' + manifest['batch_id'] + ':' + slot['slot_id'] + ':' + slot['nonce'])


def slot_for(authority, slot_id):
    release.require(authority)
    matches = [s for s in authority.manifest['slots'] if s['slot_id'] == slot_id]
    release.check(len(matches) == 1, 'Exact declared slot')
    return matches[0]


def peer_slot(manifest, worker_id, role):
    matches = [s for s in manifest['slots'] if s.get('worker_id') == worker_id and s['role'] == role]
    release.check(len(matches) == 1, 'One exact peer slot')
    return matches[0]


def live_join(manifest, slot, actual, *, job_id, local_context=None):
    """Verify a scheduler/proc observation; not a JSON permission issuer."""
    release.number(job_id)
    name, comment = labels(manifest, slot)
    release.check(actual['job_id'] == job_id and actual['uid'] == manifest['owner_uid']
                  and actual['job_name'] == name and actual['comment'] == comment
                  and actual['state'] == 'RUNNING' and actual['requeue'] == 0 and actual['restarts'] == 0,
                  'Exact unrequeued live job/name/nonce/UID join')
    release.check(actual['partition'] in slot['partitions'].split(',') and actual['qos'] == slot['qos']
                  and actual['walltime_s'] == slot['walltime_s'] and actual['cpus'] == slot['cpus']
                  and actual['memory_bytes'] == slot['memory_bytes'] and actual['gpus'] == slot['gpus'],
                  'Actual job allocation differs from approved slot')
    release.token(actual['node']); release.check(type(actual['submit']) is str and actual['submit'], 'Submit identity required')
    if local_context is not None:
        release.check(local_context['node'] == actual['node'] and local_context['uid'] == actual['uid']
                      and ('/job_' + job_id + '/step_batch/') in local_context['cgroup'] + '/', 'Live local job/process domain join')
        release.check(re.fullmatch('[0-9a-f-]{36}', local_context['boot_id']), 'Local boot identity required')
    return {'schema': 'isolation-live-join-v1', 'batch_id': manifest['batch_id'], 'attempt_id': manifest['attempt_id'],
            'slot_id': slot['slot_id'], 'worker_id': slot.get('worker_id'), 'nonce': slot['nonce'],
            'job_id': job_id, 'submit': actual['submit'], 'uid': actual['uid'], 'node': actual['node'],
            'boot_id': None if local_context is None else local_context['boot_id'],
            'time_namespace': None if local_context is None else local_context['time_namespace'],
            'allocation': deepcopy(actual), 'manifest_sha256': release.object_sha(manifest)}


def join_pair(worker, observer):
    release.check(worker['job_id'] != observer['job_id'] and worker['slot_id'] != observer['slot_id']
                  and all(worker[k] == observer[k] for k in ('batch_id', 'attempt_id', 'worker_id', 'uid', 'node', 'boot_id', 'time_namespace', 'manifest_sha256')),
                  'External O must be a distinct job on the same bound node/boot')
    return {'worker': deepcopy(worker), 'observer': deepcopy(observer),
            'lease_sha256': release.object_sha({'worker': worker, 'observer': observer})}


def pre_native_barrier(pairs):
    release.check(len(pairs) == 2, 'Two complete W/O pairs before native lifetime starts')
    joins = [p[role] for p in pairs for role in ('worker', 'observer')]
    release.check(len({j['job_id'] for j in joins}) == 4
                  and len({(j['node'], j['boot_id'], j['time_namespace']) for j in joins}) == 1,
                  'Four independent jobs on one actual node/boot/time namespace required')
    cpus = [j['hard_resources']['logical_cpu_ids'] for j in joins]
    release.check(all(len(c) == 1 and type(c[0]) is int for c in cpus)
                  and len({c[0] for c in cpus}) == 4, 'Four independently enforced disjoint CPU sets required')
    return {'status': 'pre_native_bindings_consistent', 'jobs': [j['job_id'] for j in joins],
            'node': joins[0]['node'], 'boot_id': joins[0]['boot_id'], 'time_namespace': joins[0]['time_namespace'],
            'cpus': cpus, 'C_lifetime_started': False}


def observed_overlap(windows):
    release.check(len(windows) == 2 and len({(w['node'], w['boot_id'], w['time_namespace']) for w in windows}) == 1,
                  'Cross-node/boot/timeNS raw monotonic subtraction forbidden')
    for w in windows:
        release.integer(w['first_prepare_ns'], 1); release.integer(w['last_finish_ns'], 1)
        release.check(w['first_prepare_ns'] < w['last_finish_ns'], 'Nonempty measured service epoch')
    overlap = min(w['last_finish_ns'] for w in windows)-max(w['first_prepare_ns'] for w in windows)
    return {'status': 'observed_worker_service_overlap' if overlap > 0 else 'overlap_not_observed',
            'overlap_ns': max(0, overlap), 'scope': 'same_host_worker_service_epochs_including_case_setup_and_cleanup',
            'payload_CPU_parallelism_proved': False}


def parse_job(raw, job_id):
    """One exact scontrol --oneliner job row; no aliases or inferred empty state."""
    release.number(job_id)
    fields = {}
    lines = raw.strip().splitlines(); release.check(len(lines) == 1, 'One job row')
    for item in lines[0].split():
        if '=' not in item:
            continue
        k, v = item.split('=', 1); release.check(k not in fields, 'Duplicate job field'); fields[k] = v
    release.check(fields.get('JobId') == job_id and not any(k in fields for k in ('ArrayJobId', 'HetJobId')), 'No arrays/heterogeneous jobs')
    uid = re.fullmatch(r'[^()\s]+\(([1-9][0-9]*)\)', fields.get('UserId', ''))
    release.check(uid and fields.get('NumNodes') == '1' and fields.get('BatchHost') == fields.get('NodeList'), 'Single node/nonroot UID')
    tres = dict(part.split('=', 1) for part in fields['AllocTRES'].split(','))
    memory = re.fullmatch(r'([0-9]+)([KMGT]?)', tres['mem']); release.check(memory, 'Explicit allocated RAM')
    duration = re.fullmatch(r'(?:(\d+)-)?(\d+):(\d{2}):(\d{2})', fields['TimeLimit'])
    release.check(duration, 'Explicit time limit')
    seconds = ((int(duration[1] or 0)*24+int(duration[2]))*60+int(duration[3]))*60+int(duration[4])
    return {'job_id': job_id, 'uid': int(uid[1]), 'node': fields['NodeList'], 'submit': fields['SubmitTime'],
            'start_time': fields['StartTime'],
            'job_name': fields['JobName'], 'comment': fields['Comment'], 'state': fields['JobState'],
            'partition': fields['Partition'], 'qos': fields['QOS'], 'walltime_s': seconds,
            'requeue': int(fields['Requeue']), 'restarts': int(fields['Restarts']), 'cpus': int(tres['cpu']),
            'memory_bytes': int(memory[1])*{'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}[memory[2]],
            'gpus': int(tres.get('gres/gpu', '0'))}
