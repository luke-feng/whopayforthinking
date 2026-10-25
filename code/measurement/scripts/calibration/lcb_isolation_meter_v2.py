"""I single-allocation metering. Read-only counters, explicit primary/cross.

The role binding comes from release_v2's live join. Numeric role endpoints
come only from the separately registered task-epilog recorder; this module
does not launch it or grant endpoint/site acceptance.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import re
import stat

import lcb_worker_metering_v1 as counters
import lcb_worker_metering_v2 as accounting

NS = 10**9
GIB = 1024**3
READ_MAX_NS = 5_000_000
ENDPOINT_MAX_NS = 1_000_000_000  # the recorder's bracket today (see lcb_task_epilog_v1.MAX_READ_NS)
ENDPOINT_BUDGETS = (20_000_000, ENDPOINT_MAX_NS)  # records written while the budget was 20 ms stay valid
CASE_MAX = 96
FIXED_MAX = 32
SAMPLE_MAX = FIXED_MAX + 3 * CASE_MAX
CGROOT = accounting.CGROOT
ROLES = {'D': 'dispatcher', 'W1': 'worker', 'O1': 'observer', 'E1': 'execution',
         'W2': 'worker', 'O2': 'observer', 'E2': 'execution'}
PRIMARY_COLLECTOR = {role: {'E1':'W1', 'E2':'W2'}.get(role, role) for role in ROLES}
CONTEXT = ('job_id', 'step_id', 'role_id', 'kind', 'nonce', 'node', 'boot_id', 'uid')
EPILOG_SCHEMA = 'task-epilog-endpoint-v1'
GATES = {'scientific_cost': False, 'candidate_execution_authorized': False,
         'main_matrix_authorized': False, 'cost_sample_eligible': False,
         'endpoint_acquisition_accepted': False}


def check(ok, why):
    if not ok:
        raise ValueError(why)


def natural(value):
    return type(value) is int and value >= 0


def cpus(value):
    check(type(value) is list and value and all(natural(n) for n in value)
          and value == sorted(set(value)), 'Actual sorted CPU set required')
    return value


def parse_cpus(raw):
    check(type(raw) is str and raw.strip(), 'Missing actual cpuset')
    values = []
    for part in raw.strip().split(','):
        check(re.fullmatch(r'[0-9]+(?:-[0-9]+)?', part), 'Malformed cpuset')
        ends = [int(n) for n in part.split('-')]
        low, high = ends[0], ends[-1]
        check(low <= high, 'Reversed cpuset range')
        values.extend(range(low, high + 1))
    check(len(values) == len(set(values)), 'Duplicate cpuset CPU')
    return cpus(sorted(values))


def binding(value):
    check(type(value) is dict and set(CONTEXT) <= set(value) and 'domains' in value,
          'Live role binding required')
    check(type(value['job_id']) is str and re.fullmatch('[1-9][0-9]*', value['job_id'])
          and type(value['step_id']) is str and re.fullmatch('0|[1-9][0-9]*', value['step_id']),
          'Numeric role step in one allocation required')
    kinds={**ROLES,'G':'inference'}
    check(value['role_id'] in kinds and value['kind'] == kinds[value['role_id']], 'Role/kind differs')
    check(type(value['nonce']) is str and re.fullmatch(r'[0-9a-f]{64}', value['nonce'])
          and type(value['uid']) is int and value['uid'] > 0
          and all(type(value[k]) is str and value[k] for k in ('node', 'boot_id')), 'Role context malformed')
    check(set(value['domains']) == {'user', 'slurm'}, 'Exact role user/slurm domains required')
    for leaf, domain in value['domains'].items():
        expected = CGROOT + '/job_' + value['job_id'] + '/step_' + value['step_id'] + '/' + leaf
        identity = domain['identity']
        check(identity['path'] == expected and natural(identity['device'])
              and natural(identity['inode']) and identity['inode'] > 0, 'Physical role domain differs')
        cpus(domain['cpu_ids'])
        check(domain['memory_max_bytes'] is None or natural(domain['memory_max_bytes']), 'Memory limit malformed')
        if leaf == 'user':
            check(len(domain['cpu_ids']) >= (8 if value['role_id']=='G' else 1)
                  and (domain['memory_max_bytes'] is None or domain['memory_max_bytes'] >= GIB),
                  'Role user has fewer CPUs or less memory than requested')  # actual sets are recorded
    return deepcopy(value)


def physical(identity):
    context = identity['context']
    return (context['node'], context['boot_id'], identity['path'], identity['device'], identity['inode'],
            identity['cpu_stat_device'], identity['cpu_stat_inode'])


def domain_key(role, leaf, identity):
    return (role['job_id'], role['step_id'], role['role_id'], role['nonce'], leaf, *physical(identity))


def check_identity(role, leaf, identity):
    expected = role['domains'][leaf]['identity']
    check(all(identity[k] == expected[k] for k in ('path', 'device', 'inode'))
          and identity['context']['node'] == role['node']
          and identity['context']['boot_id'] == role['boot_id'], 'Counter/role physical identity differs')


def snapshot(value):
    value = deepcopy(value)
    identity = value['identity']
    identity['context'] = counters.CollectorContext(**identity['context'])
    value['identity'] = counters.DomainIdentity(**identity)
    return counters.Snapshot(**value)


def _recorder_file(value, name):
    raw = value['raw']
    identity = value['identity']
    check(type(raw) is str and len(raw.encode('ascii')) <= 1024**2
          and hashlib.sha256(raw.encode('ascii')).hexdigest() == value['sha256'], 'Recorder raw hash differs')
    check(natural(identity['dev']) and natural(identity['ino']) and identity['ino'] > 0
          and stat.S_ISREG(identity['mode']), 'Recorder counter file identity invalid')
    if name == 'cgroup.procs':
        check(all(re.fullmatch('[1-9][0-9]*', item) for item in raw.split()), 'Malformed process list')
        parsed = sorted(int(item) for item in raw.split())
        check(len(parsed) == len(set(parsed)), 'Duplicate process ID')
        check(type(value['parsed']) is list and all(type(v) is int for v in value['parsed']),
              'Malformed parsed process list')
    else:
        parsed = counters._rows(raw)
        check(type(value['parsed']) is dict and all(type(v) is int for v in value['parsed'].values()),
              'Malformed parsed counters')
    check(parsed == value['parsed'], 'Recorder parsed/raw values differ')
    if name == 'cpu.stat':
        check({'usage_usec', 'user_usec', 'system_usec'} <= set(parsed), 'Incomplete CPU counters')
    if name == 'cgroup.events':
        check(parsed.get('populated') in (0, 1), 'Missing populated flag')
    return parsed


def _recorder_node(node):
    identity = node['identity']
    check(natural(identity['dev']) and natural(identity['ino']) and identity['ino'] > 0
          and stat.S_ISDIR(identity['mode']), 'Recorder directory identity invalid')
    return {name: _recorder_file(node[name], name) for name in ('cgroup.procs', 'cgroup.events', 'cpu.stat')}


def _recorder_tree(tree):
    nodes = tree['nodes']
    check(type(nodes) is dict and {'.', 'task_0'} <= set(nodes) <= {'.', 'task_0', 'task_special'},
          'Exact user/task_0 with optional task_special subtree required')
    for node in nodes.values():
        parsed = _recorder_node(node)
        check(parsed['cgroup.procs'] == [] and parsed['cgroup.events']['populated'] == 0,
              'Nonempty user subtree')
    return nodes


def _endpoint_counter(role, leaf, node, cpu, timing):
    directory, counter = node['identity'], cpu['identity']
    expected = role['domains'][leaf]['identity']
    check((directory['dev'], directory['ino']) == (expected['device'], expected['inode']),
          'Recorder physical domain differs')
    return {'physical_identity': [role['node'], role['boot_id'], expected['path'], directory['dev'],
                                  directory['ino'], counter['dev'], counter['ino']],
            'started_ns': timing['begin_mono_ns'], 'finished_ns': timing['end_mono_ns'],
            'usage_usec': _recorder_file(cpu, 'cpu.stat')['usage_usec']}


def adapt_task_epilog(record, role_binding, *, expected_config_sha256=None):
    """Adapt Beauvoir's task-epilog-endpoint-v1 original without executing it.

    Missing/nonempty/over-budget observations stay unidentified. Contradictory
    role identities are rejected, not converted into another role's endpoint.
    """
    role = binding(role_binding)
    out = {'schema': 'isolation-role-endpoint-v2', 'endpoint_type': 'task_epilog_recorder_v1',
           'role_binding': role, 'status': 'unidentified', 'reason': 'missing_recorder',
           'original': deepcopy(record), **GATES}
    if record is None:
        return out
    check(type(record) is dict, 'Recorder must be an original object')
    config = record.get('config')
    check('config' not in record or type(config) is dict, 'Recorder config must be an object')
    seen = config.get('sha256') if config is not None else None
    if expected_config_sha256 is not None:
        check(type(expected_config_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_config_sha256),
              'Expected endpoint config digest malformed')
        if seen not in (None, ''):
            check(seen == expected_config_sha256, 'Recorder config digest differs')
    context = record.get('context')
    if not isinstance(context, dict):
        out['reason'] = 'missing_context'
        return out
    missing = []
    for key in CONTEXT:
        if key not in context or context[key] is None or context[key] == '':
            if key != 'kind':
                missing.append(key)
        else:
            check(context[key] == role[key], 'Recorder context differs: ' + key)
    if missing:
        out['reason'] = 'missing_context:' + ','.join(missing)
        return out
    try:
        check(record['schema'] == EPILOG_SCHEMA and record['status'] == 'captured', 'Recorder unavailable')
        check(expected_config_sha256 is not None, 'Missing expected endpoint config digest')
        check(seen == expected_config_sha256, 'Missing recorder config digest')
        timing = record['timing']
        started, ended = timing['begin_mono_ns'], timing['end_mono_ns']
        check(natural(started) and natural(ended) and 0 <= ended - started <= ENDPOINT_MAX_NS,
              'Recorder exceeds its observation budget')
        check(timing['duration_ns'] == ended - started and timing['within_budget'] is True
              and timing['budget_ns'] in ENDPOINT_BUDGETS and ended - started <= timing['budget_ns'],
              'Recorder elapsed time differs')
        check(natural(timing['begin_wall_ns']) and timing['begin_wall_ns'] <= timing['end_wall_ns'],
              'Recorder wall bracket invalid')
        recorder = record['recorder']
        slurm_path = role['domains']['slurm']['identity']['path'].removeprefix('/sys/fs/cgroup')
        check(recorder['cgroup_path'] == slurm_path and recorder['proc_self_cgroup'] == '0::' + slurm_path + '\n'
              and recorder['uid'] == recorder['effective_uid'] == role['uid']
              and recorder['resuid'] == [role['uid']] * 3, 'Recorder not in role slurm domain/UID')
        user, slurm = record['user'], record['slurm']
        check(user['path'] == role['domains']['user']['identity']['path']
              and slurm['path'] == role['domains']['slurm']['identity']['path'], 'Recorder domain path differs')
        before = _recorder_tree(user['before'])
        after = _recorder_tree(user['after'])
        check(before == after, 'Endpoint subtree changed')
        check(before['.']['cpu.stat'] == user['cpu_snapshot'] == after['.']['cpu.stat'], 'User CPU snapshots differ')
        user_point = _endpoint_counter(role, 'user', before['.'], user['cpu_snapshot'], timing)
        check(record['endpoint_usage_usec'] == user_point['usage_usec'] and record['errors'] == [],
              'Endpoint value/errors differ from raw counters')
        first, last = (_recorder_node(slurm[k]) for k in ('before', 'after'))
        check(slurm['before']['identity'] == slurm['after']['identity'] and all(
              slurm['before'][name]['identity'] == slurm['after'][name]['identity']
              for name in ('cgroup.procs', 'cgroup.events', 'cpu.stat')), 'Management identities changed')
        check(first['cpu.stat']['usage_usec'] <= last['cpu.stat']['usage_usec'], 'Management CPU rollback')
        management = _endpoint_counter(role, 'slurm', slurm['after'], slurm['after']['cpu.stat'], timing)
        out.update(status='captured', reason=None, started_ns=started, finished_ns=ended,
                   user_snapshot=user_point, slurm_snapshot=management)
    except (KeyError, TypeError, ValueError) as exc:
        out['reason'] = str(exc)
    return out


def _require(authority, role_binding, *, primary_role=None):
    from lcb_isolation_release_v2 import require
    gpu = getattr(authority, 'manifest', {}).get('schema') == 'isolation-batch-manifest-v3'
    collector = (role_binding['role_id'] if gpu else PRIMARY_COLLECTOR[role_binding['role_id']]) if primary_role is None else primary_role
    check(collector in {*ROLES,'G'}, 'Unknown primary collector role')
    require(authority, phase='runtime', role=collector)
    try:
        actual, manifest = authority.runtime_receipt, authority.manifest
        check(all(role_binding[k] == actual[k] for k in ('job_id', 'node', 'boot_id')),
              'Meter subject differs from runtime allocation')
        check(role_binding['uid'] == manifest['owner_uid'] == authority.uid, 'Meter owner differs')
        rows = [row for row in manifest['roles'] if row['role_id'] == role_binding['role_id']]
        check(len(rows) == 1 and rows[0]['nonce'] == role_binding['nonce']
              and rows[0]['kind'] == role_binding['kind'], 'Meter role/nonce differs from manifest')
        _mem = role_binding['domains']['user']['memory_max_bytes']
        check(len(role_binding['domains']['user']['cpu_ids']) >= rows[0]['cpus']
              and (_mem is None or _mem >= rows[0]['memory_bytes']),
              'Meter role has fewer resources than the manifest asked for')
        collectors = [row for row in manifest['roles'] if row['role_id'] == collector]
        check(len(collectors) == 1 and collectors[0]['kind'] == ({**ROLES,'G':'inference'})[collector]
              and collectors[0]['cpus'] >= (8 if collector=='G' else 1)
              and collectors[0]['memory_bytes'] >= GIB
              and re.fullmatch('[0-9a-f]{64}', collectors[0]['nonce']),
              'Collector role/resources/nonce differ from manifest')
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise PermissionError('Runtime/manifest-bound metering subject required: ' + str(exc)) from exc
    return authority


def _resources(reader):
    raw, _ = counters._read_at(reader._fd, 'cpuset.cpus.effective')
    memory, _ = counters._read_at(reader._fd, 'memory.max')
    limit = None if memory.strip() == 'max' else int(memory.strip())
    return {'cpu_ids': parse_cpus(raw), 'memory_max_bytes': limit,
            'cpuset_raw': raw, 'memory_max_raw': memory}


class Capture:
    def __init__(self, authority, role_binding, journal, *, reader_factory=None,
                 resource_reader=None, endpoint_config_sha256=None, primary_role=None):
        self.authority, self.journal = authority, journal
        self.require = _require
        self.role_binding = binding(role_binding)
        self.collector_role = primary_role or PRIMARY_COLLECTOR.get(self.role_binding['role_id'],self.role_binding['role_id'])
        self.require(authority, self.role_binding,primary_role=self.collector_role)
        self.factory = reader_factory or counters.ReadOnlyCpuDomain
        self.resource_reader = resource_reader or _resources
        self.readers, self.counts, self.case_counts = {}, {}, {}
        self.origins, self.samples, self.endpoints = [], [], []
        self.subjects = set()
        self.subject_provenance = {}
        self.retired_cross = set()
        self.closed = False
        self.endpoint_config_sha256 = endpoint_config_sha256
        self.endpoint_attempted = False
        try:
            self._add(self.role_binding, 'primary')
        except BaseException:
            self.close()
            raise

    def _add(self, role, provenance):
        subject = (role['role_id'], role['step_id'])
        check(subject not in self.subjects and len(self.subjects) < 7, 'Duplicate metering subject')
        self.subjects.add(subject)
        self.subject_provenance[subject] = provenance
        for leaf in ('user', 'slurm'):
            key = (role['role_id'], role['step_id'], leaf)
            check(key not in self.readers, 'Duplicate metering subject')
            reader = None
            try:
                reader = self.factory(role['domains'][leaf]['identity']['path'])
                identity = asdict(reader.identity)
                check_identity(role, leaf, identity)
                resources = self.resource_reader(reader)
                check(all(resources[k] == role['domains'][leaf][k] for k in ('cpu_ids', 'memory_max_bytes')),
                      'Actual domain resources differ from live binding')
                row = {'schema': 'isolation-meter-origin-v2', 'role_binding': role, 'domain': leaf,
                       'provenance': provenance, 'collector_role':self.collector_role,
                       'identity': identity, 'resources': resources,
                       'key': list(domain_key(role, leaf, identity)), **GATES}
                self.journal.append('isolation_meter_origin_v2', deepcopy(row))
                self.origins.append(row)
                self.readers[key] = (reader, role, leaf, provenance)
                self.counts[key] = 0
            except (OSError, ValueError) as exc:
                if reader is not None:
                    reader.close()
                self.journal.append('isolation_meter_unidentified_v2',
                                    {'role_binding': role, 'domain': leaf, 'provenance': provenance, 'error': str(exc)})

    def add_cross(self, role_binding):
        self.require(self.authority, self.role_binding)
        check(not self.closed, 'Capture closed')
        role = binding(role_binding)
        check(all(role[k] == self.role_binding[k] for k in ('job_id', 'node', 'boot_id', 'uid')),
              'Cross subject outside allocation')
        check(role['role_id'] != self.role_binding['role_id'], 'Self read is already primary')
        self.require(self.authority, role, primary_role=self.collector_role)
        self._add(role, 'cross')

    def sample(self, event, *, case_id=None):
        self.require(self.authority, self.role_binding)
        check(not self.closed and type(event) is str and event, 'Capture closed or event missing')
        check(case_id in (None, 'controls', 'cpu', 'reuse'), 'Unknown case')
        result = []
        for key, (reader, role, leaf, provenance) in self.readers.items():
            limit_key = (key, case_id)
            check(self.counts[key] < SAMPLE_MAX and self.case_counts.get(limit_key, 0) <
                  (FIXED_MAX if case_id is None else CASE_MAX), 'Finite sample budget exhausted')
            snap, bracket = accounting.captured_snapshot(reader)
            check_identity(role, leaf, asdict(snap.identity))
            row = {'schema': 'isolation-meter-sample-v2', 'role_binding': role, 'domain': leaf,
                   'provenance': provenance, 'collector_role':self.collector_role,
                   'event': event, 'case_id': case_id,
                   'snapshot': asdict(snap), 'wall_bracket': bracket,
                   'clock_error_ns': accounting.PROTOCOL_CLOCK_ERROR_NS,
                   'within_read_budget': snap.finished_ns - snap.started_ns <= READ_MAX_NS, **GATES}
            self.journal.append('isolation_meter_sample_v2', deepcopy(row))
            self.samples.append(row)
            result.append(row)
            self.counts[key] += 1
            self.case_counts[limit_key] = self.case_counts.get(limit_key, 0) + 1
        return result

    def retire_cross(self, role_id):
        """Seal an already registered cross subject without signals or deletion."""
        self.require(self.authority, self.role_binding)
        check(not self.closed and role_id in ROLES, 'Capture closed or unknown cross role')
        matches = [subject for subject in self.subjects if subject[0] == role_id]
        check(len(matches) == 1 and self.subject_provenance[matches[0]] == 'cross',
              'Only a registered cross subject may be retired')
        subject = matches[0]
        check(subject not in self.retired_cross, 'Cross subject already retired')
        keys = [key for key, value in self.readers.items()
                if key[:2] == subject and value[3] == 'cross']
        for key in keys:
            self.readers.pop(key)[0].close()
        self.retired_cross.add(subject)
        self.journal.append('isolation_meter_cross_retired_v2', {
            'collector_role':self.collector_role, 'subject_role':role_id,
            'step_id':subject[1], 'closed_domains':[key[2] for key in keys],
            'originals_retained':True})

    def endpoint(self, record):
        self.require(self.authority, self.role_binding)
        check(not self.closed and not self.endpoint_attempted, 'Once-only primary endpoint')
        self.endpoint_attempted = True
        row = {'schema':'isolation-role-endpoint-v2','endpoint_type':'task_epilog_recorder_v1',
               'role_binding':deepcopy(self.role_binding),'status':'rejected',
               'reason':'endpoint_adaptation_incomplete','original':deepcopy(record),**GATES}
        self.endpoints.append(row)
        self.journal.append('isolation_meter_endpoint_attempt_v2', {
            'role_binding':deepcopy(self.role_binding), 'status':'rejected_until_adapted',
            'expected_config_sha256':self.endpoint_config_sha256, 'once_consumed':True})
        try:
            row = adapt_task_epilog(record, self.role_binding,
                                    expected_config_sha256=self.endpoint_config_sha256)
        except (ValueError, TypeError, KeyError) as exc:
            row['reason']=type(exc).__name__+': '+str(exc)
            self.journal.append('isolation_meter_endpoint_v2', deepcopy(row))
            raise
        self.endpoints[0]=row
        self.journal.append('isolation_meter_endpoint_v2', deepcopy(row))
        return row

    def export_record(self):
        return {'role_binding': deepcopy(self.role_binding), 'collector_role':self.collector_role,
                'origins': deepcopy(self.origins),
                'samples': deepcopy(self.samples), 'endpoint': deepcopy(self.endpoints[0]) if self.endpoints else None,
                'endpoint_config_sha256':self.endpoint_config_sha256}

    def close(self):
        for reader, _, _, _ in self.readers.values():
            reader.close()
        self.readers = {}
        self.closed = True


def adapt_legacy_cross(rows, role_binding):
    """v1 reads may corroborate only; same allocation never implies primary."""
    role = binding(role_binding)
    result = []
    for row in rows:
        check(row['job_id'] == role['job_id'] and row['step_id'] == role['step_id'], 'Legacy subject differs')
        leaf = {'workload': 'user', 'control_plane': 'slurm'}[row['kind']]
        check_identity(role, leaf, row['snapshot']['identity'])
        result.append({'schema': 'isolation-meter-sample-v2', 'role_binding': role, 'domain': leaf,
                       'provenance': 'cross', 'event': row['event'], 'case_id': row.get('case_id'),
                       'snapshot': deepcopy(row['snapshot']), 'wall_bracket': deepcopy(row.get('wall_bracket')),
                       'clock_error_ns': accounting.PROTOCOL_CLOCK_ERROR_NS,
                       'within_read_budget': row['snapshot']['finished_ns'] - row['snapshot']['started_ns'] <= READ_MAX_NS,
                       'endpoint_type': 'same_host_post_exit_read', **GATES})
    return result
