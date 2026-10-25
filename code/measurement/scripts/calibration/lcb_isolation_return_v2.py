"""Offline I-v2 originals -> M input + conditional analysis; no live authority.

collect(root, *, expected_hashes=None) reads a finite roster only; without
expected_hashes its hashes are inventory facts, not independent verification.
assemble(root, base_raw, cpu_raw, collector_receipt) requires independent hashes.
Neither function writes files, calls Slurm, issues an Authority, or executes code.

collector_receipt schema: isolation-return-collector-v2, source_snapshot,
files_sha256, and base/cpu receipts. Each receipt contains argv, environment,
returncode, stderr, stdout_sha256, started_wall_ns, finished_wall_ns. The exact
argv is /usr/bin/sacct --clusters=cluster --duplicates --parsable2
--jobs=<bound allocation> --format=<BASE_FIELDS or CPU_FIELDS>. Five Python
collector journals are owner-role-<role>.jsonl (D,W1,O1,W2,O2); E data is in
W's journal. Their <role>.clock.json files and clock-qualification.json must
all qualify, or the analysis withholds costs. Endpoint/clock files may be
explicitly absent (hash None), never synthesized. Endpoints use epilog.encoded;
configs/<role>.json also uses epilog.encoded and must match <role>.launch.json
and Capture's endpoint_config_sha256. Other JSON uses release.encoded.
Wait PIDs identify srun launchers, not tasks.
allocation.json is validate_runtime_receipt's input; allocation-resources.json
is runtime.resource_group's output. allocation-clock.json has monotonic_ns,
wall_ns and protocol_clock_error_ns=1e9. Other fixed inputs are 7-joins.json,
dispatch-result.json, D.wait.json, five role-<role>.result.json files and seven
<role>.meter.json files. _names() gives the exact hash roster. collect() can
produce an inventory, but that does not authenticate its own observations.
The caller authenticates the expected hashes/source_snapshot independently.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat

import lcb_isolation_batch_v2 as batch
import lcb_isolation_release_v2 as release
import lcb_isolation_meter_v2 as meter
import lcb_isolation_meter_export_v2 as exporter
import lcb_task_epilog_v1 as epilog
import lcb_worker_metering_v2 as accounting

SCHEMA = 'isolation-return-v2'
RECEIPT_SCHEMA = 'isolation-return-collector-v2'
BASE_FIELDS = accounting.BASE_FIELDS
CPU_FIELDS = accounting.CPU_FIELDS
ENV = {'PATH':'/usr/bin:/bin', 'LC_ALL':'C', 'TZ':'UTC'}
MAX_FILE = 32*1024**2
MAX_TOTAL = 256*1024**2
COLLECTORS = tuple(role for role in batch.ROLE_IDS if meter.PRIMARY_COLLECTOR[role] == role)
DOCUMENTS = ('manifest.json', 'owner-approval.json', 'reviewed-release.json',
             'allocation.json', 'allocation-resources.json', 'allocation-clock.json',
             '7-joins.json', 'dispatch-result.json', 'D.wait.json', 'clock-qualification.json')
METER_KINDS = {'isolation_meter_origin_v2':'origins', 'isolation_meter_sample_v2':'samples',
               'isolation_meter_endpoint_v2':'endpoint'}
TERMINAL = {'COMPLETED','FAILED','CANCELLED','TIMEOUT','OUT_OF_MEMORY',
            'NODE_FAIL','BOOT_FAIL','PREEMPTED','DEADLINE','REVOKED'}

FAILURE_NAMES = ('D-failure.json', 'D-failure-closeout.json', 'batch.stop.json',
                 'bootstrap-outcome.json', 'bootstrap-receipt.json', 'submission.json',
                 'control-joins.json', 'allocation.stderr', 'allocation.stdout',
                 *(role+suffix for role in batch.ROLE_IDS
                   for suffix in ('.started.json', '.bound.json', '.proposal.json',
                                  '.request.json', '.wait.json', '.stderr', '.stdout')))

check = release.check


def _names():
    return (*DOCUMENTS, *(role+'.meter.json' for role in batch.ROLE_IDS),
            *('endpoints/'+role+'.json' for role in batch.ROLE_IDS),
            *('configs/'+role+'.json' for role in batch.ROLE_IDS),
            *(role+'.launch.json' for role in batch.ROLE_IDS),
            *(role+'.clock.json' for role in COLLECTORS),
            *('role-'+role+'.result.json' for role in COLLECTORS),
            *('owner-role-'+role+'.jsonl' for role in COLLECTORS))


def _may_be_missing(name):
    return name.startswith('endpoints/') or name.endswith('.clock.json') or name=='clock-qualification.json'


def _read(root_fd, name):
    parent = os.dup(root_fd)
    fd = None
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent); parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        check(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
              before.st_uid == os.getuid() and not before.st_mode & 0o022 and
              0 <= before.st_size <= MAX_FILE, 'Unsafe bounded original: '+name)
        chunks, size = [], 0
        while True:
            part = os.read(fd, min(65536, MAX_FILE+1-size))
            if not part:
                break
            chunks.append(part); size += len(part)
            check(size <= MAX_FILE, 'Original grew: '+name)
        check(size == before.st_size and release._identity(before) == release._identity(os.fstat(fd))
              == release._identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
              'Original changed: '+name)
        return b''.join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _journal(raw):
    lines = raw.splitlines(keepends=True)
    check(lines and len(lines) <= 8192, 'Finite nonempty role journal required')
    previous, mono = '0'*64, 0
    rows = []
    for i, line in enumerate(lines, 1):
        check(len(line) <= 262144, 'Journal row bound')
        row = release.strict(line)
        check(set(row) == {'seq','kind','monotonic_ns','wall_ns','previous_sha256','data'}
              and release.encoded(row) == line, 'Canonical journal schema required')
        check(type(row['seq']) is int and row['seq'] == i and row['previous_sha256'] == previous,
              'Journal sequence/hash chain differs')
        check(meter.natural(row['monotonic_ns']) and row['monotonic_ns'] >= mono
              and type(row['wall_ns']) is int and row['wall_ns'] > 0, 'Journal clock differs')
        previous, mono = release.sha(line), row['monotonic_ns']
        rows.append(row)
    return rows


def collect(root, *, expected_hashes=None):
    """Read fixed originals only; no keys, native binaries, or arbitrary filenames."""
    root = Path(root)
    check(root.is_absolute() and root.resolve(strict=True) == root, 'Canonical local originals root required')
    names = set(_names())
    if expected_hashes is not None:
        check(type(expected_hashes) is dict and set(expected_hashes) == names, 'Exact independent original hash roster required')
        for name, digest in expected_hashes.items():
            if digest is None:
                check(_may_be_missing(name), 'Only absent endpoint/clock may have hash None')
            else:
                release.digest(digest)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    raw_files, missing, total = {}, [], 0
    try:
        for name in _names():
            try:
                raw = _read(fd, name)
            except FileNotFoundError:
                check(_may_be_missing(name) and
                      (expected_hashes is None or expected_hashes[name] is None), 'Missing required original: '+name)
                missing.append(name)
                continue
            total += len(raw); check(total <= MAX_TOTAL, 'Originals total size bound')
            if expected_hashes is not None:
                check(release.sha(raw) == expected_hashes[name], 'Independent original hash differs: '+name)
            raw_files[name] = raw
    finally:
        os.close(fd)
    docs, journals = {}, {}
    for name, raw in raw_files.items():
        if name.endswith('.jsonl'):
            journals[name.removeprefix('owner-role-').removesuffix('.jsonl')] = _journal(raw)
        else:
            value = release.strict(raw)
            encoder = epilog.encoded if name.startswith(('endpoints/', 'configs/')) else release.encoded
            check(type(value) is dict and encoder(value) == raw, 'Canonical original required: '+name)
            docs[name] = value
    return {'documents':docs, 'journals':journals, 'raw':raw_files,
            'missing_endpoints':[n for n in missing if n.startswith('endpoints/')],
            'missing_clocks':[n for n in missing if not n.startswith('endpoints/')],
            'sha256':{name:release.sha(raw_files[name]) if name in raw_files else None for name in _names()}}


def _approval(docs, receipt):
    m = batch.validate_manifest(docs['manifest.json'])
    owner, review = docs['owner-approval.json'], docs['reviewed-release.json']
    source = receipt['source_snapshot']
    check(type(source) is dict, 'Independent source snapshot required')
    for key in ('registration_sha256','assets_sha256','endpoint_site_acceptance_sha256'):
        release.digest(source[key])
    check(re.fullmatch('[0-9a-f]{40}', source['head']) and
          re.fullmatch('[0-9a-f]{40}', source['source_sha']), 'Fixed source identities required')
    shared = {'schema','purpose','source_sha','registration_sha256','assets_sha256','manifest_sha256',
              'endpoint_site_acceptance_sha256','candidate_execution_authorized','main_matrix_authorized','scancel_authorized'}
    async_keys = ('submit_by_ns','start_by_ns','max_run_s','absolute_end_by_ns')
    check(set(review) == shared | {'decision', *async_keys} and review['schema']=='isolation-reviewed-release-v2'
          and review['purpose']==batch.PURPOSE and review['decision']=='approved', 'Exact reviewed I-v2 R required')
    owner_keys = {'schema','purpose','owner_approved','owner_uid','review_sha256','source_head',
                  'registration_sha256','assets_sha256','manifest_sha256','roles_sha256','nonce',
                  'endpoint_site_acceptance_sha256','submit_by_ns','start_by_ns','max_run_s','absolute_end_by_ns',
                  'candidate_execution_authorized','main_matrix_authorized','scancel_authorized'}
    check(set(owner)==owner_keys and owner['schema']=='isolation-owner-approval-v2'
          and owner['purpose']==batch.PURPOSE and owner['owner_approved'] is True,
          'Exact archived owner approval required')
    for doc in (owner, review):
        check(all(doc[k] is False for k in ('candidate_execution_authorized','main_matrix_authorized','scancel_authorized')),
              'Archive cannot grant candidate/main/cancel authority')
        check(doc['manifest_sha256']==release.object_sha(m) and
              all(doc[k]==source[k] for k in ('registration_sha256','assets_sha256','endpoint_site_acceptance_sha256')),
              'Archived approval source/assets/manifest differs')
    check(owner['owner_uid']==m['owner_uid'] and type(owner['owner_uid']) is int
          and owner['review_sha256']==release.object_sha(review) and owner['nonce']==m['nonce']
          and owner['roles_sha256']==release.object_sha(m['roles'])
          and owner['source_head']==m['source_head']==source['head']
          and review['source_sha']==source['source_sha']
          and m['assets_sha256']==source['assets_sha256']
          and m['endpoint_site_acceptance_sha256']==source['endpoint_site_acceptance_sha256']
          and all(type(owner[k]) is int and owner[k]==m[k] for k in
                  async_keys)
          and all(type(review[k]) is int and review[k]==m[k] for k in async_keys),
          'Archived owner identity/roles/window differs')
    return m


def collect_failure(root, base_raw, cpu_raw, collector_receipt):
    """Preserve a failed terminal run, never synthesize inputs to assemble().

    Unlike the success roster, diagnostic originals may be missing or contain
    incomplete JSON. Their bytes and absence are recorded, not interpreted as
    valid measurements. The three approval inputs, allocation and accounting
    identities are still required and checked. No keys or arbitrary paths.
    """
    root = Path(root)
    check(root.is_absolute() and root.resolve(strict=True) == root, 'Canonical local originals root required')
    names = tuple(dict.fromkeys((*_names(), *FAILURE_NAMES)))
    raw_files, missing, total = {}, [], 0
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for name in names:
            try:
                raw = _read(fd, name)
            except FileNotFoundError:
                missing.append(name)
                continue
            total += len(raw)
            check(total <= MAX_TOTAL, 'Originals total size bound')
            raw_files[name] = raw
    finally:
        os.close(fd)
    docs = {}
    for name in ('manifest.json', 'owner-approval.json', 'reviewed-release.json', 'allocation.json'):
        check(name in raw_files, 'Missing failure identity input: '+name)
        value = release.strict(raw_files[name])
        check(type(value) is dict and release.encoded(value) == raw_files[name],
              'Canonical failure identity input required: '+name)
        docs[name] = value
    receipt = deepcopy(collector_receipt)
    check(receipt.get('schema') == RECEIPT_SCHEMA, 'Independent collector receipt v2 required')
    manifest = _approval(docs, receipt)
    actual = batch.validate_runtime_receipt(manifest, docs['allocation.json'])
    job_id = actual['job_id']
    for label, raw, fields in (('base',base_raw,BASE_FIELDS), ('cpu',cpu_raw,CPU_FIELDS)):
        _command_receipt(receipt[label],raw,job_id,fields)
    base, cpu = accounting.table(base_raw,BASE_FIELDS), accounting.table(cpu_raw,CPU_FIELDS)
    check(job_id in base and set(base) == set(cpu), 'Failure accounting job/row coverage differs')
    allowed = {job_id, job_id+'.batch', job_id+'.extern', *(job_id+'.'+str(i) for i in range(7))}
    check(set(base) <= allowed, 'Foreign failure accounting step')
    for identifier, row in base.items():
        uid = str(manifest['owner_uid'])
        check(row['UID'] == uid if identifier == job_id else row['UID'] in ('',uid),
              'Failure accounting owner differs')
        check(row['Cluster'] == 'cluster' and row['NodeList'] == actual['node']
              and row['State'].split()[0] in TERMINAL and cpu[identifier]['State'] == row['State'],
              'Failure accounting node/terminal identity differs')
    check(any(row['State'] != 'COMPLETED' or row['ExitCode'] != '0:0' for row in base.values()),
          'Failure collection requires failed terminal accounting; success remains strict')
    _parent_tres(base[job_id]['AllocTRES'])
    start, end = _epoch(base[job_id]['Start']), _epoch(base[job_id]['End'])
    check(start <= end and abs(actual['actual_start_ns']-start) <= meter.NS,
          'Failure accounting/runtime start differs')
    for row in base.values():
        check(start-meter.NS <= _epoch(row['Start']) <= _epoch(row['End']) <= end+meter.NS,
              'Failure step lies outside parent lifetime')
    check(min(receipt[k]['started_wall_ns'] for k in ('base','cpu'))+meter.NS >= end,
          'Failure accounting collection precedes terminal time')
    hashes = {name:release.sha(raw_files[name]) if name in raw_files else None for name in names}
    summary = {'schema':'isolation-failure-originals-v2', 'status':'failed_unidentified_originals_only',
               'job_id':job_id, 'manifest_sha256':release.object_sha(manifest),
               'files_sha256':hashes, 'missing_originals':missing,
               'accounting_states':{key:value['State'] for key,value in base.items()},
               'analysis':None, 'meter_input':None, 'scientific_cost':False,
               'cost_sample_eligible':False, 'runtime_authority_issued':False,
               'candidate_execution_authorized':False, 'main_matrix_authorized':False}
    return {'raw':raw_files, 'summary':summary}


def _subjects(manifest, actual, bundle):
    check(set(bundle) in ({'joins','subjects'}, {'schema','joins','subjects','manifest_sha256'}) and type(bundle['subjects']) is dict
          and set(bundle['subjects'])==set(batch.ROLE_IDS), 'Exact seven joins/subjects bundle required')
    if 'schema' in bundle:
        check(bundle['schema']=='isolation-seven-joins-v2' and bundle['manifest_sha256']==release.object_sha(manifest),
              'Seven-role bundle manifest differs')
    joins = batch.validate_joins(manifest, bundle['joins'], runtime_receipt=actual)
    by_role = {j['role_id']:j for j in joins}
    subjects = {}
    for rid in batch.ROLE_IDS:
        subject = meter.binding(bundle['subjects'][rid]); join = by_role[rid]
        check(all(subject[k]==join[k] for k in meter.CONTEXT), 'Subject context differs from D join')
        domain = subject['domains']['user']
        check(all(domain['identity'][k] == join['user_cgroup'][k] for k in ('path','device','inode'))
              and '/sys/fs/cgroup'+join['cgroup_path'] == join['user_cgroup']['path']+'/task_0'
              and domain['cpu_ids']==join['cpu_ids'] and domain['memory_max_bytes']==join['memory_max_bytes'],
              'Subject kernel resources differ from D join')
        subjects[rid] = subject
    return by_role, subjects


def _command_receipt(value, raw, job_id, fields):
    check(type(value) is dict, 'Original sacct command receipt required')
    expected = ['/usr/bin/sacct','--clusters=cluster','--duplicates','--parsable2',
                '--jobs='+job_id, '--format='+fields]
    check(value['argv']==expected and value['environment']==ENV and value['returncode']==0
          and value['stderr']=='' and value['stdout_sha256']==release.sha(raw)
          and value.get('binary_sha256')==accounting.SACCT_SHA256 and value.get('wait_completed') is True
          and value.get('error') is None and value.get('cleanup_error') is None,
          'sacct command identity/result differs')
    start, end = value['started_wall_ns'], value['finished_wall_ns']
    check(type(start) is int and type(end) is int and 0 < start <= end, 'sacct collection time bracket')
    return {'started_wall_ns':start, 'finished_wall_ns':end}


def _epoch(value):
    check(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',value), 'Raw UTC second accounting time required')
    return int(datetime.strptime(value,'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp())*meter.NS


def _waits(dispatch, d_wait, d_journal):
    rows = dispatch.get('waits')
    if type(rows) is dict:
        check(set(rows)==set(batch.ROLE_IDS)-{'D'}, 'Six owned child waits required')
        check(all(row.get('role_id',rid)==rid for rid,row in rows.items()), 'Wait key/role differs')
        rows = [dict(row,role_id=rid) for rid,row in rows.items()]
    check(type(rows) is list and len(rows)==6, 'Six owned child waits required')
    check(d_wait.get('role_id')=='D', 'Bootstrap D wait required')
    starts = [r['data'] for r in d_journal if r['kind']=='owned_srun_started']
    waits = [r['data'] for r in d_journal if r['kind']=='owned_srun_wait']
    check(len(starts)==len(waits)==6, 'D journal must bind six owned launchers and waits')
    rows = [*rows, d_wait]
    result = {}
    for row in rows:
        rid = row.get('role_id')
        check(rid in batch.ROLE_IDS and rid not in result and type(row['pid']) is int and row['pid']>0
              and row.get('wait_completed') is True, 'Explicit completed launcher wait required')
        rc = row.get('returncode',row.get('rc'))
        wall = row['wait_ns']
        mono = row['wait_mono_ns']
        check(type(rc) is int and type(mono) is int and mono>=0
              and type(wall) is int and wall>0, 'Explicit completed wait result required')
        check('rc' not in row or 'returncode' not in row or row['rc']==rc, 'Conflicting wait return codes')
        if rid!='D':
            launched = [s for s in starts if s['role_id']==rid]
            ended = [s for s in waits if s['role_id']==rid]
            check(len(launched)==len(ended)==1 and launched[0]['pid']==row['pid'] and ended[0]==row,
                  'Child launcher/wait differs from D journal')
        result[rid] = {'pid':row['pid'],'returncode':rc,'wait_ns':mono,'wall_ns':wall}
    return result


def _endpoint_configs(collected, manifest, actual, subjects):
    docs, raw = collected['documents'], collected['raw']
    hashes = {}
    for rid in batch.ROLE_IDS:
        name = 'configs/'+rid+'.json'
        config = epilog.validate_config(docs[name])
        subject = subjects[rid]
        expected = {'schema':epilog.CONFIG_SCHEMA, 'role_id':rid, 'nonce':subject['nonce'],
                    'owner_uid':manifest['owner_uid'], 'job_id':actual['job_id'],
                    'node':actual['node'], 'boot_id':actual['boot_id'],
                    'record_path':manifest['attempt_root']+'/endpoints/'+rid+'.json'}
        check(config == expected and epilog.encoded(config) == raw[name], 'Endpoint config original differs')
        digest = release.sha(raw[name])
        launch = docs[rid+'.launch.json']
        plan = launch['plan']
        check(set(launch) == {'plan','config_sha256'} and launch['config_sha256'] == digest
              and plan['role_id'] == rid and plan['role_nonce'] == subject['nonce']
              and plan['job_id'] == actual['job_id'] and plan['execution_authorized'] is False
              and plan['run_end_ns'] == batch.run_end_ns(manifest, actual['actual_start_ns'])
              and plan['argv'].count('--jobid='+actual['job_id']) == 1
              and plan['argv'].count('--task-epilog='+manifest['attempt_root']+'/task-epilog') == 1,
              'Launch endpoint config/role binding differs')
        if rid != 'D':
            starts = [r['data'] for r in collected['journals']['D']
                      if r['kind'] == 'owned_srun_started' and r['data']['role_id'] == rid]
            check(len(starts) == 1 and starts[0]['plan'] == plan, 'Launch differs from D original journal')
        hashes[rid] = launch['config_sha256']
    return hashes


def _meter_records(collected, subjects, config_hashes):
    docs, journals = collected['documents'], collected['journals']
    evidence = Counter()
    for collector, rows in journals.items():
        for row in rows:
            if row['kind'] in METER_KINDS:
                evidence[(collector,row['kind'],release.object_sha(row['data']))] += 1
    records = {}
    for rid in batch.ROLE_IDS:
        value = deepcopy(docs[rid+'.meter.json'])
        collector = meter.PRIMARY_COLLECTOR[rid]
        check(value['role_binding']==subjects[rid] and value.get('collector_role',collector)==collector,
              'Meter subject/primary collector differs')
        check(value.get('endpoint_config_sha256') == config_hashes[rid], 'Capture endpoint config digest differs')
        for key, kind in (('origins','isolation_meter_origin_v2'),('samples','isolation_meter_sample_v2')):
            check(type(value[key]) is list, 'Meter record list required')
            for row in value[key]:
                check(row['provenance'] in ('primary','cross') and row.get('collector_role',collector)==collector,
                      'Explicit fixed collector/provenance required')
                subject = meter.binding(row['role_binding'])
                check(subject==subjects[subject['role_id']] and
                      (row['provenance']=='cross' or subject['role_id']==rid), 'Foreign primary/cross meter subject')
                stamp = (collector,kind,release.object_sha(row))
                check(evidence[stamp]>0, 'Meter row absent from actual collector journal')
                evidence[stamp] -= 1
        endpoint = value.get('endpoint')
        raw = docs.get('endpoints/'+rid+'.json')
        if raw is not None and isinstance(raw.get('config'),dict) and raw['config'].get('path') not in (None,''):
            config = docs['configs/'+rid+'.json']
            expected_path = config['record_path'].rsplit('/endpoints/',1)[0]+'/configs/'+rid+'.json'
            check(raw['config']['path'] == expected_path, 'Endpoint config path differs from generated config')
        if endpoint is not None:
            check(endpoint.get('original')==raw, 'Meter endpoint differs from separate original')
            stamp = (collector,'isolation_meter_endpoint_v2',release.object_sha(endpoint))
            check(evidence[stamp]>0, 'Meter endpoint absent from collector journal')
            evidence[stamp] -= 1
        value['endpoint'] = meter.adapt_task_epilog(raw, subjects[rid],
                              expected_config_sha256=config_hashes[rid])
        records[rid] = value
    check(not any(evidence.values()), 'Unexported/duplicated meter journal originals')
    return records


def _allocation_resources(value, actual, joins):
    expected_path = meter.CGROOT+'/job_'+actual['job_id']
    check(value['identity']['path']==expected_path and
          type(value['identity']['device']) is int and value['identity']['device']>=0 and
          type(value['identity']['inode']) is int and value['identity']['inode']>0,
          'Allocation resource identity differs')
    cpus = meter.parse_cpus(value['cpuset_raw'])
    check(cpus==value['cpu_ids']==sorted(j['cpu_ids'][0] for j in joins.values())
          and len(cpus)==7, 'Allocation/role CPU resources differ')
    check(value['memory_max_raw'].strip()==str(8*meter.GIB) and
          value['memory_max_bytes']==actual['memory_bytes']==8*meter.GIB,
          'Allocation memory resource differs')
    return cpus


def _parent_tres(raw):
    rows = {}
    for item in raw.split(','):
        parts = item.split('=')
        check(len(parts)==2 and parts[0] not in rows, 'Parent TRES fields differ')
        rows[parts[0]]=parts[1]
    check(set(rows) in ({'cpu','mem','node'},{'cpu','mem','node','billing'}) and
          rows['cpu']=='7' and rows['node']=='1', 'Parent CPU/node/GPU TRES differs')
    mem = re.fullmatch(r'([1-9][0-9]*)([KMG]?)',rows['mem'])
    check(mem is not None and int(mem[1])*{'':1,'K':1024,'M':1024**2,'G':1024**3}[mem[2]]==8*meter.GIB,
          'Parent memory TRES differs')


def assemble(root, base_raw, cpu_raw, collector_receipt):
    """Validate archived bindings; build M input without issuing live authority."""
    receipt = deepcopy(collector_receipt)
    check(type(receipt) is dict and receipt.get('schema')==RECEIPT_SCHEMA, 'Independent collector receipt v2 required')
    check(type(base_raw) is bytes and type(cpu_raw) is bytes, 'Original accounting bytes required')
    originals = collect(root, expected_hashes=receipt['files_sha256'])
    docs = originals['documents']
    manifest = _approval(docs, receipt)
    actual = batch.validate_runtime_receipt(manifest, docs['allocation.json'])
    joins, subjects = _subjects(manifest, actual, docs['7-joins.json'])
    cpu_ids = _allocation_resources(docs['allocation-resources.json'],actual,joins)
    job_id = actual['job_id']
    base_bracket = _command_receipt(receipt['base'],base_raw,job_id,BASE_FIELDS)
    cpu_bracket = _command_receipt(receipt['cpu'],cpu_raw,job_id,CPU_FIELDS)
    base, cpu = accounting.table(base_raw,BASE_FIELDS), accounting.table(cpu_raw,CPU_FIELDS)
    expected = {job_id,job_id+'.batch',job_id+'.extern',*(job_id+'.'+j['step_id'] for j in joins.values())}
    check(set(base)==set(cpu)==expected, 'Exact allocation/role/accounting roster required')
    for identifier, row in base.items():
        uid = str(manifest['owner_uid'])
        uid_matches = row['UID']==uid if identifier==job_id else row['UID'] in ('',uid)
        check(row['Cluster']=='cluster' and uid_matches and row['NodeList']==actual['node']
              and row['State'].split()[0] in TERMINAL and cpu[identifier]['State']==row['State'],
              'Accounting owner/node/terminal identity differs')
    _parent_tres(base[job_id]['AllocTRES'])
    start, end = _epoch(base[job_id]['Start']), _epoch(base[job_id]['End'])
    check(start<=end and abs(actual['actual_start_ns']-start)<=meter.NS, 'Accounting/runtime start differs')
    for identifier, row in base.items():
        if identifier != job_id:
            step_start, step_end = _epoch(row['Start']), _epoch(row['End'])
            check(identifier.startswith(job_id+'.') and start-meter.NS<=step_start<=step_end<=end+meter.NS,
                  'Step accounting lies outside parent identity/lifetime')
    check(_epoch(base[job_id]['Submit'])<=manifest['submit_by_ns'] and
          end<=batch.run_end_ns(manifest,actual['actual_start_ns'])+meter.NS,
          'Accounting outside original queue/run window')
    check(min(base_bracket['started_wall_ns'],cpu_bracket['started_wall_ns'])+meter.NS>=end,
          'Accounting collection precedes terminal time')
    waits = _waits(docs['dispatch-result.json'],docs['D.wait.json'],originals['journals']['D'])
    config_hashes = _endpoint_configs(originals, manifest, actual, subjects)
    records = _meter_records(originals, subjects, config_hashes)
    anchor = docs['allocation-clock.json']
    check(set(anchor)=={'monotonic_ns','wall_ns','protocol_clock_error_ns'} and
          meter.natural(anchor['monotonic_ns']) and type(anchor['wall_ns']) is int and anchor['wall_ns']>0
          and anchor['protocol_clock_error_ns']==meter.NS, 'Fixed allocation clock anchor required')
    offset = anchor['wall_ns']-anchor['monotonic_ns']
    for rows in originals['journals'].values():
        for row in rows:
            check(abs((row['wall_ns']-row['monotonic_ns'])-offset)<=meter.NS, 'Journal clock domains disagree')
    lower, upper = start-meter.NS, end+meter.NS
    check(lower-offset>=0 and upper>lower, 'Accounting clock envelope invalid')
    allocation = {'job_id':job_id,'node':actual['node'],'boot_id':actual['boot_id'],'uid':manifest['owner_uid'],
                  'cpu_ids':cpu_ids,'memory_bytes':actual['memory_bytes'],
                  'started_ns':lower-offset,'finished_ns':upper-offset,
                  'started_wall_ns':lower,'finished_wall_ns':upper,
                  'clock_qualification':None,
                  'accounting_start_utc':base[job_id]['Start'],'accounting_end_utc':base[job_id]['End'],
                  'clock_bound_ns':meter.NS,'time_scope':'UTC-second accounting envelope, not exact allocation duration'}
    allocation['accounting_evidence'] = {
        'schema':exporter.ACCOUNTING_SCHEMA,
        'context':{k:allocation[k] for k in ('job_id','node','boot_id','uid')},
        'base_raw':base_raw.decode('utf-8'), 'cpu_raw':cpu_raw.decode('utf-8'),
        'base_sha256':release.sha(base_raw), 'cpu_sha256':release.sha(cpu_raw),
        'base_receipt':deepcopy(receipt['base']), 'cpu_receipt':deepcopy(receipt['cpu']),
        'base_receipt_sha256':release.object_sha(receipt['base']),
        'cpu_receipt_sha256':release.object_sha(receipt['cpu'])}
    clocks = {role:docs.get(role+'.clock.json') for role in COLLECTORS}
    if clocks['D'] is not None and docs.get('clock-qualification.json') is not None:
        check(originals['raw']['D.clock.json']==originals['raw']['clock-qualification.json'],
              'D and allocation clock qualification originals differ')
    qualified = not originals['missing_clocks']
    for role in COLLECTORS:
        rows = originals['journals'][role]
        results = [row['data'] for row in rows if row['kind']=='result']
        check(len(results)==1 and results[0]==docs['role-'+role+'.result.json'], 'Role result differs from journal')
        observations = [row['data'] for row in rows if row['kind']=='clock_qualification']
        if clocks[role] is not None:
            check(observations==[clocks[role]], 'Role clock original differs from journal')
        qualified &= exporter.clock_qualified({**allocation,'clock_qualification':clocks[role]})
    check(docs['role-D.result.json']==docs['dispatch-result.json'], 'Dispatcher result originals differ')
    if qualified:
        allocation['clock_qualification'] = clocks['D']
    allocation['role_clock_qualifications'] = clocks
    allocation['clock_inheritance'] = {'E1':'W1','E2':'W2'}
    dispatch = docs['dispatch-result.json']
    check(type(dispatch.get('pending')) is list, 'Explicit pending role list required')
    runtime_failed = dispatch.get('status')!='all_owned_steps_waited_pending_review' or bool(dispatch['pending'])
    for rid, record in records.items():
        wait = waits[rid]
        check(lower<=wait['wall_ns']<=upper and
              abs(wait['wall_ns']-wait['wait_ns']-offset)<=meter.NS, 'Wait outside accounting/clock envelope')
        for row in record['samples']:
            if row['provenance']=='primary':
                check(row['snapshot']['finished_ns']<=wait['wait_ns'], 'Meter sample follows subject wait')
        endpoint = docs.get('endpoints/'+rid+'.json')
        if endpoint is not None:
            check(endpoint['timing']['end_mono_ns']<=wait['wait_ns'], 'Endpoint follows completed subject wait')
        step = base[job_id+'.'+joins[rid]['step_id']]
        runtime_failed |= wait['returncode']!=0 or step['State']!='COMPLETED' or step['ExitCode']!='0:0'
    analysis = exporter.analyze_allocation(allocation,records,expected_config_sha256=config_hashes)
    return {'schema':SCHEMA,'status':'assembled_conditional_analysis_not_runtime_acceptance',
            'manifest_sha256':release.object_sha(manifest),'owner_sha256':release.object_sha(docs['owner-approval.json']),
            'review_sha256':release.object_sha(docs['reviewed-release.json']),
            'originals_sha256':originals['sha256'],'collector_receipt_sha256':release.object_sha(receipt),
            'runtime_outcome':'failed' if runtime_failed else 'completed',
            'meter_input':{'allocation':allocation,'role_records':records,
                           'expected_config_sha256':config_hashes},
            'analysis':analysis,'missing_endpoints':originals['missing_endpoints'],
            'missing_clocks':originals['missing_clocks'],
            'accounting_interval_scope':'1s-expanded UTC-second envelope; resource occupancy is a bound, not exact billing',
            'scientific_cost':False,'endpoint_acquisition_accepted':False,'runtime_authority_issued':False,
            'candidate_execution_authorized':False,'main_matrix_authorized':False}
