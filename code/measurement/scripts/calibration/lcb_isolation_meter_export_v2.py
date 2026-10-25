"""Conditional I-v2 CPU ledgers from supplied originals; no runtime execution.

The caller authenticates the source/journal/recorder originals. This pure
module checks their physical identities and accounting relationships, never
accepts the site endpoint mechanism or produces a scientific cost point.
"""
from copy import deepcopy
from dataclasses import asdict
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
from types import SimpleNamespace

import lcb_isolation_meter_v2 as capture
import lcb_worker_metering_v2 as display

check = capture.check
NS, GIB = capture.NS, capture.GIB
CASES = ('controls', 'cpu', 'reuse')
CLOCK_ERROR_NS = display.PROTOCOL_CLOCK_ERROR_NS
ACCOUNTING_SCHEMA = 'isolation-accounting-evidence-v2'
TERMINAL = {'COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT', 'OUT_OF_MEMORY',
            'NODE_FAIL', 'BOOT_FAIL', 'PREEMPTED', 'DEADLINE', 'REVOKED'}


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _display_interval(point, quantum):
    """Closed conservative interval; no direction of display rounding assumed."""
    return {'lower': max(0, point - quantum), 'upper': point + quantum}


def accounting_evidence(allocation, role_records):
    """Recheck original tables and fixed-client receipts; accept no parsed shortcut."""
    value = allocation.get('accounting_evidence')
    check(type(value) is dict and set(value) == {'schema', 'context', 'base_raw', 'cpu_raw',
          'base_sha256', 'cpu_sha256', 'base_receipt', 'cpu_receipt',
          'base_receipt_sha256', 'cpu_receipt_sha256'} and value['schema'] == ACCOUNTING_SCHEMA,
          'Original accounting evidence required')
    context = {k: allocation[k] for k in ('job_id', 'node', 'boot_id', 'uid')}
    check(value['context'] == context, 'Accounting allocation/node/boot/owner differs')
    parsed, brackets = {}, {}
    for kind, fields in (('base', display.BASE_FIELDS), ('cpu', display.CPU_FIELDS)):
        check(type(value[kind + '_raw']) is str, 'Raw accounting text required')
        raw = value[kind + '_raw'].encode('utf-8')
        digest = value[kind + '_sha256']
        receipt = value[kind + '_receipt']
        check(type(receipt) is dict, 'Original sacct receipt object required')
        check(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest)
              and _sha(raw) == digest and _sha(_encoded(receipt)) == value[kind + '_receipt_sha256'],
              'Accounting original/receipt hash differs')
        expected = ['/usr/bin/sacct', '--clusters=cluster', '--duplicates', '--parsable2',
                    '--jobs=' + allocation['job_id'], '--format=' + fields]
        check(receipt.get('argv') == expected and receipt.get('environment') == display.ENV
              and type(receipt.get('returncode')) is int and receipt['returncode'] == 0
              and receipt.get('stderr') == '' and receipt.get('stdout_sha256') == digest
              and receipt.get('binary_sha256') == display.SACCT_SHA256
              and receipt.get('wait_completed') is True and receipt.get('error') is None
              and receipt.get('cleanup_error') is None, 'Fixed sacct client/receipt binding differs')
        start, end = receipt.get('started_wall_ns'), receipt.get('finished_wall_ns')
        check(capture.natural(start) and start > 0 and capture.natural(end) and start <= end,
              'Accounting collection bracket differs')
        brackets[kind] = {'started_wall_ns': start, 'finished_wall_ns': end}
        parsed[kind] = display.table(raw, fields)
    job = allocation['job_id']
    expected = {job, job + '.batch', job + '.extern'} | {
        job + '.' + record['role_binding']['step_id'] for record in role_records.values()}
    check(set(parsed['base']) == expected and set(parsed['cpu']) <= expected,
          'Exact accounting JobIDRaw roster required')
    parent = parsed['base'][job]
    parent_start, parent_end = display.epoch_ns(parent['Start']), display.epoch_ns(parent['End'])
    check(parent_start <= parent_end, 'Parent accounting lifetime reversed')
    for field, stamp in (('started_wall_ns', parent_start), ('finished_wall_ns', parent_end)):
        if allocation.get(field) is not None:
            check(capture.natural(allocation[field]) and abs(allocation[field] - stamp) <= CLOCK_ERROR_NS,
                  'Allocation clock envelope differs from original parent accounting')
    tres = {}
    for item in parent['AllocTRES'].split(','):
        parts = item.split('=')
        check(len(parts) == 2 and parts[0] not in tres, 'Malformed parent allocation TRES')
        tres[parts[0]] = parts[1]
    memory = re.fullmatch(r'([1-9][0-9]*)([KMG]?)', tres.get('mem', ''))
    check(tres.get('cpu') == str(len(allocation['cpu_ids'])) and tres.get('node') == '1' and memory
          and int(memory[1]) * {'':1, 'K':1024, 'M':1024**2, 'G':1024**3}[memory[2]] == allocation['memory_bytes']
          and set(tres) <= {'cpu','node','mem','billing'}, 'Parent TRES differs from actual allocation')
    for identifier, row in parsed['base'].items():
        check(row['JobIDRaw'] == identifier and row['Cluster'] == 'cluster'
              and row['NodeList'] == allocation['node']
              and row['UID'] in ((str(allocation['uid']),) if identifier == job else ('', str(allocation['uid'])))
              and row['State'].split()[0] in TERMINAL, 'Accounting owner/node/terminal identity differs')
        start, end = display.epoch_ns(row['Start']), display.epoch_ns(row['End'])
        check(parent_start - NS <= start <= end <= parent_end + NS,
              'Step accounting outside parent identity/lifetime')
        other = parsed['cpu'].get(identifier)
        if other is not None:
            check(other['JobIDRaw'] == identifier and other['State'] == row['State'], 'CPU/base JobIDRaw/state differs')
    for bracket in brackets.values():
        check(bracket['started_wall_ns'] >= parent_end, 'Accounting collected before terminal End')
    return {**parsed, 'brackets': brackets, 'evidence': value, 'context': context}


def _terminal_upper(allocation, evidence, step_id):
    needed(clock_qualified(allocation), 'Clock qualification missing or failed')
    identifier = allocation['job_id'] + '.' + step_id
    row = evidence['base'][identifier]
    # End is second-truncated. Both the accounting-to-wall and wall-to-monotonic
    # comparisons retain their fixed clock error; never clip to a free timestamp.
    upper_wall = display.epoch_ns(row['End']) + NS + 2 * CLOCK_ERROR_NS
    upper_mono = allocation['started_ns'] + upper_wall - allocation['started_wall_ns']
    return upper_mono, {'JobIDRaw': identifier, 'node': allocation['node'], 'boot_id': allocation['boot_id'],
                        'End': row['End'], 'base_sha256': evidence['evidence']['base_sha256'],
                        'base_receipt_sha256': evidence['evidence']['base_receipt_sha256'],
                        'clock_error_ns': CLOCK_ERROR_NS, 'end_resolution_ns': NS}


def clock_qualified(allocation):
    """Reconstruct the inherited clock qualification; a true flag is insufficient."""
    record = allocation.get('clock_qualification')
    if not isinstance(record, dict) or record.get('qualified') is not True or \
            record.get('protocol_clock_error_ns') != CLOCK_ERROR_NS:
        return False
    if 'NTPSynchronized=yes' not in str(record.get('first_raw', '')).splitlines():
        return False
    match = re.search(r'^\s*Offset:\s*([+-]?[0-9.]+)\s*(us|µs|μs|ms|s)\s*$',
                      str(record.get('second_raw', '')), re.MULTILINE)
    if match is None:
        return False
    try:
        scale = {'us': 1000, 'µs': 1000, 'μs': 1000, 'ms': 10**6, 's': NS}[match[2]]
        offset_ok = abs(Decimal(match[1])) * scale <= 100_000_000
    except InvalidOperation:
        return False
    start, end = allocation.get('started_wall_ns'), allocation.get('finished_wall_ns')
    return (offset_ok and capture.natural(start) and capture.natural(end) and start <= end and
            abs((end - start) - (allocation['finished_ns'] - allocation['started_ns'])) <= 2 * CLOCK_ERROR_NS)


def _wall_bracket(started, finished, wall_started, wall_finished, allocation):
    needed(capture.natural(wall_started) and capture.natural(wall_finished)
           and wall_started <= wall_finished, 'Missing/invalid wall bracket')
    offset = allocation['started_wall_ns'] - allocation['started_ns']
    needed(abs(wall_started - started - offset) <= 2 * CLOCK_ERROR_NS
           and abs(wall_finished - finished - offset) <= 2 * CLOCK_ERROR_NS,
           'Wall/monotonic clock bracket differs')


class Unidentified(ValueError):
    pass


def needed(ok, why):
    if not ok:
        raise Unidentified(why)


def _allocation(value):
    check(type(value) is dict and all(k in value for k in
          ('job_id', 'node', 'boot_id', 'uid', 'cpu_ids', 'memory_bytes', 'started_ns', 'finished_ns')),
          'Allocation facts incomplete')
    capture.cpus(value['cpu_ids'])
    check(len(value['cpu_ids']) == 7 and value['memory_bytes'] == 8 * GIB,
          'Actual seven-CPU/eight-GiB allocation required')
    check(capture.natural(value['started_ns']) and capture.natural(value['finished_ns'])
          and value['started_ns'] < value['finished_ns'], 'Allocation time bounds invalid')
    return value


def _resources(role, leaf, origin):
    actual = origin['resources']
    check(capture.parse_cpus(actual['cpuset_raw']) == actual['cpu_ids'] == role['domains'][leaf]['cpu_ids'],
          'Raw actual cpuset differs')
    raw = actual['memory_max_raw'].strip()
    limit = None if raw == 'max' else int(raw)
    check(limit == actual['memory_max_bytes'] == role['domains'][leaf]['memory_max_bytes'],
          'Raw actual memory limit differs')


def _series(record, role, leaf, allocation):
    needed(clock_qualified(allocation), 'Clock qualification missing or failed')
    origins = [r for r in record['origins'] if r['domain'] == leaf and r['provenance'] == 'primary']
    check(len(origins) <= 1, 'Duplicate primary domain origin')
    needed(len(origins) == 1, 'Missing primary ' + leaf + ' origin')
    origin = origins[0]
    check(origin['role_binding'] == role, 'Primary origin role differs')
    capture.check_identity(role, leaf, origin['identity'])
    check(origin['key'] == list(capture.domain_key(role, leaf, origin['identity'])), 'Origin key differs')
    _resources(role, leaf, origin)
    rows = [r for r in record['samples'] if r['domain'] == leaf and r['provenance'] == 'primary']
    needed(rows, 'Missing primary ' + leaf + ' samples')
    check(len(rows) <= capture.SAMPLE_MAX, 'Domain sample bound exceeded')
    result, seen, counts = [], set(), {}
    for row in rows:
        check(row['role_binding'] == role, 'Primary sample role differs')
        snap = capture.snapshot(row['snapshot'])
        check(asdict(snap.identity) == origin['identity'], 'Held counter identity changed')
        check(snap.snapshot_id not in seen, 'Duplicate primary snapshot')
        seen.add(snap.snapshot_id)
        case = row['case_id']
        check(case in (None, *CASES), 'Unknown case')
        counts[case] = counts.get(case, 0) + 1
        check(counts[case] <= (capture.FIXED_MAX if case is None else capture.CASE_MAX), 'Case/fixed sample bound')
        needed(snap.error is None and snap.usage_usec is not None, 'Missing CPU read')
        needed(row['within_read_budget'] is True and snap.finished_ns - snap.started_ns <= capture.READ_MAX_NS,
               'Ordinary read exceeds 5ms')
        bracket = row.get('wall_bracket')
        needed(row.get('clock_error_ns') == CLOCK_ERROR_NS and type(bracket) is dict
               and bracket.get('snapshot_id') == snap.snapshot_id, 'Missing/fixed-1s clock bracket identity')
        _wall_bracket(snap.started_ns, snap.finished_ns, bracket.get('started_wall_ns'),
                      bracket.get('finished_wall_ns'), allocation)
        check(allocation['started_ns'] <= snap.started_ns <= snap.finished_ns <= allocation['finished_ns'],
              'Read outside allocation time')
        if result:
            previous = result[-1][1]
            check(previous.finished_ns <= snap.started_ns and previous.usage_usec <= snap.usage_usec,
                  'Counter rollback or reordered reads')
        result.append((row, snap))
    return origin, result


def _cpu_window(begin, end, used, cpu_count, why='Actual cpuset CPU capacity exceeded'):
    check(capture.natural(begin) and capture.natural(end) and begin <= end
          and capture.natural(used), 'Malformed CPU demand window')
    check(used <= cpu_count * ((end - begin + 999) // 1000) + 1, why)
    return begin, end, used


def _intervals(series, started, cpu_count):
    snaps = [snap for _, snap in series]
    triples = [(started, snaps[0].finished_ns, snaps[0].usage_usec)]
    triples.extend((left.started_ns, right.finished_ns, right.usage_usec - left.usage_usec)
                   for left, right in zip(snaps, snaps[1:]))
    return [_cpu_window(begin, end, used, cpu_count) for begin, end, used in triples]


def demands_fit(intervals, cpu_count=7):
    """Necessary finite-window feasibility, not a reconstruction of scheduling."""
    check(type(cpu_count) is int and 1 <= cpu_count <= 7 and len(intervals) <= 8192,
          'Bounded physical CPU feasibility input required')
    for start, end, used in intervals:
        check(capture.natural(start) and capture.natural(end) and capture.natural(used) and start <= end,
              'Malformed CPU demand window')
    ordered = sorted(intervals, key=lambda row: row[1])
    for begin in sorted({row[0] for row in intervals}):
        demand, count = 0, 0
        for start, end, used in ordered:
            if start >= begin:
                demand += used
                count += 1
            if end >= begin and demand > cpu_count * ((end - begin + 999) // 1000) + count:
                return False
    return True


def _role_report(record, role, allocation, evidence, expected_config_sha256):
    report = {'role_id': role['role_id'], 'kind': role['kind'], 'status': 'unidentified',
              'user_cpu_us': None, 'control_plane_endpoint_observed_cpu_us': None,
              'control_plane_last_read_lower_us': None,
              'control_plane_tail_upper_us': None, 'user_conservation': None,
              'endpoint_type': 'task_epilog_recorder_v1', 'problems': [], **capture.GATES}
    intervals = []
    available = {}
    for leaf in ('user', 'slurm'):
        try:
            available[leaf] = _series(record, role, leaf, allocation)
            intervals.extend(_intervals(available[leaf][1], allocation['started_ns'],
                                        len(role['domains'][leaf]['cpu_ids'])))
        except Unidentified as exc:
            report['problems'].append(str(exc))
    endpoint = record.get('endpoint')
    if endpoint is not None and endpoint.get('endpoint_type') == 'task_epilog_recorder_v1':
        endpoint = capture.adapt_task_epilog(endpoint.get('original'), role,
                    expected_config_sha256=expected_config_sha256)
    else:
        endpoint = capture.adapt_task_epilog(None, role,
                    expected_config_sha256=expected_config_sha256)
    report['endpoint_status'] = endpoint['status']
    if endpoint['status'] == 'captured':
        try:
            needed(clock_qualified(allocation), 'Clock qualification missing or failed')
            timing = endpoint['original']['timing']
            _wall_bracket(timing['begin_mono_ns'], timing['end_mono_ns'], timing['begin_wall_ns'],
                          timing['end_wall_ns'], allocation)
        except Unidentified as exc:
            endpoint = {**endpoint, 'status': 'unidentified', 'reason': str(exc)}
            report['endpoint_status'] = 'unidentified'
    if 'slurm' in available:
        origin, series = available['slurm']
        last = series[-1][1]
        report['control_plane_last_read_lower_us'] = last.usage_usec
        if endpoint['status'] == 'captured':
            final = SimpleNamespace(**endpoint['slurm_snapshot'])
            check(tuple(final.physical_identity) == capture.physical(origin['identity']),
                  'Management endpoint physical identity differs')
            check(last.finished_ns <= final.started_ns <= final.finished_ns <= allocation['finished_ns']
                  and final.usage_usec >= last.usage_usec, 'Management endpoint rollback/time')
            delta = final.usage_usec - last.usage_usec
            intervals.append(_cpu_window(last.started_ns, final.finished_ns, delta,
                             len(role['domains']['slurm']['cpu_ids']), 'Management CPU capacity exceeded'))
            last = final
            report['control_plane_endpoint_observed_cpu_us'] = final.usage_usec
        terminal, source = _terminal_upper(allocation, evidence, role['step_id'])
        check(last.finished_ns <= terminal, 'Management observation follows bound terminal End')
        report['control_plane_terminal_evidence'] = source
        report['control_plane_cpu_ids'] = role['domains']['slurm']['cpu_ids']
        report['control_plane_tail_upper_us'] = len(role['domains']['slurm']['cpu_ids']) * (
            (terminal - last.started_ns + 999) // 1000)
        report['control_plane_tail_scope'] = 'unobserved_cleanup_bound_not_a_point'
    if 'user' not in available:
        return report, intervals
    try:
        needed(endpoint['status'] == 'captured', 'Numeric user endpoint unidentified: ' + str(endpoint['reason']))
        origin, series = available['user']
        final = SimpleNamespace(**endpoint['user_snapshot'])
        check(tuple(final.physical_identity) == capture.physical(origin['identity']),
              'User endpoint physical identity differs')
        last = series[-1][1]
        check(last.finished_ns <= final.started_ns <= final.finished_ns <= allocation['finished_ns'],
              'User endpoint precedes last read or exceeds allocation')
        check(final.usage_usec >= last.usage_usec, 'User endpoint counter rollback')
        tail = final.usage_usec - last.usage_usec
        intervals.append(_cpu_window(last.started_ns, final.finished_ns, tail, 1, 'User tail exceeds one CPU'))
        cases, covered = [], []
        if role['role_id'] != 'D':
            for case in CASES:
                begins = [(i, snap) for i, (row, snap) in enumerate(series)
                          if row['case_id'] == case and row['event'] == 'case_begin']
                ends = [(i, snap) for i, (row, snap) in enumerate(series)
                        if row['case_id'] == case and row['event'] in ('case_end', 'case_closed')]
                needed(len(begins) == len(ends) == 1, 'Missing or duplicate case boundary: ' + case)
                left, right = begins[0], ends[0]
                needed(left[0] < right[0] and (not covered or covered[-1][1] <= left[0]), 'Cases overlap/reorder')
                covered.append((left[0], right[0]))
                used = right[1].usage_usec - left[1].usage_usec
                _cpu_window(left[1].started_ns, right[1].finished_ns, used, 1)
                cases.append({'case_id': case, 'cpu_us': used})
        prefix = series[0][1].usage_usec
        outside_intervals = []
        for i, ((_, before), (_, after)) in enumerate(zip(series, series[1:])):
            if not any(left <= i < right for left, right in covered):
                _cpu_window(before.started_ns, after.finished_ns,
                            after.usage_usec - before.usage_usec, 1)
                outside_intervals.append({'first_snapshot': before.snapshot_id, 'last_snapshot': after.snapshot_id,
                                          'cpu_us': after.usage_usec - before.usage_usec})
        outside = sum(row['cpu_us'] for row in outside_intervals)
        check(outside >= 0, 'Negative outside CPU')
        left = prefix + sum(case['cpu_us'] for case in cases) + outside + tail
        # Adjacent counter differences telescope; this is a partition identity,
        # not independent evidence of conservation. Bounds are checked above.
        check(left == final.usage_usec, 'Role CPU partition identity failed')
        report.update(status='records_consistent_pending_site_endpoint_review', user_cpu_us=final.usage_usec,
                      user_conservation={'equality': 'by_construction',
                                         'prefix_cpu_us': prefix, 'cases': cases, 'outside_cpu_us': outside,
                                         'outside_intervals': outside_intervals,
                                         'measured_tail_cpu_us': tail, 'endpoint_cpu_us': final.usage_usec,
                                         'left_cpu_us': left, 'right_cpu_us': final.usage_usec},
                      coordination_only=role['role_id'] == 'D')
    except Unidentified as exc:
        report['problems'].append(str(exc))
    return report, intervals


def _sacct(step_id, allocation, evidence):
    identifier = allocation['job_id'] + '.' + step_id
    row = evidence['base'][identifier]
    result = {'step_id': step_id, 'JobIDRaw': identifier, 'user_cpu_us': None, 'display_quantum_us': None,
              'display_residual_us': None,
              'status': 'unidentified', 'endpoint_type': 'sacct_terminal', 'provenance': 'primary',
              'cpu_sha256': evidence['evidence']['cpu_sha256'],
              'cpu_receipt_sha256': evidence['evidence']['cpu_receipt_sha256'], **capture.GATES}
    try:
        needed(clock_qualified(allocation), 'Clock qualification missing or failed')
        needed(row['State'] == 'COMPLETED' and row['ExitCode'] == '0:0', 'Non-normal terminal accounting')
        raw = evidence['cpu'].get(identifier)
        needed(raw is not None, 'Missing sacct endpoint')
        values = [display.duration_us(raw[k]) for k in ('TotalCPU', 'UserCPU', 'SystemCPU')]
        needed(all(v is not None for v in values), 'Missing sacct endpoint')
        needed(display.displayed_additivity(*values, raw), 'CPU display additivity differs')
        total, quantum = values[0], display.duration_quantum_us(raw['TotalCPU'])
        check(total <= len(allocation['cpu_ids']) * ((allocation['finished_ns'] - allocation['started_ns'] + 999) // 1000) + quantum,
              'Accounting endpoint exceeds allocation capacity')
        result.update(status='display_endpoint_pending_review', user_cpu_us=total,
                      display_residual_us=total - values[1] - values[2],
                      display_quantum_us=quantum,
                      display_interval_us=_display_interval(total, quantum))
    except (KeyError, Unidentified) as exc:
        result['reason'] = str(exc)
    return result


def analyze_allocation(allocation, role_records, *, expected_config_sha256, sacct_endpoints=None):
    """Seven role records plus exactly-once batch/extern endpoint observations.

    Allocation includes clock originals, wall/monotonic bounds and original
    accounting_evidence. Role records come from Capture.export_record(). The
    caller must supply the exact seven-role config digest map authenticated
    from D's launch records, independently of the meter/endpoint records. Free
    sacct_endpoints and terminal_end_ns are refused, not used as fallback facts.
    """
    allocation = _allocation(allocation)
    check(type(role_records) is dict and set(role_records) == set(capture.ROLES), 'Exact seven-role roster required')
    check(type(expected_config_sha256) is dict and set(expected_config_sha256) == set(capture.ROLES),
          'Exact caller launch config digest roster required')
    for name, digest in expected_config_sha256.items():
        check(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest),
              'Caller launch config digest malformed')
        check(role_records[name].get('endpoint_config_sha256') == digest,
              'Capture endpoint config digest differs from caller launch')
    check(sacct_endpoints is None, 'Free sacct endpoint dictionaries are not accepted')
    evidence = accounting_evidence(allocation, role_records)
    reports, intervals, physical, steps, user_cpus, nonces, cross_rows = {}, [], set(), set(), set(), set(), []
    for name in capture.ROLES:
        record = role_records[name]
        check('terminal_end_ns' not in record and 'last_user_cpu_us' not in record,
              'Free terminal/last-user numbers are not accepted')
        check(len(record['origins']) <= 14 and len(record['samples']) <= 14 * capture.SAMPLE_MAX,
              'Bounded role meter records required')
        role = capture.binding(record['role_binding'])
        check(role['role_id'] == name and all(role[k] == allocation[k] for k in ('job_id', 'node', 'boot_id', 'uid')),
              'Role/allocation context differs')
        check(role['step_id'] not in steps and role['nonce'] not in nonces, 'Role step/nonce reused')
        steps.add(role['step_id']); nonces.add(role['nonce'])
        actual = set(role['domains']['user']['cpu_ids'])
        check(not actual & user_cpus and actual <= set(allocation['cpu_ids']), 'Role user CPUs overlap/outside allocation')
        user_cpus |= actual
        check(set(role['domains']['slurm']['cpu_ids']) <= set(allocation['cpu_ids']), 'Management cpuset outside allocation')
        for origin in record['origins']:
            check(origin['provenance'] in ('primary', 'cross'), 'Explicit origin provenance required')
            check(origin['domain'] in ('user', 'slurm'), 'Unknown physical domain')
            if origin['provenance'] == 'cross':
                continue
            check(origin['role_binding'] == role, 'Primary origin has a foreign role')
            identity = origin['identity']
            key = (identity['context']['node'], identity['context']['boot_id'], identity['device'],
                   identity['inode'], identity['cpu_stat_device'], identity['cpu_stat_inode'])
            check(key not in physical, 'Primary physical domain counted twice')
            physical.add(key)
        for row in record['samples']:
            check(row['provenance'] in ('primary', 'cross'), 'Explicit sample provenance required')
            check(row.get('endpoint_type') != 'same_host_post_exit_read' or row['provenance'] == 'cross',
                  'v1 same-host reads are cross-only')
            if row['provenance'] == 'cross':
                cross_rows.append(row)
        reports[name], parts = _role_report(record, role, allocation, evidence, expected_config_sha256[name])
        intervals.extend(parts)
    seen_cross = set()
    for row in cross_rows:
        subject = capture.binding(row['role_binding'])
        check(subject == role_records[subject['role_id']]['role_binding'], 'Cross subject binding differs')
        snap = capture.snapshot(row['snapshot'])
        capture.check_identity(subject, row['domain'], asdict(snap.identity))
        primary = [origin for origin in role_records[subject['role_id']]['origins']
                   if origin['provenance'] == 'primary' and origin['domain'] == row['domain']]
        if len(primary) == 1:
            check(capture.physical(asdict(snap.identity)) == capture.physical(primary[0]['identity']),
                  'Cross read physical counter differs from primary')
        key = (capture.domain_key(subject, row['domain'], asdict(snap.identity)), snap.snapshot_id)
        check(key not in seen_cross, 'Duplicate cross record')
        seen_cross.add(key)
    ancillary = {}
    parent = {'base': deepcopy(evidence['base'][allocation['job_id']]),
              'cpu': deepcopy(evidence['cpu'].get(allocation['job_id'])), 'provenance': 'cross'}
    for step_id in ('batch', 'extern'):
        result = _sacct(step_id, allocation, evidence)
        ancillary[step_id] = result
        if result['user_cpu_us'] is not None:
            intervals.append((allocation['started_ns'], allocation['finished_ns'], result['user_cpu_us']))
    check(demands_fit(intervals, len(allocation['cpu_ids'])), 'Observed demands exceed global seven-CPU feasibility')
    user_values = [r['user_cpu_us'] for r in reports.values()] + [r['user_cpu_us'] for r in ancillary.values()]
    management = [r['control_plane_endpoint_observed_cpu_us'] for r in reports.values()]
    management_lower = [r['control_plane_last_read_lower_us'] for r in reports.values()]
    quantum = sum(r['display_quantum_us'] for r in ancillary.values()) if all(
        r['display_quantum_us'] is not None for r in ancillary.values()) else None
    known_user = sum(v for v in user_values if v is not None)
    accounted = sum(user_values) + sum(management) if all(v is not None for v in user_values + management) else None
    return {'schema': 'isolation-meter-export-v2', 'status': 'conditional_records_only_not_endpoint_acceptance',
            'runtime_execution_performed_by_exporter': False, 'site_endpoint_acceptance_required': True,
            'clock_qualified': bool(clock_qualified(allocation)), 'clock_error_ns': CLOCK_ERROR_NS,
            'roles': reports, 'coordination': {'D': reports['D'], **ancillary},
            'parent_cross_only': parent, 'cross_records_not_added': len(cross_rows),
            'user_cpu_us': sum(user_values) if all(v is not None for v in user_values) else None,
            'known_user_displayed_sum_us': known_user if any(v is not None for v in user_values) else None,
            'management_endpoint_observed_cpu_us': sum(management) if all(v is not None for v in management) else None,
            'management_last_read_lower_us': sum(management_lower) if all(v is not None for v in management_lower) else None,
            'accounted_observed_cpu_us': accounted,
            'accounted_observed_scope': 'user_endpoints_plus_epilog_management_observations_only',
            'display_quantum_us': quantum,
            'user_cpu_interval_us': _display_interval(sum(user_values), quantum)
                if all(v is not None for v in user_values) and quantum is not None else None,
            'accounted_observed_interval_us': _display_interval(accounted, quantum)
                if accounted is not None and quantum is not None else None,
            'batch_extern_management': 'unidentified_until_separate_actual_domain_observations',
            'full_physical_cpu_us': None, 'global_feasibility':
                'known_demands_only_feasible_not_completeness' if clock_qualified(allocation) else 'unidentified_clock',
            'reserved_cpu_time_us': len(allocation['cpu_ids']) * ((allocation['finished_ns'] - allocation['started_ns'] + 999) // 1000),
            'coordination_allocation': 'once_only_never_prorated_to_workers', **capture.GATES}


export = analyze_allocation
