"""Pure I wire/ELF/provenance checks; no process, socket, signal or run API.

WWI1 deliberately differs from P's WWP1. Layout is still little-endian 352
bytes. values[0] is the case index; worker records use zero. C's sequence is
worker-wide, other actors' sequences restart for each fresh case. SCM_RIGHTS
is handled by the lifecycle adapter, never by this codec. A decoded frame is
an observation, not isolation admission. Native capability is fixed trusted
fixtures; the W adapter's assets/R/owner/mechanism gates authorize execution.
Payload fdmask is an observation on entry, before any payload-side cleanup.
The self-installed post-exec filter covers trusted fixtures only. Candidate
filter installation in J before exec belongs to N and is not implemented here.
"""
import hashlib
from pathlib import Path
import re
import stat
import struct

MAGIC = 0x57574931
VERSION = 1
FRAME = struct.Struct('<4I2Q8q256s')
MAX_FRAMES = 2048
CASES = ('controls', 'cpu', 'reuse')
ROLES = {1: 'controller', 2: 'factory', 3: 'init', 4: 'judge',
         5: 'payload', 6: 'supervisor'}
EVENTS = dict(enumerate((
    'hello', 'authenticated', 'idle', 'prepare', 'created', 'mapping',
    'context', 'limit', 'armed', 'judge_fd', 'running', 'payload_fd',
    'payload_result', 'judge_reap', 'init_reap', 'case_finish', 'stopped',
    'failed', 'frontend_fd', 'frontend_times', 'frontend_exec', 'peer',
    'identity', 'fd_audit', 'filter', 'root', 'outer_reap', 'pidfd_exit',
    'factory_auth', 'begin', 'case_stop', 'judge_ready', 'fd_sentinel',
    'kernel', 'resource', 'resource_detail', 'payload_bound'), 1))
COMMANDS = {'auth': 100, 'prepare': 101, 'start': 102, 'stop': 103, 'payload_ack': 106}
FD_EVENTS = {'created': 1, 'judge_fd': 1, 'payload_fd': 1}
CASE_TOTAL_NS = 30_000_000_000
SETUP_NS = 10_000_000_000
SERVICE_NS = 10_000_000_000
CPU_SERVICE_BUDGET_NS = 3_000_000_000
CLEANUP_NS = 10_000_000_000
WORKER_TOTAL_NS = 120_000_000_000
STOP_NS = 10_000_000_000
PRIVATE_NPROC = 32
CANDIDATE_TASK_MAX = 30
CPU_ITERATIONS = 250_000_000
FILTER_SCOPE = 'trusted_fixture_post_exec_only'
SOURCE_FILES = ('scripts/calibration/native/isolation_worker_v1.c',
                'scripts/calibration/native/isolation_worker_abi_v1.h',
                'scripts/calibration/lcb_isolation_native_v1.py',
                'scripts/calibration/lcb_isolation_build_v1.py')
NATIVE_FILES = SOURCE_FILES[:2]
FLAGS = ('-std=c11', '-O2', '-ffreestanding', '-fno-builtin',
         '-fno-stack-protector', '-fno-pie', '-Wall', '-Wextra', '-Werror',
         '-nostdlib', '-static', '-no-pie', '-Wl,-e,_start')
REVIEWED_RUNTIME = '/apps/site/opt/x86_64_v3/apptainer-1.5.0-hlqnf6rbvgnmd5pa6nkxfofhtrltalh5/bin/apptainer'
REVIEWED_RUNTIME_SHA256 = '91f0cf1b1a1f3031535d178f136aca9e4ca2aca3735fe1834f028cac6e320a0f'
REVIEWED_SIF = '/data/site/www27-assets-20261008/inference.sif'
REVIEWED_SIF_SHA256 = 'dd834f4fe0707a6834cffde61afe42d08b97876e87e12382af2739434762fba2'
GATES = {'execution_authorized': False, 'candidate_execution_authorized': False,
         'nproc_boundary_accepted': False, 'isolation_accepted': False,
         'main_matrix_authorized': False, 'cost_sample_eligible': False}


def check(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def nonce_check(nonce):
    check(type(nonce) is str and re.fullmatch('[0-9a-f]{64}', nonce), 'nonce64 required')
    return nonce


def literal_path(value):
    check(type(value) is str and value.startswith('/') and str(Path(value)) == value
          and '..' not in Path(value).parts
          and not any(c in value for c in (':', ',', '\n', '\r', '\0'))
          and len(value.encode()) < 1800, 'canonical literal absolute path required')
    return value


def controller_argv(config, output_dir, control_socket):
    """Encode only the native argv; no srun, fork or execution. Parent is W.batch."""
    check(config['runtime_path'] == REVIEWED_RUNTIME
          and config['runtime_sha256'] == REVIEWED_RUNTIME_SHA256
          and config['sif_path'] == REVIEWED_SIF
          and config['sif_sha256'] == REVIEWED_SIF_SHA256, 'reviewed P frontend/SIF required')
    helper = literal_path(config['helper_path'])
    check(re.fullmatch('[0-9a-f]{64}', config['helper_sha256']), 'new ELF hash required')
    check(config.get('private_nproc', 32) == 32, 'fixed private budget required')
    root, sock = literal_path(str(output_dir)), literal_path(str(control_socket))
    check(len(sock.encode()) < 108 and len((root + '/controls/control.sock').encode()) < 108,
          'UNIX socket path too long')
    return [helper, '--controller', REVIEWED_RUNTIME, REVIEWED_SIF, helper, root,
            sock, nonce_check(config['nonce'])]


def frontend_env(pin, starter):
    """Pure binding conversion. Adapter must hash/check the actual held assets."""
    keys = ('inode', 'dev_major', 'dev_minor', 'bytes', 'mtime_ns', 'ctime_ns', 'gid', 'mode')
    check(set(pin) == set(keys) and all(type(pin[k]) is int and pin[k] >= 0 for k in keys),
          'eight-field final frontend pin required')
    check(set(starter) == {'inode', 'dev_major', 'dev_minor'}
          and all(type(v) is int and v >= 0 for v in starter.values()), 'starter pin required')
    check(pin['inode'] > 0 and starter['inode'] > 0, 'nonzero inode required')
    return {**{'WWW27_I_FRONTEND_' + suffix: str(pin[key]) for key, suffix in zip(keys,
        ('INODE', 'MAJOR', 'MINOR', 'BYTES', 'MTIME', 'CTIME', 'GID', 'MODE'))},
        **{'WWW27_I_STARTER_' + suffix: str(starter[key]) for key, suffix in
           (('inode', 'INODE'), ('dev_major', 'MAJOR'), ('dev_minor', 'MINOR'))}}


def encode_command(action, *, seq, nonce, case_id=None):
    check(action in COMMANDS and type(seq) is int and 0 < seq < 2**64, 'fixed command/sequence required')
    nonce_check(nonce)
    if action in ('prepare', 'start', 'payload_ack'):
        check(case_id in CASES, 'fixed fixture required; no program or candidate API')
        index = CASES.index(case_id) + 1
    else:
        check(case_id is None, 'worker command has no case')
        index = 0
    return FRAME.pack(MAGIC, VERSION, 6, COMMANDS[action], seq, 0,
                      index, index, 0, 0, 0, 0, 0, 0, nonce.encode().ljust(256, b'\0'))


def decode_frame(packet):
    check(type(packet) is bytes and len(packet) == FRAME.size, 'one exact 352-byte frame required')
    magic, version, role, event, seq, ns, *tail = FRAME.unpack(packet)
    text = tail.pop()
    check(magic == MAGIC and version == VERSION and role in ROLES and role != 6
          and event in EVENTS and seq > 0 and ns > 0, 'unknown I observation; P/command frames refused')
    end = text.find(b'\0')
    check(end >= 0 and not any(text[end:]), 'noncanonical text padding')
    check(0 <= tail[0] <= 3, 'case index outside fixed manifest')
    return {'actor': ROLES[role], 'role': role, 'event': EVENTS[event],
            'event_id': event, 'seq': seq, 'ns': ns, 'case_index': tail[0],
            'values': tail, 'text': text[:end].decode('utf-8', 'strict')}


def validate_command(packet, *, action, seq, nonce, case_id=None):
    """Pure exact-byte oracle for the native nonce/sequence/case command gate."""
    check(type(packet) is bytes and packet == encode_command(
        action, seq=seq, nonce=nonce, case_id=case_id), 'wrong/replayed command binding')


def decode_frames(data):
    check(type(data) is bytes and 0 < len(data) <= MAX_FRAMES * FRAME.size
          and len(data) % FRAME.size == 0, 'truncated/oversized I trace')
    rows, last = [], {}
    for at in range(0, len(data), FRAME.size):
        row = decode_frame(data[at:at + FRAME.size])
        key = (0 if row['role'] == 1 else row['case_index'], row['role'])
        previous = last.get(key, (0, 0))
        check(row['seq'] > previous[0] and row['ns'] >= previous[1], 'replayed/nonmonotonic actor')
        last[key] = row['seq'], row['ns']
        rows.append(row)
    return rows


def cpu_checksum():
    """Affine exponentiation: verify the fixed finite work in O(log n)."""
    count, mult, plus, acc_mult, acc_plus = CPU_ITERATIONS, 1664525, 1013904223, 1, 0
    while count:
        if count & 1:
            acc_mult = (acc_mult * mult) & 0xffffffff
            acc_plus = (acc_plus * mult + plus) & 0xffffffff
        plus = ((mult + 1) * plus) & 0xffffffff
        mult = (mult * mult) & 0xffffffff
        count >>= 1
    return (acc_mult + acc_plus) & 0xffffffff


def verify_trace(data, *, nonce):
    """Check recorded protocol/value consistency, never grant any I/N label."""
    nonce_check(nonce)
    rows = decode_frames(data)
    def one(role, event, case):
        found = [r for r in rows if r['role'] == role and r['event'] == event and r['case_index'] == case]
        check(len(found) == 1, 'expected exactly one ' + event)
        return found[0]
    check(not any(r['event'] == 'failed' for r in rows), 'native failure retained')
    begin, hello, auth = (one(1, event, 0) for event in ('begin', 'hello', 'authenticated'))
    check(rows[0] is hello and rows.index(hello) < rows.index(begin) < rows.index(auth)
          and begin['text'] == hello['text'] == auth['text'] == nonce,
          'worker nonce/order differs')
    check(hello['values'][1] > 0 and hello['values'][2] > 0, 'controller PID/UID missing')
    previous = rows.index(auth)
    for case, name in enumerate(CASES, 1):
        ordered = [one(role, event, case) for role, event in
                   ((1, 'prepare'), (2, 'created'), (3, 'limit'), (3, 'judge_fd'),
                    (3, 'armed'), (1, 'running'), (4, 'payload_fd'), (1, 'payload_bound'), (5, 'payload_result'),
                    (3, 'judge_reap'), (2, 'init_reap'), (1, 'pidfd_exit'),
                    (1, 'case_finish'), (1, 'idle'))]
        positions = [rows.index(r) for r in ordered]
        check(previous < positions[0] and positions == sorted(positions), 'case stages out of order')
        previous = positions[-1]
        prepare, _, limit, _, armed, _, _, bound, result, judge, init, exits, finish, _ = ordered
        check(bound['values'][1] > 0 and bound['values'][2] > 0 and bound['values'][3] > 0,
              'C/W payload identity ACK missing')
        if case == 2:
            check(bound['ns'] <= result['ns'] <= bound['ns'] + CPU_SERVICE_BUDGET_NS,
                  'CPU fixture exceeds fixed 3 s service budget')
        check(prepare['text'] == finish['text'] == result['text'] == name, 'case identity differs')
        check(prepare['ns'] < prepare['values'][1] <= prepare['ns'] + CASE_TOTAL_NS,
              'case deadline extended')
        check(finish['ns'] <= prepare['values'][1], 'case completed after deadline')
        check(limit['values'][1:5] == [0, -1, 32, 32], 'NPROC installation/raise observation differs')
        check(armed['values'][1:4] == [1, 0, 1], 'NNP/filter/capability observation differs')
        roots = [r for r in rows if r['role'] == 3 and r['case_index'] == case and r['event'] == 'root']
        check(len(roots) == 2 and [r['text'] for r in roots] == ['fresh-private-proc', 'private-empty-root']
              and roots[0]['values'][1:] == [0, 0, 0, 0, 0, 1, 1]
              and roots[1]['values'][1:] == [0, 0, 0, 0, 0, -2, -2]
              and rows.index(limit) < rows.index(roots[0]) < rows.index(roots[1]) < rows.index(armed),
              'private mount/proc/chroot observations missing or failed')
        caps = [r for r in rows if r['role'] == 3 and r['case_index'] == case
                and r['event'] == 'context' and r['text'] == 'post-drop-caps']
        check(len(caps) == 1 and caps[0]['values'][1:] == [0, 0, 0, 0, 0, 0, 1],
              'raw post-drop capabilities/NNP missing')
        identities = [r for r in rows if r['role'] == 1 and r['case_index'] == case and r['event'] == 'identity']
        check(len(identities) == 4 and {r['values'][1] for r in identities} == {0, 1, 2, 3}
              and all(re.fullmatch(r'(user|pid|mnt|net):\[[0-9]+\]', r['text'])
                      and r['values'][2] > 0 and r['values'][3] > 0 for r in identities),
              'four independent namespace observations missing')
        sentinel = one(3, 'fd_sentinel', case)
        audit = one(4, 'fd_audit', case)
        check(sentinel['values'][1] == 31 and audit['values'][1:4] == [0, 0, 0],
              'FD sentinel or bounded payload EOF/reap missing')
        policy = one(3, 'filter', case)
        check(policy['text'] == 'supervisor-allowlist' and policy['values'][1] >= 20,
              'full filter installation record missing')
        frontend, times, observed = (one(1, e, case) for e in ('frontend_fd', 'frontend_times', 'frontend_exec'))
        check(frontend['values'][1] > 0 and frontend['values'][5] == 0
              and frontend['values'][4] & 0o170000 == 0o100000
              and not frontend['values'][4] & 0o6022
              and frontend['values'][4] & 0o111 and 0 < frontend['values'][6] <= 256 * 1024**2
              and times['values'][1] == frontend['values'][7] and times['values'][2] > 0
              and observed['text'] in ('frontend-exec-observed', 'starter-exec-observed')
              and observed['values'][2:5] == observed['values'][5:8]
              and (observed['text'] != 'frontend-exec-observed'
                   or observed['values'][2:5] == frontend['values'][1:4]),
              'held frontend/preexec/proc-exe evidence differs')
        expected = cpu_checksum() if case == 2 else 0
        check(result['values'][1:] == [expected, 0, 15, -1, -2, 32, 1], 'fixed payload observations differ')
        check(judge['values'][1:4] == [0, 0, -10] and init['values'][1:4] == [0, 0, 1],
              'case-owned reaping incomplete')
        check(exits['values'][1:4] == [1, 1, 1] and finish['values'][1:4] == [1, 0, hello['values'][1]],
              'case cleanup/C persistent identity differs')
        check(any(r['role'] == 1 and r['event'] == 'outer_reap' and r['case_index'] == case
                  for r in rows), 'runtime reaping missing')
        check(all(r['values'][2] == 0 for r in rows if r['role'] == 1
                  and r['event'] == 'outer_reap' and r['case_index'] == case), 'runtime child failed')
    stopped = one(1, 'stopped', 0)
    check(rows[-1] is stopped and rows.index(stopped) > previous
          and stopped['values'][1:3] == [1, 3] and stopped['ns'] <= begin['values'][1],
          'worker stop incomplete/late')
    return {'schema': 'isolation-native-trace-check-v1', 'status': 'records_consistent_pending_review',
            'trace_sha256': sha(data), 'nonce': nonce, 'cases': list(CASES),
            'private_nproc_proposed': 32, 'whole_worker_empty_asserted': False,
            'filter_scope': FILTER_SCOPE, 'candidate_filter_preexec_implemented': False,
            'evidence': 'record_validation_only_not_field_acceptance', **GATES}


def elf_identity(data):
    check(type(data) is bytes and 120 <= len(data) <= 8 * 1024**2, 'bounded ELF bytes required')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    check(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[0][7] in (0, 3)
          and h[1:4] == (2, 62, 1) and h[8] == 64, 'static Linux x86-64 ET_EXEC required')
    phoff, size, count = h[5], h[9], h[10]
    check(size == 56 and 0 < count <= 64 and phoff >= 64 and phoff + count * 56 <= len(data),
          'ELF program table invalid')
    executable, stack = False, False
    for i in range(count):
        kind, flags, offset, address, _, filesz, memsz, align = struct.unpack_from('<II6Q', data, phoff + i * 56)
        check(kind not in (2, 3) and not (flags & 1 and flags & 2), 'dynamic loader or W+X refused')
        check(offset + filesz <= len(data) and filesz <= memsz, 'ELF segment outside file')
        check(align in (0, 1) or align & (align - 1) == 0, 'ELF alignment invalid')
        if kind == 0x6474e551:
            check(not flags & 1, 'executable stack refused')
            stack = True
        if kind == 1 and flags & 1 and address <= h[4] < address + filesz:
            executable = True
    check(executable and stack, 'ELF entry or non-executable stack missing')
    return {'sha256': sha(data), 'bytes': len(data), 'machine': 'x86_64',
            'static': True, 'entry': h[4], 'executed': False}


def source_manifest(root):
    """Read-only byte roster; Git commit/cleanliness belongs to the owner adapter."""
    root = Path(root)
    check(root.is_absolute() and root.resolve(strict=True) == root, 'canonical source root required')
    result = {}
    for name in SOURCE_FILES:
        path = root / name
        check(not any(p.is_symlink() for p in (path, *path.parents)), 'source symlink refused')
        before = path.stat()
        check(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 2**20, 'bounded regular source required')
        raw = path.read_bytes()
        after = path.stat()
        check((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
              == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
              and len(raw) == before.st_size, 'source changed during read')
        result[name] = sha(raw)
    return result


def verify_build_record(record, elf_bytes, *, source_sha, sources):
    check(type(source_sha) is str and re.fullmatch('[0-9a-f]{40}', source_sha), 'fixed source SHA required')
    check(set(sources) == set(SOURCE_FILES), 'exact I source roster required')
    check(all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in sources.values()),
          'source hashes required')
    before = record.get('source_before')
    compiler = record.get('compiler_before')
    check(type(before) is dict and before.get('head') == source_sha
          and before.get('status_porcelain') == '' and type(before.get('repository')) is str
          and set(before.get('files_sha256', {})) == set(SOURCE_FILES)
          and all(before['files_sha256'][k] == sources[k] for k in NATIVE_FILES),
          'source-before native binding missing')
    check(type(compiler) is dict and compiler.get('path') == '/usr/bin/gcc'
          and type(compiler.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', compiler['sha256'])
          and type(compiler.get('identity')) is list and len(compiler['identity']) == 8
          and all(type(x) is int and x >= 0 for x in compiler['identity'])
          and compiler['identity'][6] == 0 and not compiler['identity'][5] & 0o6022,
          'root-owned stable compiler identity missing')
    elf = elf_identity(elf_bytes)
    check(record.get('schema') == 'isolation-native-owner-build-v1'
          and record.get('source_sha') == source_sha
          and record.get('source_files_sha256') == {n: sources[n] for n in NATIVE_FILES}
          and record.get('helper_sha256') == elf['sha256'] and record.get('flags') == list(FLAGS)
          and record.get('target') == 'x86_64-linux-gnu' and record.get('helper_executed') is False
          and record.get('source_before') == record.get('source_after')
          and record.get('compiler_before') == record.get('compiler_after'), 'I build provenance differs')
    commands = record.get('commands')
    check(type(commands) is list and len(commands) == 3
          and [r.get('name') for r in commands] == ['gcc-version', 'gcc-target', 'build']
          and all(type(r.get('returncode')) is int and r['returncode'] == 0
                  and r.get('error') is None
                  and r.get('environment') == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
                  and all(type(r.get(k)) is str and re.fullmatch('[0-9a-f]{64}', r[k])
                          for k in ('stdout_sha256', 'stderr_sha256'))
                  for r in commands),
          'complete successful fixed GCC receipts required')
    check(commands[0]['argv'] == ['/usr/bin/gcc', '--version']
          and commands[1]['argv'] == ['/usr/bin/gcc', '-dumpmachine']
          and commands[2]['argv'] == ['/usr/bin/gcc', *FLAGS,
              record['source_before']['repository'] + '/' + SOURCE_FILES[0], '-o', record['helper_path']],
          'unreviewed compiler argv')
    return elf
