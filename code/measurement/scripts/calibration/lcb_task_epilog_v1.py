"""Bounded task-epilog endpoint facts; no scheduler calls or executable input.

Public API: collect_endpoint(config_path=None, config_sha256=None).  Missing
arguments use WWW27_EPILOG_CONFIG and WWW27_EPILOG_CONFIG_SHA256.  Only a
captured record has an endpoint_usage_usec.  Publication is outside the 20 ms
observation bracket and never overwrites an existing record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import sys
import time

CONFIG_SCHEMA = 'task-epilog-config-v1'
SCHEMA = 'task-epilog-endpoint-v1'
PYTHON = '/usr/bin/python3.12'
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'}
CONFIG_ENV = 'WWW27_EPILOG_CONFIG'
HASH_ENV = 'WWW27_EPILOG_CONFIG_SHA256'
CGROUP_ROOT = Path('/sys/fs/cgroup')
CGROUP_PREFIX = '/system.slice/slurmstepd.scope'
# A step's counters are final when the epilog runs, so the bracket only guards against a stalled read. It was 20 ms until one
# 25 ms reading (a busy node) made a whole 12-hour-capable cell lose a role endpoint; typical readings take about 2 ms.
MAX_READ_NS = 1_000_000_000
MAX_FILE_BYTES = 1024 * 1024
MAX_TREE_NODES = 128
MAX_TREE_DEPTH = 8
CONFIG_KEYS = {'schema', 'role_id', 'nonce', 'owner_uid', 'job_id', 'node',
               'boot_id', 'record_path'}
STAT_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
             'st_size', 'st_mtime_ns', 'st_ctime_ns')


def check(ok, why):
    if not ok:
        raise ValueError(why)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            check(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def bad(_):
        raise ValueError('nonfinite JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def metadata(value):
    return {name.removeprefix('st_'): getattr(value, name) for name in STAT_KEYS}


def literal_path(value):
    check(type(value) is str and value and '\x00' not in value and '\n' not in value
          and '\r' not in value and len(value.encode()) <= 2048, 'literal path required')
    path = Path(value)
    check(path.is_absolute() and str(path) == value and '..' not in path.parts,
          'canonical absolute path required')
    return path


def private_directory(value, uid=None):
    path = literal_path(str(value))
    uid = os.getuid() if uid is None else uid
    info = path.stat()
    check(stat.S_ISDIR(info.st_mode) and info.st_uid == uid, 'owner-owned directory required')  # no ancestor walk, no mode equality
    return path


def open_directory(value):
    """Open the directory and retain its descriptor. Symlinked ancestors are allowed: where the owner keeps the
    attempt is not part of the measurement."""
    path = literal_path(str(value))
    return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def _read_fd(fd, maximum):
    before = os.fstat(fd)
    check(stat.S_ISREG(before.st_mode), 'regular file required')
    check(before.st_size <= maximum, 'file size bound')
    parts, size = [], 0
    while True:
        part = os.read(fd, min(65536, maximum + 1 - size))
        if not part:
            break
        parts.append(part)
        size += len(part)
        check(size <= maximum, 'read size bound')
    check(metadata(before) == metadata(os.fstat(fd)), 'file changed during read')
    return b''.join(parts), metadata(before)


def read_file(path, maximum=MAX_FILE_BYTES, *, private=False):
    path = literal_path(str(path))
    parent = open_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        raw, info = _read_fd(fd, maximum)
        check(info == metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
              'named file changed')
        if private:
            check(info['uid'] == os.getuid() and stat.S_IMODE(info['mode']) == 0o600
                  and info['nlink'] == 1, 'private owner file required')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def validate_config(value):
    check(type(value) is dict and set(value) == CONFIG_KEYS, 'exact config keys required; no command fields')
    check(value['schema'] == CONFIG_SCHEMA, 'config schema')
    check(type(value['role_id']) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', value['role_id']),
          'literal role_id required')
    check(type(value['nonce']) is str and re.fullmatch(r'[0-9a-f]{64}', value['nonce']), '64-hex nonce required')
    check(type(value['owner_uid']) is int and value['owner_uid'] > 0, 'nonroot owner required')
    check(type(value['job_id']) is str and re.fullmatch(r'[1-9][0-9]{0,11}', value['job_id']), 'job_id required')
    check(type(value['node']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value['node']),
          'one literal node required')
    check(type(value['boot_id']) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']),
          'boot_id required')
    literal_path(value['record_path'])
    return value


def load_config(path, digest):
    check(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest), 'independent config SHA256 required')
    path = literal_path(str(path))
    private_directory(path.parent)
    raw = read_file(path, 65536, private=True)
    check(sha(raw) == digest, 'config digest mismatch')
    value = validate_config(strict(raw))
    check(encoded(value) == raw, 'canonical config bytes required')
    check(value['owner_uid'] == os.getuid() == os.geteuid(), 'config owner mismatch')
    target = literal_path(value['record_path'])
    private_directory(target.parent)
    check(target != path and not os.path.lexists(target), 'new record path required; no overwrite/retry')
    return value


def publish(path, raw):
    """Publish one complete file atomically, without replacing any existing name.

    An unsuccessful publication retains its private temporary original.
    """
    path = literal_path(str(path))
    private_directory(path.parent)
    parent = open_directory(path.parent)
    temp = '.' + path.name + '.' + secrets.token_hex(12) + '.partial'
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                check(count > 0, 'short publication write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(path.name)
        os.rename(temp, path.name, src_dir_fd=parent, dst_dir_fd=parent)  # plain rename works on every filesystem
        os.fsync(parent)
    finally:
        os.close(parent)


def wrapper_bytes(recorder_path):
    """Only the fixed interpreter and this recorder's collect entry are allowed."""
    import shlex
    path = literal_path(str(recorder_path))
    return ('#!/bin/sh\nexec ' + PYTHON + ' -I -B ' + shlex.quote(str(path)) + ' collect\n').encode()


def _numbers(raw, *, pids=False):
    text = raw.decode('ascii', 'strict')
    if pids:
        values = text.split()
        check(all(re.fullmatch(r'[1-9][0-9]*', v) for v in values), 'invalid cgroup PID list')
        check(len(values) == len(set(values)), 'duplicate cgroup PID')
        return sorted(map(int, values))
    result = {}
    for line in text.splitlines():
        fields = line.split()
        check(len(fields) == 2 and re.fullmatch(r'[a-z_][a-z0-9_.]*', fields[0])
              and re.fullmatch(r'0|[1-9][0-9]*', fields[1]) and fields[0] not in result,
              'invalid cgroup counter')
        result[fields[0]] = int(fields[1])
    return result


def _file_at(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        raw, info = _read_fd(fd, MAX_FILE_BYTES)
        check(info == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'cgroup file replaced')
        digest = sha(raw)
        try:
            parsed = _numbers(raw, pids=name == 'cgroup.procs')
            if name == 'cgroup.events':
                check(parsed.get('populated') in (0, 1), 'missing populated counter')
            if name == 'cpu.stat':
                check({'usage_usec', 'user_usec', 'system_usec'} <= set(parsed), 'missing CPU counters')
        except ValueError as exc:
            # Keep the complete bounded bytes without a lossy text conversion.
            exc.counter_file_observation = {'file_name': name, 'raw_hex': raw.hex(),
                                            'raw_length': len(raw), 'sha256': digest}
            raise
        return {'identity': info, 'raw': raw.decode('ascii'), 'sha256': digest, 'parsed': parsed}
    finally:
        os.close(fd)


def _node(fd):
    before = metadata(os.fstat(fd))
    value = {'identity': before, **{n: _file_at(fd, n) for n in ('cgroup.procs', 'cgroup.events', 'cpu.stat')}}
    check(before == metadata(os.fstat(fd)), 'cgroup directory changed')
    return value


def _tree(fd, bindings):
    nodes = {}

    def visit(current, relative, depth):
        check(depth <= MAX_TREE_DEPTH and len(nodes) < MAX_TREE_NODES, 'cgroup subtree bound')
        nodes[relative] = _node(current)
        key = 'user' if relative == '.' else 'user/'+relative
        bindings[key]['snapshots'].append(nodes[relative]['identity'])
        for name in sorted(os.listdir(current)):
            info = os.stat(name, dir_fd=current, follow_symlinks=False)
            check(not stat.S_ISLNK(info.st_mode), 'cgroup symlink refused')
            if stat.S_ISDIR(info.st_mode):
                check(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and name not in ('.', '..'), 'cgroup child name')
                child_relative = name if relative == '.' else relative+'/'+name
                child_key = 'user/'+child_relative
                if child_key not in bindings:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=current)
                    bindings[child_key] = {'fd':child, 'parent':current, 'name':name,
                                           'identity':metadata(os.fstat(child)), 'snapshots':[]}
                binding = bindings[child_key]
                check(binding['parent'] == current and metadata(info) == binding['identity']
                      == metadata(os.fstat(binding['fd'])), 'tree directory binding changed')
                visit(binding['fd'], child_relative, depth+1)
    visit(fd, '.', 0)
    return {'nodes': nodes}


def _check_directory_bindings(bindings):
    """Keep all directory FDs until every saved snapshot is rejoined by name."""
    for binding in bindings.values():
        observed = metadata(os.fstat(binding['fd']))
        named = metadata(os.stat(binding['name'], dir_fd=binding['parent'], follow_symlinks=False))
        check(observed == named == binding['identity'] and
              all(snapshot == observed for snapshot in binding['snapshots']),
              'sampled directory binding changed')


def _read_context(config):
    check(platform.system() == 'Linux' and sys.version_info[:2] == (3, 12), 'Linux Python 3.12 required')
    uid = os.getuid()
    job = os.environ.get('SLURM_JOB_ID', '')
    step = os.environ.get('SLURM_STEP_ID', '')
    boot = read_file('/proc/sys/kernel/random/boot_id', 128).decode().strip()
    # /proc/self is a kernel symlink; the file reader deliberately refuses
    # symlink components. Use the literal current PID without weakening it.
    raw = read_file('/proc/'+str(os.getpid())+'/cgroup', 16384).decode('ascii')
    path = raw[3:].strip() if raw.startswith('0::') else None
    return ({'role_id': config['role_id'], 'nonce': config['nonce'], 'job_id': job,
             'step_id': step, 'node': os.uname().nodename.split('.')[0], 'boot_id': boot, 'uid': uid},
            {'pid': os.getpid(), 'ppid': os.getppid(), 'uid': uid,
             'resuid': list(os.getresuid()), 'effective_uid': os.geteuid(),
             'slurmd_nodename': os.environ.get('SLURMD_NODENAME'),
             'proc_self_cgroup': raw, 'cgroup_path': path, 'python': sys.version,
             'executable': sys.executable})


def _validate_context(config, context, recorder):
    check(all(context[k] == config[expected] for k, expected in
              (('job_id','job_id'), ('node','node'), ('boot_id','boot_id'), ('uid','owner_uid'))),
          'observed recorder identity differs from config')
    check(context['uid'] == recorder['effective_uid'] and
          recorder['resuid'] == [context['uid']]*3, 'recorder UID differs')
    step = context['step_id']
    check(re.fullmatch(r'0|[1-9][0-9]{0,11}', step), 'numeric step binding required')
    check(recorder['slurmd_nodename'] == config['node'], 'Slurm node identity differs')
    path = CGROUP_PREFIX+'/job_'+context['job_id']+'/step_'+step+'/slurm'
    check(recorder['proc_self_cgroup'] == '0::'+path+'\n',
          'recorder must be outside user subtree, in this step/slurm')


def sample_step_cgroups(job_id, step_id, *, _cgroup_root=None):
    """Read-only snapshot API for the separate batch-side fact witness.

    This API does not claim an endpoint. _cgroup_root is test injection only;
    it is never accepted in configuration or by the CLI.
    """
    check(re.fullmatch(r'[1-9][0-9]{0,11}', job_id) and re.fullmatch(r'0|[1-9][0-9]{0,11}', step_id),
          'literal numeric job/step IDs required')
    root = CGROUP_ROOT if _cgroup_root is None else Path(_cgroup_root)
    step_path = root/CGROUP_PREFIX.lstrip('/')/('job_'+job_id)/('step_'+step_id)
    step_fd = open_directory(step_path)
    bindings = {}
    try:
        step_identity = metadata(os.fstat(step_fd))
        for name in ('user', 'slurm'):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=step_fd)
            bindings[name] = {'fd':fd, 'parent':step_fd, 'name':name,
                              'identity':metadata(os.fstat(fd)), 'snapshots':[]}
        user, slurm = bindings['user']['fd'], bindings['slurm']['fd']
        before = _tree(user, bindings)
        control_before = _node(slurm)
        bindings['slurm']['snapshots'].append(control_before['identity'])
        cpu = _file_at(user, 'cpu.stat')
        after = _tree(user, bindings)
        control_after = _node(slurm)
        bindings['slurm']['snapshots'].append(control_after['identity'])
        _check_directory_bindings(bindings)
        check(step_identity == metadata(os.fstat(step_fd)) == metadata(step_path.lstat()), 'step directory replaced')
        return {'step_identity': step_identity,
                'user': {'path': str(step_path/'user'), 'before': before, 'cpu_snapshot': cpu, 'after': after},
                'slurm': {'path': str(step_path/'slurm'), 'before': control_before, 'after': control_after}}
    finally:
        for binding in reversed(list(bindings.values())):
            os.close(binding['fd'])
        os.close(step_fd)


def _empty(tree):
    return all(not node['cgroup.procs']['parsed'] and node['cgroup.events']['parsed']['populated'] == 0
               for node in tree['nodes'].values())


def _stable_user(user):
    before, after = user['before']['nodes'], user['after']['nodes']
    if set(before) != set(after):
        return False
    for name in before:
        if before[name]['identity'] != after[name]['identity']:
            return False
        for filename in ('cgroup.procs', 'cgroup.events', 'cpu.stat'):
            if before[name][filename] != after[name][filename]:
                return False
    return before['.']['cpu.stat'] == user['cpu_snapshot'] == after['.']['cpu.stat']


def capture_endpoint(config):
    """Measure only; the public collector publishes this record afterwards."""
    validate_config(config)
    begin_mono, begin_wall = time.monotonic_ns(), time.time_ns()
    record = {'schema': SCHEMA, 'status': 'unidentified_context',
              'context': {'role_id': config['role_id'], 'nonce': config['nonce'],
                          'job_id': config['job_id'], 'step_id': None, 'node': config['node'],
                          'boot_id': config['boot_id'], 'uid': config['owner_uid']},
              'recorder': None, 'user': None, 'slurm': None, 'step_identity': None,
              'endpoint_usage_usec': None, 'errors': [],
              'scope': 'one_step_user_endpoint_only_not_release_or_full_physical_cost'}
    stage = 'context'
    try:
        context, recorder = _read_context(config)
        record.update(context=context, recorder=recorder)
        _validate_context(config, context, recorder)
        stage = 'sample'
        sampled = sample_step_cgroups(context['job_id'], context['step_id'])
        record.update(sampled)
        before_names = set(record['user']['before']['nodes'])
        after_names = set(record['user']['after']['nodes'])
        required = {'.', 'task_0'}
        allowed = required | {'task_special'}
        if not (required <= before_names <= allowed and required <= after_names <= allowed):
            record['status'] = 'unidentified_subtree_layout'
            record['errors'].append({'stage':'sample', 'type':'UnexpectedSubtree',
                                     'message':'only user, task_0 and optional task_special are allowed'})
        elif not _empty(record['user']['before']) or not _empty(record['user']['after']):
            record['status'] = 'unidentified_nonempty_subtree'
        elif not _stable_user(record['user']):
            record['status'] = 'unidentified_subtree_changed'
        else:
            record['status'] = 'captured'
            record['endpoint_usage_usec'] = record['user']['cpu_snapshot']['parsed']['usage_usec']
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        record['status'] = 'unidentified_context' if stage == 'context' else 'unidentified_io'
        error = {'stage': stage, 'type': type(exc).__name__, 'message': str(exc)}
        observation = getattr(exc, 'counter_file_observation', None)
        if observation is not None:
            error['counter_file_observation'] = observation
        record['errors'].append(error)
    end_wall, end_mono = time.time_ns(), time.monotonic_ns()
    duration = end_mono-begin_mono
    within = 0 <= duration <= MAX_READ_NS
    record['timing'] = {'begin_mono_ns': begin_mono, 'end_mono_ns': end_mono,
                        'begin_wall_ns': begin_wall, 'end_wall_ns': end_wall,
                        'duration_ns': duration, 'budget_ns': MAX_READ_NS, 'within_budget': within,
                        'scope': 'context_and_subtree_sampling_excludes_config_and_publication'}
    if not within:
        record['status'] = 'unidentified_timeout'
        record['errors'].append({'stage': 'sample', 'type': 'BudgetExceeded', 'message': str(MAX_READ_NS // 10**6) + 'ms observation bracket exceeded'})
    if record['status'] != 'captured':
        record['endpoint_usage_usec'] = None
    return record


def collect_endpoint(config_path=None, config_sha256=None):
    config_path = os.environ.get(CONFIG_ENV) if config_path is None else config_path
    config_sha256 = os.environ.get(HASH_ENV) if config_sha256 is None else config_sha256
    check(config_path is not None, 'config path environment missing')
    config = load_config(config_path, config_sha256)
    record = capture_endpoint(config)
    record['config'] = {'path': str(config_path), 'sha256': config_sha256}
    publish(config['record_path'], encoded(record))
    return record


def plan():
    return {'schema': SCHEMA, 'config_schema': CONFIG_SCHEMA, 'config_keys': sorted(CONFIG_KEYS),
            'config_environment': [CONFIG_ENV, HASH_ENV], 'interpreter': PYTHON,
            'maximum_observation_ns': MAX_READ_NS, 'scheduler_commands': [],
            'endpoint_only_when_status': 'captured', 'candidate_execution_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'collect', 'inspect'))
    parser.add_argument('--record')
    args = parser.parse_args()
    if args.action == 'plan':
        check(args.record is None, 'plan has no record input')
        value = plan()
    elif args.action == 'inspect':
        check(args.record is not None, 'inspect requires a record')
        value = strict(read_file(args.record))
        check(value['schema'] == SCHEMA, 'record schema differs')
    else:
        check(args.record is None, 'collect only accepts hash-bound config environment')
        try:
            value = collect_endpoint()
        except Exception as exc:
            # No record could be written, so the endpoint is missing and the quantity stays unidentified.
            # The reason goes to the step's stderr; exit 0 keeps Slurm from also counting a TaskEpilog failure.
            print('epilog_error: '+type(exc).__name__+': '+str(exc), file=sys.stderr, flush=True)
            return
    print(encoded(value).decode(), end='')
    # Exit 0 always: Slurm logs a nonzero TaskEpilog status against the step, and the outcome is in the record itself.


if __name__ == '__main__':
    main()
