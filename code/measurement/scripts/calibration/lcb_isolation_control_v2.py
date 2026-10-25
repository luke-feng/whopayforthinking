"""I v2 authenticated role IPC and native lifecycle; D owns srun clients.

W/O/D are separate steps in one allocation. The dispatcher starts E as a
sibling step and owns its srun wait. No v1/S/P permit is accepted here.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import select
import socket
import struct
import time
from copy import deepcopy

import lcb_isolation_release_v2 as release
import lcb_isolation_batch_v2 as batch
import lcb_isolation_native_v1 as native
import lcb_supervision_site_v3 as site
import lcb_isolation_runtime_v2 as runtime


class InfrastructureError(runtime.InfrastructureError, TimeoutError):
    """A coordination/deadline failure, never a candidate or fixture verdict."""


class Journal:
    def __init__(self, root, name):
        self.path = Path(root)/name; release.path_check(self.path.parent, private=True)
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        self.seq = 0; self.previous = '0'*64

    def append(self, kind, data):
        release.check(self.seq < 8192, 'Bounded I journal')
        row = {'seq': self.seq+1, 'kind': kind, 'monotonic_ns': time.monotonic_ns(),
               'wall_ns': time.time_ns(), 'previous_sha256': self.previous, 'data': data}
        raw = release.encoded(row); release.check(len(raw) <= 262144, 'Bounded I journal row')
        view = memoryview(raw)
        while view:
            n = os.write(self.fd, view); release.check(n > 0, 'Journal short write'); view = view[n:]
        os.fsync(self.fd); self.seq += 1; self.previous = release.sha(raw)

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


def remaining(deadline_ns, maximum=5):
    seconds = (deadline_ns-time.monotonic_ns())/10**9
    if seconds <= 0:
        raise InfrastructureError('I infrastructure deadline exceeded; no fixture verdict or retry')
    return min(seconds, maximum)


def role_deadline(authority, live_join=None):
    release.require(authority, phase='runtime')
    if live_join is not None:
        release.check(all(live_join[k] == authority.runtime_receipt[k] for k in ('job_id', 'node', 'boot_id'))
                      and live_join['role_id'] == authority.role,
                      'Live join differs from runtime role/allocation')
    deadline = release.integer(authority.deadline_mono_ns, 1)
    remaining(deadline)
    return deadline


def wait_deadline(authority, field=None, *, live_join=None, hard_deadline_ns=None):
    """Compatibility stage label; no v1 floors or refreshed role deadline."""
    release.check(field is None or type(field) is str, 'Literal stage label required')
    deadline = role_deadline(authority, live_join)
    if hard_deadline_ns is not None:
        deadline = min(deadline, hard_deadline_ns)
    remaining(deadline)
    return deadline


def _execution_slot(authority, slot):
    """An E slot is held only by its paired W authority, with E's own nonce."""
    release.check(type(slot) is dict and slot.get('role_id') in ('E1', 'E2'), 'Exact E1/E2 slot required')
    release.require(authority, phase='runtime', role='W' + slot['role_id'][1])
    expected = batch.role_for(authority.manifest, slot['role_id'])
    release.check(slot == expected and expected['kind'] == 'execution', 'Execution slot/nonce differs from manifest')
    release.check(authority.uid == authority.manifest['owner_uid'], 'Runtime owner differs')
    return deepcopy(expected)


def _execution_join(authority, slot, identity, step_id, confirmed):
    release.check(type(confirmed) is dict, 'D must return an explicit execution live join')
    if 'join' in confirmed:
        release.check(set(confirmed) == {'join', 'subject', 'process', 'context'}
                      and site.process_identity(confirmed['process']) == site.process_identity(identity),
                      'D process record differs from held native peer')
        subject, joined = confirmed['subject'], confirmed['join']
        release.check(all(subject[k] == joined[k] for k in
                          ('job_id', 'step_id', 'role_id', 'kind', 'nonce', 'node', 'boot_id', 'uid'))
                      and subject['domains']['user']['identity'] == joined['user_cgroup']
                      and subject['domains']['user']['cpu_ids'] == joined['cpu_ids']
                      and subject['domains']['user']['memory_max_bytes'] == joined['memory_max_bytes'],
                      'D execution subject differs from joined resource identity')
        confirmed = joined
    context = site.LinuxHost().context()
    rebuilt = batch.live_join(authority.manifest, slot['role_id'], authority.runtime_receipt,
        step_id=step_id, pid=identity['pid'], pid_start_ticks=identity['start_ticks'], uid=identity['uid'],
        node=context['node'].split('.',1)[0], boot_id=context['boot_id'],
        cgroup_path=confirmed['cgroup_path'], cgroup_device=confirmed['cgroup_device'],
        cgroup_inode=confirmed['cgroup_inode'], user_cgroup=confirmed['user_cgroup'], cpu_ids=confirmed['cpu_ids'],
        memory_max_bytes=confirmed['memory_max_bytes'], role_nonce=slot['nonce'])
    release.check(confirmed == rebuilt and identity['cgroup'] == rebuilt['cgroup_path'],
                  'D execution join differs from held native peer/slot')
    return deepcopy(rebuilt)


def _listen(path):
    p = Path(path); release.path_check(p.parent, private=True)
    release.check(len(str(p).encode()) < 108 and not p.exists(), 'Fresh short IPC path required')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    try:
        sock.bind(str(p)); os.chmod(p, 0o600); sock.listen(1)
        return sock
    except BaseException:
        sock.close(); raise


def _accept(listener, deadline_ns):
    listener.settimeout(remaining(deadline_ns, (deadline_ns-time.monotonic_ns())/10**9))
    conn, _ = listener.accept(); conn.setblocking(False)
    return conn


def kernel_peer(sock, authority, expected_job, *, expected_exe_sha, native_peer=False, expected_argv=None, expected_step=None):
    release.require(authority, phase='runtime')
    release.number(expected_job)
    release.check(expected_job == authority.runtime_receipt['job_id'], 'Peer outside runtime allocation')
    if expected_step is not None:
        release.number(expected_step, zero=True)
    pid, uid, _ = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    original = struct.unpack('i', sock.getsockopt(socket.SOL_SOCKET, 77, 4))[0]  # SO_PEERPIDFD
    handle = None
    try:
        release.check(uid == authority.owner['owner_uid'] and site.pidfd_task(original) == pid, 'Original peer/UID')
        poll = select.poll(); poll.register(original, select.POLLIN)
        release.check(not poll.poll(0), 'Original socket peer already exited')
        host = site.LinuxHost(); context = host.context(); observed = host.process(pid)
        release.check(context['node'].split('.', 1)[0] == authority.runtime_receipt['node']
                      and context['boot_id'] == authority.runtime_receipt['boot_id'],
                      'Peer host epoch differs from allocation')
        pattern = r'/system\.slice/slurmstepd\.scope/job_' + expected_job + r'/step_(0|[1-9][0-9]*)/user(?:/[^/]+)*'
        match = re.fullmatch(pattern, observed['cgroup'])
        release.check(match is not None and observed['uid'] == authority.uid, 'v2 peers must be numeric owner role steps')
        if expected_step is not None:
            release.check(match[1] == expected_step, 'Peer step differs from the role binding')
        if native_peer:
            release.number(match[1], zero=True)
        handle = host.track(pid, uid, site.CGBASE+'/job_'+expected_job+'/step_'+match[1])
        for ns, key in (('pid', 'pid_namespace'), ('time', 'time_namespace')):
            release.check(os.readlink('/proc/'+str(pid)+'/ns/'+ns) == context[key], 'Peer namespace differs')
        info = host.executable_info(pid)
        if expected_argv is not None:
            args = runtime.read_proc('/proc/'+str(pid)+'/cmdline', 16384)
            release.check(args.endswith(b'\0') and args[:-1].decode().split('\0') == expected_argv,
                          'Peer exact registered role argv differs')
        release.check(info['status'] == 'observed' and info['sha256'] == expected_exe_sha
                      and not handle.state()['exited'] and not poll.poll(0), 'Peer executable identity differs')
        return handle, match[1]
    except BaseException:
        if handle is not None:
            handle.close()
        raise
    finally:
        os.close(original)


def key_bytes(path):
    raw = release.read(path, 32, private=True)
    release.check(len(raw) == 32, 'Private I authentication key required')
    return raw


def seal(value, key):
    return {'body': value, 'mac': hmac.new(key, release.encoded(value), hashlib.sha256).hexdigest()}


def authenticate(packet, key):
    release.check(set(packet) == {'body', 'mac'} and type(packet['mac']) is str
                  and hmac.compare_digest(packet['mac'], seal(packet['body'], key)['mac']), 'I ready MAC mismatch')
    return packet['body']


class ReadyConnection:
    """Both a kernel peer identity and independent HMAC/sequence/challenge binding."""
    def __init__(self, sock, authority, peer_job, lease, key, peer_role_id, peer_step):
        release.require(authority, phase='runtime')
        release.number(peer_step, zero=True)
        release.check(sock.family == socket.AF_UNIX and sock.type & 15 == socket.SOCK_SEQPACKET,
                      'Local seqpacket role channel required')
        self.sock, self.authority, self.lease, self.key = sock, authority, lease, key
        peer_slot = batch.role_for(authority.manifest, peer_role_id)
        argv = [authority.assets['python']['path'], '-I', '-B',
                str(release.ROOT/'scripts/calibration/lcb_isolation_owner_v2.py'), 'role',
                '--root', str(authority.root), '--owner-sha256', authority.owner_sha,
                '--review-sha256', authority.review_sha, '--role-id', peer_role_id, '--execute']
        self.peer, _ = kernel_peer(sock, authority, peer_job,
            expected_exe_sha=authority.assets['python']['sha256'], expected_argv=argv, expected_step=peer_step)
        self.sent = self.received = 0

    def send(self, event, data):
        release.require(self.authority, phase='runtime')
        release.check(not self.peer.state()['exited'] and self.sent < 8192, 'Ready peer exited or packet budget exhausted')
        self.sent += 1
        body = {'schema': 'isolation-ready-v2', 'lease': self.lease, 'seq': self.sent, 'event': event, 'data': data}
        raw = release.encoded(seal(body, self.key)); release.check(len(raw) <= 65536, 'Ready packet bound')
        release.check(self.sock.send(raw, socket.MSG_NOSIGNAL | socket.MSG_DONTWAIT) == len(raw), 'Short ready packet')

    def receive(self, deadline_ns):
        release.require(self.authority, phase='runtime')
        deadline_ns = min(deadline_ns, self.authority.deadline_mono_ns)
        poll = select.poll(); poll.register(self.sock.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            if self.authority.role.startswith('O') and (self.authority.root/'batch.stop.json').exists():
                raise runtime.CooperativeStop('Observer finishing a cooperative shutdown')
            if poll.poll(int(remaining(deadline_ns, .1)*1000)):
                break
            release.require(self.authority, phase='runtime')
        raw, anc, flags, _ = self.sock.recvmsg(65537, 1024)
        _close_rights(anc)
        release.check(raw and len(raw) <= 65536 and not anc and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'Malformed ready packet')
        body = authenticate(release.strict(raw), self.key)
        release.check(set(body) == {'schema', 'lease', 'seq', 'event', 'data'}
                      and body['schema'] == 'isolation-ready-v2' and body['lease'] == self.lease
                      and type(body['seq']) is int and body['seq'] == self.received+1
                      and not self.peer.state()['exited'], 'Ready replay/foreign lease/dead peer')
        self.received += 1
        return body

    def request(self, event, data, deadline_ns):
        challenge = release.object_sha({'lease': self.lease, 'event': event, 'data': data, 'seq': self.sent+1})
        self.send(event, {'challenge': challenge, 'value': data})
        result = self.receive(deadline_ns)
        release.check(result['event'] == 'ack' and result['data'] == {'challenge': challenge, 'event': event}, 'Observer did not authenticate exact event')

    def close(self):
        self.peer.close(); self.sock.close()


def _close_rights(ancillary):
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            for fd in struct.unpack(str(len(raw)//4)+'i', raw[:len(raw)//4*4]):
                os.close(fd)


class NativeChannel:
    def __init__(self, authority, execution_slot, journal, env, *, broker, live_join=None,
                 defer_hello=False):
        slot = _execution_slot(authority, execution_slot)
        self.authority, self.slot, self.journal = authority, slot, journal
        self.seq = 0; self.rows = []; self.handles = {}
        self.actor_last = {}; self.next_case = 0; self.phase = 'starting'; self.peer = None
        self.sock = self.listener = None; self.broker = broker
        self.last_receipt = None
        self.started_ns = time.monotonic_ns()
        self.run_deadline_ns = role_deadline(authority, live_join)
        self.deadline_ns = self.run_deadline_ns
        release.check(all(callable(getattr(broker, name, None)) for name in
                          ('request_execution', 'bind_execution', 'wait_execution')), 'D execution broker required')
        env = deepcopy(env)
        root = authority.root/('native-'+slot['worker_id'])
        self.root = root
        socket_path = authority.root/('c-'+slot['worker_id']+'.sock')
        lock = env.pop('_runtime_lock')
        cfg = {'helper_path': authority.assets['native_elf']['path'],
               'helper_sha256': authority.assets['native_elf']['sha256'],
               'runtime_path': lock['runtime']['path'], 'runtime_sha256': lock['runtime']['sha256'],
               'sif_path': lock['cpu_sif']['path'], 'sif_sha256': lock['cpu_sif']['sha256'],
               'nonce': slot['nonce'], 'private_nproc': 32}
        argv = native.controller_argv(cfg, root, socket_path)
        pins = {k: v for k, v in env.items() if k.startswith('WWW27_I_')}
        expected_pins = {'WWW27_I_FRONTEND_' + name for name in
                         ('INODE', 'MAJOR', 'MINOR', 'BYTES', 'MTIME', 'CTIME', 'GID', 'MODE')} | {
                         'WWW27_I_STARTER_' + name for name in ('INODE', 'MAJOR', 'MINOR')}
        release.check(set(pins) == expected_pins and all(type(v) is str and re.fullmatch(r'0|[1-9][0-9]*', v)
                      for v in pins.values()), 'Exact final frontend pin input')
        pin_raw = ''.join(k+'='+pins[k]+'\n' for k in sorted(pins)).encode()
        self.argv = argv
        try:
            self.host = site.LinuxHost()
            os.mkdir(root, 0o700)
            self.listener = _listen(socket_path)
            release.write_new(root/'frontend-preexec.env', pin_raw)
            journal.append('frontend_preexec', {'path': str(root/'frontend-preexec.env'), 'sha256': release.sha(pin_raw)})
            # A request is data, never an arbitrary executable supplied to D.
            # The dispatcher recomputes the native argv and pins independently.
            broker.request_execution(slot, root, socket_path, argv, pins, self.deadline_ns)
            self.sock = _accept(self.listener, self.deadline_ns)
            self.peer, self.step_id = kernel_peer(self.sock, authority, authority.runtime_receipt['job_id'],
                expected_exe_sha=authority.assets['native_elf']['sha256'], native_peer=True, expected_argv=argv)
            self.identity = dict(self.peer.identity)
            confirmed = broker.bind_execution(slot, self.identity, self.step_id, self.deadline_ns)
            self.execution_join = _execution_join(authority, slot, self.identity, self.step_id, confirmed)
            self.phase = 'bound'
            if not defer_hello:
                self.receive_hello()
        except BaseException:
            self.close(); raise

    def receive_hello(self):
        release.check(self.phase == 'bound', 'Consume native HELLO exactly once')
        self._until('hello', 0, self.deadline_ns)
        row = self.rows[-1]
        release.check(row['text'] == self.slot['nonce']
                      and row['values'][1] == self.identity['pid']
                      and row['values'][2] == self.identity['uid'], 'Native hello/controller binding')
        # The timestamp is C's emission, never our delayed consumption time.
        self.deadline_ns = min(self.deadline_ns, row['ns']+native.SETUP_NS)
        remaining(self.deadline_ns)
        self.phase = 'hello'
        self.journal.append('native_ready', {'identity':self.identity, 'step_id':self.step_id,
            'nonce':self.slot['nonce'], 'native_sha256':self.authority.assets['native_elf']['sha256']})

    def authenticate(self):
        _execution_slot(self.authority, self.slot)
        release.check(self.phase == 'hello', 'Authenticate once after both HELLO controllers are ready')
        bootstrap_deadline = self.deadline_ns
        self._command('auth'); self._until('authenticated', 0, bootstrap_deadline)
        begun = [r for r in self.rows if r['event'] == 'begin' and r['actor'] == 'controller']
        release.check(len(begun) == 1 and begun[0]['ns'] < begun[0]['values'][1]
                      <= begun[0]['ns']+native.WORKER_TOTAL_NS, 'Native fixed lifetime origin')
        self.deadline_ns = min(self.run_deadline_ns, begun[0]['values'][1]); self.phase = 'idle'
        remaining(self.deadline_ns)

    def _command(self, action, case=None):
        _execution_slot(self.authority, self.slot)
        remaining(min(self.deadline_ns, self.run_deadline_ns))
        self.seq += 1
        raw = native.encode_command(action, seq=self.seq, nonce=self.slot['nonce'], case_id=case)
        release.check(self.sock.send(raw, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == len(raw), 'Short native command')
        self.journal.append('native_command', {'action': action, 'case_id': case, 'seq': self.seq,
                                             'packet_sha256': release.sha(raw)})

    def _one(self, deadline_ns):
        _execution_slot(self.authority, self.slot)
        deadline_ns = min(deadline_ns, self.deadline_ns, self.run_deadline_ns)
        poll = select.poll(); poll.register(self.sock.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
        while not poll.poll(int(remaining(deadline_ns, .05)*1000)):
            _execution_slot(self.authority, self.slot)
        raw, anc, flags, _ = self.sock.recvmsg(native.FRAME.size+1, 64)
        rights = []
        # Retain every delivered FD before validating any ancillary header.
        for level, kind, data in anc:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                count = len(data) // 4
                rights.extend(struct.unpack(str(count)+'i', data[:count*4]))
        try:
            release.check(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'Truncated native frame')
            for level, kind, data in anc:
                release.check(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS and len(data) % 4 == 0,
                              'Unexpected native ancillary')
            row = native.decode_frame(raw)
            release.check(len(rights) == native.FD_EVENTS.get(row['event'], 0), 'Exact native pidfd event roster')
            key = (0 if row['role'] == 1 else row['case_index'], row['role'])
            last = self.actor_last.get(key, (0, 0))
            release.check(row['seq'] > last[0] and row['ns'] >= last[1]
                          and len(self.rows) < native.MAX_FRAMES, 'Native replay/overflow')
            self.actor_last[key] = row['seq'], row['ns']
            if rights:
                release.check(row['case_index'] == self.next_case+1, 'Foreign case pidfd')
                fd = rights.pop(); handle = None
                try:
                    pid = site.pidfd_task(fd)
                    release.check(pid > 0 and row['event'] not in self.handles, 'Dead/duplicate native role pidfd')
                    handle = self.host.track(pid, self.authority.owner['owner_uid'],
                                             site.CGBASE+'/job_'+self.authority.runtime_receipt['job_id']+'/step_'+self.step_id)
                    release.check(site.pidfd_task(fd) == pid, 'Pidfd task changed during bind')
                    self.handles[row['event']] = handle
                    self.journal.append('native_pidfd_binding', {'case_index': row['case_index'],
                        'event': row['event'], 'host_identity': dict(handle.identity), 'pidfd_observed': site.pidfd_task(fd) == pid})
                except BaseException:
                    if handle is not None and row['event'] not in self.handles:
                        handle.close()
                    raise
                finally:
                    os.close(fd)
            self.rows.append(row); self.journal.append('native_frame', row)
            release.check(row['event'] != 'failed', 'Native failure; stop dispatch permanently')
            if row['event'] == 'payload_fd':
                self._payload_ack(self.handles['payload_fd'], row)
            return row
        finally:
            for fd in rights:
                os.close(fd)

    def _payload_ack(self, payload, row):
        release.check(self.phase == 'running' and 'judge_fd' in self.handles, 'Payload must be paused during W identity bind')
        judge = self.handles['judge_fd']
        pid = payload.identity['pid']; parent = judge.identity['pid']
        raw = runtime.read_proc('/proc/'+str(pid)+'/stat', 16384).decode()
        ppid = int(raw.rsplit(')', 1)[1].split()[1])
        namespaces = {n: os.readlink('/proc/'+str(pid)+'/ns/'+n) for n in ('user', 'pid', 'mnt', 'net')}
        judge_ns = {n: os.readlink('/proc/'+str(parent)+'/ns/'+n) for n in namespaces}
        release.check(ppid == parent and namespaces == judge_ns
                      and namespaces['pid'] != os.readlink('/proc/'+str(self.identity['pid'])+'/ns/pid')
                      and self.host.executable_info(pid)['sha256'] == self.authority.assets['native_elf']['sha256']
                      and not payload.state()['exited'] and not judge.state()['exited'], 'W payload identity/ancestry/new namespace bind failed')
        context = self.host.context(); index = row['case_index']
        binding = {'manifest_sha256': release.object_sha(self.authority.manifest), 'worker_id': self.slot['worker_id'],
                   'execution_role_id': self.slot['role_id'], 'execution_nonce': self.slot['nonce'],
                   'case_index': index, 'node': context['node'], 'boot_id': context['boot_id'],
                   'time_namespace': context['time_namespace'], 'payload': dict(payload.identity),
                   'parent': dict(judge.identity), 'namespaces': namespaces, 'bound_ns': time.monotonic_ns()}
        key = key_bytes(self.authority.root/('key-'+self.slot['worker_id']))
        runtime.publish(self.authority.root/('payload-bound-'+self.slot['worker_id']+'-'+str(index)+'.json'), seal(binding, key))
        prepare = [r for r in self.rows[self.case_start:] if r['actor'] == 'controller' and r['event'] == 'prepare']
        release.check(len(prepare) == 1, 'Bound native service deadline required for payload ACK')
        deadline = min(self.case_deadline, self.deadline_ns, self.run_deadline_ns, prepare[0]['values'][3])
        for worker in batch.WORKERS:
            path = self.authority.root/('payload-bound-'+worker+'-'+str(index)+'.json')
            packet = runtime.wait_object(path, deadline)
            other = authenticate(packet, key_bytes(self.authority.root/('key-'+worker)))
            expected = batch.role_for(self.authority.manifest, 'E'+str(batch.WORKERS.index(worker)+1))
            release.check(other['manifest_sha256'] == binding['manifest_sha256'] and other['case_index'] == index
                          and other['worker_id'] == worker and other['execution_role_id'] == expected['role_id']
                          and other['execution_nonce'] == expected['nonce']
                          and all(other[k] == binding[k] for k in ('node', 'boot_id', 'time_namespace')),
                          'Both workers must bind paused payloads in the same host epoch before ACK')
        remaining(deadline)  # ACK barrier expiry is infrastructure_error.
        release.check(not payload.state()['exited'], 'Payload exited before bound ACK')
        self.journal.append('payload_identity_bound_before_release', binding)
        self._command('payload_ack', native.CASES[index-1])

    def _until(self, event, case_index, deadline_ns):
        while True:
            row = self._one(deadline_ns)
            release.check(row['case_index'] in (0, case_index), 'Cross-case native frame')
            if row['event'] == event:
                release.check(row['case_index'] == case_index, 'Wrong native event case')
                return row

    def start_case(self, case_id, request_sha256, deadline_ns):
        _execution_slot(self.authority, self.slot); release.digest(request_sha256)
        release.check(self.phase == 'idle' and self.next_case < 3
                      and case_id == native.CASES[self.next_case], 'One case per worker; fixed order; no retry')
        self.phase = 'prepare'; self.case_start = len(self.rows)
        self.case_deadline = min(deadline_ns, self.deadline_ns, self.run_deadline_ns, time.monotonic_ns()+native.CASE_TOTAL_NS)
        self._command('prepare', case_id)
        armed = self._until('armed', self.next_case+1, self.case_deadline)
        release.check(armed['values'][1:4] == [1, 0, 1] and set(self.handles) == {'created', 'judge_fd'},
                      'Fresh I/J with filter, NNP, zero capabilities required before payload')
        limit = [r for r in self.rows[self.case_start:] if r['event'] == 'limit']
        release.check(len(limit) == 1 and limit[0]['values'][1:5] == [0, -1, 32, 32], 'Locked private32 not P8')
        peers = [r for r in self.rows[self.case_start:] if r['event'] == 'peer'
                 and r['actor'] == 'controller' and r['case_index'] == self.next_case+1]
        release.check(len(peers) == 1, 'One current-case controller PEER frame required')
        peer = peers[0]
        values = peer['values']
        release.check(peer['text'] == 'factory-exe-cgroup-pidfd' and len(values) >= 6
                      and all(type(values[i]) is int and values[i] > 0 for i in (1, 4))
                      and values[2] == self.authority.uid and values[5] == values[1],
                      'Native outer factory/runtime peer binding differs')
        self.phase = 'armed'; self.request_sha256 = request_sha256
        return {'case_id': case_id, 'request_sha256': request_sha256,
                'roles': {k: dict(h.identity) for k, h in self.handles.items()}, 'armed': armed,
                'outer': {'factory': values[1], 'runtime': values[4]}, 'outer_evidence':deepcopy(peer)}

    def run_case(self, case_id, deadline_ns):
        _execution_slot(self.authority, self.slot)
        release.check(self.phase == 'armed' and native.CASES[self.next_case] == case_id, 'Only armed fixed case')
        self.phase = 'running'; self._command('start', case_id)
        self._until('case_finish', self.next_case+1, min(deadline_ns, self.case_deadline))
        self.phase = 'case_cleanup'
        self._until('idle', self.next_case+1, min(deadline_ns, self.case_deadline))
        release.check(set(self.handles) == {'created', 'judge_fd', 'payload_fd'}, 'Full I/J/payload pidfd roster')
        states = {k: h.state() for k, h in self.handles.items()}
        release.check(all(s['exited'] is True and s['registered_process_reaped'] is True for s in states.values()),
                      'Exit alone is not case reap')
        rows = self.rows[self.case_start:]
        exits = [r for r in rows if r['event'] == 'pidfd_exit' and r['actor'] == 'controller']
        outer = [r for r in rows if r['event'] == 'outer_reap' and r['actor'] == 'controller']
        finish = [r for r in rows if r['event'] == 'case_finish']
        release.check(len(exits) == len(finish) == 1 and exits[0]['values'][1:4] == [1, 1, 1]
                      and finish[0]['values'][1:4] == [1, 0, self.identity['pid']]
                      and outer and all(r['values'][2] == 0 for r in outer) and not self.peer.state()['exited'],
                      'Full case-owned reaping with persistent live C required')
        receipt = {'case_id': case_id, 'request_sha256': self.request_sha256, 'states': states,
                   'native_frames_sha256': release.object_sha(rows), 'persistent_C_live': True,
                   'whole_E_empty_asserted': False}
        for handle in self.handles.values():
            handle.close()
        self.handles = {}; self.next_case += 1; self.phase = 'idle'; self.last_receipt = receipt
        return receipt

    def stop(self, deadline_ns):
        _execution_slot(self.authority, self.slot)
        release.check(self.phase == 'idle' and self.next_case == 3 and not self.handles, 'Drain only after all fixed cases reaped')
        self.phase = 'draining'; self._command('stop')
        stopped = self._until('stopped', 0, min(deadline_ns, self.run_deadline_ns, time.monotonic_ns()+native.STOP_NS))
        while not self.peer.state()['registered_process_reaped']:
            time.sleep(remaining(min(deadline_ns, self.deadline_ns), .005))
        release.check(stopped['values'][1:3] == [1, 3], 'Incomplete native stop')
        self.phase = 'stopped'
        return {'C': dict(self.identity), 'state': self.peer.state(), 'stopped': stopped}

    def wait_launcher(self, deadline_ns):
        # D is the real srun parent. Its wait record is evidence; W cannot reap
        # another process's child or invent a local wait result.
        _execution_slot(self.authority, self.slot)
        deadline_ns = min(deadline_ns, self.run_deadline_ns)
        remaining(deadline_ns)
        code = self.broker.wait_execution(self.slot, deadline_ns)
        release.check(type(code) is int and code == 0, 'Native srun failed; no automatic retry')
        trace = release.read(self.root/'worker.trace.bin', native.MAX_FRAMES*native.FRAME.size,
                             private=True, deadline_ns=deadline_ns)
        return native.verify_trace(trace, nonce=self.slot['nonce'])

    def close(self):
        for handle in self.handles.values():
            handle.close()
        self.handles = {}
        if self.peer is not None:
            self.peer.close(); self.peer = None
        for sock in (self.sock, self.listener):
            if sock is not None:
                sock.close()
        self.sock = self.listener = None
        # On failure never kill guessed jobs/C or auto-resubmit. Native parent
        # liveness guards and Slurm no-requeue/walltime remain the bounded stop.
