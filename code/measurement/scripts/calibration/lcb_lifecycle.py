"""Linux cell-scoped shutdown. No model imports, no global kill or GPU reset.

Only the owner-run collector uses LinuxHost. Tests inject a virtual host/clock.
Signals use pidfds, after rechecking start ticks, UID, cgroup and cell membership.
"""
from dataclasses import asdict, dataclass
import csv
import io
import os
from pathlib import Path
import re
import signal
import subprocess
import time

PROTOCOL = 'cell-release-v1'
POLICY = {'graceful_s': 60., 'term_s': 15., 'kill_s': 15.,
          'barrier_s': 120., 'poll_s': .5, 'memory_tolerance_mib': 0.}


class OwnershipError(RuntimeError):
    pass


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    pgid: int
    sid: int
    start_ticks: int
    uid: int
    cgroup: str
    state: str

    @property
    def identity(self):
        return self.pid, self.start_ticks, self.uid, self.cgroup

    @property
    def alive(self):
        return self.state not in ('Z', 'X', 'x')


def parse_stat(text):
    # comm can contain spaces and parentheses; fields after its final ')' start
    # at field 3 (state), and starttime is field 22.
    head, tail = text.rsplit(')', 1)
    pid = int(head.split('(', 1)[0].strip())
    fields = tail.split()
    return pid, fields[0], int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19])


def unified_cgroup(text):
    rows = [line[3:] for line in text.splitlines() if line.startswith('0::')]
    if len(rows) != 1 or not rows[0].startswith('/'):
        raise OwnershipError('Require visible unified cgroup v2 path')
    return rows[0]


def in_scope(path, parent):
    return path == parent or path.startswith(parent.rstrip('/') + '/')


class LinuxHost:
    def __init__(self, gpu_uuid):
        if not re.fullmatch(r'GPU-[0-9a-fA-F-]+', gpu_uuid):
            raise OwnershipError('Explicit full GPU UUID required')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise OwnershipError('Linux pidfd support required; no unsafe PID fallback')
        self.gpu_uuid = gpu_uuid
        self.uid, self.self_pid = os.getuid(), os.getpid()
        self.cgroup = unified_cgroup(Path('/proc/self/cgroup').read_text())
        job = os.environ.get('SLURM_JOB_ID', '')
        if not job.isdigit() or ('/job_' + job + '/') not in self.cgroup + '/':
            raise OwnershipError('Collector cgroup does not identify the current Slurm job')
        self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.pid_namespace = os.readlink('/proc/self/ns/pid')
        fd = os.pidfd_open(self.self_pid)
        os.close(fd)  # Capability probe only, never signal the controller.

    def read(self, pid):
        path = Path('/proc') / str(pid)
        try:
            first = parse_stat((path/'stat').read_text())
            uid = path.stat().st_uid
            cgroup = unified_cgroup((path/'cgroup').read_text())
            last = parse_stat((path/'stat').read_text())
        except (FileNotFoundError, ProcessLookupError):
            return None
        if first[0] != last[0] or first[-1] != last[-1]:
            raise OwnershipError('PID changed while reading /proc')
        p, state, parent, group, session, start = last
        return Process(p, parent, group, session, start, uid, cgroup, state)

    def processes(self):
        result = []
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                # Inspect membership before reading UID/cgroup of other users.
                fields = parse_stat((path/'stat').read_text())
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            result.append(fields)
        return result

    def signal_process(self, expected, sig):
        if expected.pid == self.self_pid or expected.uid != self.uid or not in_scope(expected.cgroup, self.cgroup):
            raise OwnershipError('Refuse controller/foreign process signal')
        current = self.read(expected.pid)
        if current is None or not current.alive:
            return False
        if current.identity != expected.identity or (current.sid, current.pgid) != (expected.sid, expected.pgid):
            raise OwnershipError('Process identity/scope changed before signal')
        try:
            fd = os.pidfd_open(expected.pid)
        except ProcessLookupError:
            return False
        try:
            again = self.read(expected.pid)
            if again is None:
                return False
            if again.identity != expected.identity or (again.sid, again.pgid) != (expected.sid, expected.pgid):
                raise OwnershipError('PID reused during pidfd acquisition')
            signal.pidfd_send_signal(fd, sig)
            return True
        except ProcessLookupError:
            return False
        finally:
            os.close(fd)

    def gpu(self):
        base = ['nvidia-smi', '-i', self.gpu_uuid]
        self.last_gpu_observation = {'wall_ns': time.time_ns(), 'gpu_uuid': self.gpu_uuid,
                                     'query_status': 'incomplete', 'queries': []}
        responses = []
        for query in ('--query-compute-apps=pid,used_memory', '--query-gpu=uuid,memory.used'):
            command = base + [query, '--format=csv,noheader,nounits']
            try:
                response = subprocess.run(command,capture_output=True,text=True,timeout=5,check=False)
            except subprocess.TimeoutExpired:
                self.last_gpu_observation['queries'].append({'command':command,'error':'timeout'})
                raise OwnershipError('nvidia-smi observation timed out')
            self.last_gpu_observation['queries'].append({'command':command,'returncode':response.returncode,
                                                         'stdout':response.stdout,'stderr':response.stderr})
            if response.returncode:
                raise OwnershipError('nvidia-smi query failed; raw diagnostics preserved')
            responses.append(response)
        a,b = responses
        apps = []
        for row in csv.reader(io.StringIO(a.stdout)):
            if not row or not any(x.strip() for x in row):
                continue
            if len(row) != 2 or not row[0].strip().isdigit():
                raise OwnershipError('Unparseable GPU process observation')
            memory = float(row[1].strip())
            if not 0 <= memory < 10**9:
                raise OwnershipError('Invalid GPU process memory observation')
            apps.append({'pid': int(row[0]), 'used_memory_mib': memory})
        rows = list(csv.reader(io.StringIO(b.stdout.strip())))
        if len(rows) != 1 or len(rows[0]) != 2 or rows[0][0].strip() != self.gpu_uuid:
            raise OwnershipError('GPU identity changed')
        memory = float(rows[0][1].strip())
        if not 0 <= memory < 10**9:
            raise OwnershipError('Invalid device memory observation')
        result = {'wall_ns': time.time_ns(), 'gpu_uuid': self.gpu_uuid, 'apps': apps,
                'memory_used_mib': memory, 'raw_compute_apps': a.stdout, 'raw_gpu': b.stdout,
                'query_compute_apps': 'pid,used_memory; csv,noheader,nounits'}
        self.last_gpu_observation=result
        return result


class CellLifecycle:
    def __init__(self, host, baseline, *, clock=time.monotonic, wall=time.time_ns, sleep=time.sleep, policy=None,
                 observe_clock_ns=time.perf_counter_ns):
        self.host, self.baseline = host, baseline
        self.clock, self.wall, self.sleep = clock, wall, sleep
        self.policy = dict(POLICY if policy is None else policy)
        self.root = None
        self.known = {}
        self.events, self.errors = [], []
        self.last_live = []
        self.last_gpu = baseline
        self.result = None
        self.observe_clock_ns = observe_clock_ns
        self.observe_durations_ns = []
        if baseline['apps']:
            raise OwnershipError('GPU occupied before this cell; do not launch or kill occupants')
        if not 0 <= baseline['memory_used_mib'] <= 64:
            raise OwnershipError('Unexpected pre-cell GPU memory; do not treat it as an idle baseline')

    def attach(self, pid):
        try:
            root = self.host.read(pid)
        except Exception as exc:
            self.errors.append('Root identity unavailable: ' + str(exc))
            raise
        if (root is None or root.pid == self.host.self_pid or root.ppid != self.host.self_pid or root.uid != self.host.uid or
            not in_scope(root.cgroup, self.host.cgroup) or root.sid != pid or root.pgid != pid):
            self.errors.append('Unable to establish new cell SID/PGID identity')
            raise OwnershipError(self.errors[-1])
        self.root = root
        self.known[root.pid] = root
        self.events.append({'event': 'attached', 'wall_ns': self.wall(), 'root': asdict(root)})

    def member(self, process):
        return self.root is not None and (process.sid == self.root.sid or process.pgid == self.root.pgid)

    def register(self, process):
        if (self.root is None or process.pid == self.host.self_pid or process.uid != self.host.uid or
            not in_scope(process.cgroup, self.host.cgroup) or process.start_ticks < self.root.start_ticks or
            not self.member(process)):
            raise OwnershipError('Unconfirmed process in cell scope')
        previous = self.known.get(process.pid)
        if previous and (previous.identity != process.identity or
                         (previous.sid, previous.pgid) != (process.sid, process.pgid)):
            raise OwnershipError('Recorded PID identity or session changed')
        if not previous:
            self.events.append({'event': 'discovered', 'wall_ns': self.wall(), 'process': asdict(process)})
        self.known[process.pid] = process

    def observe(self):
        # Separate measurement clock: no changes to lifecycle deadlines or decisions.
        began = self.observe_clock_ns()
        try:
            return self._observe()
        finally:
            self.observe_durations_ns.append(self.observe_clock_ns() - began)

    def _observe(self):
        if self.errors:
            raise OwnershipError(self.errors[-1])
        try:
            # Check every recorded identity even if it changed SID/PGID.
            for old in list(self.known.values()):
                current = self.host.read(old.pid)
                if current is not None:
                    self.register(current)
            if self.root is not None:
                for pid, state, ppid, pgid, sid, start in self.host.processes():
                    if sid == self.root.sid or pgid == self.root.pgid:
                        process = self.host.read(pid)
                        if process is not None:
                            self.register(process)
            live = []
            for pid in list(self.known):
                current = self.host.read(pid)
                if current is not None:
                    self.register(current)  # Recheck races after enumeration.
                    if current.alive:
                        live.append(current)
            self.last_live = [p.pid for p in live]
            return live
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ': ' + str(exc))
            raise

    def snapshot(self):
        live = self.observe()
        try:
            self.last_gpu = self.host.gpu()
        except Exception:
            self.last_gpu = getattr(self.host,'last_gpu_observation',self.last_gpu)
            raise
        for app in self.last_gpu['apps']:
            pid = app['pid']
            process = self.host.read(pid)
            if process is not None:
                self.register(process)
            elif pid not in self.known:
                raise OwnershipError('Unknown GPU process; no signal permitted')
        # A stale NVML PID is still a barrier: wait for it to disappear.
        clean = (not live and not self.last_gpu['apps'] and
                 self.last_gpu['memory_used_mib'] <= self.baseline['memory_used_mib'] + self.policy['memory_tolerance_mib'])
        return clean

    def wait(self, seconds, reap):
        deadline = self.clock() + seconds
        clean_observations = 0
        while True:
            reap()
            if self.snapshot():
                clean_observations += 1
                if clean_observations >= 2:
                    return True
            else:
                clean_observations = 0
            if self.clock() >= deadline:
                return False
            self.sleep(min(self.policy['poll_s'], deadline-self.clock()))

    def signal_members(self, sig):
        live = self.observe()
        # No process-group broadcast: pidfd targets are identity-checked, so a
        # recycled PID or foreign process cannot be swept into killpg.
        for process in sorted(live, key=lambda p: p.pid == self.root.pid):
            sent = self.host.signal_process(process, sig)
            self.events.append({'event': 'signal', 'wall_ns': self.wall(), 'pid': process.pid,
                                'start_ticks': process.start_ticks, 'signal': int(sig), 'sent': sent})

    def close(self, stop, reap):
        if self.result is not None:
            return self.result
        began = self.wall()
        released = False
        try:
            try:
                result = stop()  # Nonblocking stop request + stdin close.
            except (OSError, ValueError) as exc:
                result = {'pipe_error': type(exc).__name__ + ': ' + str(exc)}
            self.events.append({'event': 'stop_requested', 'wall_ns': self.wall(), 'result': result})
            released = self.wait(self.policy['graceful_s'], reap)
            for sig, seconds in ((signal.SIGTERM, self.policy['term_s']), (signal.SIGKILL, self.policy['kill_s'])):
                if released:
                    break
                self.signal_members(sig)
                released = self.wait(seconds, reap)
            if not released:
                released = self.wait(self.policy['barrier_s'], reap)
        except Exception as exc:
            message = type(exc).__name__ + ': ' + str(exc)
            if message not in self.errors:
                self.errors.append(message)
        if not released and not self.errors:
            self.errors.append('Release deadlines exhausted; backend processes or GPU resources still present')
        self.result = {'lifecycle_protocol': PROTOCOL, 'release_status': 'released' if released else 'timeout',
            'engine_release_wall_ns': self.wall() if released else None, 'release_check_end_wall_ns': self.wall(),
            'release_check_start_wall_ns': began, 'release_observation_semantics': 'confirmed_absence_at_barrier_not_exact_exit',
            'backend_attached': self.root is not None, 'required_clean_observations': 2,
            'host_boot_id':getattr(self.host,'boot_id',None),'host_pid_namespace':getattr(self.host,'pid_namespace',None),
            'tracked_processes': [asdict(p) for p in self.known.values()],
            'remaining_backend_pids':self.last_live,
            'observe_timing': {'schema': 'lcb-observe-timing-v1', 'clock': 'perf_counter_ns', 'unit': 'ns',
                'durations_ns': list(self.observe_durations_ns), 'count': len(self.observe_durations_ns),
                'total_ns': sum(self.observe_durations_ns),
                'max_ns': max(self.observe_durations_ns, default=None),
                'scope': 'All observe calls from backend startup through release, including failed calls; '
                         'process discovery and identity checks only, excluding NVML queries, sleeps and signals. '
                         'Do not subtract this sum from engine times or generation windows.'},
            'last_nvidia_smi': self.last_gpu, 'baseline_nvidia_smi': self.baseline,
            'policy': self.policy, 'events': self.events, 'errors': self.errors}
        return self.result
