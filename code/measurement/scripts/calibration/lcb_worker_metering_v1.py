"""Persistent-worker CPU accounting; no launcher, registration, or cgroup writes.

Synthetic points are conditional on supplied observations. Collected lifetime
points are blocked: no complete no-admin endpoint protocol is established.
A callback cannot lift that acquisition blocker. See the worker-metering-v1
contract. This module deliberately does not import lcb_cpu.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import time
from typing import Callable
import uuid


SCHEMA = "worker-metering-v1"
PHASES = ("setup", "service", "standby", "cleanup", "tail")
REQUIRED_PHASES = {"setup", "service", "cleanup", "tail"}
PACKAGE_STATUS = "blocked_no_admin_lifetime_endpoints"
ENDPOINT_BLOCKER_ID = "M-ENDPOINT-001"
GATES = {
    "runtime_registered": False,
    "trusted_probe_authorized": False,
    "candidate_execution_authorized": False,
    "main_matrix_authorized": False,
    "cost_sample_eligible": False,
}


def endpoint_status():
    """An acquisition blocker, not a pending signature-verifier implementation."""
    return {
        "blocker_id": ENDPOINT_BLOCKER_ID,
        "status": PACKAGE_STATUS,
        "ready_for_field": False,
        "collected_lifetime_point_supported": False,
        "callback_scope": "synthetic_only",
        "missing_proof_obligations": [
            "whole_domain_birth_and_bootstrap_provenance",
            "complete_final_counter_before_or_across_slurm_deletion",
            "collector_bootstrap_and_post_last_read_cpu_tail",
            "authenticated_acquisition_protocol_under_existing_no_admin_authority",
        ],
    }


def _nat(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonempty text")


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("A SHA-256 receipt digest is required")


def _rows(raw):
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        if (len(fields) != 2 or fields[0] in result
                or not re.fullmatch(r"[0-9]+", fields[1])):
            raise ValueError("Malformed or duplicate counter row")
        result[fields[0]] = int(fields[1])
    return result


def parse_cpu_stat(raw):
    if not isinstance(raw, str):
        raise ValueError("Raw cpu.stat text is required")
    rows = _rows(raw)
    if "usage_usec" not in rows:
        raise ValueError("Missing usage_usec")
    return rows["usage_usec"]


@dataclass(frozen=True)
class CollectorContext:
    node: str
    boot_id: str
    mount_id: str
    mount_namespace: str
    cgroup_namespace: str
    source: str = "cgroup2"

    def __post_init__(self):
        for key, value in asdict(self).items():
            _text(value, key)
        if self.source not in {"cgroup2", "synthetic"}:
            raise ValueError("Unknown collector source")


@dataclass(frozen=True)
class DomainIdentity:
    context: CollectorContext
    path: str
    device: int
    inode: int
    cpu_stat_device: int
    cpu_stat_inode: int
    handle_epoch: str

    def __post_init__(self):
        path = PurePosixPath(self.path)
        if (not path.is_absolute() or str(path) != self.path
                or ".." in path.parts or self.path.startswith("//")):
            raise ValueError("Canonical absolute domain path required")
        for key in ("device", "inode", "cpu_stat_device", "cpu_stat_inode"):
            _nat(getattr(self, key), key)
        _text(self.handle_epoch, "handle_epoch")

    @property
    def fingerprint(self):
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    identity: DomainIdentity
    started_ns: int
    finished_ns: int
    usage_usec: int | None
    populated_before: bool | None
    populated_after: bool | None
    raw_cpu_stat: str | None
    error: str | None = None
    raw_events_before: str | None = None
    raw_events_after: str | None = None

    def __post_init__(self):
        _text(self.snapshot_id, "snapshot_id")
        _nat(self.started_ns, "started_ns")
        _nat(self.finished_ns, "finished_ns")
        if self.finished_ns < self.started_ns:
            raise ValueError("Snapshot clock reversed")
        for state in (self.populated_before, self.populated_after):
            if state is not None and type(state) is not bool:
                raise ValueError("Populated observations must be bool or null")
        if self.usage_usec is None:
            _text(self.error, "missing counter error")
        else:
            _nat(self.usage_usec, "usage_usec")
            if self.error is not None or parse_cpu_stat(self.raw_cpu_stat) != self.usage_usec:
                raise ValueError("Counter and raw cpu.stat disagree")
            for raw, state in ((self.raw_events_before, self.populated_before),
                               (self.raw_events_after, self.populated_after)):
                if raw is None and self.identity.context.source == "cgroup2":
                    raise ValueError("Collected endpoints require raw cgroup.events")
                if raw is not None:
                    value = _rows(raw).get("populated")
                    if value not in (0, 1) or state is not bool(value):
                        raise ValueError("Raw populated observation disagrees")


def _open_dir(path):
    """Walk every component without following symlinks, including ancestors."""
    canonical = PurePosixPath(str(path))
    if (not canonical.is_absolute() or str(canonical) != str(path)
            or ".." in canonical.parts or str(path).startswith("//")):
        raise ValueError("Canonical absolute domain path required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in canonical.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(fd, name):
    child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
    try:
        stat = os.fstat(child)
        data = os.read(child, 65537)
        if len(data) > 65536:
            raise ValueError("Oversized cgroup file")
        return data.decode("ascii"), (stat.st_dev, stat.st_ino)
    finally:
        os.close(child)


def _file_identity_at(fd, name):
    child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
    try:
        stat = os.fstat(child)
        return stat.st_dev, stat.st_ino
    finally:
        os.close(child)


def _live_context(domain_fd):
    # fdinfo identifies the actual mount behind the pinned handle, including
    # stacked mounts. A longest-path guess from mountinfo is insufficient.
    ids = [line.split(":", 1)[1].strip()
           for line in Path(f"/proc/self/fdinfo/{domain_fd}").read_text().splitlines()
           if line.startswith("mnt_id:")]
    if len(ids) != 1 or not ids[0].isdigit():
        raise ValueError("Missing pinned-descriptor mount identity")
    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        if fields[0] == ids[0]:
            matches.append(after.split()[0])
    if matches != ["cgroup2"]:
        raise ValueError("Domain is not on a cgroup v2 mount")
    def ns(name):
        stat = os.stat("/proc/self/ns/" + name)
        return f"{stat.st_dev}:{stat.st_ino}"
    return CollectorContext(
        os.uname().nodename, Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        ids[0], ns("mnt"), ns("cgroup"),
    )


class ReadOnlyCpuDomain:
    """Pin an existing domain for one uninterrupted epoch, never recreate it.

    fixture_context must explicitly have source='synthetic'. The normal hook
    checks Linux mount/boot/namespace identity on every snapshot. No hook is
    invoked on import; callers must separately obtain runtime authorization.
    """
    def __init__(self, path, *, fixture_context=None):
        self.path = str(path)
        if fixture_context is not None and fixture_context.source != "synthetic":
            raise ValueError("Fixture context must be marked synthetic")
        self._fixture = fixture_context
        self._fd = _open_dir(self.path)
        self._sequence = 0
        try:
            context = fixture_context or _live_context(self._fd)
            stat = os.fstat(self._fd)
            _, counter_identity = _read_at(self._fd, "cpu.stat")
            kind, _ = _read_at(self._fd, "cgroup.type")
            if kind.strip() != "domain":
                raise ValueError("Only hierarchical domain cgroups are supported")
            self.identity = DomainIdentity(context, self.path, stat.st_dev, stat.st_ino,
                                           *counter_identity, uuid.uuid4().hex)
            self._check_binding()
        except BaseException:
            self.close()
            raise

    def _check_binding(self):
        if self._fd is None:
            raise ValueError("Collector handle is closed")
        live = _open_dir(self.path)
        try:
            stat = os.fstat(live)
            if (stat.st_dev, stat.st_ino) != (self.identity.device, self.identity.inode):
                raise ValueError("Domain deleted or replaced")
            file_id = _file_identity_at(live, "cpu.stat")
            if file_id != (self.identity.cpu_stat_device, self.identity.cpu_stat_inode):
                raise ValueError("cpu.stat endpoint replaced")
            kind, _ = _read_at(live, "cgroup.type")
            if kind.strip() != "domain":
                raise ValueError("Domain changed cgroup type")
            if self._fixture is None and _live_context(live) != self.identity.context:
                raise ValueError("Boot, mount, or namespace identity changed")
        finally:
            os.close(live)

    def snapshot(self):
        start = time.monotonic_ns()
        self._sequence += 1
        usage = raw = before = after = error = None
        raw_before = raw_after = None
        try:
            self._check_binding()
            raw_before, _ = _read_at(self._fd, "cgroup.events")
            before_rows = _rows(raw_before)
            raw, file_id = _read_at(self._fd, "cpu.stat")
            if file_id != (self.identity.cpu_stat_device, self.identity.cpu_stat_inode):
                raise ValueError("cpu.stat endpoint replaced during read")
            usage = parse_cpu_stat(raw)
            raw_after, _ = _read_at(self._fd, "cgroup.events")
            after_rows = _rows(raw_after)
            if any(rows.get("populated") not in (0, 1) for rows in (before_rows, after_rows)):
                raise ValueError("Missing populated observation")
            before, after = bool(before_rows["populated"]), bool(after_rows["populated"])
            self._check_binding()
        except (OSError, ValueError, UnicodeError) as exc:
            # Retain an explicit failed endpoint; never turn disappearance into zero.
            usage = None
            error = f"{type(exc).__name__}: {exc}"
        return Snapshot(f"{self.identity.handle_epoch}:{self._sequence}", self.identity,
                        start, time.monotonic_ns(), usage, before, after, raw, error,
                        raw_before, raw_after)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@dataclass(frozen=True)
class Window:
    window_id: str
    phase: str
    start_snapshot: str
    end_snapshot: str

    def __post_init__(self):
        for name in ("window_id", "start_snapshot", "end_snapshot"):
            _text(getattr(self, name), name)
        if self.phase not in PHASES:
            raise ValueError("Unknown cost phase")


@dataclass(frozen=True)
class BoundaryReceipt:
    snapshot_id: str
    identity_fingerprint: str
    fence_ns: int
    receipt_sha256: str

    def __post_init__(self):
        _text(self.snapshot_id, "snapshot_id")
        _digest(self.identity_fingerprint)
        _digest(self.receipt_sha256)
        _nat(self.fence_ns, "fence_ns")


@dataclass(frozen=True)
class CpuEnvelope:
    cpu_count: int
    start_ns: int
    end_ns: int
    receipt_sha256: str

    def __post_init__(self):
        _nat(self.cpu_count, "cpu_count")
        _nat(self.start_ns, "start_ns")
        _nat(self.end_ns, "end_ns")
        _digest(self.receipt_sha256)
        if self.cpu_count == 0 or self.end_ns < self.start_ns:
            raise ValueError("Invalid CPU envelope")


@dataclass(frozen=True)
class ResourceReading:
    metric: str
    value: int
    receipt_sha256: str

    def __post_init__(self):
        if self.metric not in {"memory_peak_bytes", "swap_peak_bytes", "gpu_usec", "energy_uj"}:
            raise ValueError("Unknown bootstrap resource metric")
        _nat(self.value, "resource value")
        _digest(self.receipt_sha256)


@dataclass(frozen=True)
class DomainLedger:
    domain_id: str
    owner: str
    snapshots: tuple[Snapshot, ...]
    windows: tuple[Window, ...]
    required_end_ns: int
    origin: BoundaryReceipt | None = None
    final: BoundaryReceipt | None = None
    envelope: CpuEnvelope | None = None
    bootstrap_resources: tuple[ResourceReading, ...] = ()
    purpose: str = "online"


# Retained for synthetic arithmetic regressions only. Authenticating an assertion
# cannot create missing origin/final measurements. Collected inputs fail closed
# even if a caller supplies a callback returning True.
EvidenceVerifier = Callable[[str, DomainIdentity, object], bool]


def _boundary(kind, receipt, snapshot, verifier):
    if receipt is None:
        return f"missing_{kind}_receipt"
    if (receipt.snapshot_id != snapshot.snapshot_id
            or receipt.identity_fingerprint != snapshot.identity.fingerprint):
        raise ValueError(f"{kind} receipt is bound to another endpoint")
    if receipt.fence_ns > snapshot.started_ns:
        return f"{kind}_fence_after_counter_read"
    if snapshot.usage_usec is None:
        return f"missing_{kind}_counter"
    if snapshot.populated_before is not False or snapshot.populated_after is not False:
        return f"{kind}_not_observed_quiescent"
    if kind == "origin" and snapshot.usage_usec != 0:
        return "origin_not_zero"
    if snapshot.identity.context.source != "synthetic":
        return ENDPOINT_BLOCKER_ID + ":collected_boundary_protocol_unavailable"
    if verifier is None or verifier(kind, snapshot.identity, receipt) is not True:
        return f"unverified_{kind}_receipt"
    return None


def _domain_report(ledger, verifier):
    _text(ledger.domain_id, "domain_id")
    _text(ledger.owner, "owner")
    _nat(ledger.required_end_ns, "required_end_ns")
    if ledger.purpose not in {"online", "offline_audit"}:
        raise ValueError("Unknown domain purpose")
    if len(ledger.snapshots) < 2 or not ledger.windows:
        raise ValueError("At least two snapshots and one window are required")
    first, last = ledger.snapshots[0], ledger.snapshots[-1]
    if ledger.required_end_ns < last.finished_ns:
        raise ValueError("Lifetime ends before last snapshot")
    if len({s.snapshot_id for s in ledger.snapshots}) != len(ledger.snapshots):
        raise ValueError("Duplicate snapshot ID")
    previous_usage = None
    for index, snapshot in enumerate(ledger.snapshots):
        if snapshot.identity != first.identity:
            raise ValueError("Domain/boot/handle identity changed or cross-case contamination")
        if index and snapshot.started_ns < ledger.snapshots[index - 1].finished_ns:
            raise ValueError("Overlapping or reversed snapshot reads")
        if snapshot.usage_usec is not None:
            if previous_usage is not None and snapshot.usage_usec < previous_usage:
                raise ValueError("CPU counter decreased")
            previous_usage = snapshot.usage_usec
    if len({w.window_id for w in ledger.windows}) != len(ledger.windows):
        raise ValueError("Duplicate window export")
    if len(ledger.windows) != len(ledger.snapshots) - 1:
        raise ValueError("Windows must exhaust the snapshot chain")
    phase_rows = {phase: [] for phase in PHASES}
    rows = []
    phase_order = {"setup": 0, "service": 1, "standby": 1, "cleanup": 2, "tail": 3}
    prior_phase = 0
    for window, start, end in zip(ledger.windows, ledger.snapshots, ledger.snapshots[1:]):
        if (window.start_snapshot, window.end_snapshot) != (start.snapshot_id, end.snapshot_id):
            raise ValueError("Window gap, overlap, or reordered endpoint")
        if phase_order[window.phase] < prior_phase:
            raise ValueError("Setup must precede service, then cleanup and tail")
        prior_phase = phase_order[window.phase]
        delta = None if start.usage_usec is None or end.usage_usec is None else end.usage_usec - start.usage_usec
        phase_rows[window.phase].append(delta)
        rows.append({"window_id": window.window_id, "phase": window.phase,
                     "start_snapshot": start.snapshot_id, "end_snapshot": end.snapshot_id,
                     "cpu_usec": delta, "status": "measured_delta" if delta is not None else "unidentified",
                     "wall_ns_bounds": [end.started_ns - start.finished_ns,
                                        end.finished_ns - start.started_ns]})
    phases = {phase: (None if any(v is None for v in values) else sum(values))
              for phase, values in phase_rows.items()}
    known = sum(row["cpu_usec"] for row in rows if row["cpu_usec"] is not None)
    delta_complete = all(row["cpu_usec"] is not None for row in rows)
    endpoint_delta = (None if first.usage_usec is None or last.usage_usec is None
                      else last.usage_usec - first.usage_usec)
    if delta_complete and endpoint_delta != known:
        raise ValueError("Window conservation failed")
    reasons = []
    if first.identity.context.source != "synthetic":
        reasons.append(ENDPOINT_BLOCKER_ID + ":no_reviewed_no_admin_acquisition")
    boundary_reasons = {}
    if not delta_complete:
        reasons.append("missing_window_counter")
    for kind, receipt, snapshot in (("origin", ledger.origin, first), ("final", ledger.final, last)):
        reason = _boundary(kind, receipt, snapshot, verifier)
        boundary_reasons[kind] = reason
        if reason:
            reasons.append(reason)
    missing_phases = REQUIRED_PHASES - {w.phase for w in ledger.windows}
    if missing_phases:
        reasons.append("missing_lifecycle_phases:" + ",".join(sorted(missing_phases)))
    readings = {}
    for reading in ledger.bootstrap_resources:
        if reading.metric in readings:
            raise ValueError("Duplicate bootstrap metric")
        readings[reading.metric] = asdict(reading)
    upper = None
    envelope = ledger.envelope
    if envelope is not None:
        if envelope.start_ns > first.started_ns or envelope.end_ns < ledger.required_end_ns:
            raise ValueError("CPU envelope does not cover requested lifetime")
        if (first.identity.context.source == "synthetic" and verifier is not None
                and verifier("cpu_envelope", first.identity, envelope) is True):
            upper = ((envelope.end_ns - envelope.start_ns) * envelope.cpu_count + 999) // 1000
            if upper < known or (endpoint_delta is not None and upper < endpoint_delta):
                raise ValueError("CPU observations exceed verified envelope")
    complete = not reasons
    return {
        "domain_id": ledger.domain_id, "owner": ledger.owner, "purpose": ledger.purpose,
        "identity": asdict(first.identity), "windows": rows,
        "phase_cpu_usec": phases, "phase_present": {p: bool(phase_rows[p]) for p in PHASES},
        "window_cpu_usec": known if delta_complete else None,
        "endpoint_delta_usec": endpoint_delta,
        "whole_lifetime_cpu_usec": known if complete else None,
        "status": "point_from_supplied_evidence" if complete else "unidentified",
        "unidentified_reasons": reasons,
        "post_last_snapshot": "sealed_by_verified_final_receipt" if not boundary_reasons["final"]
                              else "unidentified_residual",
        "conservation": "exact" if delta_complete else "unidentified",
        "diagnostic_bounds": {"lower_cpu_usec": max(known, endpoint_delta or 0), "upper_cpu_usec": upper,
                              "completes_point_cost_gate": False},
        "bootstrap": {"setup_window_cpu_usec": phases["setup"],
                      "setup_window_wall_ns_bounds": [sum(r["wall_ns_bounds"][index] for r in rows
                                                          if r["phase"] == "setup") for index in (0, 1)],
                      "whole_bootstrap_cpu_usec": phases["setup"] if complete else None,
                      "resources": {name: readings.get(name) for name in
                                    ("memory_peak_bytes", "swap_peak_bytes", "gpu_usec", "energy_uj")}},
    }


def analyze(ledgers, *, required_components, verify_evidence=None):
    """Validate and reduce disjoint hierarchy roots; preserve child diagnostics.

    required_components maps every frozen component/role to a domain_id, or
    None when unaccounted. It must include external observers, comparators and
    dedicated collectors, not only candidate processes. It is a review input,
    not discovered or certified by this pure calculation.
    verify_evidence exercises synthetic fixtures only; it cannot authorize or
    authenticate collected lifetime points while M-ENDPOINT-001 is unresolved.
    """
    ledgers = tuple(ledgers)
    if not ledgers or not required_components:
        raise ValueError("Nonempty domains and frozen component inventory required")
    if len({d.domain_id for d in ledgers}) != len(ledgers):
        raise ValueError("Duplicate domain ID")
    reports = {d.domain_id: _domain_report(d, verify_evidence) for d in ledgers}
    by_id = {d.domain_id: d for d in ledgers}
    identities = {d.domain_id: d.snapshots[0].identity for d in ledgers}
    views = {}
    physical = set()
    paths = set()
    for ident in identities.values():
        ctx = ident.context
        key = (ctx.node, ctx.boot_id)
        view = (ctx.mount_id, ctx.mount_namespace, ctx.cgroup_namespace, ctx.source)
        if key in views and views[key] != view:
            raise ValueError("Multiple hierarchy views could hide overlapping domains")
        views[key] = view
        # Also reject two handles/aliases for one physical domain.
        key = (ctx.node, ctx.boot_id, ident.device, ident.inode)
        if key in physical:
            raise ValueError("Duplicate physical domain")
        physical.add(key)
        key = (ctx.node, ctx.boot_id, ident.path)
        if key in paths:
            raise ValueError("Replaced or duplicated path across domains")
        paths.add(key)
    roots = {}
    for name, ident in identities.items():
        ancestors = [other for other, parent in identities.items()
                     if ident.context == parent.context
                     and PurePosixPath(ident.path).is_relative_to(PurePosixPath(parent.path))]
        root = min(ancestors, key=lambda x: len(PurePosixPath(identities[x].path).parts))
        roots[name] = root
        if by_id[root].purpose != by_id[name].purpose:
            raise ValueError("Online and offline scopes overlap")
        if root != name:
            parent, child = by_id[root], by_id[name]
            if (child.snapshots[0].started_ns < parent.snapshots[0].finished_ns
                    or child.snapshots[-1].finished_ns > parent.snapshots[-1].started_ns
                    or child.required_end_ns > parent.required_end_ns):
                raise ValueError("Child lifetime lies outside measured parent coverage")
            outer_delta = reports[root]["endpoint_delta_usec"]
            inner_delta = reports[name]["endpoint_delta_usec"]
            if outer_delta is not None and inner_delta is not None and inner_delta > outer_delta:
                raise ValueError("Nested counter exceeds containing root")
    selected = sorted(set(roots.values()))
    uncovered = []
    component_roots = {}
    for component, domain in required_components.items():
        _text(component, "component")
        if domain is None:
            uncovered.append(component)
            component_roots[component] = None
        elif domain not in roots:
            raise ValueError("Inventory references unknown domain")
        else:
            component_roots[component] = roots[domain]
    if set(selected) - set(component_roots.values()):
        raise ValueError("Every selected root needs explicit ownership in inventory")
    chosen = [reports[name] for name in selected]
    window_complete = all(r["window_cpu_usec"] is not None for r in chosen) and not uncovered
    lifetime_complete = all(r["whole_lifetime_cpu_usec"] is not None for r in chosen) and not uncovered
    def total(field, complete):
        return sum(r[field] for r in chosen) if complete else None
    phase_totals = {p: (sum(r["phase_cpu_usec"][p] for r in chosen)
                        if all(r["phase_cpu_usec"][p] is not None for r in chosen) and not uncovered else None)
                    for p in PHASES}
    online = [r for r in chosen if r["purpose"] == "online"]
    online_complete = bool(online) and not uncovered and all(r["phase_cpu_usec"][p] is not None
                                            for r in online for p in ("service", "standby"))
    upper_known = all(r["diagnostic_bounds"]["upper_cpu_usec"] is not None for r in chosen) and not uncovered
    return {
        "schema": SCHEMA, "gates": dict(GATES),
        "package_status": PACKAGE_STATUS, "ready_for_field": False,
        "endpoint_acquisition": endpoint_status(),
        "source_kind": "synthetic" if any(i.context.source == "synthetic" for i in identities.values()) else "collected_unaccepted",
        "selected_roots": selected, "included_under_root": roots,
        "component_roots": component_roots, "uncovered_components": sorted(uncovered),
        "domains": reports, "phase_cpu_usec": phase_totals,
        "window_cpu_usec": total("window_cpu_usec", window_complete),
        "whole_lifetime_cpu_usec": total("whole_lifetime_cpu_usec", lifetime_complete),
        "online_service_window_cpu_usec": sum(r["phase_cpu_usec"]["service"] + r["phase_cpu_usec"]["standby"]
                                               for r in online) if online_complete else None,
        "status": "point_from_supplied_evidence" if lifetime_complete else "unidentified",
        "diagnostic_bounds": {"lower_cpu_usec": sum(r["diagnostic_bounds"]["lower_cpu_usec"] for r in chosen),
                              "upper_cpu_usec": sum(r["diagnostic_bounds"]["upper_cpu_usec"] for r in chosen) if upper_known else None,
                              "completes_point_cost_gate": False},
        "physical_cost_point": None,
    }


def online_timing(*, clock_domain, request_received_ns, selection_started_ns, delivered_ns):
    """Actual online arrival-to-delivery time on one identified monotonic clock."""
    _text(clock_domain, "clock_domain")
    for name, value in (("request_received_ns", request_received_ns),
                        ("selection_started_ns", selection_started_ns), ("delivered_ns", delivered_ns)):
        _nat(value, name)
    if not request_received_ns <= selection_started_ns <= delivered_ns:
        raise ValueError("Online timestamps out of order")
    return {"clock_domain": clock_domain, "tau_ns": delivered_ns - request_received_ns,
            "online_wait_ns": selection_started_ns - request_received_ns,
            "selection_to_delivery_ns": delivered_ns - selection_started_ns,
            "offline_queue_included": False}


def export_ledger(ledger):
    """Lossless JSON-ready raw observations; no file I/O or acceptance label."""
    return {"schema": SCHEMA, "ledger": asdict(ledger)}


def import_ledger(record):
    if set(record) != {"schema", "ledger"} or record["schema"] != SCHEMA:
        raise ValueError("Unknown ledger schema")
    row = dict(record["ledger"])
    snapshots = []
    for raw in row["snapshots"]:
        snapshot = dict(raw)
        identity = dict(snapshot["identity"])
        identity["context"] = CollectorContext(**identity["context"])
        snapshot["identity"] = DomainIdentity(**identity)
        snapshots.append(Snapshot(**snapshot))
    row["snapshots"] = tuple(snapshots)
    row["windows"] = tuple(Window(**raw) for raw in row["windows"])
    for kind in ("origin", "final"):
        if row.get(kind) is not None:
            row[kind] = BoundaryReceipt(**row[kind])
    if row.get("envelope") is not None:
        row["envelope"] = CpuEnvelope(**row["envelope"])
    row["bootstrap_resources"] = tuple(ResourceReading(**raw) for raw in row.get("bootstrap_resources", ()))
    return DomainLedger(**row)
