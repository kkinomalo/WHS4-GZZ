"""Read-only inventory of external process handles that target the game.

The native adapter uses ``NtQuerySystemInformation`` with
``SystemExtendedHandleInformation`` to take a bounded system-handle snapshot.
For handles owned by another process it requests ``PROCESS_DUP_HANDLE``, makes
a query-only duplicate when Windows permits it, and calls ``GetProcessId`` on
that duplicate.  No target memory is read or written and no source handle is
closed or modified.

This module reports facts only.  Access masks such as ``VM_READ`` and
``VM_WRITE`` are retained for a detector to interpret later; their presence is
not labelled as cheating here.  A first successful poll establishes a
baseline, while newly appearing handles are emitted immediately and persistent
handles are not re-emitted unless their observable state changes.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import math
import os
import sys
import time
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

from ..core.context import SensorContext
from ..core.events import SensorBatch, SensorEvent
from .process_relationships import is_steam_launch_parent_access


SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
STATUS_INFO_LENGTH_MISMATCH = ctypes.c_int32(0xC0000004).value

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

WATCHED_PROCESS_ACCESS = (
    PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_DUP_HANDLE
)

_ACCESS_BITS = (
    (PROCESS_CREATE_THREAD, "CREATE_THREAD"),
    (PROCESS_VM_OPERATION, "VM_OPERATION"),
    (PROCESS_VM_READ, "VM_READ"),
    (PROCESS_VM_WRITE, "VM_WRITE"),
    (PROCESS_DUP_HANDLE, "DUP_HANDLE"),
)
_SYSTEM_PIDS = frozenset({0, 4})


def decode_process_access(granted_access: int) -> tuple[str, ...]:
    """Decode only the process rights used by the ESP detector contract."""

    if isinstance(granted_access, bool) or not isinstance(granted_access, int):
        raise TypeError("granted_access must be an integer")
    if granted_access < 0:
        raise ValueError("granted_access must be non-negative")
    return tuple(label for bit, label in _ACCESS_BITS if granted_access & bit)


class HandleEnumerationError(RuntimeError):
    """A complete, trustworthy system-handle snapshot could not be acquired."""

    def __init__(self, operation: str, status: int | None = None) -> None:
        self.operation = str(operation)
        self.status = None if status is None else int(status)
        suffix = "" if self.status is None else f" (NTSTATUS 0x{self.status & 0xFFFFFFFF:08X})"
        super().__init__(f"system handle enumeration failed: {self.operation}{suffix}")


class HandleInventoryUnavailable(OSError):
    """The platform/API cannot provide the requested inventory."""


@dataclass(frozen=True, slots=True)
class SystemHandleEntry:
    """One raw entry returned by ``SystemExtendedHandleInformation``."""

    object_address: int
    owner_pid: int
    handle_value: int
    granted_access: int
    object_type_index: int
    handle_attributes: int = 0

    def __post_init__(self) -> None:
        for name in (
            "object_address",
            "owner_pid",
            "handle_value",
            "granted_access",
            "object_type_index",
            "handle_attributes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class SystemHandleSnapshot:
    """Bounded raw snapshot before process-handle resolution."""

    entries: tuple[SystemHandleEntry, ...]
    total_handle_count: int
    scanned_handle_count: int
    buffer_size: int
    truncated: bool = False

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        if any(not isinstance(entry, SystemHandleEntry) for entry in entries):
            raise TypeError("entries must contain SystemHandleEntry values")
        object.__setattr__(self, "entries", entries)
        for name in ("total_handle_count", "scanned_handle_count", "buffer_size"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.scanned_handle_count != len(entries):
            raise ValueError("scanned_handle_count must match entries")
        if self.total_handle_count < self.scanned_handle_count:
            raise ValueError("total_handle_count cannot be smaller than scanned_handle_count")


@dataclass(frozen=True, slots=True)
class ProcessHandleRecord:
    """A resolved external handle whose kernel object is an exact game process."""

    source_pid: int
    source_handle_value: int
    target_pid: int
    granted_access: int
    source_image: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "source_pid",
            "source_handle_value",
            "target_pid",
            "granted_access",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.source_pid <= 0 or self.target_pid <= 0:
            raise ValueError("source_pid and target_pid must be positive")
        if self.source_image is not None and not isinstance(self.source_image, str):
            raise TypeError("source_image must be a string or None")

    @property
    def access_labels(self) -> tuple[str, ...]:
        return decode_process_access(self.granted_access)


@dataclass(frozen=True, slots=True)
class HandleInventorySnapshot:
    """Resolved facts and acquisition-health counters from one native scan."""

    records: tuple[ProcessHandleRecord, ...]
    observed_at: float
    total_handle_count: int = 0
    scanned_handle_count: int = 0
    candidate_handle_count: int = 0
    truncated: bool = False
    target_mapping_count: int = 0
    source_open_failures: int = 0
    duplicate_failures: int = 0
    get_process_id_failures: int = 0

    def __post_init__(self) -> None:
        records = tuple(self.records)
        if any(not isinstance(record, ProcessHandleRecord) for record in records):
            raise TypeError("records must contain ProcessHandleRecord values")
        object.__setattr__(self, "records", records)
        if (
            isinstance(self.observed_at, bool)
            or not isinstance(self.observed_at, (int, float))
            or not math.isfinite(float(self.observed_at))
            or self.observed_at < 0
        ):
            raise ValueError("observed_at must be finite and non-negative")
        object.__setattr__(self, "observed_at", float(self.observed_at))
        for name in (
            "total_handle_count",
            "scanned_handle_count",
            "candidate_handle_count",
            "target_mapping_count",
            "source_open_failures",
            "duplicate_failures",
            "get_process_id_failures",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

    def details(self) -> dict[str, object]:
        return {
            "inventory_record_count": len(self.records),
            "total_handle_count": self.total_handle_count,
            "scanned_handle_count": self.scanned_handle_count,
            "candidate_handle_count": self.candidate_handle_count,
            "truncated": self.truncated,
            "target_mapping_count": self.target_mapping_count,
            "source_open_failures": self.source_open_failures,
            "duplicate_failures": self.duplicate_failures,
            "get_process_id_failures": self.get_process_id_failures,
        }


@runtime_checkable
class HandleInventoryProvider(Protocol):
    """Injectable boundary used by cross-platform tests and the sensor."""

    def __call__(
        self,
        target_pids: frozenset[int],
        excluded_owner_pids: frozenset[int],
    ) -> HandleInventorySnapshot:
        """Return exact target-handle facts without assigning a verdict."""


_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:
    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
        _fields_ = (
            ("Object", ctypes.c_void_p),
            ("UniqueProcessId", ctypes.c_size_t),
            ("HandleValue", ctypes.c_size_t),
            ("GrantedAccess", wintypes.ULONG),
            ("CreatorBackTraceIndex", wintypes.USHORT),
            ("ObjectTypeIndex", wintypes.USHORT),
            ("HandleAttributes", wintypes.ULONG),
            ("Reserved", wintypes.ULONG),
        )

    _ntdll.NtQuerySystemInformation.argtypes = (
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    )
    _ntdll.NtQuerySystemInformation.restype = wintypes.LONG

    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.GetCurrentProcess.argtypes = ()
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.DuplicateHandle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    _kernel32.DuplicateHandle.restype = wintypes.BOOL
    _kernel32.GetProcessId.argtypes = (wintypes.HANDLE,)
    _kernel32.GetProcessId.restype = wintypes.DWORD
    _kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL


def _validate_limit(name: str, value: int, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def enumerate_system_handles(
    *,
    initial_buffer_bytes: int = 1 << 20,
    maximum_buffer_bytes: int = 64 << 20,
    maximum_handles: int = 500_000,
) -> SystemHandleSnapshot:
    """Take a bounded raw system-handle snapshot using the native NT API.

    A 32-bit Python process is rejected explicitly because parsing a 64-bit
    game's extended-handle records from WOW64 is not reliable enough for an
    evidence-producing sensor.
    """

    initial_buffer_bytes = _validate_limit(
        "initial_buffer_bytes", initial_buffer_bytes, minimum=4096
    )
    maximum_buffer_bytes = _validate_limit(
        "maximum_buffer_bytes", maximum_buffer_bytes, minimum=initial_buffer_bytes
    )
    maximum_handles = _validate_limit("maximum_handles", maximum_handles, minimum=1)
    if not _IS_WINDOWS:
        raise HandleInventoryUnavailable("handle inventory is available only on Windows")
    if sys.maxsize <= 0xFFFFFFFF or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise HandleInventoryUnavailable(
            "64-bit Python is required for a 64-bit game handle inventory"
        )

    size = initial_buffer_bytes
    while True:
        buffer = ctypes.create_string_buffer(size)
        returned = wintypes.ULONG(0)
        status = int(
            _ntdll.NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer,
                size,
                ctypes.byref(returned),
            )
        )
        if status == 0:
            break
        if status != STATUS_INFO_LENGTH_MISMATCH:
            raise HandleEnumerationError("NtQuerySystemInformation", status)
        requested = max(size * 2, int(returned.value) + 64 * 1024)
        if requested > maximum_buffer_bytes:
            raise HandleEnumerationError(
                f"required buffer exceeds {maximum_buffer_bytes} bytes", status
            )
        size = requested

    pointer_size = ctypes.sizeof(ctypes.c_size_t)
    header_size = pointer_size * 2
    entry_size = ctypes.sizeof(_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    if size < header_size:
        raise HandleEnumerationError("response shorter than header")
    total = int(ctypes.c_size_t.from_buffer(buffer, 0).value)
    parsable = max(0, (size - header_size) // entry_size)
    scan_count = min(total, parsable, maximum_handles)
    truncated = scan_count < total

    entries: list[SystemHandleEntry] = []
    for index in range(scan_count):
        offset = header_size + index * entry_size
        native = _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer(buffer, offset)
        entries.append(
            SystemHandleEntry(
                object_address=int(native.Object or 0),
                owner_pid=int(native.UniqueProcessId),
                handle_value=int(native.HandleValue),
                granted_access=int(native.GrantedAccess),
                object_type_index=int(native.ObjectTypeIndex),
                handle_attributes=int(native.HandleAttributes),
            )
        )
    return SystemHandleSnapshot(
        entries=tuple(entries),
        total_handle_count=total,
        scanned_handle_count=len(entries),
        buffer_size=size,
        truncated=truncated,
    )


def _handle_value(handle: object) -> int:
    if handle is None:
        return 0
    if isinstance(handle, int):
        return handle
    return int(ctypes.cast(handle, ctypes.c_void_p).value or 0)


def _query_process_image(handle: object) -> str | None:
    capacity = 32768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = wintypes.DWORD(capacity)
    if not _kernel32.QueryFullProcessImageNameW(
        handle, 0, buffer, ctypes.byref(length)
    ):
        return None
    value = buffer.value[: int(length.value)].strip()
    return value or None


RawEnumerationProvider = Callable[[], SystemHandleSnapshot]


class WindowsHandleInventoryProvider:
    """Resolve raw handle entries to exact target PIDs without memory access."""

    def __init__(
        self,
        *,
        enumeration_provider: RawEnumerationProvider = enumerate_system_handles,
        self_pid: int | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._enumerate = enumeration_provider
        self._self_pid = os.getpid() if self_pid is None else int(self_pid)
        self._clock = clock

    def __call__(
        self,
        target_pids: frozenset[int],
        excluded_owner_pids: frozenset[int],
    ) -> HandleInventorySnapshot:
        targets = frozenset(int(pid) for pid in target_pids if int(pid) > 0)
        if not targets:
            return HandleInventorySnapshot(records=(), observed_at=self._clock())
        if not _IS_WINDOWS:
            raise HandleInventoryUnavailable("handle inventory is available only on Windows")
        if sys.maxsize <= 0xFFFFFFFF:
            raise HandleInventoryUnavailable(
                "64-bit Python is required for a 64-bit game handle inventory"
            )

        target_marker_handles: dict[int, object] = {}
        source_handles: dict[int, tuple[object, str | None]] = {}
        source_open_failures = 0
        duplicate_failures = 0
        get_process_id_failures = 0
        candidate_count = 0
        try:
            # Marker handles let the same kernel snapshot expose the exact
            # object address for each target.  This is a fallback when an
            # external handle lacks query rights required by GetProcessId.
            for target_pid in targets:
                handle = _kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, False, target_pid
                )
                if handle:
                    target_marker_handles[target_pid] = handle

            raw = self._enumerate()
            marker_by_value = {
                _handle_value(handle): pid
                for pid, handle in target_marker_handles.items()
            }
            target_by_object: dict[int, int] = {}
            process_type_indexes: set[int] = set()
            for entry in raw.entries:
                if entry.owner_pid != self._self_pid:
                    continue
                target_pid = marker_by_value.get(entry.handle_value)
                if target_pid is None:
                    continue
                if entry.object_address:
                    target_by_object[entry.object_address] = target_pid
                process_type_indexes.add(entry.object_type_index)

            records: list[ProcessHandleRecord] = []
            excluded = _SYSTEM_PIDS | {self._self_pid} | set(targets) | set(
                excluded_owner_pids
            )
            current_process = _kernel32.GetCurrentProcess()
            for entry in raw.entries:
                if entry.owner_pid in excluded:
                    continue
                if entry.owner_pid > 0xFFFFFFFF:
                    continue
                if not entry.granted_access & WATCHED_PROCESS_ACCESS:
                    continue
                mapped_target = target_by_object.get(entry.object_address)
                if (
                    mapped_target is None
                    and process_type_indexes
                    and entry.object_type_index not in process_type_indexes
                ):
                    continue
                candidate_count += 1

                cached = source_handles.get(entry.owner_pid)
                if cached is None:
                    source_handle = _kernel32.OpenProcess(
                        PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                        False,
                        entry.owner_pid,
                    )
                    can_query_image = bool(source_handle)
                    if not source_handle:
                        source_handle = _kernel32.OpenProcess(
                            PROCESS_DUP_HANDLE, False, entry.owner_pid
                        )
                    if not source_handle:
                        source_open_failures += 1
                        if mapped_target is not None:
                            records.append(
                                ProcessHandleRecord(
                                    source_pid=entry.owner_pid,
                                    source_handle_value=entry.handle_value,
                                    target_pid=mapped_target,
                                    granted_access=entry.granted_access,
                                )
                            )
                        continue
                    source_image = (
                        _query_process_image(source_handle) if can_query_image else None
                    )
                    cached = (source_handle, source_image)
                    source_handles[entry.owner_pid] = cached

                source_handle, source_image = cached
                duplicate = wintypes.HANDLE()
                duplicated = bool(
                    _kernel32.DuplicateHandle(
                        source_handle,
                        wintypes.HANDLE(entry.handle_value),
                        current_process,
                        ctypes.byref(duplicate),
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        False,
                        0,
                    )
                )
                resolved_target: int | None = None
                if duplicated:
                    try:
                        value = int(_kernel32.GetProcessId(duplicate))
                        if value:
                            resolved_target = value
                        else:
                            get_process_id_failures += 1
                    finally:
                        _kernel32.CloseHandle(duplicate)
                else:
                    duplicate_failures += 1

                # The object-address mapping is exact within this same kernel
                # snapshot and recovers handles that have VM_READ but no query
                # right.  It is never exported as evidence.
                if resolved_target is None:
                    resolved_target = mapped_target
                if resolved_target not in targets:
                    continue
                records.append(
                    ProcessHandleRecord(
                        source_pid=entry.owner_pid,
                        source_handle_value=entry.handle_value,
                        target_pid=resolved_target,
                        granted_access=entry.granted_access,
                        source_image=source_image,
                    )
                )

            records.sort(
                key=lambda item: (
                    item.target_pid,
                    item.source_pid,
                    item.source_handle_value,
                    item.granted_access,
                )
            )
            return HandleInventorySnapshot(
                records=tuple(records),
                observed_at=self._clock(),
                total_handle_count=raw.total_handle_count,
                scanned_handle_count=raw.scanned_handle_count,
                candidate_handle_count=candidate_count,
                truncated=raw.truncated,
                target_mapping_count=len(target_by_object),
                source_open_failures=source_open_failures,
                duplicate_failures=duplicate_failures,
                get_process_id_failures=get_process_id_failures,
            )
        finally:
            for handle, _image in source_handles.values():
                if handle:
                    _kernel32.CloseHandle(handle)
            for handle in target_marker_handles.values():
                if handle:
                    _kernel32.CloseHandle(handle)


def _record_key(
    record: ProcessHandleRecord,
    subject_id: str,
) -> tuple[str, int, int, int]:
    return (
        subject_id,
        record.source_pid,
        record.source_handle_value,
        record.target_pid,
    )


def _record_state(record: ProcessHandleRecord) -> tuple[int, str]:
    return (record.granted_access, (record.source_image or "").casefold())


class CurrentProcessHandleSensor:
    """Emit normalized facts for external handles targeting exact game PIDs."""

    sensor_id = "current_process_handles"

    def __init__(
        self,
        *,
        enumeration_provider: HandleInventoryProvider | None = None,
        self_pid: int | None = None,
        cooldown_seconds: float = 30.0,
        monotonic_clock: Callable[[], float] = time.monotonic,
        source_identity_provider: Callable[[str], Mapping[str, Any]] | None = None,
        excluded_pid_provider: Callable[[], Iterable[int]] | None = None,
        steam_source_verifier: Callable[[str], bool] | None = None,
    ) -> None:
        if (
            isinstance(cooldown_seconds, bool)
            or not isinstance(cooldown_seconds, (int, float))
            or not math.isfinite(float(cooldown_seconds))
            or cooldown_seconds < 0
        ):
            raise ValueError("cooldown_seconds must be finite and non-negative")
        self._self_pid = os.getpid() if self_pid is None else int(self_pid)
        if self._self_pid <= 0:
            raise ValueError("self_pid must be positive")
        self._provider = enumeration_provider or WindowsHandleInventoryProvider(
            self_pid=self._self_pid
        )
        # Retained in the public signature for configuration compatibility.
        # Unchanged handles are now state-deduplicated for their entire lifetime.
        self._cooldown = float(cooldown_seconds)
        self._monotonic = monotonic_clock
        self._source_identity_provider = source_identity_provider
        self._excluded_pid_provider = excluded_pid_provider
        self._steam_source_verifier = steam_source_verifier
        self._session_id: str | None = None
        self._has_baseline = False
        self._active_records: dict[tuple[str, int, int, int], tuple[int, str]] = {}

    def reset_baseline(self) -> None:
        self._has_baseline = False
        self._active_records.clear()

    def poll(self, context: SensorContext) -> SensorBatch:
        if not isinstance(context, SensorContext):
            raise TypeError("context must be SensorContext")
        if not context.targets:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="waiting",
                message="waiting for the game process",
            )
        if self._session_id != context.session_id:
            self._session_id = context.session_id
            self.reset_baseline()

        target_pids = frozenset(context.target_by_pid)
        try:
            registered_pids = frozenset(
                int(pid)
                for pid in (
                    self._excluded_pid_provider()
                    if self._excluded_pid_provider is not None
                    else ()
                )
                if int(pid) > 0
            )
        except Exception:
            registered_pids = frozenset()
        try:
            snapshot = self._provider(
                target_pids, registered_pids | frozenset({self._self_pid})
            )
            if not isinstance(snapshot, HandleInventorySnapshot):
                raise TypeError("enumeration provider returned an invalid snapshot")
        except HandleInventoryUnavailable as exc:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="unavailable",
                message=str(exc),
            )
        except HandleEnumerationError as exc:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="error",
                message=str(exc),
            )
        except (OSError, PermissionError) as exc:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="unavailable",
                message=f"process handle inventory unavailable: {exc}",
            )
        except Exception as exc:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="error",
                message=f"process handle inventory failed: {exc}",
            )

        target_by_pid = context.target_by_pid
        valid_records = tuple(
            record
            for record in snapshot.records
            if record.target_pid in target_by_pid
            and record.source_pid
            not in (_SYSTEM_PIDS | {self._self_pid} | set(registered_pids))
            and record.source_pid != record.target_pid
            and bool(record.granted_access & WATCHED_PROCESS_ACCESS)
        )
        details = snapshot.details()
        details["filtered_record_count"] = len(valid_records)
        details["excluded_anticheat_pid_count"] = len(registered_pids)

        keyed = {
            _record_key(record, target_by_pid[record.target_pid].subject_id): record
            for record in valid_records
        }
        active_keys = set(keyed)
        for stale_key in set(self._active_records) - active_keys:
            self._active_records.pop(stale_key, None)

        if not self._has_baseline:
            self._has_baseline = True
            self._active_records = {
                key: _record_state(record) for key, record in keyed.items()
            }
            details.update(
                {
                    "baseline_created": True,
                    "baseline_record_count": len(valid_records),
                    "deduplicated_count": len(valid_records),
                }
            )
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="online",
                message=f"created baseline from {len(valid_records)} matching handle(s)",
                details=details,
                observed_at_ms=int(round(snapshot.observed_at * 1000.0)),
            )

        events: list[SensorEvent] = []
        deduplicated = 0
        for key in sorted(keyed):
            record = keyed[key]
            state = _record_state(record)
            previous = self._active_records.get(key)
            steam_source_verified = False
            if (
                previous is None
                and self._steam_source_verifier is not None
                and record.source_image
            ):
                try:
                    steam_source_verified = bool(
                        self._steam_source_verifier(record.source_image)
                    )
                except Exception:
                    steam_source_verified = False
            if previous is None and is_steam_launch_parent_access(
                target=target_by_pid[record.target_pid],
                source_pid=record.source_pid,
                source_image=record.source_image,
                granted_access=record.granted_access,
                observed_at=snapshot.observed_at,
                source_verified=steam_source_verified,
            ):
                self._active_records[key] = state
                deduplicated += 1
                continue
            if previous == state:
                deduplicated += 1
                continue
            observation_kind = "new" if previous is None else "changed"
            self._active_records[key] = state
            target = target_by_pid[record.target_pid]
            identity: dict[str, Any] = {}
            if self._source_identity_provider is not None and record.source_image:
                try:
                    identity = dict(
                        self._source_identity_provider(record.source_image)
                    )
                except Exception as exc:
                    identity = {
                        "identity_status": "error",
                        "identity_error": str(exc),
                    }
            if "sha256" in identity:
                identity["source_sha256"] = identity.pop("sha256")
            events.append(
                SensorEvent(
                    session_id=context.session_id,
                    sensor_id=self.sensor_id,
                    event_type="process_access",
                    subject_id=target.subject_id,
                    timestamp_ms=int(round(snapshot.observed_at * 1000.0)),
                    payload={
                        "inventory_source": (
                            "NtQuerySystemInformation/"
                            "SystemExtendedHandleInformation"
                        ),
                        "observation_kind": observation_kind,
                        "previous_granted_access": (
                            previous[0] if previous is not None else None
                        ),
                        "source_pid": record.source_pid,
                        "source_image": record.source_image,
                        "source_handle_value": record.source_handle_value,
                        "source_handle_value_hex": (
                            f"0x{record.source_handle_value:X}"
                        ),
                        "target_pid": record.target_pid,
                        "target_image": target.executable_path,
                        "granted_access": record.granted_access,
                        "granted_access_hex": f"0x{record.granted_access:08X}",
                        "access_labels": list(record.access_labels),
                        **identity,
                    },
                )
            )

        details.update(
            {
                "baseline_created": False,
                "deduplicated_count": deduplicated,
                "emitted_count": len(events),
            }
        )
        return SensorBatch(
            sensor_id=self.sensor_id,
            status="online",
            events=tuple(events),
            message=f"emitted {len(events)} external process-handle fact(s)",
            details=details,
            observed_at_ms=int(round(snapshot.observed_at * 1000.0)),
        )


__all__ = [
    "HandleEnumerationError",
    "HandleInventoryProvider",
    "HandleInventorySnapshot",
    "HandleInventoryUnavailable",
    "CurrentProcessHandleSensor",
    "ProcessHandleRecord",
    "SystemHandleEntry",
    "SystemHandleSnapshot",
    "WindowsHandleInventoryProvider",
    "WATCHED_PROCESS_ACCESS",
    "decode_process_access",
    "enumerate_system_handles",
]
