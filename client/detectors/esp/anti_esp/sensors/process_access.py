"""Factual Sysmon ProcessAccess adapter for exact game process instances."""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Iterable, Mapping

from ..core.context import SensorContext
from ..core.events import SensorBatch, SensorEvent
from ..sysmon import SysmonPoller, SysmonProcessAccess
from .process_relationships import is_steam_launch_parent_access


class SysmonProcessAccessSensor:
    """Convert Sysmon Event ID 10 records to normalized facts.

    This class performs target-instance filtering, but intentionally does not
    assign risk, consult an allowlist, or decide that an access is malicious.
    """

    sensor_id = "sysmon_process_access"

    def __init__(
        self,
        *,
        poller: Any | None = None,
        self_pid: int | None = None,
        clock: Callable[[], float] = time.time,
        stale_tolerance_seconds: float = 2.0,
        source_identity_provider: Callable[[str], Mapping[str, Any]] | None = None,
        excluded_pid_provider: Callable[[], Iterable[int]] | None = None,
        steam_source_verifier: Callable[[str], bool] | None = None,
    ) -> None:
        if stale_tolerance_seconds < 0:
            raise ValueError("stale_tolerance_seconds must be non-negative")
        self._poller = poller or SysmonPoller(include_existing=True)
        self._self_pid = os.getpid() if self_pid is None else int(self_pid)
        self._clock = clock
        self._stale_tolerance = float(stale_tolerance_seconds)
        self._source_identity_provider = source_identity_provider
        self._excluded_pid_provider = excluded_pid_provider
        self._steam_source_verifier = steam_source_verifier

    def _belongs_to_current_target(
        self,
        record: SysmonProcessAccess,
        context: SensorContext,
        excluded_pids: frozenset[int] = frozenset(),
    ) -> bool:
        if record.source_process_id == self._self_pid or record.source_process_id in excluded_pids:
            return False
        if record.target_process_id is None:
            return False
        target = context.target_by_pid.get(int(record.target_process_id))
        if target is None:
            return False
        if (
            record.source_process_id is not None
            and record.source_process_id == record.target_process_id
        ):
            return False
        if record.timestamp is None:
            return True
        # A matching PID and process creation time prevent PID-reuse records
        # from being attributed to the current game instance.  The session
        # boundary is independently important: SysmonPoller can return
        # existing Event ID 10 records, so a record from before this test must
        # not become evidence for the newly started session merely because the
        # same game process was already running.
        lower_bound = max(
            context.session_started_at,
            target.created_at if target.created_at is not None else 0.0,
        )
        if record.timestamp + self._stale_tolerance < lower_bound:
            return False
        steam_source_verified = False
        if self._steam_source_verifier is not None and record.source_image:
            try:
                steam_source_verified = bool(
                    self._steam_source_verifier(record.source_image)
                )
            except Exception:
                steam_source_verified = False
        return not is_steam_launch_parent_access(
            target=target,
            source_pid=record.source_process_id,
            source_image=record.source_image,
            granted_access=record.granted_access,
            observed_at=record.timestamp,
            source_verified=steam_source_verified,
        )

    def _event_from_record(
        self,
        record: SysmonProcessAccess,
        context: SensorContext,
        fallback_timestamp: float,
    ) -> SensorEvent:
        assert record.target_process_id is not None
        target = context.target_by_pid[int(record.target_process_id)]
        access = record.granted_access
        timestamp = fallback_timestamp if record.timestamp is None else record.timestamp
        event_id = (
            f"{context.session_id}:sysmon-event10:{record.computer}:{record.record_id}"
            if record.record_id is not None
            else None
        )
        kwargs: dict[str, Any] = {}
        if event_id is not None:
            kwargs["event_id"] = event_id
        source_identity: dict[str, Any] = {}
        if self._source_identity_provider is not None and record.source_image:
            try:
                source_identity = dict(
                    self._source_identity_provider(record.source_image)
                )
            except Exception as exc:
                source_identity = {
                    "identity_status": "error",
                    "identity_error": str(exc),
                }
        if "sha256" in source_identity:
            source_identity["source_sha256"] = source_identity.pop("sha256")
        return SensorEvent(
            session_id=context.session_id,
            sensor_id=SysmonProcessAccessSensor.sensor_id,
            event_type="process_access",
            subject_id=target.subject_id,
            timestamp_ms=int(round(timestamp * 1000.0)),
            sequence=record.record_id if record.record_id is not None and record.record_id >= 0 else None,
            payload={
                "record_id": record.record_id,
                "sysmon_event_id": record.event_id,
                "computer": record.computer,
                "source_pid": record.source_process_id,
                "source_thread_id": record.source_thread_id,
                "source_image": record.source_image,
                "source_user": record.source_user,
                "target_pid": record.target_process_id,
                "target_image": record.target_image,
                "target_user": record.target_user,
                "granted_access": access,
                "granted_access_hex": (
                    f"0x{access:08X}" if access is not None else record.granted_access_raw
                ),
                "access_labels": list(record.access_labels),
                "call_trace": record.call_trace,
                "rule_name": record.rule_name,
                "data": dict(record.data),
                **source_identity,
            },
            **kwargs,
        )

    def poll(self, context: SensorContext) -> SensorBatch:
        if not isinstance(context, SensorContext):
            raise TypeError("context must be SensorContext")
        if not context.targets:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="waiting",
                message="waiting for the game process",
            )

        try:
            result = self._poller.poll()
        except Exception as exc:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="error",
                message=f"Sysmon collection failed: {exc}",
            )

        details = result.status.to_dict()
        details.update(
            {
                "scanned_count": result.scanned_count,
                "truncated": result.truncated,
                "configuration_verified": False,
            }
        )
        if not result.status.available:
            return SensorBatch(
                sensor_id=self.sensor_id,
                status="unavailable",
                message=result.status.message,
                details=details,
            )

        now = self._clock()
        try:
            excluded_pids = frozenset(
                int(pid)
                for pid in (
                    self._excluded_pid_provider()
                    if self._excluded_pid_provider is not None
                    else ()
                )
                if int(pid) > 0
            )
        except Exception:
            excluded_pids = frozenset()
        events = tuple(
            self._event_from_record(record, context, now)
            for record in result.events
            if self._belongs_to_current_target(record, context, excluded_pids)
        )
        details["excluded_anticheat_pid_count"] = len(excluded_pids)
        return SensorBatch(
            sensor_id=self.sensor_id,
            status="online",
            events=events,
            message=f"collected {len(events)} matching access record(s)",
            details=details,
            observed_at_ms=int(round(now * 1000.0)),
        )


__all__ = ["SysmonProcessAccessSensor"]
