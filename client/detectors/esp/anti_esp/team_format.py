"""Adapter from internal ESP evidence to the team's shared result payload."""

from __future__ import annotations

import hashlib
import math
import ntpath
from typing import Any, Iterable, Mapping

from .core.events import SensorEvent, TeamDetectionEvent
from .models import EvidenceEvent
from .shared_transport import validate_common_event


_PRIVATE_EVIDENCE_KEYS = frozenset(
    {
        "computer",
        "computername",
        "sourceuser",
        "targetuser",
        "user",
        "username",
        "title",
        "windowtitle",
    }
)
_PATH_EVIDENCE_KEYS = frozenset(
    {
        "executablepath",
        "gameexecutable",
        "imagepath",
        "modulepath",
        "path",
        "processpath",
        "sourceimage",
        "sourcepath",
        "targetimage",
        "targetpath",
    }
)
_IDENTITY_EVIDENCE_KEYS = frozenset(
    {
        "sha256",
        "source_sha256",
        "signature_status",
        "signature_native_code",
        "signature_native_code_hex",
        "signature_backend",
    }
)
_EVENT_EVIDENCE_KEYS: dict[str, frozenset[str]] = {
    "process_access": frozenset(
        {
            "inventory_source",
            "observation_kind",
            "previous_granted_access",
            "source_pid",
            "source_image",
            "target_pid",
            "target_image",
            "granted_access",
            "granted_access_hex",
            "access_labels",
        }
    )
    | _IDENTITY_EVIDENCE_KEYS,
    "window_overlap": frozenset(
        {
            "game_pid",
            "window_pid",
            "hwnd",
            "process_path",
            "class_name",
            "extended_style",
            "style_labels",
            "window_rect",
            "intersection_rect",
            "game_overlap_ratio",
            "candidate_overlap_ratio",
        }
    )
    | _IDENTITY_EVIDENCE_KEYS,
}
_MODULE_EVIDENCE_KEYS = frozenset(
    {
        "target_pid",
        "module_name",
        "module_path",
        "image_size",
        "previous_image_size",
        "observation_phase",
        "baseline_created",
    }
) | _IDENTITY_EVIDENCE_KEYS


def _path_digest(value: str) -> str:
    normalized = ntpath.normcase(ntpath.normpath(value.strip()))
    return hashlib.sha256(normalized.encode("utf-8", errors="surrogatepass")).hexdigest()


def _public_path(value: str) -> tuple[str, str]:
    """Return a useful basename plus an irreversible full-path fingerprint."""

    stripped = value.strip().rstrip("\\/")
    basename = ntpath.basename(stripped) or "<path>"
    return basename, _path_digest(value)


def _public_sensor_event_id(sensor_event: SensorEvent) -> str:
    """Keep cross-log correlation without exposing raw IDs containing host data."""

    material = "\0".join(
        (
            sensor_event.session_id,
            sensor_event.sensor_id,
            sensor_event.event_id,
        )
    )
    digest = hashlib.sha256(material.encode("utf-8", errors="surrogatepass")).hexdigest()
    return f"sensor-sha256:{digest}"


def _allowed_evidence_keys(event_type: str) -> frozenset[str]:
    if event_type.startswith("module_"):
        return _MODULE_EVIDENCE_KEYS
    return _EVENT_EVIDENCE_KEYS.get(event_type, frozenset())


def _public_event_evidence(sensor_event: SensorEvent) -> dict[str, Any]:
    """Select only fields needed for central scoring/review.

    Local raw sensor logs retain the complete payload.  In particular, Sysmon's
    arbitrary ``data`` mapping, call trace, rule name, host and account fields
    never cross this central-telemetry boundary.
    """

    allowed = _allowed_evidence_keys(sensor_event.event_type)
    selected = {
        key: value for key, value in sensor_event.payload.items() if key in allowed
    }
    public = _public_evidence(selected)
    return public if isinstance(public, dict) else {}


def _public_evidence(value: Any) -> Any:
    """Detach shared evidence while removing endpoint/user-identifying labels."""

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            normalized = "".join(char for char in str(key).casefold() if char.isalnum())
            if normalized in _PRIVATE_EVIDENCE_KEYS:
                continue
            if normalized in _PATH_EVIDENCE_KEYS and isinstance(item, str):
                basename, digest = _public_path(item)
                sanitized[str(key)] = basename
                sanitized[f"{key}_path_sha256"] = digest
                continue
            sanitized[str(key)] = _public_evidence(item)
        return sanitized
    if isinstance(value, list):
        return [_public_evidence(item) for item in value]
    return value


def _raw_points(event: EvidenceEvent) -> int:
    """Return the documented ESP-module raw weight for one evidence item."""

    if event.category == "process_tamper":
        return 3
    if event.category == "memory_read":
        return 2
    if event.category in {"handle_duplicate", "overlay"}:
        return 1
    if event.category == "behavioral_signal":
        reason = event.reason.casefold()
        if "known-bad" in reason or "blacklist" in reason:
            return 3
        return 1
    return 0


class TeamEventAdapter:
    """Build the exact common Event without coupling sensors to team output."""

    def __init__(
        self,
        *,
        session_started_at: float,
        player_id: str,
        module: str = "esp",
        clock_skew_tolerance_seconds: float = 2.0,
    ) -> None:
        if (
            isinstance(session_started_at, bool)
            or not isinstance(session_started_at, (int, float))
            or not math.isfinite(float(session_started_at))
            or session_started_at < 0
        ):
            raise ValueError("session_started_at must be finite and non-negative")
        if not isinstance(player_id, str) or not player_id.strip():
            raise ValueError("player_id must be a non-empty string")
        if not isinstance(module, str) or not module.strip():
            raise ValueError("module must be a non-empty string")
        if (
            isinstance(clock_skew_tolerance_seconds, bool)
            or not isinstance(clock_skew_tolerance_seconds, (int, float))
            or not math.isfinite(float(clock_skew_tolerance_seconds))
            or clock_skew_tolerance_seconds < 0
        ):
            raise ValueError(
                "clock_skew_tolerance_seconds must be finite and non-negative"
            )
        self.session_started_at_ms = int(round(float(session_started_at) * 1000.0))
        self.clock_skew_tolerance_ms = int(
            round(float(clock_skew_tolerance_seconds) * 1000.0)
        )
        self.player_id = player_id.strip()
        self.module = module.strip().lower()

    def convert(
        self,
        sensor_event: SensorEvent,
        evidence_events: Iterable[EvidenceEvent],
    ) -> TeamDetectionEvent | None:
        if not isinstance(sensor_event, SensorEvent):
            raise TypeError("sensor_event must be SensorEvent")
        evidence = tuple(evidence_events)
        if any(not isinstance(item, EvidenceEvent) for item in evidence):
            raise TypeError("evidence_events must contain EvidenceEvent values")
        linked = tuple(
            item
            for item in evidence
            if item.session_id == sensor_event.session_id
            and item.details.get("sensor_event_id") == sensor_event.event_id
        )
        raw_score = sum(_raw_points(item) for item in linked)
        if not linked or raw_score <= 0:
            return None

        elapsed_ms = sensor_event.timestamp_ms - self.session_started_at_ms
        if elapsed_ms < -self.clock_skew_tolerance_ms:
            # Do not relabel materially pre-session observations as occurring
            # at t=0.  A small tolerance remains for independent Windows event
            # timestamps that can differ slightly at the session boundary.
            return None

        reasons = tuple(dict.fromkeys(item.reason for item in linked if item.reason))
        elapsed_ms = max(0, elapsed_ms)
        public_evidence = _public_event_evidence(sensor_event)
        public_evidence.update(
            {
                "sensor_event_id": _public_sensor_event_id(sensor_event),
                "event_type": sensor_event.event_type,
                "categories": list(dict.fromkeys(item.category for item in linked)),
            }
        )
        result = TeamDetectionEvent(
            session_id=sensor_event.session_id,
            player_id=self.player_id,
            module=self.module,
            timestamp_ms=elapsed_ms,
            evidence=public_evidence,
            reasons=reasons,
            raw_score=raw_score,
        )
        # Keep the local events.jsonl contract identical to shared 0.2.0 even
        # when the central sender is disabled.
        validate_common_event(result.to_dict())
        return result


__all__ = ["TeamEventAdapter"]
