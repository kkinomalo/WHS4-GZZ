"""Read the Launcher's anti-cheat PID registry without trusting bare PIDs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Callable, Mapping

from ..windows_api import get_process_creation_time


_WINDOWS_EPOCH_OFFSET_SECONDS = 11_644_473_600.0
_FILETIME_TICKS_PER_SECOND = 10_000_000.0
_READ_ATTEMPTS = 25
_READ_RETRY_SECONDS = 0.02


def _filetime_to_unix_seconds(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    converted = value / _FILETIME_TICKS_PER_SECOND - _WINDOWS_EPOCH_OFFSET_SECONDS
    return converted if converted >= 0 else None


def default_registry_path() -> Path:
    configured_log_dir = os.environ.get("AC_LAUNCHER_LOG_DIR")
    if configured_log_dir:
        return Path(configured_log_dir) / "anticheat_pids.json"
    return (
        Path(__file__).resolve().parents[4]
        / "Launcher"
        / "logs"
        / "anticheat_pids.json"
    )


class AntiCheatPidRegistry:
    """Return only registry PIDs whose current creation time still matches.

    The Launcher's legacy ``modules`` mapping contains bare PIDs and is not safe
    against PID reuse.  This reader deliberately consumes only the launcher and
    ``entries`` records that carry the FILETIME captured at process creation.
    If a process cannot be queried, it is not excluded from detection.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        creation_time_provider: Callable[[int], float | None] = get_process_creation_time,
        tolerance_seconds: float = 0.001,
    ) -> None:
        self.path = Path(path) if path is not None else default_registry_path()
        self._creation_time = creation_time_provider
        self._tolerance = float(tolerance_seconds)
        if self._tolerance < 0:
            raise ValueError("tolerance_seconds must be non-negative")

    @staticmethod
    def _candidate(record: Mapping[str, object]) -> tuple[int, int] | None:
        pid = record.get("pid")
        created = record.get("create_time")
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or isinstance(created, bool)
            or not isinstance(created, int)
            or created <= 0
        ):
            return None
        return pid, created

    def _load(self) -> Mapping[str, object]:
        for attempt in range(_READ_ATTEMPTS):
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
                return value if isinstance(value, dict) else {}
            except FileNotFoundError:
                return {}
            except (OSError, UnicodeError, json.JSONDecodeError):
                # Launcher.registry writes with os.replace.  On Windows a reader
                # can briefly lose the race with that replacement; treating the
                # one failed read as an empty registry makes LocalGuard detect
                # its own processes.  Retry for the same bounded 0.5 s window as
                # the Launcher reader, then fail open to normal detection.
                if attempt + 1 >= _READ_ATTEMPTS:
                    return {}
                time.sleep(_READ_RETRY_SECONDS)
        return {}

    def live_pids(self) -> frozenset[int]:
        document = self._load()
        candidates: list[tuple[int, int]] = []

        launcher = self._candidate(
            {
                "pid": document.get("launcher_pid"),
                "create_time": document.get("launcher_create_time"),
            }
        )
        if launcher is not None:
            candidates.append(launcher)

        entries = document.get("entries")
        if isinstance(entries, dict):
            for raw in entries.values():
                if isinstance(raw, dict):
                    candidate = self._candidate(raw)
                    if candidate is not None:
                        candidates.append(candidate)

        live: set[int] = set()
        for pid, expected_filetime in candidates:
            expected = _filetime_to_unix_seconds(expected_filetime)
            if expected is None:
                continue
            try:
                actual = self._creation_time(pid)
            except Exception:
                actual = None
            if actual is not None and abs(float(actual) - expected) <= self._tolerance:
                live.add(pid)
        return frozenset(live)

    def __call__(self) -> frozenset[int]:
        return self.live_pids()


__all__ = ["AntiCheatPidRegistry", "default_registry_path"]
