"""Stable process/session context passed to LocalGuard sensors."""

from __future__ import annotations

from dataclasses import dataclass
import math
import time


def _finite_time(name: str, value: float | int) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    converted = float(value)
    if not math.isfinite(converted) or converted < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return converted


@dataclass(frozen=True, slots=True)
class ProcessTarget:
    """One exact game process instance, resistant to PID reuse when possible."""

    pid: int
    executable_path: str
    created_at: float | None = None
    parent_pid: int | None = None
    parent_created_at: float | None = None
    parent_executable_path: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("pid must be a positive integer")
        if not isinstance(self.executable_path, str) or not self.executable_path.strip():
            raise ValueError("executable_path must be a non-empty string")
        object.__setattr__(self, "executable_path", self.executable_path.strip())
        if self.created_at is not None:
            object.__setattr__(
                self, "created_at", _finite_time("created_at", self.created_at)
            )
        if self.parent_pid is not None:
            if (
                isinstance(self.parent_pid, bool)
                or not isinstance(self.parent_pid, int)
                or self.parent_pid <= 0
            ):
                raise ValueError("parent_pid must be a positive integer or None")
        if self.parent_created_at is not None:
            object.__setattr__(
                self,
                "parent_created_at",
                _finite_time("parent_created_at", self.parent_created_at),
            )
            if self.parent_pid is None:
                raise ValueError("parent_created_at requires parent_pid")
        if self.parent_executable_path is not None:
            if (
                not isinstance(self.parent_executable_path, str)
                or not self.parent_executable_path.strip()
            ):
                raise ValueError("parent_executable_path must be non-empty or None")
            if self.parent_pid is None:
                raise ValueError("parent_executable_path requires parent_pid")
            object.__setattr__(
                self, "parent_executable_path", self.parent_executable_path.strip()
            )

    @property
    def subject_id(self) -> str:
        creation = (
            str(int(round(self.created_at * 1000.0)))
            if self.created_at is not None
            else "unknown"
        )
        return f"game-process:{self.pid}:{creation}"


@dataclass(frozen=True, slots=True)
class SensorContext:
    """Immutable context shared with every sensor during one poll cycle."""

    session_id: str
    targets: tuple[ProcessTarget, ...] = ()
    session_started_at: float = 0.0
    observed_at: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ValueError("session_id must be a non-empty string")
        object.__setattr__(self, "session_id", self.session_id.strip())
        targets = tuple(self.targets)
        if any(not isinstance(target, ProcessTarget) for target in targets):
            raise TypeError("targets must contain only ProcessTarget values")
        pids = [target.pid for target in targets]
        if len(pids) != len(set(pids)):
            raise ValueError("targets cannot contain duplicate PIDs")
        object.__setattr__(self, "targets", targets)
        object.__setattr__(
            self,
            "session_started_at",
            _finite_time("session_started_at", self.session_started_at),
        )
        observed = self.observed_at or time.time()
        object.__setattr__(self, "observed_at", _finite_time("observed_at", observed))

    @property
    def target_by_pid(self) -> dict[int, ProcessTarget]:
        return {target.pid: target for target in self.targets}


__all__ = ["ProcessTarget", "SensorContext"]
