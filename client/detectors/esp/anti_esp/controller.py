from __future__ import annotations

import ctypes
import os
import math
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4

from .config import Settings
from .core.context import ProcessTarget, SensorContext
from .core.session import SessionTelemetryWriter
from .detectors.esp_detector import EspEventDetector
from .models import EvidenceEvent
from .overlay import OverlayMonitor
from .pipeline import EspDetectionPipeline
from .policy import FileFingerprintCache, source_is_allowlisted
from .scoring import DEFAULT_POLICIES, SuspicionEngine
from .sensors.anticheat_registry import AntiCheatPidRegistry
from .sensors.file_identity import FileIdentityEnricher
from .sensors.handle_sensor import CurrentProcessHandleSensor
from .sensors.identity import PseudonymousIdentity
from .sensors.module_events import LoadedModuleSensor
from .sensors.process_access import SysmonProcessAccessSensor
from .sensors.process_relationships import SteamExecutableVerifier
from .sensors.window_overlap import WindowOverlapSensor
from .store import SQLiteEvidenceStore
from .sysmon import SysmonPoller
from .team_format import TeamEventAdapter
from .windows_api import ProcessInfo, find_processes_by_name


def _is_process_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class AntiEspController:
    """Coordinates sensors, evidence storage, and explainable scoring.

    The controller intentionally performs no automatic punishment.  Its only
    response mode is observation: record factual events and expose a review
    score with a separate observation-confidence value.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        poller: Any | None = None,
        overlay_monitor: OverlayMonitor | None = None,
        process_provider: Callable[[str], Iterable[ProcessInfo]] = find_processes_by_name,
        store: SQLiteEvidenceStore | None = None,
        clock: Callable[[], float] = time.time,
        process_access_sensor: Any | None = None,
        module_sensor: Any | None = None,
        window_sensor: Any | None = None,
        telemetry_writer: SessionTelemetryWriter | None = None,
        handle_sensor: Any | None = None,
        session_started_at: float | None = None,
        team_event_sink: Callable[[dict[str, Any], str], bool] | None = None,
        anticheat_pid_provider: Callable[[], Iterable[int]] | None = None,
        elevation_provider: Callable[[], bool] = _is_process_elevated,
    ) -> None:
        self.settings = settings
        self._clock = clock
        self._session_started_at = (
            float(session_started_at)
            if session_started_at is not None
            else self._clock()
        )
        if not math.isfinite(self._session_started_at) or self._session_started_at < 0:
            raise ValueError("session_started_at must be finite and non-negative")
        self.session_id = (
            settings.telemetry.session_id
            or (telemetry_writer.session_id if telemetry_writer is not None else None)
            or self._generated_session_id()
        )
        self._process_provider = process_provider
        # The first bounded query is included. Current game PID and creation time
        # checks below reject stale records while retaining accesses that happened
        # after the game started but before this monitor UI was opened.
        poller = poller or SysmonPoller(include_existing=True)
        registered_anticheat_pids = (
            anticheat_pid_provider or AntiCheatPidRegistry().live_pids
        )
        self._fingerprints = FileFingerprintCache()
        self._file_identity = FileIdentityEnricher(fingerprints=self._fingerprints)
        steam_source_verifier = SteamExecutableVerifier(self._file_identity)
        self._process_access_sensor = process_access_sensor or SysmonProcessAccessSensor(
            poller=poller,
            self_pid=os.getpid(),
            clock=clock,
            source_identity_provider=self._file_identity,
            excluded_pid_provider=registered_anticheat_pids,
            steam_source_verifier=steam_source_verifier,
        )
        # ``overlay_monitor`` remains a compatibility injection point for old
        # tests/callers. Production uses the strict factual window sensor.
        self._legacy_overlay = overlay_monitor
        self._window_sensor = window_sensor or WindowOverlapSensor(
            cooldown_seconds=settings.overlay.cooldown_seconds,
            self_pid=os.getpid(),
            clock=clock,
            process_identity_provider=self._file_identity,
        )
        self._module_sensor = module_sensor or LoadedModuleSensor(
            identity_provider=(
                self._file_identity
                if settings.module_monitor.verify_signatures
                else lambda path: {"sha256": self._fingerprints.sha256(path)}
            ),
            clock=clock,
        )
        self._handle_sensor = handle_sensor or CurrentProcessHandleSensor(
            self_pid=os.getpid(),
            cooldown_seconds=settings.handle_monitor.cooldown_seconds,
            source_identity_provider=self._file_identity,
            excluded_pid_provider=registered_anticheat_pids,
            steam_source_verifier=steam_source_verifier,
        )
        self._store = store or SQLiteEvidenceStore(settings.database_path)
        policies = {
            category: replace(
                policy,
                window_seconds=min(
                    policy.window_seconds,
                    settings.event_window_seconds,
                ),
            )
            for category, policy in DEFAULT_POLICIES.items()
        }
        self._engine = SuspicionEngine(policies=policies)
        pepper_text = os.environ.get(settings.identity.pepper_environment)
        identity = PseudonymousIdentity(
            enabled=settings.identity.enabled,
            pepper=pepper_text,
            clock=clock,
        ).generate()
        self._telemetry = telemetry_writer
        if self._telemetry is None and settings.telemetry.enabled:
            self._telemetry = SessionTelemetryWriter(
                settings.telemetry.root,
                session_id=self.session_id,
                game_executable=settings.game_executable,
                host_identity=identity.to_dict(),
                test_metadata={
                    "scenario": settings.telemetry.scenario,
                    "cheat_on_ms": settings.telemetry.cheat_on_ms,
                    "cheat_off_ms": settings.telemetry.cheat_off_ms,
                },
            )
        self._detector = EspEventDetector(
            minimum_overlay_overlap_ratio=settings.overlay.minimum_overlap_ratio,
            allowlisted_paths=settings.allowlist.paths,
            allowlisted_sha256=settings.allowlist.sha256,
        )
        self._pipeline = EspDetectionPipeline(
            detectors=(self._detector,),
            store=self._store,
            scoring=self._engine,
            team_adapter=TeamEventAdapter(
                session_started_at=self._session_started_at,
                player_id=settings.telemetry.player_id,
            ),
            telemetry=self._telemetry,
            team_event_sink=team_event_sink,
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._closed = False
        self._fatal_error: str | None = None
        try:
            self._elevated = bool(elevation_provider())
        except Exception:
            self._elevated = False
        self._last_overlay_scan = 0.0
        self._last_module_scan = 0.0
        self._last_handle_scan = 0.0
        self._game_pids: tuple[int, ...] = ()
        self._sensor_state: dict[str, dict[str, Any]] = {
            "collector": {"status": "waiting", "available": True},
            "privilege": {
                "status": "online" if self._elevated else "unavailable",
                "elevated": self._elevated,
                "message": (
                    "administrator token available"
                    if self._elevated
                    else "administrator privileges are required for complete collection"
                ),
            },
            "sysmon": {"status": "waiting", "available": False},
            "game": {"status": "waiting", "running": False},
            "overlay": {
                "status": "waiting" if settings.overlay.enabled else "disabled",
                "enabled": settings.overlay.enabled,
            },
            "modules": {
                "status": "waiting" if settings.module_monitor.enabled else "disabled",
                "enabled": settings.module_monitor.enabled,
            },
            "handles": {
                "status": "waiting" if settings.handle_monitor.enabled else "disabled",
                "enabled": settings.handle_monitor.enabled,
            },
            "identity": identity.to_dict(),
            "telemetry": {
                "status": "online" if self._telemetry is not None else "disabled",
                "enabled": self._telemetry is not None,
                "session_id": self.session_id,
                "player_id": settings.telemetry.player_id,
            },
        }

    def _generated_session_id(self) -> str:
        timestamp = datetime.fromtimestamp(
            self._session_started_at, tz=timezone.utc
        ).strftime("%Y%m%d_%H%M%S")
        return f"esp_{timestamp}_{uuid4().hex[:8]}"

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def fatal_error(self) -> str | None:
        with self._lock:
            return self._fatal_error

    @property
    def telemetry_session_dir(self) -> Path | None:
        return self._telemetry.session_dir if self._telemetry is not None else None

    def mark_failed(self, reason: object) -> None:
        """Record a foreground/session failure for manifest finalization."""

        message = str(reason).strip()
        if not message:
            message = "unspecified controller failure"
        with self._lock:
            if self._fatal_error is None:
                self._fatal_error = message

    def start(self) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("controller is closed")
            if self._fatal_error is not None:
                raise RuntimeError(
                    "collector previously stopped after a fatal error; "
                    "create a new controller and session"
                )
            if self.running:
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="anti-esp-monitor",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, timeout_seconds: float | None = None) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            timeout = (
                max(2.0, self.settings.poll_interval_seconds * 4.0)
                if timeout_seconds is None
                else max(0.0, float(timeout_seconds))
            )
            thread.join(timeout=timeout)
            if thread.is_alive():
                # Retain the reference: reporting stopped here would allow a
                # second collector to start and close() could invalidate the
                # SQLite connection under the still-running first collector.
                raise TimeoutError(
                    "collector did not stop before the timeout; retry after the "
                    "current sensor poll returns"
                )
        with self._lock:
            if self._thread is thread:
                self._thread = None

    def close(self) -> None:
        self.stop()
        close_error: Exception | None = None
        with self._lock:
            if not self._closed:
                try:
                    if self._telemetry is not None:
                        self._telemetry.close(
                            status="failed" if self._fatal_error else "completed",
                            failure_reason=self._fatal_error,
                        )
                except Exception as exc:
                    close_error = exc
                try:
                    self._store.close()
                except Exception as exc:
                    if close_error is None:
                        close_error = exc
                finally:
                    self._closed = True
        if close_error is not None:
            raise close_error

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            started = time.monotonic()
            try:
                self.poll_once()
            except Exception as exc:
                with self._lock:
                    self._fatal_error = str(exc)
                    self._sensor_state["collector"] = {
                        "status": "error",
                        "message": f"collector stopped after fatal error: {exc}",
                    }
                return
            with self._lock:
                self._sensor_state["collector"] = {
                    "status": "online",
                    "available": True,
                    "message": "collector loop is running",
                }
            elapsed = time.monotonic() - started
            self._stop_event.wait(
                max(0.05, self.settings.poll_interval_seconds - elapsed)
            )

    def poll_once(self) -> int:
        """Collect one sensor cycle and return the number of new evidence events."""

        now = self._clock()
        legacy_events: list[EvidenceEvent] = []
        inserted = 0

        try:
            processes = tuple(self._process_provider(self.settings.game_executable))
            targets_by_pid = {
                int(process.pid): ProcessTarget(
                    int(process.pid),
                    process.image_path or self.settings.game_executable,
                    process.created_at,
                    process.parent_pid,
                    process.parent_created_at,
                    process.parent_image_path,
                )
                for process in processes
            }
            targets = tuple(targets_by_pid[pid] for pid in sorted(targets_by_pid))
            game_pids = tuple(sorted({target.pid for target in targets}))
            game_created_at = {
                target.pid: target.created_at
                for target in targets
                if target.created_at is not None
            }
            game_state = {
                "status": "online" if game_pids else "waiting",
                "running": bool(game_pids),
                "pids": list(game_pids),
                "created_at": game_created_at,
                "message": (
                    f"watching {len(game_pids)} game process(es)"
                    if game_pids
                    else "waiting for the game process"
                ),
            }
        except Exception as exc:
            targets = ()
            game_pids = ()
            game_created_at = {}
            game_state = {
                "status": "error",
                "running": False,
                "pids": [],
                "message": f"process enumeration failed: {exc}",
            }

        with self._lock:
            if game_pids != self._game_pids:
                self._window_sensor.reset_cooldowns()
                self._handle_sensor.reset_baseline()
                if self._legacy_overlay is not None:
                    self._legacy_overlay.reset_cooldowns()
            self._game_pids = game_pids
            self._sensor_state["game"] = game_state

        context = SensorContext(
            self.session_id,
            targets,
            session_started_at=self._session_started_at,
            observed_at=now,
        )

        access_batch = self._process_access_sensor.poll(context)
        sysmon_state = dict(access_batch.details)
        sysmon_state.update(
            {
                "status": access_batch.status,
                "available": access_batch.status == "online",
                "message": access_batch.message,
                "events": len(access_batch.events),
            }
        )
        inserted += self._pipeline.process_batch(access_batch).accepted_evidence_count

        handle_state: dict[str, Any]
        if not self.settings.handle_monitor.enabled:
            handle_state = {"status": "disabled", "enabled": False}
        elif not game_pids:
            handle_state = {
                "status": "waiting",
                "enabled": True,
                "message": "waiting for the game process",
            }
        elif (
            now - self._last_handle_scan
            >= self.settings.handle_monitor.scan_interval_seconds
        ):
            handle_batch = self._handle_sensor.poll(context)
            inserted += self._pipeline.process_batch(
                handle_batch
            ).accepted_evidence_count
            self._last_handle_scan = now
            handle_state = {
                **dict(handle_batch.details),
                "status": handle_batch.status,
                "enabled": True,
                "events": len(handle_batch.events),
                "message": handle_batch.message,
            }
        else:
            with self._lock:
                handle_state = dict(self._sensor_state["handles"])

        overlay_state: dict[str, Any]
        if not self.settings.overlay.enabled:
            overlay_state = {"status": "disabled", "enabled": False}
        elif not game_pids:
            overlay_state = {
                "status": "waiting",
                "enabled": True,
                "message": "waiting for a visible game window",
            }
        elif now - self._last_overlay_scan >= self.settings.overlay_scan_interval_seconds:
            if self._legacy_overlay is not None:
                try:
                    overlay_events: list[EvidenceEvent] = []
                    visible_game_window = False
                    for game_pid in game_pids:
                        overlay_events.extend(
                            self._legacy_overlay.scan(
                                game_pid, session_id=self.session_id
                            )
                        )
                        visible_game_window = visible_game_window or bool(
                            getattr(
                                self._legacy_overlay, "last_game_window_found", True
                            )
                        )
                    overlay_events = [
                        event
                        for event in overlay_events
                        if not self._overlay_source_is_allowlisted(event)
                    ]
                    legacy_events.extend(overlay_events)
                    self._last_overlay_scan = now
                    overlay_state = {
                        "status": "online" if visible_game_window else "waiting",
                        "enabled": True,
                        "events": len(overlay_events),
                        "game_window_found": visible_game_window,
                        "message": (
                            "visible game window found"
                            if visible_game_window
                            else "game process found; waiting for a visible game window"
                        ),
                    }
                except Exception as exc:
                    overlay_state = {
                        "status": "error",
                        "enabled": True,
                        "message": f"overlay scan failed: {exc}",
                    }
            else:
                overlap_batch = self._window_sensor.poll(context)
                inserted += self._pipeline.process_batch(
                    overlap_batch
                ).accepted_evidence_count
                self._last_overlay_scan = now
                overlay_state = {
                    **dict(overlap_batch.details),
                    "status": overlap_batch.status,
                    "enabled": True,
                    "events": len(overlap_batch.events),
                    "message": overlap_batch.message,
                }
        else:
            with self._lock:
                overlay_state = dict(self._sensor_state["overlay"])

        module_state: dict[str, Any]
        if not self.settings.module_monitor.enabled:
            module_state = {"status": "disabled", "enabled": False}
        elif not game_pids:
            module_state = {
                "status": "waiting",
                "enabled": True,
                "message": "waiting for the game process",
            }
        elif (
            now - self._last_module_scan
            >= self.settings.module_monitor.scan_interval_seconds
        ):
            module_batch = self._module_sensor.poll(context)
            inserted += self._pipeline.process_batch(
                module_batch
            ).accepted_evidence_count
            self._last_module_scan = now
            module_state = {
                **dict(module_batch.details),
                "status": module_batch.status,
                "enabled": True,
                "events": len(module_batch.events),
                "message": module_batch.message,
            }
        else:
            with self._lock:
                module_state = dict(self._sensor_state["modules"])

        with self._lock:
            self._sensor_state["sysmon"] = sysmon_state
            self._sensor_state["overlay"] = overlay_state
            self._sensor_state["modules"] = module_state
            self._sensor_state["handles"] = handle_state

        for event in legacy_events:
            if self._store.append(event):
                self._engine.add_event(event)
                inserted += 1
        return inserted

    def _overlay_source_is_allowlisted(self, event: EvidenceEvent) -> bool:
        source_path = event.details.get("process_path")
        if not isinstance(source_path, str) or not source_path:
            return False
        trusted, _digest = source_is_allowlisted(
            source_path,
            allowlist=self.settings.allowlist,
            fingerprints=self._fingerprints,
        )
        return trusted

    def _observation_confidence(self) -> float:
        with self._lock:
            sysmon = dict(self._sensor_state["sysmon"])
            game = dict(self._sensor_state["game"])
            overlay = dict(self._sensor_state["overlay"])
            modules = dict(self._sensor_state["modules"])
            handles = dict(self._sensor_state["handles"])
            privilege = dict(self._sensor_state["privilege"])
        if not self.running or not bool(game.get("running")):
            return 0.0

        confidence = 15.0  # The exact target process is present.
        if bool(sysmon.get("available")):
            # Channel availability does not prove that the expected Event 10
            # filter is active, so this intentionally cannot yield 100 alone.
            confidence += 50.0
            if bool(sysmon.get("truncated")):
                confidence -= 15.0
        if (
            self.settings.overlay.enabled
            and str(overlay.get("status", "")).lower() == "online"
        ):
            confidence += 20.0
        if (
            self.settings.module_monitor.enabled
            and str(modules.get("status", "")).lower() == "online"
        ):
            confidence += 15.0
        if (
            self.settings.handle_monitor.enabled
            and str(handles.get("status", "")).lower() == "online"
        ):
            confidence += 15.0
        confidence = min(100.0, max(0.0, confidence))

        required_online = [
            bool(privilege.get("elevated")),
            bool(sysmon.get("available"))
            and str(sysmon.get("status", "")).lower() == "online",
        ]
        for enabled, state in (
            (self.settings.overlay.enabled, overlay),
            (self.settings.module_monitor.enabled, modules),
            (self.settings.handle_monitor.enabled, handles),
        ):
            if enabled:
                required_online.append(str(state.get("status", "")).lower() == "online")
        if not all(required_online):
            insufficient_cap = max(
                0.0, self._engine.minimum_observation_confidence - 1.0
            )
            return min(insufficient_cap, confidence)
        return confidence

    def snapshot(self) -> dict[str, Any]:
        snapshot = self._engine.score(
            now=self._clock(),
            observation_confidence=self._observation_confidence(),
        ).to_dict()
        # The dashboard and reports use a compact, review-oriented vocabulary.
        if snapshot["status"] == "HIGH" and snapshot["suspicion"] >= 90.0:
            snapshot["status"] = "CRITICAL"
        return snapshot

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        events = self._store.recent(limit=limit, session_id=self.session_id)
        output: list[dict[str, Any]] = []
        for event in events:
            data = event.to_dict()
            policy = self._engine.policies.get(event.category)
            if policy is not None:
                # This is the event's base contribution before deduplication and
                # category caps; actual category totals live in ScoreSnapshot.
                data["points"] = round(
                    policy.points_per_event * event.strength * event.reliability,
                    2,
                )
            details = data.get("details", {})
            data["access"] = details.get(
                "granted_access_hex", details.get("style_labels")
            )
            output.append(data)
        return output

    def sensor_status(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {name: dict(value) for name, value in self._sensor_state.items()}

    def export_jsonl(self, path: str | Path) -> int:
        return self._store.export_jsonl(path, session_id=self.session_id)

    def add_evidence(self, event: EvidenceEvent) -> bool:
        """Test/replay hook that applies normal persistence and scoring rules."""

        if self._store.append(event):
            self._engine.add_event(event)
            return True
        return False

    def __enter__(self) -> "AntiEspController":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is not None:
            self.mark_failed(exc or exc_type)
        self.close()


__all__ = ["AntiEspController"]
