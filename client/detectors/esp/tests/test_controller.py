import tempfile
import threading
import time
import unittest
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import PropertyMock, patch

from anti_esp.config import AllowlistSettings, Settings, TelemetrySettings
from anti_esp.controller import AntiEspController
from anti_esp.models import EvidenceEvent
from anti_esp.overlay import OverlayMonitor
from anti_esp.store import SQLiteEvidenceStore
from anti_esp.sysmon import (
    SysmonPollResult,
    SysmonProcessAccess,
    SysmonStatus,
)
from anti_esp.windows_api import ProcessInfo


class FakePoller:
    def __init__(self, events):
        self.events = tuple(events)

    def poll(self):
        events, self.events = self.events, ()
        return SysmonPollResult(
            status=SysmonStatus(True, True, True, "ready", "ready"),
            events=events,
            scanned_count=len(events),
        )


class BlockingPoller:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def poll(self):
        self.calls += 1
        self.entered.set()
        self.release.wait(timeout=5.0)
        return SysmonPollResult(
            status=SysmonStatus(True, True, True, "ready", "ready")
        )


class FailingStore:
    def append_many_with_outbox(self, events, outbox_factory):
        raise OSError("database is full")

    def append(self, event):
        raise OSError("database is full")

    def close(self):
        pass


class CloseTrackingStore(SQLiteEvidenceStore):
    def __init__(self):
        super().__init__(":memory:")
        self.close_called = False

    def close(self):
        self.close_called = True
        super().close()


class CloseFailingTelemetry:
    session_id = "close_failure_001"
    session_dir = Path("telemetry-not-written")

    def close(self, **_kwargs):
        raise OSError("manifest close failed")


class FakeOverlay:
    def reset_cooldowns(self):
        pass

    def scan(self, game_pid, *, session_id="default"):
        return []


class EmittingOverlay(FakeOverlay):
    def scan(self, game_pid, *, session_id="default"):
        return [
            EvidenceEvent(
                category="overlay",
                strength=0.8,
                reliability=0.8,
                source="windows:window-enumeration",
                reason="test overlay",
                details={"process_path": "C:\\Trusted\\overlay.exe"},
                session_id=session_id,
                subject_id=str(game_pid),
            )
        ]


class FailingOverlay(FakeOverlay):
    def scan(self, game_pid, *, session_id="default"):
        raise OSError("window enumeration failed")


def process_access_event():
    return SysmonProcessAccess(
        record_id=42,
        event_id=10,
        timestamp=1_700_000_000.0,
        computer="TEST",
        source_process_id=123,
        source_thread_id=124,
        source_image="C:\\Tools\\reader.exe",
        source_user="TEST\\user",
        target_process_id=777,
        target_image="C:\\Game\\PenguinHotel-Win64-Shipping.exe",
        target_user="TEST\\user",
        granted_access=0x10,
        granted_access_raw="0x10",
        call_trace="",
        rule_name="",
        data={},
    )


class ControllerTests(unittest.TestCase):
    def test_controller_writes_exact_team_event_and_raw_sensor_log(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(
                database_path=Path(temp) / "events.db",
                telemetry=TelemetrySettings(
                    enabled=True,
                    root=Path(temp) / "sessions",
                    session_id="esp_001",
                    player_id="player_042",
                    scenario="esp",
                    cheat_on_ms=30_000,
                    cheat_off_ms=70_000,
                ),
            )
            controller = AntiEspController(
                settings,
                poller=FakePoller([process_access_event()]),
                overlay_monitor=FakeOverlay(),
                process_provider=lambda _: [
                    ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
                ],
                clock=lambda: 1_700_000_001.0,
            )
            self.assertEqual(controller.poll_once(), 1)
            session_dir = controller.telemetry_session_dir
            controller.close()

            self.assertIsNotNone(session_dir)
            event = json.loads((session_dir / "events.jsonl").read_text("utf-8"))
            self.assertEqual(event["session_id"], "esp_001")
            self.assertEqual(event["player_id"], "player_042")
            self.assertEqual(event["module"], "esp")
            self.assertEqual(event["raw_score"], 2)
            self.assertEqual(event["timestamp_ms"], 0)
            self.assertTrue(
                (session_dir / "raw" / "sysmon_process_access.jsonl").exists()
            )
            manifest = json.loads((session_dir / "manifest.json").read_text("utf-8"))
            self.assertEqual(manifest["test_metadata"]["cheat_on_ms"], 30_000)

    def test_poll_once_stores_and_scores_memory_access(self):
        with tempfile.TemporaryDirectory() as temp:
            now = 1_700_000_001.0
            settings = Settings(database_path=Path(temp) / "events.db")
            controller = AntiEspController(
                settings,
                poller=FakePoller([process_access_event()]),
                overlay_monitor=FakeOverlay(),
                process_provider=lambda _: [
                    ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
                ],
                store=SQLiteEvidenceStore(Path(temp) / "events.db"),
                clock=lambda: now,
            )
            try:
                self.assertEqual(controller.poll_once(), 1)
                events = controller.recent_events()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["category"], "memory_read")
                self.assertEqual(events[0]["access"], "0x00000010")
                # poll_once is testable without claiming that the background
                # monitor is alive; confidence therefore stays insufficient.
                self.assertEqual(controller.snapshot()["status"], "INSUFFICIENT")
            finally:
                controller.close()

    def test_no_game_keeps_observation_confidence_at_zero(self):
        settings = Settings(database_path=Path(":memory:"))
        controller = AntiEspController(
            settings,
            poller=FakePoller([]),
            overlay_monitor=FakeOverlay(),
            process_provider=lambda _: [],
            store=SQLiteEvidenceStore(":memory:"),
        )
        try:
            controller.poll_once()
            snapshot = controller.snapshot()
            self.assertEqual(snapshot["observation_confidence"], 0.0)
            self.assertEqual(snapshot["status"], "INSUFFICIENT")
        finally:
            controller.close()

    def test_missing_admin_or_sysmon_forces_insufficient_instead_of_low(self):
        def make_controller(*, elevated):
            controller = AntiEspController(
                Settings(database_path=Path(":memory:")),
                poller=FakePoller([]),
                overlay_monitor=FakeOverlay(),
                process_provider=lambda _: [],
                store=SQLiteEvidenceStore(":memory:"),
                elevation_provider=lambda: elevated,
            )
            controller._sensor_state["game"] = {"status": "online", "running": True}
            controller._sensor_state["overlay"] = {"status": "online", "enabled": True}
            controller._sensor_state["sysmon"] = {
                "status": "online",
                "available": True,
            }
            return controller

        with patch.object(
            AntiEspController, "running", new_callable=PropertyMock, return_value=True
        ):
            no_admin = make_controller(elevated=False)
            try:
                snapshot = no_admin.snapshot()
                self.assertLess(
                    snapshot["observation_confidence"],
                    no_admin._engine.minimum_observation_confidence,
                )
                self.assertEqual(snapshot["status"], "INSUFFICIENT")
            finally:
                no_admin.close()

            no_sysmon = make_controller(elevated=True)
            try:
                no_sysmon._sensor_state["sysmon"] = {
                    "status": "unavailable",
                    "available": False,
                }
                snapshot = no_sysmon.snapshot()
                self.assertLess(
                    snapshot["observation_confidence"],
                    no_sysmon._engine.minimum_observation_confidence,
                )
                self.assertEqual(snapshot["status"], "INSUFFICIENT")
            finally:
                no_sysmon.close()

    def test_overlay_path_allowlist_suppresses_event(self):
        settings = Settings(
            database_path=Path(":memory:"),
            allowlist=AllowlistSettings(paths=("c:\\trusted\\overlay.exe",)),
        )
        controller = AntiEspController(
            settings,
            poller=FakePoller([]),
            overlay_monitor=EmittingOverlay(),
            process_provider=lambda _: [
                ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
            ],
            store=SQLiteEvidenceStore(":memory:"),
        )
        try:
            self.assertEqual(controller.poll_once(), 0)
            self.assertEqual(controller.recent_events(), [])
        finally:
            controller.close()

    def test_same_name_event_for_non_running_target_pid_is_ignored(self):
        controller = AntiEspController(
            Settings(database_path=Path(":memory:")),
            poller=FakePoller(
                [replace(process_access_event(), target_process_id=999)]
            ),
            overlay_monitor=FakeOverlay(),
            process_provider=lambda _: [
                ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
            ],
            store=SQLiteEvidenceStore(":memory:"),
            clock=lambda: 1_700_000_001.0,
        )
        try:
            self.assertEqual(controller.poll_once(), 0)
            self.assertEqual(controller.recent_events(), [])
        finally:
            controller.close()

    def test_event_older_than_current_game_process_is_ignored(self):
        controller = AntiEspController(
            Settings(database_path=Path(":memory:")),
            poller=FakePoller([process_access_event()]),
            overlay_monitor=FakeOverlay(),
            process_provider=lambda _: [
                ProcessInfo(
                    777,
                    "C:\\Game\\PenguinHotel-Win64-Shipping.exe",
                    created_at=1_700_000_010.0,
                )
            ],
            store=SQLiteEvidenceStore(":memory:"),
            clock=lambda: 1_700_000_011.0,
        )
        try:
            self.assertEqual(controller.poll_once(), 0)
        finally:
            controller.close()

    def test_missing_visible_game_window_keeps_overlay_waiting(self):
        controller = AntiEspController(
            Settings(database_path=Path(":memory:")),
            poller=FakePoller([]),
            overlay_monitor=OverlayMonitor(window_provider=lambda: []),
            process_provider=lambda _: [
                ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
            ],
            store=SQLiteEvidenceStore(":memory:"),
        )
        try:
            controller.poll_once()
            state = controller.sensor_status()["overlay"]
            self.assertEqual(state["status"], "waiting")
            self.assertFalse(state["game_window_found"])
        finally:
            controller.close()

    def test_overlay_failure_is_reported_as_sensor_error(self):
        controller = AntiEspController(
            Settings(database_path=Path(":memory:")),
            poller=FakePoller([]),
            overlay_monitor=FailingOverlay(),
            process_provider=lambda _: [
                ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
            ],
            store=SQLiteEvidenceStore(":memory:"),
        )
        try:
            controller.poll_once()
            state = controller.sensor_status()["overlay"]
            self.assertEqual(state["status"], "error")
            self.assertIn("window enumeration failed", state["message"])
        finally:
            controller.close()

    def test_stop_timeout_keeps_live_thread_and_prevents_duplicate_collector(self):
        poller = BlockingPoller()
        controller = AntiEspController(
            Settings(database_path=Path(":memory:"), poll_interval_seconds=0.1),
            poller=poller,
            overlay_monitor=FakeOverlay(),
            process_provider=lambda _: [
                ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
            ],
            store=SQLiteEvidenceStore(":memory:"),
        )
        try:
            controller.start()
            self.assertTrue(poller.entered.wait(timeout=1.0))

            with self.assertRaises(TimeoutError):
                controller.stop(timeout_seconds=0.01)
            self.assertTrue(controller.running)

            controller.start()
            self.assertEqual(poller.calls, 1)

            poller.release.set()
            controller.stop(timeout_seconds=1.0)
            self.assertFalse(controller.running)
        finally:
            poller.release.set()
            if controller.running:
                controller.stop(timeout_seconds=1.0)
            controller.close()

    def test_fatal_store_error_is_exposed_in_collector_sensor(self):
        controller = AntiEspController(
            Settings(database_path=Path(":memory:"), poll_interval_seconds=0.1),
            poller=FakePoller([process_access_event()]),
            overlay_monitor=FakeOverlay(),
            process_provider=lambda _: [
                ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
            ],
            store=FailingStore(),
            clock=lambda: 1_700_000_001.0,
        )
        try:
            controller.start()
            deadline = time.monotonic() + 1.0
            while controller.running and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(controller.running)
            state = controller.sensor_status()["collector"]
            self.assertEqual(state["status"], "error")
            self.assertIn("database is full", state["message"])
        finally:
            controller.close()

    def test_fatal_collector_marks_telemetry_session_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(
                database_path=Path(":memory:"),
                poll_interval_seconds=0.1,
                telemetry=TelemetrySettings(
                    enabled=True,
                    root=Path(temp) / "sessions",
                    session_id="failed_001",
                    player_id="player_042",
                ),
            )
            controller = AntiEspController(
                settings,
                poller=FakePoller([process_access_event()]),
                overlay_monitor=FakeOverlay(),
                process_provider=lambda _: [
                    ProcessInfo(777, "C:\\Game\\PenguinHotel-Win64-Shipping.exe")
                ],
                store=FailingStore(),
                clock=lambda: 1_700_000_001.0,
            )
            controller.start()
            deadline = time.monotonic() + 1.0
            while controller.running and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(controller.running)
            controller.close()

            manifest_path = (
                Path(temp) / "sessions" / "failed_001" / "manifest.json"
            )
            manifest = json.loads(manifest_path.read_text("utf-8"))
            self.assertEqual(manifest["status"], "failed")
            self.assertIn("database is full", manifest["failure_reason"])

    def test_store_is_closed_even_when_telemetry_close_fails(self):
        store = CloseTrackingStore()
        controller = AntiEspController(
            Settings(database_path=Path(":memory:")),
            poller=FakePoller([]),
            overlay_monitor=FakeOverlay(),
            process_provider=lambda _: [],
            store=store,
            telemetry_writer=CloseFailingTelemetry(),
        )
        with self.assertRaisesRegex(OSError, "manifest close failed"):
            controller.close()
        self.assertTrue(store.close_called)

    def test_context_exception_marks_telemetry_session_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(
                database_path=Path(temp) / "events.db",
                telemetry=TelemetrySettings(
                    enabled=True,
                    root=Path(temp) / "sessions",
                    session_id="context_failed_001",
                    player_id="player_042",
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "boom"):
                with AntiEspController(
                    settings,
                    poller=FakePoller([]),
                    overlay_monitor=FakeOverlay(),
                    process_provider=lambda _: [],
                ):
                    raise RuntimeError("boom")

            manifest_path = (
                Path(temp)
                / "sessions"
                / "context_failed_001"
                / "manifest.json"
            )
            manifest = json.loads(manifest_path.read_text("utf-8"))
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["failure_reason"], "boom")


if __name__ == "__main__":
    unittest.main()
