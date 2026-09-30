import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from client.LocalGuard.external_access.common import ArtifactCache, ArtifactInspector
from client.LocalGuard.external_access.common.models import TargetProcess
from client.LocalGuard.external_access.process_access.access_rights import PROCESS_VM_WRITE
from client.LocalGuard.external_access.process_access.allowlist import (
    ProcessAllowlist,
    ProcessAllowlistEntry,
)
from client.LocalGuard.external_access.process_access.handle_sensor import HandleSensorUnavailable
from client.LocalGuard.external_access.process_access.models import ExternalHandleObservation
from client.LocalGuard.external_access.process_access.runner import (
    ProcessAccessRunner,
    ScanReport,
    _configure_shared_client,
    _enforce_error_limit,
    _next_error_streak,
    _write_local_and_send,
)


class _FixedLocator:
    def __init__(self, game):
        self._game = game

    def find(self):
        return self._game


class _FixedSensor:
    def __init__(self, observations):
        self._observations = observations

    def scan(self, _game):
        return self._observations


class _FailingSensor:
    def scan(self, _game):
        raise HandleSensorUnavailable("access denied")


class ProcessAccessRunnerTests(unittest.TestCase):
    def test_error_limit_exits_with_watchdog_visible_code(self):
        _enforce_error_limit(2, 3)
        with self.assertRaises(SystemExit) as raised:
            _enforce_error_limit(3, 3)
        self.assertEqual(raised.exception.code, 2)

    def test_shared_client_uses_a_process_access_specific_outbox(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "client.LocalGuard.external_access.process_access.runner.ClientConfig.from_env",
            return_value=object(),
        ), mock.patch(
            "client.LocalGuard.external_access.process_access.runner.configure_client"
        ):
            configured = _configure_shared_client()
            configured_path = Path(os.environ["GZZ_TELEMETRY_OUTBOX"])

        self.assertTrue(configured)
        self.assertEqual(
            configured_path.parts[-4:],
            ("logs", "outbox", "external_access", "client.sqlite3"),
        )

    def test_exact_game_pid_is_required_by_the_default_locator(self):
        with mock.patch(
            "client.LocalGuard.external_access.process_access.runner.ProcessLocator"
        ) as locator:
            ProcessAccessRunner(
                game_executable_name="game.exe",
                game_pid=9876,
                session_id="normal_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
            )

        locator.assert_called_once_with(
            "game.exe", expected_pid=9876, require_unique=True
        )

    def test_shared_writer_records_locally_before_queuing_same_event(self):
        event = {
            "session_id": "esp_001",
            "player_id": "player_042",
            "module": "external_access",
            "timestamp_ms": 100,
            "evidence": {"submodule": "external_process"},
            "reasons": ["test"],
            "raw_score": 1,
        }
        calls = []

        with mock.patch(
            "client.LocalGuard.external_access.process_access.runner.append_detection_jsonl",
            side_effect=lambda path, result: calls.append(("local", path, result)),
        ), mock.patch(
            "client.LocalGuard.external_access.process_access.runner.send_detection",
            side_effect=lambda result: calls.append(("shared", result))
            or SimpleNamespace(status="queued", event_id="event-1"),
        ):
            _write_local_and_send(Path("events.jsonl"), event)

        self.assertEqual(calls[0][0], "local")
        self.assertEqual(calls[1][0], "shared")
        self.assertIs(calls[0][2], calls[1][1])

    def test_error_streak_resets_after_a_successful_scan(self):
        failed = ScanReport(True, 0, 0, 0, 1, error="access denied")
        succeeded = ScanReport(True, 0, 0, 0, 1)

        self.assertEqual(_next_error_streak(1, failed), 2)
        self.assertEqual(_next_error_streak(2, succeeded), 0)

    def test_writes_one_result_for_a_risky_observation(self):
        saved = []
        game = TargetProcess(500, "game.exe", Path("C:/game.exe"), 1.0)
        observation = ExternalHandleObservation(700, "tool.exe", None, PROCESS_VM_WRITE)
        clock_values = iter([10.0, 10.0, 10.010, 10.020, 10.030])
        runner = ProcessAccessRunner(
            game_executable_name="game.exe",
            session_id="round_12",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_FixedLocator(game),
            sensor=_FixedSensor([observation]),
            artifact_cache=ArtifactCache(ArtifactInspector(lambda _: ("trusted", "Test"))),
            writer=lambda _path, result: saved.append(result),
            clock=lambda: next(clock_values),
        )

        report = runner.scan_once()

        self.assertTrue(report.game_found)
        self.assertEqual(report.observed_processes, 1)
        self.assertEqual(report.allowed_processes, 0)
        self.assertEqual(report.emitted_detections, 1)
        self.assertEqual(saved[0]["raw_score"], 3)  # VM_WRITE 2 + unavailable trust info 1
        self.assertIn("Process executable trust information is unavailable", saved[0]["reasons"])
        self.assertIn("scan_duration_ms", saved[0]["evidence"])

    def test_game_not_running_does_not_write_a_result(self):
        saved = []
        runner = ProcessAccessRunner(
            game_executable_name="game.exe",
            session_id="round_12",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_FixedLocator(None),
            sensor=_FixedSensor([]),
            writer=lambda _path, result: saved.append(result),
        )

        report = runner.scan_once()

        self.assertFalse(report.game_found)
        self.assertEqual(saved, [])

    def test_sensor_permission_failure_returns_error_without_writing(self):
        saved = []
        game = TargetProcess(500, "game.exe", Path("C:/game.exe"), 1.0)
        clock_values = iter([10.0, 10.0, 10.010])
        runner = ProcessAccessRunner(
            game_executable_name="game.exe",
            session_id="round_12",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_FixedLocator(game),
            sensor=_FailingSensor(),
            writer=lambda _path, result: saved.append(result),
            clock=lambda: next(clock_values),
        )

        report = runner.scan_once()

        self.assertTrue(report.game_found)
        self.assertEqual(report.emitted_detections, 0)
        self.assertEqual(report.error, "access denied")
        self.assertEqual(saved, [])

    def test_exact_name_and_hash_allowlist_suppresses_a_reviewed_process(self):
        saved = []
        game = TargetProcess(500, "game.exe", Path("C:/game.exe"), 1.0)
        fixture = Path(__file__)
        import hashlib

        fixture_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
        observation = ExternalHandleObservation(700, fixture.name, fixture, PROCESS_VM_WRITE)
        runner = ProcessAccessRunner(
            game_executable_name="game.exe",
            session_id="normal_001",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_FixedLocator(game),
            sensor=_FixedSensor([observation]),
            allowlist=ProcessAllowlist([ProcessAllowlistEntry(fixture.name, fixture_hash)]),
            writer=lambda _path, result: saved.append(result),
        )

        report = runner.scan_once()

        self.assertEqual(report.allowed_processes, 1)
        self.assertEqual(report.emitted_detections, 0)
        self.assertEqual(saved, [])


if __name__ == "__main__":
    unittest.main()
