import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from client.LocalGuard.external_access.common import ArtifactCache, ArtifactInspector
from client.LocalGuard.external_access.common.models import TargetProcess
from client.LocalGuard.external_access.module_integrity.allowlist import (
    ModuleAllowlist,
    ModuleAllowlistEntry,
)
from client.LocalGuard.external_access.module_integrity.models import (
    LoadedModule,
    ModuleSnapshot,
)
from client.LocalGuard.external_access.module_integrity.module_sensor import (
    ModuleSensorUnavailable,
)
from client.LocalGuard.external_access.module_integrity.runner import (
    ModuleIntegrityRunner,
    ScanReport,
    _configure_shared_client,
    _enforce_error_limit,
    _finish_shared_client,
    _updated_consecutive_errors,
    _write_local_and_send,
)


class _SequenceLocator:
    def __init__(self, values):
        self._values = list(values)

    def find(self):
        return self._values.pop(0)


class _FailingLocator:
    def find(self):
        raise OSError("process snapshot failed")


class _SequenceSensor:
    def __init__(self, values):
        self._values = list(values)

    def capture(self, _pid):
        value = self._values.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class _Clock:
    def __init__(self):
        self.value = 10.0

    def __call__(self):
        self.value += 0.01
        return self.value


def loaded(path, base=0x1000, size=4096):
    path = str(path)
    return LoadedModule(Path(path).name, path, base, size)


class ModuleIntegrityRunnerTests(unittest.TestCase):
    def test_error_limit_exits_with_watchdog_visible_code_two(self):
        _enforce_error_limit(2, 3)

        with self.assertRaises(SystemExit) as raised:
            _enforce_error_limit(3, 3)

        self.assertEqual(raised.exception.code, 2)

    def test_shared_client_uses_a_module_specific_standalone_outbox(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "client.LocalGuard.external_access.module_integrity.runner.ClientConfig.from_env",
            return_value=object(),
        ), patch(
            "client.LocalGuard.external_access.module_integrity.runner.configure_client"
        ):
            configured = _configure_shared_client()
            configured_path = Path(os.environ["GZZ_TELEMETRY_OUTBOX"])

        self.assertTrue(configured)
        self.assertEqual(
            configured_path.parts[-4:],
            ("logs", "outbox", "module_integrity", "client.sqlite3"),
        )

    def test_shared_client_preserves_the_launcher_outbox_override(self):
        launcher_path = str(Path("launcher") / "module.sqlite3")
        with patch.dict(
            os.environ,
            {"GZZ_TELEMETRY_OUTBOX": launcher_path},
            clear=True,
        ), patch(
            "client.LocalGuard.external_access.module_integrity.runner.ClientConfig.from_env",
            return_value=object(),
        ), patch(
            "client.LocalGuard.external_access.module_integrity.runner.configure_client"
        ):
            configured = _configure_shared_client()
            actual = os.environ["GZZ_TELEMETRY_OUTBOX"]

        self.assertTrue(configured)
        self.assertEqual(actual, launcher_path)

    def test_consecutive_error_counter_resets_after_a_successful_scan(self):
        failed = ScanReport(
            game_found=True,
            baseline_created=False,
            initial_audit_performed=False,
            observed_modules=0,
            added_modules=0,
            removed_modules=0,
            changed_modules=0,
            allowed_modules=0,
            emitted_detections=0,
            duration_ms=1,
            error="sensor failed",
        )
        recovered = ScanReport(
            game_found=True,
            baseline_created=False,
            initial_audit_performed=False,
            observed_modules=1,
            added_modules=0,
            removed_modules=0,
            changed_modules=0,
            allowed_modules=0,
            emitted_detections=0,
            duration_ms=1,
        )

        first = _updated_consecutive_errors(0, failed)
        second = _updated_consecutive_errors(first, failed)
        reset = _updated_consecutive_errors(second, recovered)

        self.assertEqual((first, second, reset), (1, 2, 0))

    def test_session_t0_sets_the_shared_timeline_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "late.dll"
            dll.write_bytes(b"late module")
            game_module = loaded(r"C:\Game\game.exe")
            added_module = loaded(dll, 0x1800)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSnapshot(500, 2.0, (game_module, added_module)),
                    ]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("trusted", "CN=Example"))
                ),
                writer=lambda _path, result: saved.append(result),
                wall_clock=lambda: 132.5,
                session_t0=100.0,
            )

            runner.scan_once()
            runner.scan_once()

        self.assertEqual(saved[0]["timestamp_ms"], 32500)

    def test_shared_writer_records_locally_before_queuing_same_event(self):
        event = {
            "session_id": "esp_001",
            "player_id": "player_042",
            "module": "external_access",
            "timestamp_ms": 32500,
            "evidence": {"submodule": "module_integrity"},
            "reasons": ["test"],
            "raw_score": 1,
        }
        calls = []

        def write_local(path, result):
            calls.append(("local", path, result))

        def queue_shared(result):
            calls.append(("shared", result))
            return SimpleNamespace(status="queued", event_id="event-1")

        output = Path("module_integrity.jsonl")
        with patch(
            "client.LocalGuard.external_access.module_integrity.runner.append_detection_jsonl",
            side_effect=write_local,
        ), patch(
            "client.LocalGuard.external_access.module_integrity.runner.send_detection",
            side_effect=queue_shared,
        ):
            _write_local_and_send(output, event)

        self.assertEqual(calls[0], ("local", output, event))
        self.assertEqual(calls[1], ("shared", event))
        self.assertIs(calls[0][2], calls[1][1])

    def test_shared_cleanup_flushes_before_shutdown(self):
        calls = []
        with patch(
            "client.LocalGuard.external_access.module_integrity.runner.flush_client",
            side_effect=lambda timeout: calls.append(("flush", timeout)) or 1,
        ), patch(
            "client.LocalGuard.external_access.module_integrity.runner.shutdown_client",
            side_effect=lambda timeout: calls.append(("shutdown", timeout)) or True,
        ):
            _finish_shared_client()

        self.assertEqual(calls, [("flush", 3), ("shutdown", 5)])

    def test_initial_snapshot_can_be_strictly_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "startup.dll"
            dll.write_bytes(b"startup fixture")
            startup_module = loaded(dll)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game]),
                sensor=_SequenceSensor(
                    [ModuleSnapshot(500, 1.0, (startup_module,))]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("trusted", "CN=Example"))
                ),
                audit_initial_snapshot=True,
                writer=lambda _path, result: saved.append(result),
            )

            report = runner.scan_once()

        self.assertTrue(report.baseline_created)
        self.assertEqual(report.emitted_detections, 1)
        self.assertEqual(
            saved[0]["evidence"]["change_type"],
            "baseline_unreviewed",
        )

    def test_baseline_then_new_module_emits_once(self):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "extra.dll"
            dll.write_bytes(b"module fixture")
            game_module = loaded(r"C:\Game\game.exe")
            added_module = loaded(dll, 0x2000)
            game = TargetProcess(500, "game.exe", Path(r"C:\Game\game.exe"), 1.0)
            saved = []
            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSnapshot(500, 2.0, (game_module, added_module)),
                        ModuleSnapshot(500, 3.0, (game_module, added_module)),
                    ]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("unsigned", None))
                ),
                writer=lambda _path, result: saved.append(result),
                clock=_Clock(),
            )

            first = runner.scan_once()
            second = runner.scan_once()
            third = runner.scan_once()

        self.assertTrue(first.baseline_created)
        self.assertEqual(first.emitted_detections, 0)
        self.assertEqual(second.added_modules, 1)
        self.assertEqual(second.emitted_detections, 1)
        self.assertEqual(third.emitted_detections, 0)
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["raw_score"], 2)

    def test_exact_allowlist_entry_suppresses_reviewed_dll(self):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "normal.dll"
            dll.write_bytes(b"reviewed fixture")
            sha256 = hashlib.sha256(dll.read_bytes()).hexdigest()
            game_module = loaded(r"C:\Game\game.exe")
            added_module = loaded(dll, 0x2000)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="normal_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSnapshot(500, 2.0, (game_module, added_module)),
                    ]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("trusted", "CN=Example"))
                ),
                allowlist=ModuleAllowlist(
                    [ModuleAllowlistEntry("normal.dll", sha256)]
                ),
                audit_initial_snapshot=False,
                writer=lambda _path, result: saved.append(result),
            )
            runner.scan_once()
            report = runner.scan_once()

        self.assertEqual(report.allowed_modules, 1)
        self.assertEqual(report.emitted_detections, 0)
        self.assertEqual(saved, [])

    def test_sensor_failure_preserves_last_successful_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "later.dll"
            dll.write_bytes(b"later")
            game_module = loaded(r"C:\Game\game.exe")
            added_module = loaded(dll, 0x3000)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSensorUnavailable(500, "access denied", 5),
                        ModuleSnapshot(500, 3.0, (game_module, added_module)),
                    ]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("trusted", "CN=Example"))
                ),
                writer=lambda _path, result: saved.append(result),
            )
            runner.scan_once()
            failed = runner.scan_once()
            recovered = runner.scan_once()

        self.assertIsNotNone(failed.error)
        self.assertEqual(recovered.added_modules, 1)
        self.assertEqual(len(saved), 1)

    def test_disappeared_module_file_keeps_the_change_fact(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "already_unloaded.dll"
            game_module = loaded(r"C:\Game\game.exe")
            added_module = loaded(missing, 0x4000)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSnapshot(500, 2.0, (game_module, added_module)),
                    ]
                ),
                writer=lambda _path, result: saved.append(result),
            )
            runner.scan_once()
            report = runner.scan_once()

        self.assertEqual(report.emitted_detections, 1)
        self.assertEqual(saved[0]["raw_score"], 1)
        self.assertEqual(saved[0]["evidence"]["signature_status"], "unknown")
        self.assertIn("inspection_error", saved[0]["evidence"])

    def test_missing_full_module_path_never_hashes_a_cwd_name(self):
        game_module = loaded(r"C:\Game\game.exe")
        pathless = LoadedModule("unknown.dll", None, 0x5000, 4096)
        game = TargetProcess(500, "game.exe", None, 1.0)
        saved = []
        runner = ModuleIntegrityRunner(
            game_executable_name="game.exe",
            session_id="esp_001",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_SequenceLocator([game, game]),
            sensor=_SequenceSensor(
                [
                    ModuleSnapshot(500, 1.0, (game_module,)),
                    ModuleSnapshot(500, 2.0, (game_module, pathless)),
                ]
            ),
            writer=lambda _path, result: saved.append(result),
        )
        runner.scan_once()
        runner.scan_once()

        self.assertIsNone(saved[0]["evidence"]["module_path"])
        self.assertEqual(
            saved[0]["evidence"]["inspection_error"],
            "full module path is unavailable",
        )

    def test_restarted_process_creates_a_new_baseline(self):
        game_module = loaded(r"C:\Game\game.exe")
        first = TargetProcess(500, "game.exe", None, 1.0)
        restarted = TargetProcess(500, "game.exe", None, 2.0)
        saved = []
        runner = ModuleIntegrityRunner(
            game_executable_name="game.exe",
            session_id="normal_001",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_SequenceLocator([first, restarted]),
            sensor=_SequenceSensor(
                [
                    ModuleSnapshot(500, 1.0, (game_module,)),
                    ModuleSnapshot(500, 2.0, (game_module,)),
                ]
            ),
            writer=lambda _path, result: saved.append(result),
        )

        first_report = runner.scan_once()
        restarted_report = runner.scan_once()

        self.assertTrue(first_report.baseline_created)
        self.assertTrue(restarted_report.baseline_created)
        self.assertEqual(saved, [])

    def test_writer_failure_retries_change_instead_of_advancing_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / "retry.dll"
            dll.write_bytes(b"retry fixture")
            game_module = loaded(r"C:\Game\game.exe")
            added_module = loaded(dll, 0x6000)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            attempts = 0

            def flaky_writer(_path, result):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("disk temporarily unavailable")
                saved.append(result)

            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSnapshot(500, 2.0, (game_module, added_module)),
                        ModuleSnapshot(500, 3.0, (game_module, added_module)),
                    ]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("trusted", "CN=Example"))
                ),
                writer=flaky_writer,
            )
            runner.scan_once()
            failed = runner.scan_once()
            retried = runner.scan_once()

        self.assertIn("저장 실패", failed.error)
        self.assertEqual(retried.added_modules, 1)
        self.assertEqual(retried.emitted_detections, 1)
        self.assertEqual(len(saved), 1)

    def test_partial_batch_retry_continues_after_last_durable_result(self):
        with tempfile.TemporaryDirectory() as directory:
            first_dll = Path(directory) / "a.dll"
            second_dll = Path(directory) / "b.dll"
            first_dll.write_bytes(b"first")
            second_dll.write_bytes(b"second")
            game_module = loaded(r"C:\Game\game.exe")
            first_module = loaded(first_dll, 0x7000)
            second_module = loaded(second_dll, 0x8000)
            game = TargetProcess(500, "game.exe", None, 1.0)
            saved = []
            attempts = 0

            def fail_on_second_write(_path, result):
                nonlocal attempts
                attempts += 1
                if attempts == 2:
                    raise OSError("temporary second-write failure")
                saved.append(result["evidence"]["module_name"])

            runner = ModuleIntegrityRunner(
                game_executable_name="game.exe",
                session_id="esp_001",
                player_id="player_042",
                output_path=Path("ignored.jsonl"),
                locator=_SequenceLocator([game, game]),
                sensor=_SequenceSensor(
                    [
                        ModuleSnapshot(500, 1.0, (game_module,)),
                        ModuleSnapshot(
                            500,
                            2.0,
                            (game_module, first_module, second_module),
                        ),
                    ]
                ),
                artifact_cache=ArtifactCache(
                    ArtifactInspector(lambda _path: ("trusted", "CN=Example"))
                ),
                writer=fail_on_second_write,
            )
            runner.scan_once()
            failed = runner.scan_once()
            retried = runner.scan_once()

        self.assertIn("저장 실패", failed.error)
        self.assertEqual(retried.emitted_detections, 1)
        self.assertEqual(saved, ["a.dll", "b.dll"])

    def test_locator_failure_returns_error_without_discarding_state(self):
        runner = ModuleIntegrityRunner(
            game_executable_name="game.exe",
            session_id="normal_001",
            player_id="player_042",
            output_path=Path("ignored.jsonl"),
            locator=_FailingLocator(),
        )

        report = runner.scan_once()

        self.assertFalse(report.game_found)
        self.assertEqual(report.error, "process snapshot failed")


if __name__ == "__main__":
    unittest.main()
