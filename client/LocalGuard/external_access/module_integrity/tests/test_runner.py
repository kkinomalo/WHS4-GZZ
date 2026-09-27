import hashlib
import tempfile
import unittest
from pathlib import Path

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
