import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from client.LocalGuard.external_access.common import (
    ArtifactCache, ArtifactInspector, ProcessLocator, TargetProcess,
    append_detection_jsonl, build_detection_result,
)
from client.LocalGuard.external_access.common import artifact_inspector


class ArtifactInspectorTests(unittest.TestCase):
    def test_sha256_and_injected_signature_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "sample.dll"
            artifact.write_bytes(b"meccha-chameleon")
            info = ArtifactInspector(lambda _: ("trusted", "CN=Test Publisher")).inspect(artifact)
        self.assertEqual(info.sha256, hashlib.sha256(b"meccha-chameleon").hexdigest())
        self.assertEqual(info.signature_status, "trusted")

    def test_unchanged_file_uses_cache(self):
        calls = 0
        def reader(_):
            nonlocal calls
            calls += 1
            return "unsigned", None
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "sample.exe"; artifact.write_bytes(b"first")
            cache = ArtifactCache(ArtifactInspector(reader))
            self.assertEqual(cache.inspect(artifact), cache.inspect(artifact))
        self.assertEqual(calls, 1)

    def test_changed_file_invalidates_cache(self):
        calls = 0
        def reader(_):
            nonlocal calls
            calls += 1
            return "unsigned", None
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "sample.exe"; artifact.write_bytes(b"first")
            cache = ArtifactCache(ArtifactInspector(reader)); first = cache.inspect(artifact)
            artifact.write_bytes(b"second content with another size"); second = cache.inspect(artifact)
        self.assertNotEqual(first.sha256, second.sha256)
        self.assertEqual(calls, 2)

    def test_same_size_replacement_with_restored_mtime_invalidates_cache(self):
        calls = 0
        def reader(_):
            nonlocal calls
            calls += 1
            return "trusted", "CN=Test"
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "sample.dll"
            artifact.write_bytes(b"AAAA")
            original_stat = artifact.stat()
            cache = ArtifactCache(ArtifactInspector(reader))
            first = cache.inspect(artifact)

            artifact.write_bytes(b"BBBB")
            os.utime(
                artifact,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
            second = cache.inspect(artifact)

        self.assertNotEqual(first.sha256, second.sha256)
        self.assertEqual(calls, 2)

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_authenticode_uses_system_powershell_and_clean_module_path(self):
        system_directory = Path("C:/Windows/System32")
        completed = CompletedProcess(
            args=[],
            returncode=0,
            stdout="Valid\nCN=Test Publisher\n",
            stderr="",
        )
        with (
            mock.patch.object(
                artifact_inspector,
                "get_windows_system_directory",
                return_value=system_directory,
            ),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(
                artifact_inspector.subprocess,
                "run",
                return_value=completed,
            ) as run,
        ):
            status, publisher = artifact_inspector.read_windows_authenticode(
                Path("C:/game/test.dll")
            )

        self.assertEqual((status, publisher), ("trusted", "CN=Test Publisher"))
        command = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        powershell_root = system_directory / "WindowsPowerShell" / "v1.0"
        module_root = powershell_root / "Modules"
        self.assertEqual(command[0], str(powershell_root / "powershell.exe"))
        self.assertEqual(environment["PSModulePath"], str(module_root))
        self.assertEqual(
            environment["LOCALGUARD_SECURITY_MODULE"],
            str(
                module_root
                / "Microsoft.PowerShell.Security"
                / "Microsoft.PowerShell.Security.psd1"
            ),
        )


class ProcessLocatorTests(unittest.TestCase):
    def test_finds_game_and_detects_restart(self):
        original = TargetProcess(10, "PenguinHotel-Win64-Shipping.exe", None, 100.0)
        restarted = TargetProcess(11, "PenguinHotel-Win64-Shipping.exe", None, 200.0)
        locator = ProcessLocator("penguinhotel-win64-shipping.exe", lambda: [original])
        self.assertEqual(locator.find(), original)
        self.assertTrue(locator.was_restarted(original, restarted))
        self.assertFalse(locator.was_restarted(original, original))

    def test_strict_locator_rejects_ambiguous_same_name_processes(self):
        first = TargetProcess(10, "game.exe", None, 100.0)
        second = TargetProcess(11, "GAME.EXE", None, 101.0)
        locator = ProcessLocator(
            "game.exe",
            lambda: [first, second],
            require_unique=True,
        )
        with self.assertRaises(OSError):
            locator.find()

    def test_expected_pid_selects_launcher_supplied_process(self):
        first = TargetProcess(10, "game.exe", None, 100.0)
        second = TargetProcess(11, "GAME.EXE", None, 101.0)
        locator = ProcessLocator(
            "game.exe",
            lambda: [first, second],
            expected_pid=11,
            require_unique=True,
        )
        self.assertEqual(locator.find(), second)


class DetectionResultTests(unittest.TestCase):
    def test_result_is_one_jsonl_record(self):
        result = build_detection_result(
            session_id="session_20260915_001", player_id="player_042",
            module="external_access", timestamp_ms=507000,
            evidence={"access_mask": "PROCESS_VM_WRITE"},
            reasons=["Untrusted process has VM_WRITE access to the game"], raw_score=3,
        )
        with tempfile.TemporaryDirectory() as directory:
            out_path = Path(directory) / "events.jsonl"
            append_detection_jsonl(out_path, result)
            rows = out_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(json.loads(rows[0]), result)

