import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from client.LocalGuard.external_access.common import (
    ArtifactCache, ArtifactInspector, ProcessLocator, TargetProcess,
    append_detection_jsonl, build_detection_result,
)


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

