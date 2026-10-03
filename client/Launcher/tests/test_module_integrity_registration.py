import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock


LAUNCHER_DIR = Path(__file__).resolve().parents[1]
if str(LAUNCHER_DIR) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_DIR))

import modules  # noqa: E402
import process_manager  # noqa: E402


class _FakeProcess:
    pid = 4321

    @staticmethod
    def poll():
        return None


class ModuleIntegrityRegistrationTests(unittest.TestCase):
    def test_registered_command_receives_common_ids_clock_and_exact_pid(self):
        registered = modules.by_name()["module_integrity"]
        with tempfile.TemporaryDirectory() as game_root:
            argv = registered.resolved(
                {
                    "session": "normal_001",
                    "player": "player_042",
                    "t0": "1000.250",
                    "game_pid": 9876,
                    "game_root": game_root,
                }
            )

            self.assertEqual(registered.mode, modules.CONTINUOUS)
            self.assertIn(
                "client.LocalGuard.external_access.module_integrity.runner", argv
            )
            self.assertEqual(argv[argv.index("--game-pid") + 1], "9876")
            self.assertEqual(argv[argv.index("--t0") + 1], "1000.250")
            self.assertEqual(argv[argv.index("--game-root") + 1], game_root)

    def test_process_manager_passes_discovered_game_pid_to_child(self):
        module = modules.Module(
            name="pid_probe",
            owner="test",
            argv=[sys.executable, "-c", "pass", "--game-pid", "{game_pid}"],
        )
        fake_process = _FakeProcess()

        with tempfile.TemporaryDirectory() as temporary_directory, (
            mock.patch.object(process_manager, "LOG_DIR", temporary_directory)
        ), mock.patch.object(process_manager, "is_admin", return_value=True), (
            mock.patch.object(process_manager.registry, "begin_session")
        ), mock.patch.object(
            process_manager.registry, "lock", return_value=nullcontext()
        ), mock.patch.object(
            process_manager.registry, "live_pid", return_value=None
        ), mock.patch.object(
            process_manager.registry, "spawn", return_value=fake_process
        ) as spawn, mock.patch.object(process_manager.registry, "register"):
            manager = process_manager.ProcessManager(
                [module], "normal_001", "player_042", 1000.25
            )
            manager.set_game_pid(9876)
            self.assertTrue(manager.start("pid_probe"))

        child_argv = spawn.call_args.args[0]
        self.assertEqual(child_argv[child_argv.index("--game-pid") + 1], "9876")

    def test_invalid_game_pid_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory, (
            mock.patch.object(process_manager, "LOG_DIR", temporary_directory)
        ), mock.patch.object(process_manager, "is_admin", return_value=True), (
            mock.patch.object(process_manager.registry, "begin_session")
        ):
            manager = process_manager.ProcessManager(
                [], "normal_001", "player_042", 1.0
            )

        for invalid in (0, -1, True, "123"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    manager.set_game_pid(invalid)


if __name__ == "__main__":
    unittest.main()
