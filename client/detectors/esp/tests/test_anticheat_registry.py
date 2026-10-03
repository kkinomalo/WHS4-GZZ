import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from anti_esp.sensors.anticheat_registry import (
    AntiCheatPidRegistry,
    default_registry_path,
)


def filetime(unix_seconds: float) -> int:
    return int(round((unix_seconds + 11_644_473_600.0) * 10_000_000.0))


class AntiCheatPidRegistryTests(unittest.TestCase):
    def test_only_live_exact_process_instances_are_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "anticheat_pids.json"
            path.write_text(
                json.dumps(
                    {
                        "launcher_pid": 10,
                        "launcher_create_time": filetime(100.0),
                        "modules": {"legacy_only": 40},
                        "entries": {
                            "alive": {"pid": 20, "create_time": filetime(200.0)},
                            "reused": {"pid": 30, "create_time": filetime(300.0)},
                        },
                    }
                ),
                encoding="utf-8",
            )
            current = {10: 100.0, 20: 200.0, 30: 301.0, 40: 400.0}
            registry = AntiCheatPidRegistry(
                path, creation_time_provider=lambda pid: current.get(pid)
            )

            self.assertEqual(registry.live_pids(), frozenset({10, 20}))

    def test_unreadable_or_unverifiable_registry_never_excludes_a_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "anticheat_pids.json"
            path.write_text(
                json.dumps(
                    {
                        "entries": {
                            "unknown": {"pid": 50, "create_time": filetime(500.0)}
                        }
                    }
                ),
                encoding="utf-8",
            )
            registry = AntiCheatPidRegistry(
                path, creation_time_provider=lambda _pid: None
            )
            self.assertEqual(registry.live_pids(), frozenset())

            path.write_text("not-json", encoding="utf-8")
            self.assertEqual(registry.live_pids(), frozenset())

    def test_default_path_honors_launcher_log_directory_override(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"AC_LAUNCHER_LOG_DIR": directory}):
                self.assertEqual(
                    default_registry_path(),
                    Path(directory) / "anticheat_pids.json",
                )

    def test_transient_launcher_replace_race_is_retried(self):
        document = json.dumps(
            {
                "entries": {
                    "esp": {"pid": 20, "create_time": filetime(200.0)}
                }
            }
        )
        registry = AntiCheatPidRegistry(
            "ignored.json",
            creation_time_provider=lambda pid: 200.0 if pid == 20 else None,
        )

        with patch.object(
            Path,
            "read_text",
            side_effect=(PermissionError("replace in progress"), document),
        ) as reader, patch(
            "anti_esp.sensors.anticheat_registry.time.sleep"
        ) as sleeper:
            self.assertEqual(registry.live_pids(), frozenset({20}))

        self.assertEqual(reader.call_count, 2)
        sleeper.assert_called_once()


if __name__ == "__main__":
    unittest.main()
