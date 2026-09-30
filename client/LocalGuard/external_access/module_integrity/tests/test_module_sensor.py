import unittest

from client.LocalGuard.external_access.module_integrity.baseline import (
    ModuleBaselineTracker,
    diff_module_snapshots,
)
from client.LocalGuard.external_access.module_integrity.models import (
    LoadedModule,
    ModuleSnapshot,
    canonical_module_path,
)
from client.LocalGuard.external_access.module_integrity.module_sensor import (
    ToolhelpModuleSensor,
)


def module(path, base=0x10000000, size=0x1000):
    return LoadedModule(path.replace("/", "\\").rsplit("\\", 1)[-1], path, base, size)


def snapshot(pid, timestamp, *modules):
    return ModuleSnapshot(pid, timestamp, tuple(modules))


class ModuleSensorTests(unittest.TestCase):
    def test_windows_paths_are_compared_case_insensitively(self):
        self.assertEqual(
            canonical_module_path(r"C:\Game\Binaries\..\Binaries\GAME.DLL"),
            canonical_module_path(r"c:/game/binaries/game.dll"),
        )
        self.assertEqual(
            canonical_module_path(r"\\?\C:\Game\game.dll"),
            canonical_module_path(r"c:\game\GAME.DLL"),
        )

    def test_diff_classifies_added_removed_and_changed(self):
        game = module(r"C:\Game\game.exe", 0x140000000, 0x9000)
        removed = module(r"C:\Game\old.dll", 0x20000000)
        before = module(r"C:\Game\same.dll", 0x30000000, 0x1000)
        after = module(r"c:\game\SAME.dll", 0x31000000, 0x2000)
        added = module(r"C:\Temp\new.dll", 0x40000000)

        result = diff_module_snapshots(
            snapshot(123, 10.0, game, removed, before),
            snapshot(123, 11.0, game, after, added),
        )

        self.assertEqual(result.added, (added,))
        self.assertEqual(result.removed, (removed,))
        self.assertEqual(result.changed[0].before, before)
        self.assertEqual(result.changed[0].after, after)

    def test_first_success_creates_baseline_and_later_addition_is_reported_once(self):
        tracker = ModuleBaselineTracker()
        game = module(r"C:\Game\game.exe")
        dll = module(r"C:\Temp\extra.dll")

        first = tracker.observe(snapshot(77, 1.0, game))
        second = tracker.observe(snapshot(77, 2.0, game, dll))
        third = tracker.observe(snapshot(77, 3.0, game, dll))

        self.assertTrue(first.baseline_created)
        self.assertFalse(first.has_changes)
        self.assertEqual(second.added, (dll,))
        self.assertFalse(third.has_changes)

    def test_reset_makes_next_snapshot_a_new_baseline(self):
        tracker = ModuleBaselineTracker()
        tracker.observe(snapshot(10, 1.0, module(r"C:\Game\game.exe")))
        tracker.reset(10)
        self.assertTrue(tracker.observe(snapshot(10, 2.0)).baseline_created)

    def test_removed_then_reloaded_module_is_reported_again(self):
        tracker = ModuleBaselineTracker()
        game = module(r"C:\Game\game.exe")
        dll = module(r"C:\Game\plugin.dll", 0x2000)
        tracker.observe(snapshot(10, 1.0, game, dll))

        removed = tracker.observe(snapshot(10, 2.0, game))
        reloaded = tracker.observe(snapshot(10, 3.0, game, dll))

        self.assertEqual(removed.removed, (dll,))
        self.assertEqual(reloaded.added, (dll,))

    def test_sensor_uses_injected_provider_and_clock(self):
        calls = []
        expected = module(r"C:\Game\game.exe")

        def provider(pid):
            calls.append(pid)
            return [expected]

        sensor = ToolhelpModuleSensor(provider, clock=lambda: 123.5)
        result = sensor.capture(55)

        self.assertEqual(calls, [55])
        self.assertEqual(result.captured_at, 123.5)
        self.assertEqual(result.modules, (expected,))

    def test_pathless_same_name_modules_use_base_address_as_fallback_identity(self):
        first = LoadedModule("unknown.dll", None, 0x1000, 4096)
        second = LoadedModule("unknown.dll", None, 0x2000, 4096)
        result = snapshot(77, 1.0, first, second)
        self.assertEqual(len(result.modules), 2)


if __name__ == "__main__":
    unittest.main()
