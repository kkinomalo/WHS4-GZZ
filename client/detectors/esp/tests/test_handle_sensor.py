import unittest

from anti_esp.core.context import ProcessTarget, SensorContext
from anti_esp.sensors.handle_sensor import (
    CurrentProcessHandleSensor,
    HandleEnumerationError,
    HandleInventorySnapshot,
    HandleInventoryUnavailable,
    ProcessHandleRecord,
    decode_process_access,
)


class FakeProvider:
    def __init__(self, snapshots=(), error=None):
        self.snapshots = list(snapshots)
        self.error = error
        self.calls = []

    def __call__(self, target_pids, excluded_owner_pids):
        self.calls.append((target_pids, excluded_owner_pids))
        if self.error is not None:
            raise self.error
        if not self.snapshots:
            raise AssertionError("unexpected provider call")
        return self.snapshots.pop(0)


def handle(
    *,
    source_pid=200,
    source_handle_value=0x88,
    target_pid=77,
    granted_access=0x10,
    source_image=r"C:\Tools\reader.exe",
):
    return ProcessHandleRecord(
        source_pid=source_pid,
        source_handle_value=source_handle_value,
        target_pid=target_pid,
        granted_access=granted_access,
        source_image=source_image,
    )


def snapshot(*records, observed_at=101.0, **counters):
    return HandleInventorySnapshot(
        records=tuple(records),
        observed_at=observed_at,
        total_handle_count=counters.get("total_handle_count", len(records) + 100),
        scanned_handle_count=counters.get("scanned_handle_count", len(records) + 100),
        candidate_handle_count=counters.get("candidate_handle_count", len(records)),
        truncated=counters.get("truncated", False),
        target_mapping_count=counters.get("target_mapping_count", 1),
        source_open_failures=counters.get("source_open_failures", 0),
        duplicate_failures=counters.get("duplicate_failures", 0),
        get_process_id_failures=counters.get("get_process_id_failures", 0),
    )


class HandleSensorTests(unittest.TestCase):
    def setUp(self):
        self.context = SensorContext(
            "esp_001",
            (ProcessTarget(77, r"C:\Game\game.exe", created_at=100.0),),
            session_started_at=100.0,
            observed_at=101.0,
        )

    def test_access_mask_preserves_all_requested_labels(self):
        self.assertEqual(
            decode_process_access(0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040),
            ("CREATE_THREAD", "VM_OPERATION", "VM_READ", "VM_WRITE", "DUP_HANDLE"),
        )
        self.assertEqual(decode_process_access(0x100000), ())
        with self.assertRaises(TypeError):
            decode_process_access(True)

    def test_first_successful_poll_creates_baseline_without_events(self):
        provider = FakeProvider(
            [
                snapshot(
                    handle(granted_access=0x7A),
                    total_handle_count=900,
                    scanned_handle_count=900,
                )
            ]
        )
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            monotonic_clock=lambda: 10.0,
        )

        batch = sensor.poll(self.context)

        self.assertEqual(batch.status, "online")
        self.assertEqual(batch.events, ())
        self.assertTrue(batch.details["baseline_created"])
        self.assertEqual(batch.details["baseline_record_count"], 1)
        self.assertEqual(provider.calls, [(frozenset({77}), frozenset({999}))])

    def test_new_handle_emits_factual_process_access_event(self):
        baseline = handle(source_handle_value=0x10)
        added = handle(
            source_handle_value=0x20,
            granted_access=0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040,
        )
        provider = FakeProvider(
            [snapshot(baseline), snapshot(baseline, added, observed_at=102.0)]
        )
        ticks = iter((10.0, 11.0))
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            monotonic_clock=lambda: next(ticks),
        )

        self.assertEqual(sensor.poll(self.context).events, ())
        batch = sensor.poll(self.context)

        self.assertEqual(len(batch.events), 1)
        event = batch.events[0]
        self.assertEqual(event.event_type, "process_access")
        self.assertEqual(event.subject_id, "game-process:77:100000")
        self.assertEqual(event.timestamp_ms, 102000)
        self.assertEqual(event.payload["source_pid"], 200)
        self.assertEqual(event.payload["target_pid"], 77)
        self.assertEqual(event.payload["source_handle_value_hex"], "0x20")
        self.assertEqual(event.payload["granted_access_hex"], "0x0000007A")
        self.assertEqual(
            event.payload["access_labels"],
            ["CREATE_THREAD", "VM_OPERATION", "VM_READ", "VM_WRITE", "DUP_HANDLE"],
        )
        self.assertEqual(event.payload["observation_kind"], "new")
        self.assertNotIn("score", event.payload)
        self.assertNotIn("suspicious", event.payload)
        self.assertNotIn("cheat", event.payload)

    def test_persistent_handle_is_never_periodically_reemitted(self):
        current = handle()
        provider = FakeProvider(
            [
                snapshot(current, observed_at=100.0),
                snapshot(current, observed_at=105.0),
                snapshot(current, observed_at=131.0),
            ]
        )
        ticks = iter((0.0, 5.0, 31.0))
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            cooldown_seconds=30.0,
            monotonic_clock=lambda: next(ticks),
        )

        self.assertEqual(sensor.poll(self.context).events, ())
        second = sensor.poll(self.context)
        self.assertEqual(second.events, ())
        self.assertEqual(second.details["deduplicated_count"], 1)
        third = sensor.poll(self.context)
        self.assertEqual(third.events, ())
        self.assertEqual(third.details["deduplicated_count"], 1)

    def test_same_handle_access_change_emits_changed_event(self):
        before = handle(granted_access=0x10)
        after = handle(granted_access=0x30)
        provider = FakeProvider([snapshot(before), snapshot(after, observed_at=102.0)])
        sensor = CurrentProcessHandleSensor(enumeration_provider=provider, self_pid=999)

        self.assertEqual(sensor.poll(self.context).events, ())
        changed = sensor.poll(self.context)

        self.assertEqual(len(changed.events), 1)
        self.assertEqual(changed.events[0].payload["observation_kind"], "changed")
        self.assertEqual(changed.events[0].payload["previous_granted_access"], 0x10)

    def test_registered_anticheat_pid_is_excluded_before_inventory(self):
        provider = FakeProvider([snapshot(handle(source_pid=300))])
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            excluded_pid_provider=lambda: frozenset({300}),
        )

        batch = sensor.poll(self.context)

        self.assertEqual(batch.events, ())
        self.assertEqual(batch.details["filtered_record_count"], 0)
        self.assertEqual(
            provider.calls, [(frozenset({77}), frozenset({300, 999}))]
        )

    def test_only_verified_steam_launch_parent_full_handle_is_excluded(self):
        steam_context = SensorContext(
            "esp_001",
            (
                ProcessTarget(
                    77,
                    r"C:\Game\game.exe",
                    created_at=100.0,
                    parent_pid=22,
                    parent_created_at=50.0,
                    parent_executable_path=r"C:\Program Files (x86)\Steam\steam.exe",
                ),
            ),
            session_started_at=90.0,
            observed_at=101.0,
        )
        full_access = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040
        provider = FakeProvider(
            [
                snapshot(observed_at=100.0),
                snapshot(
                    handle(
                        source_pid=22,
                        source_image=r"C:\Program Files (x86)\Steam\steam.exe",
                        granted_access=full_access,
                    ),
                    observed_at=101.0,
                ),
                snapshot(
                    handle(
                        source_pid=22,
                        source_image=r"C:\Program Files (x86)\Steam\steam.exe",
                        granted_access=full_access,
                    ),
                    observed_at=120.0,
                ),
            ]
        )
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            steam_source_verifier=lambda path: path == r"C:\Program Files (x86)\Steam\steam.exe",
        )

        sensor.poll(steam_context)
        self.assertEqual(sensor.poll(steam_context).events, ())
        self.assertEqual(sensor.poll(steam_context).events, ())

    def test_unverified_renamed_steam_parent_is_not_excluded(self):
        fake_steam = r"C:\Temp\steam.exe"
        context = SensorContext(
            "esp_001",
            (
                ProcessTarget(
                    77,
                    r"C:\Game\game.exe",
                    created_at=100.0,
                    parent_pid=22,
                    parent_created_at=50.0,
                    parent_executable_path=fake_steam,
                ),
            ),
            session_started_at=90.0,
            observed_at=101.0,
        )
        full_access = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040
        provider = FakeProvider(
            [
                snapshot(observed_at=100.0),
                snapshot(
                    handle(
                        source_pid=22,
                        source_image=fake_steam,
                        granted_access=full_access,
                    ),
                    observed_at=101.0,
                ),
            ]
        )
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            steam_source_verifier=lambda _path: False,
        )

        sensor.poll(context)
        events = sensor.poll(context).events

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["source_image"], fake_steam)

    def test_closed_then_reopened_same_handle_is_new(self):
        current = handle()
        provider = FakeProvider(
            [snapshot(current), snapshot(observed_at=102.0), snapshot(current, observed_at=103.0)]
        )
        ticks = iter((1.0, 2.0, 3.0))
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            cooldown_seconds=99.0,
            monotonic_clock=lambda: next(ticks),
        )

        sensor.poll(self.context)
        sensor.poll(self.context)
        reopened = sensor.poll(self.context)
        self.assertEqual(len(reopened.events), 1)
        self.assertEqual(reopened.events[0].payload["observation_kind"], "new")

    def test_non_target_self_system_and_unwatched_records_are_filtered(self):
        provider = FakeProvider(
            [
                snapshot(
                    handle(source_pid=999),
                    handle(source_pid=4),
                    handle(source_pid=77),
                    handle(target_pid=88),
                    handle(granted_access=0x1000),
                )
            ]
        )
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            monotonic_clock=lambda: 1.0,
        )
        batch = sensor.poll(self.context)
        self.assertEqual(batch.events, ())
        self.assertEqual(batch.details["filtered_record_count"], 0)

    def test_new_session_resets_to_a_new_baseline(self):
        current = handle()
        provider = FakeProvider([snapshot(current), snapshot(current, observed_at=200.0)])
        ticks = iter((1.0, 2.0))
        sensor = CurrentProcessHandleSensor(
            enumeration_provider=provider,
            self_pid=999,
            monotonic_clock=lambda: next(ticks),
        )
        sensor.poll(self.context)
        new_context = SensorContext(
            "esp_002", self.context.targets, session_started_at=100.0, observed_at=200.0
        )
        batch = sensor.poll(new_context)
        self.assertEqual(batch.events, ())
        self.assertTrue(batch.details["baseline_created"])

    def test_no_targets_waits_without_calling_provider(self):
        provider = FakeProvider(error=AssertionError("must not run"))
        sensor = CurrentProcessHandleSensor(enumeration_provider=provider)
        batch = sensor.poll(SensorContext("esp_001", observed_at=1.0))
        self.assertEqual(batch.status, "waiting")
        self.assertEqual(provider.calls, [])

    def test_unavailable_and_enumeration_errors_are_reported_as_health(self):
        unavailable = CurrentProcessHandleSensor(
            enumeration_provider=FakeProvider(
                error=HandleInventoryUnavailable("unsupported architecture")
            )
        ).poll(self.context)
        self.assertEqual(unavailable.status, "unavailable")
        self.assertIn("unsupported architecture", unavailable.message)

        failed = CurrentProcessHandleSensor(
            enumeration_provider=FakeProvider(
                error=HandleEnumerationError("NtQuerySystemInformation", -1)
            )
        ).poll(self.context)
        self.assertEqual(failed.status, "error")
        self.assertIn("NtQuerySystemInformation", failed.message)

    def test_provider_contract_failure_does_not_escape_poll_loop(self):
        provider = FakeProvider([object()])
        batch = CurrentProcessHandleSensor(enumeration_provider=provider).poll(
            self.context
        )
        self.assertEqual(batch.status, "error")
        self.assertIn("invalid snapshot", batch.message)


if __name__ == "__main__":
    unittest.main()
