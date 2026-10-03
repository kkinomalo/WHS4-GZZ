import unittest

from anti_esp.core.context import ProcessTarget, SensorContext
from anti_esp.sensors.process_access import SysmonProcessAccessSensor
from anti_esp.sysmon import SysmonPollResult, SysmonProcessAccess, SysmonStatus


class FakePoller:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def poll(self):
        if self.error:
            raise self.error
        return self.result


def record(**changes):
    values = dict(
        record_id=42,
        event_id=10,
        timestamp=101.0,
        computer="TEST",
        source_process_id=22,
        source_thread_id=23,
        source_image=r"C:\Tools\reader.exe",
        source_user=r"TEST\user",
        target_process_id=77,
        target_image=r"C:\Game\game.exe",
        target_user=r"TEST\user",
        granted_access=0x30,
        granted_access_raw="0x30",
        call_trace="frame-a;frame-b",
        rule_name="",
        data={"SourceProcessGUID": "source-guid"},
    )
    values.update(changes)
    return SysmonProcessAccess(**values)


def ready(*events):
    return SysmonPollResult(
        SysmonStatus(True, True, True, "ready", "ready"),
        tuple(events),
        scanned_count=len(events),
    )


class ProcessAccessSensorTests(unittest.TestCase):
    def setUp(self):
        self.context = SensorContext(
            "esp_001",
            (ProcessTarget(77, r"C:\Game\game.exe", created_at=100.0),),
            session_started_at=90.0,
            observed_at=102.0,
        )

    def test_emits_factual_event_without_score_or_verdict(self):
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(ready(record())), self_pid=999, clock=lambda: 102.0
        )
        batch = sensor.poll(self.context)
        self.assertEqual(batch.status, "online")
        self.assertEqual(len(batch.events), 1)
        event = batch.events[0]
        self.assertEqual(event.event_type, "process_access")
        self.assertEqual(event.subject_id, "game-process:77:100000")
        self.assertEqual(event.payload["access_labels"], ["VM_READ", "VM_WRITE"])
        self.assertNotIn("score", event.payload)
        self.assertNotIn("suspicious", event.payload)

    def test_wrong_pid_and_stale_pid_reuse_event_are_ignored(self):
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(
                ready(
                    record(record_id=1, target_process_id=88),
                    record(record_id=2, timestamp=90.0),
                )
            ),
            self_pid=999,
        )
        self.assertEqual(sensor.poll(self.context).events, ())

    def test_pre_session_record_is_ignored_even_when_game_already_existed(self):
        context = SensorContext(
            "esp_001",
            (ProcessTarget(77, r"C:\Game\game.exe", created_at=100.0),),
            session_started_at=200.0,
            observed_at=201.0,
        )
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(ready(record(timestamp=150.0))),
            self_pid=999,
            stale_tolerance_seconds=2.0,
        )
        self.assertEqual(sensor.poll(context).events, ())

    def test_session_boundary_allows_only_explicit_clock_skew_tolerance(self):
        context = SensorContext(
            "esp_001",
            (ProcessTarget(77, r"C:\Game\game.exe", created_at=100.0),),
            session_started_at=200.0,
            observed_at=201.0,
        )
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(
                ready(
                    record(record_id=1, timestamp=198.0),
                    record(record_id=2, timestamp=197.999),
                )
            ),
            self_pid=999,
            stale_tolerance_seconds=2.0,
        )
        events = sensor.poll(context).events
        self.assertEqual([event.sequence for event in events], [1])

    def test_sensor_itself_and_game_self_access_are_ignored(self):
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(
                ready(
                    record(record_id=1, source_process_id=999),
                    record(record_id=2, source_process_id=77),
                )
            ),
            self_pid=999,
        )
        self.assertEqual(sensor.poll(self.context).events, ())

    def test_registered_anticheat_pid_is_excluded(self):
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(ready(record(source_process_id=300))),
            self_pid=999,
            excluded_pid_provider=lambda: frozenset({300}),
        )

        batch = sensor.poll(self.context)

        self.assertEqual(batch.events, ())
        self.assertEqual(batch.details["excluded_anticheat_pid_count"], 1)

    def test_steam_exception_requires_verified_parent_full_access_and_launch_time(self):
        context = SensorContext(
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
            observed_at=121.0,
        )
        steam = r"C:\Program Files (x86)\Steam\steam.exe"
        full_access = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(
                ready(
                    record(
                        record_id=1,
                        source_process_id=22,
                        source_image=steam,
                        granted_access=full_access,
                        timestamp=101.0,
                    ),
                    record(
                        record_id=2,
                        source_process_id=23,
                        source_image=steam,
                        granted_access=full_access,
                        timestamp=101.0,
                    ),
                    record(
                        record_id=3,
                        source_process_id=22,
                        source_image=steam,
                        granted_access=full_access,
                        timestamp=120.0,
                    ),
                    record(
                        record_id=4,
                        source_process_id=22,
                        source_image=steam,
                        granted_access=0x10,
                        timestamp=101.0,
                    ),
                    record(
                        record_id=5,
                        source_process_id=22,
                        source_image=r"C:\Fake\steam.exe",
                        granted_access=full_access,
                        timestamp=101.0,
                    ),
                )
            ),
            self_pid=999,
            steam_source_verifier=lambda path: path == steam,
        )

        events = sensor.poll(context).events

        self.assertEqual([event.sequence for event in events], [2, 3, 4, 5])

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
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(
                ready(
                    record(
                        source_process_id=22,
                        source_image=fake_steam,
                        granted_access=0x3A,
                        timestamp=101.0,
                    )
                )
            ),
            self_pid=999,
            steam_source_verifier=lambda _path: False,
        )

        events = sensor.poll(context).events

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["source_image"], fake_steam)

    def test_reused_steam_parent_pid_is_not_excluded(self):
        context = SensorContext(
            "esp_001",
            (
                ProcessTarget(
                    77,
                    r"C:\Game\game.exe",
                    created_at=100.0,
                    parent_pid=22,
                    parent_created_at=110.0,
                    parent_executable_path=r"C:\Steam\steam.exe",
                ),
            ),
            session_started_at=90.0,
            observed_at=111.0,
        )
        sensor = SysmonProcessAccessSensor(
            poller=FakePoller(
                ready(
                    record(
                        source_process_id=22,
                        source_image=r"C:\Steam\steam.exe",
                        granted_access=0x3A,
                        timestamp=101.0,
                    )
                )
            ),
            self_pid=999,
        )

        self.assertEqual(len(sensor.poll(context).events), 1)

    def test_unavailable_and_error_are_not_healthy_empty(self):
        unavailable = SysmonPollResult(
            SysmonStatus(False, False, False, "not_installed", "missing")
        )
        self.assertEqual(
            SysmonProcessAccessSensor(poller=FakePoller(unavailable)).poll(self.context).status,
            "unavailable",
        )
        self.assertEqual(
            SysmonProcessAccessSensor(
                poller=FakePoller(error=OSError("denied"))
            ).poll(self.context).status,
            "error",
        )

    def test_no_target_waits_without_consuming_poller(self):
        sensor = SysmonProcessAccessSensor(poller=FakePoller(error=AssertionError()))
        context = SensorContext("esp_001", observed_at=1.0)
        self.assertEqual(sensor.poll(context).status, "waiting")


if __name__ == "__main__":
    unittest.main()
