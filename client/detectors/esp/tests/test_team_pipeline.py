import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from anti_esp.core.events import SensorBatch, SensorEvent
from anti_esp.core.session import SessionTelemetryWriter
from anti_esp.detectors.esp_detector import EspEventDetector
from anti_esp.pipeline import EspDetectionPipeline
from anti_esp.scoring import SuspicionEngine
from anti_esp.store import SQLiteEvidenceStore
from anti_esp.team_format import TeamEventAdapter
from anti_esp.models import EvidenceEvent


class TeamPipelineTests(unittest.TestCase):
    @staticmethod
    def _linked_evidence(raw: SensorEvent) -> EvidenceEvent:
        return EvidenceEvent(
            timestamp=raw.timestamp_ms / 1000.0,
            category="memory_read",
            source="esp_event_detector",
            reason="External process obtained VM_READ access",
            details={"sensor_event_id": raw.event_id},
            event_id=f"evidence:{raw.event_id}",
            session_id=raw.session_id,
        )

    def test_process_access_writes_raw_and_exact_team_event(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEvidenceStore(":memory:")
            writer = SessionTelemetryWriter(
                directory, session_id="esp_001", game_executable="game.exe"
            )
            try:
                pipeline = EspDetectionPipeline(
                    detectors=(EspEventDetector(),),
                    store=store,
                    scoring=SuspicionEngine(),
                    team_adapter=TeamEventAdapter(
                        session_started_at=100.0, player_id="player_042"
                    ),
                    telemetry=writer,
                )
                raw = SensorEvent(
                    session_id="esp_001",
                    sensor_id="sysmon_process_access",
                    event_type="process_access",
                    subject_id="game-process:77:100000",
                    timestamp_ms=107_000,
                    payload={
                        "source_pid": 22,
                        "target_pid": 77,
                        "source_image": r"C:\Tools\reader.exe",
                        "granted_access": 0x10,
                        "access_labels": ["VM_READ"],
                    },
                )
                result = pipeline.process_batch(
                    SensorBatch("sysmon_process_access", "online", (raw,))
                )
                self.assertEqual(result.accepted_evidence_count, 1)
                self.assertEqual(result.team_events[0].timestamp_ms, 7000)
                self.assertEqual(result.team_events[0].raw_score, 2)
                self.assertEqual(result.team_events[0].module, "esp")
            finally:
                writer.close()
                store.close()

            session = Path(directory) / "esp_001"
            public = json.loads((session / "events.jsonl").read_text("utf-8"))
            self.assertEqual(
                set(public),
                {
                    "session_id",
                    "player_id",
                    "module",
                    "timestamp_ms",
                    "evidence",
                    "reasons",
                    "raw_score",
                },
            )
            self.assertTrue(
                (session / "raw" / "sysmon_process_access.jsonl").exists()
            )

    def test_healthy_empty_batch_does_not_create_detection_event(self):
        store = SQLiteEvidenceStore(":memory:")
        try:
            pipeline = EspDetectionPipeline(
                detectors=(EspEventDetector(),),
                store=store,
                scoring=SuspicionEngine(),
                team_adapter=TeamEventAdapter(
                    session_started_at=100.0, player_id="player_042"
                ),
            )
            result = pipeline.process_batch(SensorBatch("test", "online"))
            self.assertEqual(result.team_events, ())
        finally:
            store.close()

    def test_team_write_failure_leaves_outbox_for_idempotent_retry(self):
        class FailOnceTelemetry:
            def __init__(self):
                self.fail = True
                self.team_events = []

            def append_raw_event(self, _event):
                return None

            def append_team_event(self, event, *, idempotency_key=None):
                if self.fail:
                    self.fail = False
                    raise OSError("team event write failed")
                if (idempotency_key, event) not in self.team_events:
                    self.team_events.append((idempotency_key, event))

        store = SQLiteEvidenceStore(":memory:")
        telemetry = FailOnceTelemetry()
        pipeline = EspDetectionPipeline(
            detectors=(EspEventDetector(),),
            store=store,
            scoring=SuspicionEngine(),
            team_adapter=TeamEventAdapter(
                session_started_at=100.0, player_id="player_042"
            ),
            telemetry=telemetry,
        )
        raw = SensorEvent(
            session_id="esp_001",
            sensor_id="sysmon_process_access",
            event_type="process_access",
            subject_id="game-process:77:100000",
            timestamp_ms=107_000,
            payload={
                "source_pid": 22,
                "target_pid": 77,
                "granted_access": 0x10,
                "access_labels": ["VM_READ"],
            },
        )
        batch = SensorBatch("sysmon_process_access", "online", (raw,))
        try:
            with self.assertRaisesRegex(OSError, "team event write failed"):
                pipeline.process_batch(batch)
            self.assertEqual(store.count(), 1)
            self.assertEqual(
                store.pending_team_event_count(session_id="esp_001"), 1
            )

            delivered = pipeline.flush_team_outbox("esp_001")
            self.assertEqual(len(delivered), 1)
            self.assertEqual(store.count(), 1)
            self.assertEqual(
                store.pending_team_event_count(session_id="esp_001"), 0
            )
            self.assertEqual(len(telemetry.team_events), 1)

            duplicate = pipeline.process_batch(batch)
            self.assertEqual(duplicate.accepted_evidence_count, 0)
            self.assertEqual(len(telemetry.team_events), 1)
        finally:
            store.close()

    def test_sqlite_commit_failure_cannot_publish_team_event(self):
        class CapturingTelemetry:
            def __init__(self):
                self.team_events = []

            def append_raw_event(self, _event):
                return None

            def append_team_event(self, event, *, idempotency_key=None):
                self.team_events.append((idempotency_key, event))

        class FailNextCommit:
            def __init__(self, connection):
                self.connection = connection
                self.fail = True

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def commit(self):
                if self.fail:
                    self.fail = False
                    raise sqlite3.IntegrityError("deferred commit failure")
                return self.connection.commit()

        store = SQLiteEvidenceStore(":memory:")
        store._connection = FailNextCommit(store._connection)
        telemetry = CapturingTelemetry()
        pipeline = EspDetectionPipeline(
            detectors=(EspEventDetector(),),
            store=store,
            scoring=SuspicionEngine(),
            team_adapter=TeamEventAdapter(
                session_started_at=100.0, player_id="player_042"
            ),
            telemetry=telemetry,
        )
        raw = SensorEvent(
            session_id="esp_001",
            sensor_id="sysmon_process_access",
            event_type="process_access",
            subject_id="game-process:77:100000",
            timestamp_ms=107_000,
            payload={
                "source_pid": 22,
                "target_pid": 77,
                "granted_access": 0x10,
                "access_labels": ["VM_READ"],
            },
        )
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "deferred commit"):
                pipeline.process_batch(
                    SensorBatch("sysmon_process_access", "online", (raw,))
                )
            self.assertEqual(telemetry.team_events, [])
            self.assertEqual(store.count(), 0)
            self.assertEqual(
                store.pending_team_event_count(session_id="esp_001"), 0
            )
        finally:
            store.close()

    def test_shared_queue_failure_keeps_local_outbox_for_retry(self):
        class FailOnceSink:
            def __init__(self):
                self.calls = []

            def __call__(self, event, outbox_id):
                self.calls.append((outbox_id, event))
                return len(self.calls) > 1

        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteEvidenceStore(":memory:")
            writer = SessionTelemetryWriter(
                directory, session_id="esp_001", game_executable="game.exe"
            )
            sink = FailOnceSink()
            pipeline = EspDetectionPipeline(
                detectors=(EspEventDetector(),),
                store=store,
                scoring=SuspicionEngine(),
                team_adapter=TeamEventAdapter(
                    session_started_at=100.0, player_id="player_042"
                ),
                telemetry=writer,
                team_event_sink=sink,
            )
            raw = SensorEvent(
                session_id="esp_001",
                sensor_id="sysmon_process_access",
                event_type="process_access",
                subject_id="game-process:77:100000",
                timestamp_ms=107_000,
                payload={
                    "source_pid": 22,
                    "target_pid": 77,
                    "granted_access": 0x10,
                    "access_labels": ["VM_READ"],
                },
            )
            try:
                pipeline.process_batch(
                    SensorBatch("sysmon_process_access", "online", (raw,))
                )
                self.assertEqual(
                    store.pending_team_event_count(session_id="esp_001"), 1
                )
                event_log = Path(directory) / "esp_001" / "events.jsonl"
                self.assertEqual(len(event_log.read_text("utf-8").splitlines()), 1)

                delivered = pipeline.flush_team_outbox("esp_001")
                self.assertEqual(len(delivered), 1)
                self.assertEqual(
                    store.pending_team_event_count(session_id="esp_001"), 0
                )
                self.assertEqual(sink.calls[0][0], sink.calls[1][0])
                self.assertEqual(sink.calls[0][1], sink.calls[1][1])
            finally:
                writer.close()
                store.close()

    def test_adapter_rejects_materially_pre_session_event_instead_of_clamping(self):
        raw = SensorEvent(
            session_id="esp_001",
            sensor_id="sysmon_process_access",
            event_type="process_access",
            subject_id="game-process:77:100000",
            timestamp_ms=150_000,
            payload={"target_pid": 77},
        )
        adapter = TeamEventAdapter(
            session_started_at=200.0,
            player_id="player_042",
            clock_skew_tolerance_seconds=2.0,
        )
        self.assertIsNone(adapter.convert(raw, (self._linked_evidence(raw),)))

    def test_adapter_clamps_only_events_within_explicit_clock_skew_tolerance(self):
        adapter = TeamEventAdapter(
            session_started_at=200.0,
            player_id="player_042",
            clock_skew_tolerance_seconds=2.0,
        )
        at_boundary = SensorEvent(
            session_id="esp_001",
            sensor_id="sysmon_process_access",
            event_type="process_access",
            subject_id="game-process:77:100000",
            timestamp_ms=198_000,
            payload={"target_pid": 77},
        )
        outside_boundary = SensorEvent(
            session_id="esp_001",
            sensor_id="sysmon_process_access",
            event_type="process_access",
            subject_id="game-process:77:100000",
            timestamp_ms=197_999,
            payload={"target_pid": 77},
        )

        converted = adapter.convert(
            at_boundary, (self._linked_evidence(at_boundary),)
        )
        self.assertIsNotNone(converted)
        assert converted is not None
        self.assertEqual(converted.timestamp_ms, 0)
        self.assertIsNone(
            adapter.convert(
                outside_boundary, (self._linked_evidence(outside_boundary),)
            )
        )

    def test_adapter_removes_host_user_and_window_title_from_public_evidence(self):
        raw = SensorEvent(
            session_id="esp_001",
            sensor_id="sysmon_process_access",
            event_type="process_access",
            subject_id="game-process:77:100000",
            timestamp_ms=101_000,
            event_id="esp_001:sysmon-event10:DESKTOP-SECRET:123",
            payload={
                "computer": "DESKTOP-SECRET",
                "source_user": r"DESKTOP-SECRET\alice",
                "target_user": r"DESKTOP-SECRET\alice",
                "title": "Alice's private chat",
                "source_pid": 22,
                "source_image": r"C:\Users\alice\reader.exe",
                "target_image": r"C:\Users\alice\game.exe",
                "call_trace": r"C:\Users\alice\symbols\private.pdb+0x10",
                "rule_name": "private workstation rule",
                "data": {
                    "Computer": "DESKTOP-SECRET",
                    "SourceUser": r"DESKTOP-SECRET\alice",
                    "TargetUser": r"DESKTOP-SECRET\alice",
                    "CallTrace": "frame-a",
                    "SourceProcessGuid": "{PRIVATE-GUID}",
                },
            },
        )
        adapter = TeamEventAdapter(session_started_at=100.0, player_id="player_042")

        converted = adapter.convert(raw, (self._linked_evidence(raw),))

        self.assertIsNotNone(converted)
        assert converted is not None
        self.assertNotIn("computer", converted.evidence)
        self.assertNotIn("source_user", converted.evidence)
        self.assertNotIn("target_user", converted.evidence)
        self.assertNotIn("title", converted.evidence)
        self.assertEqual(converted.evidence["source_pid"], 22)
        self.assertEqual(converted.evidence["source_image"], "reader.exe")
        self.assertEqual(converted.evidence["target_image"], "game.exe")
        self.assertEqual(len(converted.evidence["source_image_path_sha256"]), 64)
        self.assertEqual(len(converted.evidence["target_image_path_sha256"]), 64)
        self.assertNotIn("data", converted.evidence)
        self.assertNotIn("call_trace", converted.evidence)
        self.assertNotIn("rule_name", converted.evidence)
        serialized = json.dumps(converted.to_dict(), ensure_ascii=False)
        self.assertNotIn("DESKTOP-SECRET", serialized)
        self.assertNotIn("alice", serialized.casefold())
        self.assertNotIn("PRIVATE-GUID", serialized)
        self.assertNotEqual(
            converted.evidence["sensor_event_id"], raw.event_id
        )

        repeated = adapter.convert(raw, (self._linked_evidence(raw),))
        self.assertIsNotNone(repeated)
        assert repeated is not None
        self.assertEqual(
            repeated.evidence["sensor_event_id"],
            converted.evidence["sensor_event_id"],
        )
        self.assertEqual(raw.payload["computer"], "DESKTOP-SECRET")


if __name__ == "__main__":
    unittest.main()
