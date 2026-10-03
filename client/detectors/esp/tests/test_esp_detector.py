from __future__ import annotations

import unittest

from anti_esp.core.events import SensorEvent
from anti_esp.detectors.esp_detector import EspEventDetector, detect_esp_event
from anti_esp.scoring import SuspicionEngine


def observation(
    event_type: str,
    payload: dict,
    *,
    event_id: str = "sensor-event-1",
    timestamp_ms: int = 12_500,
) -> SensorEvent:
    return SensorEvent(
        session_id="match-1",
        sensor_id="local-guard-test",
        event_type=event_type,
        subject_id="9001",
        payload=payload,
        timestamp_ms=timestamp_ms,
        event_id=event_id,
    )


class EspEventDetectorTests(unittest.TestCase):
    def test_configured_allowlist_is_pure_and_suppresses_matching_path(self):
        event = observation(
            "process_access",
            {
                "source_pid": 10,
                "target_pid": 20,
                "source_image": r"C:\Trusted\reader.exe",
                "access_labels": ["VM_READ"],
            },
        )
        detector = EspEventDetector(
            allowlisted_paths=(r"c:/trusted/READER.exe",)
        )
        self.assertEqual(detector.detect(event), ())

    def setUp(self) -> None:
        self.detector = EspEventDetector()

    def test_process_read_access_becomes_replayable_memory_evidence(self) -> None:
        event = observation(
            "process_access",
            {
                "source_pid": 4242,
                "source_image": r"C:\Tools\reader.exe",
                "target_pid": 9001,
                "granted_access": "0x10",
            },
        )

        evidence = self.detector.detect(event)

        self.assertEqual(len(evidence), 1)
        item = evidence[0]
        self.assertEqual(item.category, "memory_read")
        self.assertEqual(item.timestamp, 12.5)
        self.assertEqual(item.session_id, "match-1")
        self.assertEqual(item.subject_id, "9001")
        self.assertEqual(item.details["sensor_event_id"], "sensor-event-1")
        self.assertEqual(item.event_id, "sensor-event-1:memory_read")
        self.assertEqual(
            item.dedup_key, "process-access:memory_read:4242:9001"
        )

    def test_write_or_thread_rights_take_tamper_precedence(self) -> None:
        event = observation(
            "process_access",
            {
                "source_pid": 55,
                "target_pid": 9001,
                "access_labels": ["PROCESS_VM_READ", "PROCESS_VM_WRITE"],
            },
        )
        result = self.detector.detect(event)
        self.assertEqual([item.category for item in result], ["process_tamper"])

    def test_trusted_self_and_unattributed_access_are_rejected(self) -> None:
        trusted = observation(
            "process_access",
            {
                "source_pid": 10,
                "target_pid": 20,
                "granted_access": 0x10,
                "source_trusted": True,
            },
        )
        self_access = observation(
            "process_access",
            {"source_pid": 20, "target_pid": 20, "granted_access": 0x20},
        )
        unattributed = observation("process_access", {"granted_access": 0x10})

        self.assertEqual(self.detector.detect(trusted), ())
        self.assertEqual(self.detector.detect(self_access), ())
        self.assertEqual(self.detector.detect(unattributed), ())

    def test_authenticode_trust_alone_does_not_allowlist_steam_or_other_sources(self):
        signed_steam = observation(
            "process_access",
            {
                "source_pid": 10,
                "target_pid": 20,
                "source_image": r"C:\Program Files (x86)\Steam\steam.exe",
                "signature_status": "trusted",
                "access_labels": ["VM_READ", "VM_WRITE"],
            },
        )

        evidence = self.detector.detect(signed_steam)

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].category, "process_tamper")

    def test_overlay_needs_both_geometry_and_style_combination(self) -> None:
        event = observation(
            "window_overlap",
            {
                "game_pid": 9001,
                "window_pid": 42,
                "hwnd": 123,
                "game_overlap_ratio": 0.8,
                "candidate_overlap_ratio": 1.0,
                "style_labels": ["LAYERED", "TRANSPARENT", "TOPMOST"],
            },
        )
        evidence = self.detector.detect(event)

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].category, "overlay")
        self.assertTrue(evidence[0].details["requires_corroboration"])

        topmost_only = observation(
            "window_overlap",
            {
                "window_pid": 42,
                "game_overlap_ratio": 1.0,
                "style_labels": ["TOPMOST"],
            },
        )
        below_threshold = observation(
            "window_overlap",
            {
                "window_pid": 42,
                "game_overlap_ratio": 0.4,
                "style_labels": ["LAYERED", "TRANSPARENT"],
            },
        )
        self.assertEqual(self.detector.detect(topmost_only), ())
        self.assertEqual(self.detector.detect(below_threshold), ())

    def test_module_add_and_unsigned_state_are_low_capped_corroboration(self) -> None:
        added_event = observation(
            "module_added",
            {
                "module": {
                    "path": r"C:\Temp\overlay-helper.dll",
                    "base_address": 0x70000000,
                }
            },
            event_id="module-add",
        )
        trust_event = observation(
            "module_trust",
            {
                "module_path": r"C:\Temp\overlay-helper.dll",
                "signature_status": "unsigned",
            },
            event_id="module-trust",
        )

        evidence = self.detector.detect_many((added_event, trust_event))

        self.assertEqual(len(evidence), 2)
        self.assertEqual(
            {item.category for item in evidence}, {"behavioral_signal"}
        )
        self.assertEqual(
            {item.details["sensor_event_id"] for item in evidence},
            {"module-add", "module-trust"},
        )
        self.assertTrue(all(item.details["requires_corroboration"] for item in evidence))
        self.assertTrue(all("not proof" in item.details["interpretation"] for item in evidence))

        engine = SuspicionEngine()
        engine.add_events(evidence)
        snapshot = engine.score(now=12.5, observation_confidence=100.0)
        self.assertLess(snapshot.suspicion, engine.review_threshold)
        self.assertEqual(snapshot.status, "LOW")

    def test_changed_module_accepts_after_shape_and_baseline_is_not_alerted(self) -> None:
        changed = observation(
            "module_changed",
            {
                "before": {"path": r"C:\Game\same.dll", "image_size": 1},
                "after": {"path": r"C:\Game\same.dll", "image_size": 2},
            },
        )
        baseline = observation(
            "module_added",
            {
                "baseline_created": True,
                "module": {"path": r"C:\Game\ordinary.dll"},
            },
        )

        self.assertEqual(len(self.detector.detect(changed)), 1)
        self.assertEqual(self.detector.detect(baseline), ())

    def test_valid_or_indeterminate_signature_does_not_create_evidence(self) -> None:
        valid = observation(
            "module_trust",
            {"module_path": r"C:\Game\valid.dll", "signature_status": "valid"},
        )
        unavailable = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\unknown.dll",
                "signature_status": "unavailable",
            },
        )
        self.assertEqual(self.detector.detect(valid), ())
        self.assertEqual(self.detector.detect(unavailable), ())

    def test_rejected_signature_is_low_corroborative_not_high_confidence(self) -> None:
        rejected = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\rejected.dll",
                "signature_status": "rejected",
                "signature_native_code": 0x800B0109,
            },
        )
        evidence = self.detector.detect(rejected)

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].category, "behavioral_signal")
        self.assertTrue(evidence[0].details["requires_corroboration"])
        engine = SuspicionEngine()
        engine.add_events(evidence)
        snapshot = engine.score(now=12.5, observation_confidence=100.0)
        self.assertEqual(snapshot.status, "LOW")
        self.assertLess(snapshot.suspicion, engine.review_threshold)

    def test_baseline_signature_status_is_raw_only_unless_hash_is_known_bad(self) -> None:
        unsigned = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\startup-helper.dll",
                "signature_status": "unsigned",
                "observation_phase": "baseline",
                "baseline_created": True,
            },
        )
        rejected = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\startup-rejected.dll",
                "signature_status": "rejected",
                "signature_native_code": 0x800B0109,
                "observation_phase": "baseline",
            },
        )
        blacklisted = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\known-bad.dll",
                "signature_status": "unsigned",
                "known_bad_hash": True,
                "observation_phase": "baseline",
            },
        )

        self.assertEqual(self.detector.detect(unsigned), ())
        self.assertEqual(self.detector.detect(rejected), ())
        evidence = self.detector.detect(blacklisted)
        self.assertEqual(len(evidence), 1)
        self.assertIn("known-bad", evidence[0].reason)

    def test_native_code_key_fallback_and_indeterminate_status_precedence(self) -> None:
        native_rejection = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\legacy.dll",
                "signature_native_code": 0x800B0109,
            },
        )
        backend_error = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\indeterminate.dll",
                "signature_status": "error",
                "signature_native_code": 0x800B0109,
            },
        )

        self.assertEqual(len(self.detector.detect(native_rejection)), 1)
        self.assertEqual(self.detector.detect(backend_error), ())

    def test_provider_unknown_native_code_does_not_create_evidence(self) -> None:
        provider_unknown = observation(
            "module_trust",
            {
                "module_path": r"C:\Game\unknown-provider.dll",
                "signature_native_code": 0x800B0001,
            },
        )

        self.assertEqual(self.detector.detect(provider_unknown), ())

    def test_unknown_and_malformed_payloads_never_crash(self) -> None:
        cases = (
            observation("unknown", {"anything": True}),
            observation("window_overlap", {"game_overlap_ratio": "a lot"}),
            observation(
                "process_access",
                {"source_pid": "bad", "granted_access": {"bad": "shape"}},
            ),
            observation(
                "module_added",
                {"module": {"path": 12345}},
            ),
        )

        for event in cases:
            with self.subTest(event_type=event.event_type):
                self.assertEqual(detect_esp_event(event), ())
        self.assertEqual(self.detector.detect(object()), ())  # type: ignore[arg-type]
        self.assertEqual(self.detector.detect_many(None), ())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
