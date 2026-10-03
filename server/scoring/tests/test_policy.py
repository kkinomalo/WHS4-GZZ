"""B2a 점수 규격 점검용 테스트. 최종 치트 위험도/확률을 평가하는 테스트가 아니다."""

from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path

from server.scoring.policy import PROFILES, inspect_event, inspect_player_snapshot
from server.scoring.storage import ScoringStore


# 다양한 detector 결과를 쉽게 만들어 B2a 정책 검사를 반복한다.
def event(module="noclip", raw_score=3, evidence=None):
    return {
        "session_id": "s", "player_id": "p", "module": module,
        "timestamp_ms": 1000, "evidence": evidence or {},
        "reasons": ["signal"] if raw_score else [], "raw_score": raw_score,
    }


class PolicyDraftTests(unittest.TestCase):
    """모듈별 비율의 한계, 미확인/측정 실패 표시, 원본 저장 불변성을 검증한다."""
    def test_source_code_bounds_are_documented_not_fitted_thresholds(self):
        """확인된 상한은 코드상 raw 점수 범위이지 운영 판정 임계값이 아님."""
        self.assertEqual({name: PROFILES[name].raw_upper_bound for name in
                          ("noclip", "aimbot", "autopaint", "hide_anywhere")},
                         {"noclip": 5, "aimbot": 8, "autopaint": 35, "hide_anywhere": 3})

    def test_known_bounded_signals_have_only_within_module_raw_fraction(self):
        """특정 모듈 내부에서만 비율을 계산하고 있는지 확인."""
        cases = {"noclip": (5, 100), "aimbot": (4, 50),
                 "autopaint": (7, 20), "hide_anywhere": (3, 100)}
        for module, (raw, expected) in cases.items():
            with self.subTest(module=module):
                preview = inspect_event(event(module, raw))
                self.assertEqual(preview.state, "RAW_FRACTION_ONLY")
                self.assertEqual(preview.raw_fraction_pct, expected)

    def test_godmode_event_delta_cannot_be_used_as_current_score(self):
        """Godmode 증분 점수를 최신 스냅샷 총점으로 오해하지 않는지 확인."""
        preview = inspect_event(event("godmode", 4))
        self.assertEqual(preview.state, "POLICY_NOT_CALIBRATED")
        self.assertEqual(preview.emission, "event_delta")
        self.assertIsNone(preview.raw_fraction_pct)
        self.assertIn("history", " ".join(preview.issues))

    def test_external_access_requires_source_process_grouping(self):
        """동일 모듈 내에서도 서로 다른 접근 프로세스를 구분해야 함을 알림."""
        preview = inspect_event(event("external_access", 6, {"source_pid": 100}))
        self.assertIsNone(preview.raw_fraction_pct)
        self.assertIn("source entities", " ".join(preview.issues))

    def test_module_integrity_has_its_own_positive_only_profile(self):
        preview = inspect_event(event("module_integrity", 2, {
            "submodule": "module_integrity",
            "target_pid": 500,
            "module_path": "C:/Game/extra.dll",
        }))
        self.assertEqual(preview.emission, "positive_only")
        self.assertEqual(preview.state, "POLICY_NOT_CALIBRATED")
        self.assertIsNone(preview.raw_fraction_pct)

    def test_absent_esp_profile_is_waiting_not_zero_risk(self):
        """ESP 규격이 없다는 사실을 0 위험도로 처리하지 않는지 확인."""
        preview = inspect_event(event("esp", 1))
        self.assertEqual(preview.state, "AWAITING_DETECTOR")
        self.assertIsNone(preview.raw_fraction_pct)

    def test_unknown_future_module_does_not_crash_or_get_bogus_zero(self):
        """신규 모듈이 등록 전에도 서버가 죽지 않고 검토 상태로 남는지 확인."""
        preview = inspect_event(event("speedhack", 99))
        self.assertEqual(preview.state, "UNKNOWN_MODULE")
        self.assertIsNone(preview.raw_fraction_pct)

    def test_failed_measurements_are_not_clean(self):
        """측정 실패/OFFLINE 기록을 정상 판정으로 오인하지 않는지 확인."""
        for evidence in ({"status": "ERROR"}, {"status": "OFFLINE"},
                         {"measurement_valid": False}):
            with self.subTest(evidence=evidence):
                preview = inspect_event(event("injection", 0, evidence))
                self.assertEqual(preview.state, "MEASUREMENT_UNAVAILABLE")
                self.assertIsNone(preview.raw_fraction_pct)

    def test_autopaint_both_channels_invalid_is_not_a_zero_risk(self):
        """AutoPaint 두 채널이 모두 무효인 경우 비율을 계산하지 않음."""
        preview = inspect_event(event("autopaint", 0,
                                      {"integrity_valid": 0, "behavior_valid": 0}))
        self.assertEqual(preview.state, "MEASUREMENT_UNAVAILABLE")
        self.assertIsNone(preview.raw_fraction_pct)

    def test_raw_out_of_audited_bound_requires_review(self):
        """검토한 코드의 상한을 넘은 데이터에 재조사 상태를 부여."""
        preview = inspect_event(event("aimbot", 9))
        self.assertEqual(preview.state, "OUT_OF_AUDITED_RANGE")
        self.assertIsNone(preview.raw_fraction_pct)

    def test_noclip_and_aimbot_are_snapshot_feeds_after_shared_02(self):
        """0점도 전송하는 최신 Noclip/Aimbot을 positive-only로 남겨두지 않음."""
        for module in ("noclip", "aimbot"):
            with self.subTest(module=module):
                preview = inspect_event(event(module, 0, {"status": "NORMAL"}))
                self.assertEqual(preview.emission, "snapshot")
                self.assertEqual(preview.state, "RAW_FRACTION_ONLY")
                self.assertEqual(preview.raw_fraction_pct, 0)
                self.assertNotIn("not current health", " ".join(preview.issues))

    def test_remaining_positive_only_feed_still_warns_about_silence(self):
        """실제로 양수만 보내는 모듈의 침묵은 정상 상태로 바꾸지 않음."""
        preview = inspect_event(event("localguard_executable_hash", 1))
        self.assertEqual(preview.emission, "positive_only")
        self.assertIn("not current health", " ".join(preview.issues))

    def test_storage_remains_idempotent_and_preview_does_not_mutate(self):
        """B2a 조회가 B1 저장 상태를 변경하지 않고 중복 방지도 유지함."""
        with tempfile.TemporaryDirectory() as root:
            store = ScoringStore(Path(root) / "scoring.sqlite3")
            key = str(uuid.uuid4())
            store.process_event(event("godmode", 4), event_id=key, sequence=1)
            store.process_event(event("noclip", 3), event_id=str(uuid.uuid4()), sequence=2)
            prior = store.get_player_snapshot("s", "p")
            previews = inspect_player_snapshot(prior)
            self.assertEqual([p.module for p in previews], ["godmode", "noclip"])
            self.assertEqual(previews[0].state, "POLICY_NOT_CALIBRATED")
            self.assertEqual(previews[1].raw_fraction_pct, 60)
            self.assertEqual(store.get_player_snapshot("s", "p"), prior)


if __name__ == "__main__":
    unittest.main()
