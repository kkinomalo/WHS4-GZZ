"""B1 저장소의 안전성 회귀 테스트: 입력 중복·시간 순서·장애 복구를 검증한다."""

from __future__ import annotations

import tempfile
import unittest
import uuid
from pathlib import Path

from server.scoring.storage import ScoringStore


# 실제 shared 7필드와 동일한 모양의 테스트용 이벤트를 생성한다.
def event(*, timestamp_ms=1000, raw_score=3, module="noclip"):
    return {
        "session_id": "session_1",
        "player_id": "player_1",
        "module": module,
        "timestamp_ms": timestamp_ms,
        "evidence": {"sample": timestamp_ms},
        "reasons": ["test"] if raw_score else [],
        "raw_score": raw_score,
    }


def event_id() -> str:
    return str(uuid.uuid4())


class ScoringStoreTests(unittest.TestCase):
    """각 테스트에 임시 SQLite를 사용하여 서로의 기록이 섞이지 않게 한다."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ScoringStore(Path(self.tmp.name) / "scoring.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_event_updates_current_module_state(self):
        """처음 받은 Event가 해당 플레이어/모듈의 최신 상태가 되는지 확인."""
        key = event_id()
        receipt = self.store.process_event(event(), event_id=key, sequence=1)

        self.assertEqual(receipt.status, "processed")
        self.assertTrue(receipt.state_updated)
        state = self.store.get_module_state("session_1", "player_1", "noclip")
        self.assertIsNotNone(state)
        self.assertEqual(state.event_id, key)
        self.assertEqual(state.raw_score, 3)

    def test_retry_with_same_event_id_is_idempotent(self):
        """네트워크 재전송 시 같은 event_id가 두 번 점수에 반영되지 않는지 확인."""
        key = event_id()
        self.store.process_event(event(), event_id=key, sequence=1)
        duplicate = self.store.process_event(event(), event_id=key, sequence=1)

        self.assertEqual(duplicate.status, "duplicate")
        self.assertFalse(duplicate.state_updated)
        state = self.store.get_module_state("session_1", "player_1", "noclip")
        self.assertEqual(state.sequence, 1)

    def test_same_event_id_with_different_input_fails_closed(self):
        """같은 ID로 본문을 바꿔 보냈을 때 충돌로 거부하는지 확인."""
        key = event_id()
        self.store.process_event(event(raw_score=1), event_id=key, sequence=1)

        with self.assertRaises(RuntimeError):
            self.store.process_event(event(raw_score=3), event_id=key, sequence=1)

    def test_repeated_new_samples_replace_score_instead_of_accumulating(self):
        """3점 표본 두 번이 6점으로 누적되지 않고 최근 상태 3점이 되는지 확인."""
        self.store.process_event(event(timestamp_ms=1000, raw_score=3), event_id=event_id(), sequence=1)
        self.store.process_event(event(timestamp_ms=2000, raw_score=3), event_id=event_id(), sequence=2)

        state = self.store.get_module_state("session_1", "player_1", "noclip")
        self.assertEqual(state.raw_score, 3)
        self.assertEqual(state.timestamp_ms, 2000)
        self.assertEqual(state.sequence, 2)

    def test_late_older_sample_does_not_overwrite_newer_state(self):
        """과거 표본이 나중에 도착하더라도 현재 상태를 덮지 않는지 확인."""
        newest = event_id()
        self.store.process_event(event(timestamp_ms=5000, raw_score=3), event_id=newest, sequence=1)
        late = self.store.process_event(event(timestamp_ms=1000, raw_score=0), event_id=event_id(), sequence=2)

        self.assertFalse(late.state_updated)
        state = self.store.get_module_state("session_1", "player_1", "noclip")
        self.assertEqual(state.event_id, newest)
        self.assertEqual(state.timestamp_ms, 5000)
        self.assertEqual(state.raw_score, 3)

    def test_modules_keep_independent_current_state(self):
        """Noclip/Aimbot 같은 플레이어여도 모듈별 상태가 독립적인지 확인."""
        self.store.process_event(event(module="noclip", raw_score=3), event_id=event_id(), sequence=1)
        self.store.process_event(event(module="aimbot", raw_score=7), event_id=event_id(), sequence=2)

        snapshot = self.store.get_player_snapshot("session_1", "player_1")
        self.assertEqual([state.module for state in snapshot], ["aimbot", "noclip"])
        self.assertEqual([state.raw_score for state in snapshot], [7, 3])

    def test_module_integrity_cannot_overwrite_external_access_state(self):
        self.store.process_event(
            event(module="external_access", raw_score=7),
            event_id=event_id(),
            sequence=1,
        )
        self.store.process_event(
            event(module="module_integrity", timestamp_ms=2000, raw_score=2),
            event_id=event_id(),
            sequence=2,
        )

        external = self.store.get_module_state(
            "session_1", "player_1", "external_access"
        )
        integrity = self.store.get_module_state(
            "session_1", "player_1", "module_integrity"
        )
        self.assertIsNotNone(external)
        self.assertIsNotNone(integrity)
        self.assertEqual(external.raw_score, 7)
        self.assertEqual(integrity.raw_score, 2)

    def test_live_processing_does_not_advance_recovery_cursor(self):
        """실시간 처리만으로 복구 커서가 전진하지 않는지 확인."""
        self.store.process_event(event(), event_id=event_id(), sequence=7)
        self.assertEqual(self.store.get_recovery_cursor(), 0)

        self.store.advance_recovery_cursor(7)
        self.assertEqual(self.store.get_recovery_cursor(), 7)

    def test_recovery_cursor_cannot_advance_to_unprocessed_record(self):
        """처리하지 않은 기록을 건너뛰도록 커서를 전진시키지 못하는지 확인."""
        with self.assertRaises(RuntimeError):
            self.store.advance_recovery_cursor(1)

    def test_replay_pattern_is_safe_after_process_before_cursor_crash(self):
        """처리 후 커서 저장 전 장애 발생 시 재실행이 안전한지 확인."""
        key = event_id()
        self.store.process_event(event(), event_id=key, sequence=1)
        self.assertEqual(self.store.get_recovery_cursor(), 0)

        duplicate = self.store.process_event(event(), event_id=key, sequence=1)
        self.assertEqual(duplicate.status, "duplicate")
        self.store.advance_recovery_cursor(1)
        self.assertEqual(self.store.get_recovery_cursor(), 1)


if __name__ == "__main__":
    unittest.main()
