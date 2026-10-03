"""A 담당 LocalGuard 정책 해석 테스트. 탐지 알고리즘/실게임 정확도 검증은 아님."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from server.scoring.policies.contract import PolicyRegistry
from server.scoring.policies.localguard import SUPPORTED_MODULES, evaluate
from server.scoring.policy import inspect_event
from shared.errors import ValidationError


REPO_ROOT = Path(__file__).resolve().parents[3]


def sample(module="external_access", *, score=2, evidence=None, reasons=None):
    return {
        "session_id": "synthetic_localguard", "player_id": "test_player",
        "module": module, "timestamp_ms": 1000,
        "evidence": deepcopy(evidence) if evidence is not None else {},
        "reasons": list(reasons or []), "raw_score": score,
    }


def dll_evidence(**overrides):
    evidence = {
        "submodule": "module_integrity", "status": "SUSPICIOUS",
        "target_pid": 500, "module_path": "C:/Game/extra.dll",
        "change_type": "added", "signature_status": "unsigned",
    }
    evidence.update(overrides)
    return evidence


class LocalGuardPolicyTests(unittest.TestCase):
    def setUp(self):
        self.registry = PolicyRegistry()
        for module in SUPPORTED_MODULES:
            self.registry.register(module, evaluate)

    def analyse(self, event):
        original = deepcopy(event)
        result = self.registry.evaluate(event)
        self.assertEqual(event, original)
        self.assertEqual(result.signal, inspect_event(original))
        self.assertEqual(result.annotations.overlap_tags, ())
        if result.annotations.entity_key is not None:
            self.assertLessEqual(len(result.annotations.entity_key), 128)
        return result

    def assert_note(self, result, fragment):
        self.assertTrue(any(fragment in note for note in result.annotations.notes), fragment)

    def test_handle_positive_scopes_source_not_game(self):
        result = self.analyse(sample(evidence={
            "submodule": "external_process", "source_pid": 900, "target_pid": 500,
            "status": "SUSPICIOUS", "access_rights": ["PROCESS_VM_WRITE"],
        }))
        self.assertEqual(result.annotations.entity_key, "external_process:900")
        self.assert_note(result, "PID 재사용")

    def test_handle_zero_does_not_represent_one_old_process(self):
        result = self.analyse(sample(score=0, evidence={
            "submodule": "external_process", "status": "NORMAL", "source_pid": 900,
        }))
        self.assertIsNone(result.annotations.entity_key)
        self.assert_note(result, "과거 모든 source_pid")

    def test_all_unavailable_states_preserve_score_without_entities(self):
        for evidence in ({"status": "ERROR"}, {"status": "OFFLINE"}, {"measurement_valid": False}):
            for submodule in ("external_process", "module_integrity"):
                with self.subTest(evidence=evidence, submodule=submodule):
                    fields = dll_evidence(submodule=submodule, source_pid=900)
                    fields.update(evidence)
                    result = self.analyse(sample(score=2, evidence=fields))
                    self.assertEqual(result.signal.state, "MEASUREMENT_UNAVAILABLE")
                    self.assertEqual(result.signal.raw_score, 2)
                    self.assertIsNone(result.annotations.entity_key)

    def test_invalid_source_pid_is_not_an_entity(self):
        for pid in (True, 0, -1, 1.5, "900", 2**32, None):
            with self.subTest(pid=pid):
                result = self.analyse(sample(evidence={"submodule": "external_process", "source_pid": pid}))
                self.assertIsNone(result.annotations.entity_key)

    def test_read_only_positive_is_flagged_not_scored_or_dropped(self):
        result = self.analyse(sample(score=2, evidence={
            "submodule": "external_process", "source_pid": 900,
            "access_rights": ["PROCESS_VM_READ"],
        }))
        self.assert_note(result, "VM_READ 단독 양수")
        self.assertEqual(result.signal.raw_score, 2)

    def test_legacy_source_pid_is_not_written_back_as_submodule(self):
        event = sample(evidence={"source_pid": 900})
        result = self.analyse(event)
        self.assertEqual(result.annotations.entity_key, "external_process:900")
        self.assertNotIn("submodule", event["evidence"])
        self.assert_note(result, "과거 source_pid")

    def test_unknown_submodule_never_falls_back_to_source_pid(self):
        for fields in ({"target_pid": 500}, {"submodule": "new_channel", "source_pid": 900}):
            result = self.analyse(sample(evidence=fields))
            self.assertIsNone(result.annotations.entity_key)
            self.assert_note(result, "어느 채널인지 임의로 선택하지 않는다")

    def test_dll_scope_is_not_handle_scope(self):
        result = self.analyse(sample("module_integrity", evidence=dll_evidence(source_pid=900)))
        self.assertTrue(result.annotations.entity_key.startswith("game_module:500:"))
        self.assert_note(result, "핸들 접근 신호가 아니다")
        self.assert_note(result, "별도 저장")

    def test_legacy_external_access_dll_event_remains_readable(self):
        result = self.analyse(sample(evidence=dll_evidence()))
        self.assertTrue(result.annotations.entity_key.startswith("game_module:500:"))
        self.assert_note(result, "과거 external_access 형식")

    def test_dll_scope_canonicalizes_case_slashes_and_dot_segments(self):
        paths = ["C:/Game/extra.dll", "c:\\GAME\\unused\\..\\EXTRA.DLL", "\\\\?\\C:\\Game\\extra.dll", "\\??\\C:\\Game\\extra.dll"]
        keys = [self.analyse(sample("module_integrity", evidence=dll_evidence(module_path=p))).annotations.entity_key for p in paths]
        self.assertEqual(len(set(keys)), 1)

    def test_unc_dll_paths_canonicalize(self):
        paths = ["\\\\server\\share\\extra.dll", "\\\\?\\UNC\\server\\share\\extra.dll"]
        keys = [self.analyse(sample(evidence=dll_evidence(module_path=p))).annotations.entity_key for p in paths]
        self.assertIsNotNone(keys[0])
        self.assertEqual(keys[0], keys[1])

    def test_long_unicode_dll_path_fits_contract(self):
        result = self.analyse(sample(evidence=dll_evidence(module_path="C:/" + "모듈/" * 200 + "extra.dll")))
        self.assertIsNotNone(result.annotations.entity_key)
        self.assert_note(result, "경로 해시는 파일 해시가 아니며")

    def test_dll_different_pid_or_path_has_different_scope(self):
        events = [dll_evidence(), dll_evidence(target_pid=501), dll_evidence(module_path="C:/Other/extra.dll")]
        keys = [self.analyse(sample(evidence=e)).annotations.entity_key for e in events]
        self.assertEqual(len(set(keys)), 3)

    def test_invalid_dll_path_or_pid_never_falls_back_to_name_address_hash(self):
        for path in (None, "", "extra.dll", "C:extra.dll", "\\extra.dll", "C:/bad\x00.dll", 42):
            with self.subTest(path=path):
                result = self.analyse(sample(evidence=dll_evidence(module_path=path, module_name="extra.dll", base_address="0x1000", sha256="a"*64)))
                self.assertIsNone(result.annotations.entity_key)
        for pid in (True, 0, "500", 2**32):
            result = self.analyse(sample(evidence=dll_evidence(target_pid=pid)))
            self.assertIsNone(result.annotations.entity_key)

    def test_dll_zero_does_not_imply_previous_module_removed(self):
        result = self.analyse(sample(score=0, evidence=dll_evidence(status="NORMAL")))
        self.assertIsNone(result.annotations.entity_key)
        self.assert_note(result, "이전 DLL의 제거")

    def test_dll_initial_audit_not_new_injection_and_changed_not_text_patch(self):
        cases = [("baseline_unreviewed", "새로 주입된 DLL로 해석하지 않는다"), ("changed", "파일 바이트 변조")]
        for change, fragment in cases:
            result = self.analyse(sample(evidence=dll_evidence(change_type=change)))
            self.assert_note(result, fragment)

    def test_dll_unknown_change_has_no_entity(self):
        result = self.analyse(sample(evidence=dll_evidence(change_type="removed")))
        self.assertIsNone(result.annotations.entity_key)
        self.assert_note(result, "변화 종류를 추정하지 않는다")

    def test_dll_trust_read_failure_does_not_discard_mapping_observation(self):
        result = self.analyse(sample(score=1, evidence=dll_evidence(signature_status="unknown", inspection_error="file disappeared")))
        self.assertIsNotNone(result.annotations.entity_key)
        self.assert_note(result, "조회 실패와 DLL 매핑 관측은 구분")

    def test_dll_subchannel_bound_warns_even_when_common_profile_allows(self):
        result = self.analyse(sample(score=4, evidence=dll_evidence()))
        self.assertNotEqual(result.signal.state, "OUT_OF_AUDITED_RANGE")
        self.assert_note(result, "조사 상한은 3점")
        self.assertEqual(result.signal.raw_score, 4)

    def test_partial_and_unknown_zero_remain_distinct(self):
        result = self.analyse(sample(score=0, evidence={"submodule": "external_process", "coverage_complete": False}))
        self.assert_note(result, "부분 검사")
        self.assert_note(result, "0점만으로 검사 성공")

    def test_wrong_module_baseline_and_extra_root_fields_rejected(self):
        event = sample("not_localguard")
        with self.assertRaises(ValueError):
            evaluate(event, inspect_event(event))
        with self.assertRaises(ValueError):
            evaluate(sample(), inspect_event(sample("whistle")))
        event = sample()
        event["submodule"] = "external_process"
        with self.assertRaises(ValidationError):
            self.registry.evaluate(event)

    def test_repeated_interpretation_is_pure_not_accumulation(self):
        event = sample(evidence=dll_evidence())
        self.assertEqual(self.analyse(event), self.analyse(event))

    def test_yara_pid_and_scope_not_rule_count_or_source_handle_pid(self):
        result = self.analyse(sample("localguard_yara", score=3, evidence={
            "pid": 900, "source_pid": 100, "scope": "same_session_external_python_memory",
            "measurement_valid": True, "matched_rules": ["rule_a", "rule_b"],
            "rule_match_count": 2,
        }))
        self.assertEqual(result.annotations.entity_key, "yara_pid:900:same_session_external_python_memory")
        self.assertEqual(result.signal.raw_score, 3)
        self.assert_note(result, "최댓값")
        self.assert_note(result, "이름·존재만으로 치트를 확정하지 않는다")

    def test_yara_scopes_are_explicit_not_guessed(self):
        for scope in (None, "new_scope", "", ["selected_local_process_memory"]):
            with self.subTest(scope=scope):
                result = self.analyse(sample("localguard_yara", score=3, evidence={"pid": 900, "scope": scope, "matched_rules": ["rule_a"]}))
                self.assertIsNone(result.annotations.entity_key)
                self.assert_note(result, "scope가 없거나 미분류")

    def test_yara_inventory_zero_is_not_full_memory_clean(self):
        result = self.analyse(sample("localguard_yara", score=0, evidence={
            "pid": 500, "scope": "known_autopaint_bridge_module_inventory",
            "measurement_valid": True, "matched_rules": [],
        }))
        self.assertIsNone(result.annotations.entity_key)
        self.assert_note(result, "전체 메모리 YARA 검사")

    def test_yara_loaded_module_is_limited_scope(self):
        result = self.analyse(sample("localguard_yara", score=3, evidence={
            "pid": 500, "scope": "loaded_autopaint_bridge_module_memory", "matched_rules": ["rule_a"],
        }))
        self.assert_note(result, "전체 프로세스 정상으로 확대하지 않는다")

    def test_yara_test_rule_is_not_promoted_or_score_silently_removed(self):
        result = self.analyse(sample("localguard_yara", score=3, evidence={
            "pid": 900, "scope": "selected_local_process_memory", "matched_rules": ["test_rule", "real_rule"],
            "test_rule_match": True, "active_cheat_proven": False,
        }))
        self.assertEqual(result.signal.raw_score, 3)
        self.assert_note(result, "운영 핵 탐지 근거로 그대로 승격하지 않으며")

    def test_yara_custom_score_contract_pending_not_clipped(self):
        result = self.analyse(sample("localguard_yara", score=10))
        self.assertEqual(result.signal.state, "OUT_OF_AUDITED_RANGE")
        self.assertEqual(result.signal.raw_score, 10)
        self.assert_note(result, "사용자 지정 규칙 허용 상한 10")

    def test_yara_missing_matched_rules_or_bad_pid_never_key_from_reasons(self):
        for matched, pid in ((None, 500), ([], 500), ("rule_a", 500), (["rule_a"], True), (["rule_a"], "500")):
            result = self.analyse(sample("localguard_yara", score=3, evidence={
                "scope": "selected_local_process_memory", "pid": pid, "matched_rules": matched,
            }, reasons=["YARA Rule Matched: rule_a"]))
            self.assertIsNone(result.annotations.entity_key)

    def test_hash_multiple_executables_does_not_pick_first_entity_or_multiply(self):
        result = self.analyse(sample("localguard_executable_hash", score=1, evidence={
            "measurement_valid": True, "coverage_complete": True,
            "matched_executables": [{"pid": 10, "sha256": "a" * 64}, {"pid": 20, "sha256": "b" * 64}],
            "catalogue_sha256": "c" * 64,
        }))
        self.assertIsNone(result.annotations.entity_key)
        self.assertEqual(result.signal.raw_score, 1)
        self.assert_note(result, "첫 PID/첫 해시")
        self.assert_note(result, "실제 핵 기능 활성화를 구분")

    def test_hash_partial_positive_keeps_observed_match(self):
        result = self.analyse(sample("localguard_executable_hash", score=1, evidence={
            "measurement_valid": True, "coverage_complete": False, "matched_executables": [{"pid": 10}],
        }))
        self.assertNotEqual(result.signal.state, "MEASUREMENT_UNAVAILABLE")
        self.assertEqual(result.signal.raw_score, 1)
        self.assert_note(result, "부분 검사")

    def test_hash_incomplete_zero_and_missing_match_warn(self):
        result = self.analyse(sample("localguard_executable_hash", score=0, evidence={"coverage_complete": False}))
        self.assert_note(result, "생산자의 정상 무일치 전송 계약과 다르다")
        result = self.analyse(sample("localguard_executable_hash", score=1, evidence={"catalogue_sha256": "a" * 64}))
        self.assert_note(result, "카탈로그 해시를 실행 이미지 해시로 대신하지 않는다")

    def test_all_modules_failed_or_offline_never_infer_entities(self):
        for module in SUPPORTED_MODULES:
            for fields in ({"status": "ERROR"}, {"status": "OFFLINE"}, {"measurement_valid": False}):
                with self.subTest(module=module, fields=fields):
                    evidence = dict(fields, pid=500, source_pid=900, meta={"target_pid": 500})
                    result = self.analyse(sample(module, evidence=evidence))
                    self.assertIsNone(result.annotations.entity_key)
                    self.assertEqual(result.signal.state, "MEASUREMENT_UNAVAILABLE")
                    self.assertEqual(result.signal.raw_score, 2)

    def test_injection_and_overlay_game_pid_is_scope_not_cheat_source(self):
        for module, reason in (("injection", "exec_function_hooked"), ("overlay_hook", "overlay_hook")):
            result = self.analyse(sample(module, score=60, evidence={"meta": {"target_pid": 500}}, reasons=[reason]))
            self.assertEqual(result.annotations.entity_key, "game_pid:500")
            self.assert_note(result, "개별 후킹 사건 ID가 아니며")

    def test_memory_metadata_invalid_or_pid_string_not_parsed(self):
        for meta in (None, [], "target_pid=500", {"target_pid": "500"}, {"target_pid": True}):
            result = self.analyse(sample("injection", score=70, evidence={"meta": meta}))
            self.assertIsNone(result.annotations.entity_key)

    def test_partial_injection_and_skipped_text_comparison_keep_score(self):
        result = self.analyse(sample("injection", score=70, evidence={"status": "WARNING", "meta": {
            "target_pid": 500, "failed_checks": ["vtable"], "text_hash": "baseline missing",
        }}, reasons=["exec_function_hooked"]))
        self.assertEqual(result.signal.raw_score, 70)
        self.assert_note(result, "실패 검사")
        self.assert_note(result, "실제 비교 성공/무결성")

    def test_filesystem_broken_manifest_not_name_exemption(self):
        result = self.analyse(sample("filesystem", score=100, evidence={"meta": {
            "ue4ss_manifest": "broken", "game_dir": "C:/Game", "exempt": [{"file": "known.dll"}],
        }}, reasons=["ue4ss_runtime", "third_party_lua_mod"]))
        self.assertIsNone(result.annotations.entity_key)
        self.assertEqual(result.signal.raw_score, 100)
        self.assert_note(result, "서버에서 이름만으로 면제하지 않는다")
        self.assert_note(result, "새 위험 점수로 다시 가산하지 않는다")

    def test_filesystem_logs_not_current_behavior(self):
        result = self.analyse(sample("filesystem", score=100, reasons=["godmode_artifact", "whistle_log", "dumper_output_dir"]))
        self.assert_note(result, "현재 무적 상태·피격 무효 사건과 구분")
        self.assert_note(result, "RPC 위반 사건의 실시간 관측과 구분")
        self.assert_note(result, "과거 분석 흔적")

    def test_value_tamper_reviewed_fields_different_from_generic_changes(self):
        result = self.analyse(sample("value_tamper", score=100, reasons=[
            "config_changed_interactlength", "config_changed_maxreplicatedpaintstrokespertick", "config_changed_unknown",
        ], evidence={"meta": {"config_checks": 40, "no_live_instance": ["Survivor"], "cdo_unreadable": ["A"]}}))
        self.assertIsNone(result.annotations.entity_key)
        self.assert_note(result, "숨기 관련 조사 필드")
        self.assert_note(result, "칠하기 관련 조사 필드")
        self.assert_note(result, "미분류 reason")
        self.assert_note(result, "미관측 인스턴스")

    def test_runtime_low_positive_normal_does_not_become_zero(self):
        for module, score, reason in (
            ("godmode_runtime", 5, "invincible_enabled"),
            ("noclip_runtime", 1, "collision_bit_cleared"),
            ("aimbot_runtime", 1, "control_rotation_pattern"),
        ):
            result = self.analyse(sample(module, score=score, evidence={"status": "NORMAL", "meta": {
                "pawn_address": "0x1234", "controller_address": "0x5678", "target_pid": 500,
            }}, reasons=[reason]))
            self.assertEqual(result.signal.raw_score, score)
            self.assertIsNone(result.annotations.entity_key)
            self.assert_note(result, "NORMAL이라고 원점수를 0으로 바꾸지 않는다")
            self.assert_note(result, f"조사 상한은 {score}점")

    def test_runtime_limit_is_not_legacy_100_score_normalization(self):
        result = self.analyse(sample("noclip_runtime", score=2, reasons=["collision_bit_cleared"]))
        self.assertEqual(result.signal.raw_score, 2)
        self.assert_note(result, "Runtime 상한을 벗어난 입력")

    def test_runtime_observations_not_unobserved_behavior_signals(self):
        cases = [
            ("aimbot_runtime", "control_rotation_pattern", "마우스 입력 부재·표적 수렴·비가시 추적은 확인하지 않는다"),
            ("noclip_runtime", "collision_bit_cleared", "실제 벽 통과·blocked_path·지속 시간"),
            ("godmode_runtime", "godmode_value_pattern", "사건별 증분과 단순 합산하지 않는다"),
        ]
        for module, reason, fragment in cases:
            self.assert_note(self.analyse(sample(module, score=1, reasons=[reason])), fragment)

    def test_memory_free_text_is_not_parsed_as_keys_or_tags(self):
        result = self.analyse(sample("injection", score=70, evidence={
            "address": "0x1234 (Play -> extra.dll)", "module": "extra.dll (C:/Temp/extra.dll)",
        }, reasons=["exec_function_hooked"]))
        self.assertIsNone(result.annotations.entity_key)
        self.assert_note(result, "문자열 파싱으로")

    def test_reason_variants_never_recalculate_detector_score(self):
        cases = [
            ("injection", ["process_event_hooked", "text_section_modified", "untrusted_module"]),
            ("overlay_hook", ["inline_hook_untrusted", "overlay_hook"]),
            ("filesystem", ["proxy_dll_in_game_dir", "dumper_artifact", "unexpected_binary_in_game_dir"]),
        ]
        for module, reasons in cases:
            self.assertEqual(self.analyse(sample(module, score=100, reasons=reasons)).signal.raw_score, 100)

    def test_unknown_reason_is_not_dynamic_tag(self):
        for module in ("filesystem", "injection", "value_tamper", "overlay_hook", "aimbot_runtime"):
            result = self.analyse(sample(module, score=1, reasons=["new reason with arbitrary DLL name"]))
            self.assert_note(result, "미분류 reason")

    def test_shared_conversion_from_actual_memory_producer_preserves_low_normal(self):
        """실제 변환기를 사용하되 게임 접근 없이 합성 내부 결과만 만든다."""
        path = REPO_ROOT / "client/LocalGuard/memory_integrity/core/result.py"
        spec = importlib.util.spec_from_file_location("_localguard_result_fixture", path)
        producer = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {spec.name: producer}):
            spec.loader.exec_module(producer)
            observed = producer.DetectorResult("aimbot_runtime").add(
                "control_rotation_pattern", 1, "synthetic rotation window",
                [producer.Evidence("value", "synthetic")],
            )
            local = producer.to_team_event(observed, "fixture_session", timestamp_ms=1234, player_id="fixture_player")
            event = producer.to_shared_event(local)
        self.assertEqual(len(event), 7)
        self.assertEqual(event["evidence"]["status"], "NORMAL")
        result = self.analyse(event)
        self.assertEqual(result.signal.raw_score, 1)
        self.assert_note(result, "마우스 입력 부재")
        with self.assertRaises(ValidationError):
            self.registry.evaluate(local)

    def test_actual_legacy_replay_through_producer_conversion_not_https_proof(self):
        path = REPO_ROOT / "client/LocalGuard/memory_integrity/core/result.py"
        spec = importlib.util.spec_from_file_location("_localguard_replay_fixture", path)
        producer = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {spec.name: producer}):
            spec.loader.exec_module(producer)
        captures = [REPO_ROOT / "ReplayAnalyzer/replay-data/hide-anywhere/hide_hack_001/events.jsonl",
                    REPO_ROOT / "ReplayAnalyzer/replay-data/normal/clean_002/events.jsonl"]
        seen = set()
        for capture in captures:
            original = capture.read_bytes()
            for line in original.decode("utf-8-sig").splitlines():
                row = json.loads(line)
                if row.get("module") not in ("filesystem", "injection", "value_tamper"):
                    continue
                event = producer.to_shared_event(row)
                result = self.analyse(event)
                self.assertEqual(result.signal.raw_score, row["raw_score"])
                self.assertEqual(event["evidence"]["status"], row["status"])
                seen.add(row["module"])
            self.assertEqual(capture.read_bytes(), original)
        self.assertEqual(seen, {"filesystem", "injection", "value_tamper"})


if __name__ == "__main__":
    unittest.main()
