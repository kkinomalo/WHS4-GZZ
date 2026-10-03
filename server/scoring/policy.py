"""detector별 점수 체계 조사 및 미확정 정책을 구분하는 B2a 파일.

여기서 구하는 raw_fraction_pct는 '한 모듈의 자체 점수 범위 대비 비율'일 뿐
치트 확률/모듈 간 공통 위험도/최종 판정 점수가 아니다.
Godmode 같은 사건별 증분(event_delta)과 양수 탐지만 전송하는 모듈은
최근 이벤트 하나만으로 현재 상태를 판단할 수 없다는 점을 명시한다.
조사 대상/남은 확인 사항은 MODULE_INVENTORY.md를 참고한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from shared.schema import encode_event

from .storage import ModuleState


# 코드 조사로 얻은 모듈별 메타데이터. 정책 변경 시 이 정의만 수정할 수 있게 분리한다.
@dataclass(frozen=True)
class DetectorProfile:
    module: str
    source: str
    emission: str
    # 확인된 상한은 소스코드상 raw 점수 상한이다. 위험도/확률의 상한이 아니며
    # 탐지기 구현이 바뀌면 다시 조사해야 한다.
    raw_upper_bound: int | None
    preview_scalable: bool = False
    note: str = ""


# 하나의 입력 이벤트를 사람이 확인하기 좋은 분석 결과로 요약한다.
# state/issue는 미확인·실패 측정·재조사 필요 여부를 명시하며 최종 판정이 아니다.
@dataclass(frozen=True)
class SignalPreview:
    module: str
    raw_score: float
    emission: str
    state: str
    raw_fraction_pct: float | None
    issues: tuple[str, ...]


# 공통 7필드 Event가 실제 전송하는 module 문자열을 정확히 사용한다.
# 독립적인 출처는 별도 항목으로 보존한다. 여기에는 가중치/합산/판정 임계값이 없다.
# emission 종류:
# - snapshot: 특정 시점의 평가값
# - positive_only: 양수 탐지 시 전송. 새 기록이 없다고 정상인 것은 아니다.
# - event_delta: 새로 발생한 사건의 점수. 최근 1개만으로 누적 사건을 알 수 없다.
# - per_entity_positive_only: PID 등 원인 엔터티별로 구분해야 한다.
# - pending: 규격이 아직 없는 모듈.
_PROFILE_ITEMS = (
    DetectorProfile("noclip", "client/detectors/noclip/main.py", "snapshot", 5,
                    True, "Shared 0.2.0: every scored sample, including NORMAL 0, is sent; ERROR is explicit."),
    DetectorProfile("aimbot", "client/detectors/aimbot/detector/aimbot_detector.py", "snapshot", 8,
                    True, "Round-scoped cumulative observation snapshot; scored NORMAL 0 is also sent."),
    DetectorProfile("godmode", "client/detectors/godmode/main.py", "event_delta", None,
                    False, "raw_score=result.new_score, not cumulative score."),
    DetectorProfile("autopaint", "client/detectors/autopaint/gzz_anticheat/detector.py", "snapshot", 35,
                    True, "Raw=max(integrity,valid behavior); 35 is source-code upper bound, not an operating threshold."),
    DetectorProfile("hide_anywhere", "client/detectors/Hide_anywhere_detector/mecha_detector_v9.py", "snapshot", 3,
                    True, "Three-point pattern, or up to two one-point auxiliary signals."),
    DetectorProfile("external_access", "client/LocalGuard/external_access/process_access/detector.py", "per_entity_positive_only", 10,
                    False, "Each event can refer to a different source process/handle."),
    DetectorProfile("module_integrity", "client/LocalGuard/external_access/module_integrity/detector.py", "positive_only", 3,
                    False, "DLL changes are stored separately from external process-handle state; zero status events stay local."),
    DetectorProfile("localguard_executable_hash", "client/LocalGuard/input_signature/hash_monitor.py", "positive_only", 1,
                    False, "Presence of exact known EXE hash is not proof of activation."),
    DetectorProfile("localguard_yara", "client/LocalGuard/input_signature/yara_scanner.py", "per_entity_positive_only", 3,
                    False, "Current signature metadata max=3; scan coverage and test_only vary."),
    *(
        DetectorProfile(name, "client/LocalGuard/memory_integrity/run_session.py", "positive_only", 100,
                        False, "Internal 0..100 capped score, potential coverage/status caveats.")
        for name in (
            "filesystem", "injection", "value_tamper", "overlay_hook",
            "godmode_runtime", "noclip_runtime", "aimbot_runtime",
            "whistle", "whistle_rpc",
        )
    ),
    DetectorProfile("esp", "not in audited ZIP", "pending", None, False,
                    "Wait for ESP implementation and event/score contract."),
)
PROFILES: Mapping[str, DetectorProfile] = {p.module: p for p in _PROFILE_ITEMS}


def inspect_event(event: Mapping[str, Any]) -> SignalPreview:
    """공통 7필드 이벤트를 검증하고 모듈별 설명·주의사항을 반환한다.

    비율 계산은 소스코드상 상한이 확인되었고 의미상 허용된 모듈에 한정한다.
    특정 해시 탐지의 1/1=100%처럼 오해를 부를 항목은 계산하지 않는다.
    서로 다른 모듈 비율을 합산하거나 최종 판정을 내리지 않는다.
    """
    # shared 스키마를 통과하지 못한 입력은 분석하지 않는다.
    encode_event(event)
    module = event["module"]
    raw = event["raw_score"]
    evidence = event["evidence"]
    profile = PROFILES.get(module)
    # 등록되지 않은 신규 detector도 서버 장애를 일으키지 않고 검토 대기로 남긴다.
    if profile is None:
        return SignalPreview(module, float(raw), "unknown", "UNKNOWN_MODULE", None,
                             ("module has no reviewed scoring profile",))
    # ESP 등 아직 규격 미확인 모듈을 0 위험도로 오판하지 않는다.
    if profile.emission == "pending":
        return SignalPreview(module, float(raw), "pending", "AWAITING_DETECTOR", None,
                             (profile.note,))

    # 루트 필드는 정확히 7개다. 검사 상태/커버리지는 evidence에서만 읽는다.
    # 측정 실패·오프라인 상태를 정상(0 위험도)으로 해석하지 않는다.
    status = evidence.get("status")
    if status in ("ERROR", "OFFLINE") or evidence.get("measurement_valid") is False:
        return SignalPreview(module, float(raw), profile.emission, "MEASUREMENT_UNAVAILABLE", None,
                             ("explicit failed/offline/incomplete measurement",))
    if (module == "autopaint" and evidence.get("integrity_valid") == 0
            and evidence.get("behavior_valid") == 0):
        return SignalPreview(module, float(raw), profile.emission, "MEASUREMENT_UNAVAILABLE", None,
                             ("both AutoPaint channels explicitly invalid",))

    # 전송 방식 때문에 현재 1개 기록만으로 판단할 수 없는 한계들을 명시한다.
    issues: list[str] = []
    if status == "WARNING" or evidence.get("coverage_complete") is False:
        issues.append("partial coverage; do not infer clean status")
    if profile.emission == "event_delta":
        issues.append("requires idempotent history of NEW events; latest raw_score is insufficient")
    elif profile.emission == "per_entity_positive_only":
        issues.append("multiple source entities can be overwritten by latest module-only state")
    elif profile.emission == "positive_only":
        issues.append("no 0-point heartbeat in central feed; last detection is not current health")

    # 예상 상한을 넘으면 점수를 임의로 깎지 않고 구현 버전 재조사를 요청한다.
    if (profile.raw_upper_bound is not None and raw > profile.raw_upper_bound):
        issues.append("raw_score exceeds audited source-code bound; review detector version")
        return SignalPreview(module, float(raw), profile.emission, "OUT_OF_AUDITED_RANGE", None,
                             tuple(issues))

    # 제한된 모듈만 자체 비율 계산 허용. 다른 모듈은 판단 유보한다.
    if not profile.preview_scalable or profile.raw_upper_bound is None:
        return SignalPreview(module, float(raw), profile.emission, "POLICY_NOT_CALIBRATED", None,
                             tuple(issues))

    # 예: Noclip 3/5=60%는 'Noclip 내부 척도의 60%'일 뿐
    # Aimbot의 60%와 같은 위험도라는 뜻이 아니다.
    fraction = round(100.0 * raw / profile.raw_upper_bound, 3)
    return SignalPreview(module, float(raw), profile.emission, "RAW_FRACTION_ONLY", fraction,
                         tuple(issues))


def inspect_player_snapshot(states: Iterable[ModuleState]) -> list[SignalPreview]:
    """B1의 최신 저장 기록을 읽기 전용으로 점검한다.

    원본 DB를 수정하거나 서로 다른 모듈 점수를 더하지 않는다.
    사건 증분·엔터티별 모듈은 최신 기록만으로 부족하다는 경고를 함께 반환한다.
    """
    # 저장된 모듈별 상태를 다시 동일한 공통 7필드 Event 형식으로 만들어 검사한다.
    previews: list[SignalPreview] = []
    for state in states:
        event = {
            "session_id": state.session_id,
            "player_id": state.player_id,
            "module": state.module,
            "timestamp_ms": state.timestamp_ms,
            "evidence": state.evidence,
            "reasons": state.reasons,
            "raw_score": state.raw_score,
        }
        previews.append(inspect_event(event))
    return sorted(previews, key=lambda x: x.module)
