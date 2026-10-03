"""DLL 변화와 파일 신뢰 정보를 공통 탐지 결과로 변환한다."""

from __future__ import annotations

from typing import Any, Dict

from ..common.detection_result import build_detection_result
from .models import ModuleObservation, ScanContext


CHANGE_WEIGHTS = {
    # 정상 프로그램도 실행 중 DLL을 로드할 수 있으므로 추가 사실 자체는 낮게 둔다.
    "added": 1,
    # ASLR을 동반한 정상 unload/reload도 주소를 바꿀 수 있어 단독 가중치는 낮게 둔다.
    "changed": 1,
    # 엄격한 초기 기준선 감사에서 allowlist에 없는 시작 모듈도 단독 확정하지 않는다.
    "baseline_unreviewed": 1,
}

SIGNATURE_WEIGHTS = {
    # 미서명은 단독 확정 근거가 아니라 DLL 변화와 결합되는 보조 근거다.
    "unsigned": 1,
    # 해시 불일치나 신뢰 실패는 단순 미서명보다 강하게 반영한다.
    "invalid": 2,
}


class ModuleIntegrityDetector:
    """추가·변경 DLL 한 개를 설명 가능한 raw_score로 바꾼다."""

    # 중앙 저장 키가 위험 핸들 채널 external_access와 충돌하지 않게 독립 이름을 쓴다.
    module_name = "module_integrity"
    submodule_name = "module_integrity"

    def evaluate(
        self,
        observation: ModuleObservation,
        context: ScanContext,
    ) -> Dict[str, Any]:
        module = observation.module
        evidence: Dict[str, Any] = {
            "submodule": self.submodule_name,
            "status": "SUSPICIOUS",
            "change_type": observation.change_type,
            "target_pid": context.target_pid,
            "module_name": module.name,
            "module_path": module.path,
            "base_address": f"0x{module.base_address:X}",
            "image_size": module.image_size,
            "allowlisted": False,
        }
        score = CHANGE_WEIGHTS[observation.change_type]
        if observation.change_type == "added":
            reasons = ["Module appeared after the process baseline"]
        elif observation.change_type == "baseline_unreviewed":
            reasons = ["Initial module is absent from the reviewed allowlist"]
        else:
            reasons = ["Loaded module mapping changed after the process baseline"]
            evidence.update(
                {
                    "previous_base_address": (
                        f"0x{observation.previous_base_address:X}"
                        if observation.previous_base_address is not None
                        else None
                    ),
                    "previous_image_size": observation.previous_image_size,
                }
            )

        if observation.artifact is not None:
            artifact = observation.artifact
            evidence.update(
                {
                    "sha256": artifact.sha256,
                    "signature_status": artifact.signature_status,
                    "publisher": artifact.publisher,
                }
            )
            signature_score = SIGNATURE_WEIGHTS.get(artifact.signature_status, 0)
            if signature_score:
                score += signature_score
                reasons.append(f"Module signature is {artifact.signature_status}")
        else:
            evidence.update(
                {
                    "sha256": None,
                    "signature_status": "unknown",
                    "publisher": None,
                }
            )
            if observation.inspection_error:
                evidence["inspection_error"] = observation.inspection_error
                reasons.append("Module file trust inspection was unavailable")

        return build_detection_result(
            session_id=context.session_id,
            player_id=context.player_id,
            module=self.module_name,
            timestamp_ms=context.timestamp_ms,
            evidence=evidence,
            reasons=reasons,
            raw_score=score,
        )


__all__ = ["ModuleIntegrityDetector"]
