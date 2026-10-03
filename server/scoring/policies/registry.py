"""Scoring에서 사용하는 기본 detector 정책 등록소.

공통 PolicyRegistry 구현은 contract.py에 두고, 이 파일은 현재 main에서
실제로 사용할 detector -> handler 연결만 담당한다. 최종 위험도/가중치 계산은
여기서 수행하지 않는다.
"""

from __future__ import annotations

from typing import Any, Mapping

from . import aimbot, autopaint, esp, godmode, localguard, noclip
from .contract import PolicyEvaluation, PolicyRegistry


def build_default_registry() -> PolicyRegistry:
    """현재 Scoring에서 지원하는 detector 정책을 새 Registry에 등록한다.

    테스트나 향후 확장 코드가 독립 Registry를 만들 수 있도록 매 호출마다
    새로운 객체를 반환한다. A 담당 정책은 구현 완료 후 여기에
    같은 방식으로 추가한다.
    """
    registry = PolicyRegistry()
    registry.register("noclip", noclip.evaluate)
    registry.register("aimbot", aimbot.evaluate)
    registry.register("autopaint", autopaint.evaluate)
    registry.register("godmode", godmode.evaluate)
    registry.register("esp", esp.evaluate)
    registry.register("module_integrity", localguard.evaluate)
    return registry


# 서버 기본 경로에서는 등록 구성이 매 이벤트마다 달라지지 않으므로 한 객체를 재사용한다.
_DEFAULT_REGISTRY = build_default_registry()


def evaluate_registered_policy(event: Mapping[str, Any]) -> PolicyEvaluation:
    """공통 7필드 Event를 실제 module 이름에 맞는 기본 정책으로 평가한다.

    등록되지 않은 모듈도 contract.PolicyRegistry의 기존 동작대로 B2a 결과를
    보존하며, 임의로 정상/0위험으로 바꾸지 않는다.
    """
    return _DEFAULT_REGISTRY.evaluate(event)
