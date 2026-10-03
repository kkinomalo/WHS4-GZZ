"""LocalGuard 관측 의미만 추가하는 A 담당 정책. 원점수/저장/판정은 변경하지 않음."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
import ntpath
from typing import Any

from ..policy import SignalPreview
from .contract import PolicyAnnotations


SUPPORTED_MODULES = (
    "external_access", "module_integrity", "localguard_yara", "localguard_executable_hash",
    "filesystem", "injection", "value_tamper", "overlay_hook",
    "godmode_runtime", "noclip_runtime", "aimbot_runtime",
)

_YARA_SCOPES = frozenset((
    "selected_local_process_memory", "same_session_external_python_memory",
    "loaded_autopaint_bridge_module_memory", "known_autopaint_bridge_module_inventory",
))
_MEMORY_REASONS = {
    "filesystem": {
        "proxy_dll_in_game_dir": "게임 폴더의 사이드로딩 후보 파일 존재 관측이다. 실제 로드나 활성화를 증명하지 않는다.",
        "ue4ss_runtime": "미검토 UE4SS 파일 흔적 관측이다. UE4SS 존재만으로 특정 핵의 사용을 확정하지 않는다.",
        "third_party_lua_mod": "mods.txt의 외부 모드 활성 설정 관측이다. 실제 실행 성공·플레이 중 동작까지 확인한 것은 아니다.",
        "godmode_artifact": "Godmode 이름의 플래그/로그 흔적 관측이다. 현재 무적 상태·피격 무효 사건과 구분한다.",
        "dumper_artifact": "덤퍼 설정 흔적이다. 현재 게임 변조나 특정 핵 행동의 관측은 아니다.",
        "dumper_output_dir": "덤프 산출물 폴더 존재 관측이다. 과거 분석 흔적을 현재 핵 활성화로 바꾸지 않는다.",
        "whistle_log": "휘파람 로그 파일 존재 관측이다. Whistle RPC 위반 사건의 실시간 관측과 구분한다.",
        "unexpected_binary_in_game_dir": "정품 목록 밖 바이너리 존재 관측이다. 파일 이름만으로 악성 주입을 확정하지 않는다.",
    },
    "injection": {
        "process_event_hooked": "ProcessEvent vtable 교체 흔적이다. 특정 핵의 동작 자체를 관측한 것은 아니다.",
        "exec_function_hooked": "UFunction ExecFunction 교체 흔적이다. Whistle의 같은 종류 흔적과 중복 가능성 검토가 필요하다.",
        "text_section_modified": "기준 해시와 .text의 차이 관측이다. 기준 파일/빌드와 유효성을 별도로 확인해야 한다.",
        "untrusted_module": "모듈의 서명·경로 신뢰 관측이다. 미서명만으로 악성 DLL을 확정하지 않는다.",
    },
    "overlay_hook": {
        "inline_hook_untrusted": "비신뢰 인라인 후킹 관측이다. 정상 오버레이와 핵을 함수 흔적만으로 동일시하지 않는다.",
        "overlay_hook": "렌더링 경로 후킹 근거다. 특정 ESP 활성화·벽 너머 정보 사용의 증명은 아니다.",
    },
    "godmode_runtime": {
        "invincible_enabled": "현재 메모리의 무적 플래그 관측이다. 새 피격 무효 사건이나 지속 시간 점수는 아니다.",
        "godmode_value_pattern": "현재 체력/상태 조합 패턴 관측이다. 독립 Godmode의 사건별 증분과 단순 합산하지 않는다.",
    },
    "noclip_runtime": {
        "collision_bit_cleared": "충돌 비트 해제 상태 관측이다. 실제 벽 통과·blocked_path·지속 시간을 관측한 것은 아니다.",
    },
    "aimbot_runtime": {
        "control_rotation_pattern": "ControlRotation 시계열 패턴 관측이다. 마우스 입력 부재·표적 수렴·비가시 추적은 확인하지 않는다.",
    },
}
_RUNTIME_BOUNDS = {"godmode_runtime": 5, "noclip_runtime": 1, "aimbot_runtime": 1}
_HIDE_FIELDS = frozenset((
    "interactlength", "enableinteract", "isinviewchecklate", "usenearinteract",
    "prestencil", "searchradius", "angle", "anglebias", "ignoreupvector",
    "enabledistance", "enabledistancegimmick", "is_in_view_check_late",
))
_PAINT_FIELDS = frozenset((
    "minscreenpaintdistance", "maxbatchsize", "maxnetworkbatchespertick",
    "maxreplicatedpaintstrokespertick", "autoflushthreshold",
    "bautoflushstrokes", "brealtimenetworksync",
))


def _valid_pid(value: Any) -> bool:
    return type(value) is int and 0 < value <= 0xFFFFFFFF


def _module_scope(evidence: Mapping[str, Any]) -> str | None:
    """게임 PID와 절대 Windows DLL 경로의 관측 범위. 파일/네트워크 접근 없음.

    해시는 경로 문자열의 길이 제한용이지 파일 무결성 해시가 아니다.
    change_type/시각은 키에 넣지 않음: 사건 ID나 재전송 중복 키가 아님.
    """
    pid, path = evidence.get("target_pid"), evidence.get("module_path")
    if not _valid_pid(pid) or not isinstance(path, str) or not path.strip():
        return None
    value = path.strip().replace("/", "\\")
    lowered = value.casefold()
    if lowered.startswith("\\\\?\\unc\\"):
        value = "\\\\" + value[8:]
    elif lowered.startswith("\\\\?\\"):
        value = value[4:]
    elif lowered.startswith("\\??\\"):
        value = value[4:]
    # 상대 경로나 드라이브 없는 경로를 서버의 현재 폴더로 보완하지 않는다.
    if "\x00" in value or not ntpath.isabs(value) or not ntpath.splitdrive(value)[0]:
        return None
    normalized = ntpath.normcase(ntpath.normpath(value))
    digest = sha256(normalized.encode("utf-8")).hexdigest()
    return f"game_module:{pid}:{digest}"


def _external_access(event: Mapping[str, Any], notes: list[str]) -> str | None:
    evidence = event["evidence"]
    submodule = evidence.get("submodule")
    if event["module"] == "module_integrity":
        notes.append("module_integrity는 DLL 변화 전용 module이며 external_access 핸들 상태와 별도 저장된다.")
        if submodule not in (None, "module_integrity"):
            notes.append("module_integrity 이벤트의 submodule이 예상 계약과 다르므로 관측 범위를 만들지 않는다.")
            return None
        submodule = "module_integrity"
    else:
        notes.append("external_access는 외부 프로세스 핸들 관측 module이다. 과거 버전의 DLL 하위 채널도 호환 해석한다.")
    if submodule is None and "source_pid" in evidence:
        submodule = "external_process"
        notes.append("submodule이 없는 과거 source_pid 형식은 외부 프로세스 관측 범위로만 해석한다. 원본에 submodule을 추가하지 않는다.")

    if submodule == "external_process":
        notes.append("위험 핸들은 쓰기·메모리 조작·스레드 생성 권한의 관측이다. 해당 프로세스가 실제 핵 기능을 실행했다는 증명은 아니다.")
        notes.append("현재 VM_READ 단독은 탐지기에서 점수를 부여하지 않는다. 서버에서 읽기 권한 점수를 새로 만들지 않는다.")
        notes.append("NORMAL 0점은 이번 핸들 검사에 양수 결과가 없다는 뜻이다. 과거 모든 source_pid의 안전·종료를 증명하지 않는다.")
        rights = evidence.get("access_rights")
        if rights == ["PROCESS_VM_READ"] and event["raw_score"] > 0:
            notes.append("VM_READ 단독 양수는 조사한 탐지기 계약과 다르다. 원점수를 보존하고 전송 버전·근거를 확인한다.")
        if evidence.get("signature_status") in ("unsigned", "unknown", "invalid"):
            notes.append("서명·경로 신뢰 정보는 위험 핸들에 결합되는 보조 근거다. 미서명/조회 실패만으로 치트를 확정하지 않는다.")
        pid = evidence.get("source_pid")
        if event["raw_score"] > 0 and _valid_pid(pid):
            notes.append("source_pid는 외부 접근 주체의 관측 범위다. PID 재사용·다중 핸들·재시작을 사건 ID와 구분한다.")
            return f"external_process:{pid}"
        return None

    if submodule == "module_integrity":
        notes.append("module_integrity는 PR #78의 DLL 추가·매핑 변경·초기 기준선 감사 채널이다. 핸들 접근 신호가 아니다.")
        notes.append("후속 NORMAL 0점은 새 의심 변화가 없다는 뜻이다. 이전 DLL의 제거·무해함 또는 모든 과거 변화의 해소를 뜻하지 않는다.")
        if event["module"] == "external_access":
            notes.append("과거 external_access 형식은 핸들 상태와 최신값이 충돌할 수 있다. 신규 생산자는 module_integrity 이름을 사용한다.")
        if event["raw_score"] > 3:
            notes.append("DLL 변화 채널의 조사 상한은 3점이다. 생산자 버전과 점수 계약을 확인한다.")
        change = evidence.get("change_type")
        if change == "baseline_unreviewed":
            notes.append("초기 미검토 DLL 관측이다. 안티치트 시작 후 새로 주입된 DLL로 해석하지 않는다.")
        elif change == "changed":
            notes.append("같은 경로의 base address/image size 변화다. 파일 바이트 변조나 악성 인라인 패치를 자동 확정하지 않는다.")
        elif change == "added":
            notes.append("직전 성공 기준선 대비 DLL 추가 관측이다. 단독으로 악성 주입을 확정하지 않는다.")
        elif event["raw_score"] > 0:
            notes.append("양수 DLL 결과의 change_type이 없거나 미분류다. 변화 종류를 추정하지 않는다.")
            return None
        if evidence.get("inspection_error") or evidence.get("signature_status") == "unknown":
            notes.append("파일 신뢰 조회 실패와 DLL 매핑 관측은 구분한다. 조회 실패로 서명/파일 해시를 확정하지 않는다.")
        if event["raw_score"] > 0:
            key = _module_scope(evidence)
            if key is None:
                notes.append("유효한 target_pid·절대 DLL 경로가 없어 관측 범위 키를 만들지 않는다. DLL 이름·주소·첫 번째 다른 근거로 대신하지 않는다.")
            else:
                notes.append("game_module 키는 PID+정규화 경로의 범위다. 경로 해시는 파일 해시가 아니며 개별 로드 사건·계정·재전송 ID도 아니다.")
            return key
        return None

    notes.append("submodule이 없거나 미분류다. 핸들 접근/DLL 변경 중 어느 채널인지 임의로 선택하지 않는다.")
    return None


def _yara(event: Mapping[str, Any], notes: list[str]) -> str | None:
    evidence = event["evidence"]
    scope = evidence.get("scope")
    notes.append("YARA는 규칙 문자열/바이트 일치 관측이다. identity_verified/active_cheat_proven/cheat_confirmed를 정책이 true로 바꾸지 않는다.")
    notes.append("YARA raw_score는 일치 규칙 점수의 최댓값이다. 규칙 수·문자열 수·재검사 횟수를 곱하거나 합산하지 않는다.")
    notes.append("YARA 실패는 공통 0점 Event 대신 로컬 오류·하트비트로 남을 수 있다. 중앙의 침묵을 정상이나 검사 성공으로 해석하지 않는다.")
    if evidence.get("test_rule_match") is True:
        notes.append("테스트 규칙 일치가 포함된다. 운영 핵 탐지 근거로 그대로 승격하지 않으며 실제 규칙과의 혼합 여부는 추가 계약이 필요하다.")
    if event["raw_score"] > 3:
        notes.append("현재 기본 규칙 상한 3과 사용자 지정 규칙 허용 상한 10이 다르다. 운영 규칙/공통 프로필 합의 없이 원점수를 재보정하지 않는다.")
    if scope == "known_autopaint_bridge_module_inventory":
        notes.append("알려진 이름의 bridge DLL 목록 확인이다. 전체 메모리 YARA 검사나 AutoPaint 미사용 증명이 아니다.")
    elif scope == "loaded_autopaint_bridge_module_memory":
        notes.append("로드된 bridge 모듈 메모리 범위만 검사했다. 전체 프로세스 정상으로 확대하지 않는다.")
    elif scope == "same_session_external_python_memory":
        notes.append("외부 Python 후보의 읽을 수 있는 메모리 관측이다. Python이라는 이름·존재만으로 치트를 확정하지 않는다.")
    elif scope == "selected_local_process_memory":
        notes.append("선택한 PID의 읽을 수 있는 메모리 관측이다. 원자적 전체 프로세스 스냅샷/완전한 검사 보장은 아니다.")
    else:
        notes.append("scope가 없거나 미분류다. 검사 PID를 게임 PID 또는 외부 핵 프로세스로 추정하지 않는다.")
    matched = evidence.get("matched_rules")
    if event["raw_score"] > 0 and (not isinstance(matched, list) or not matched):
        notes.append("양수 YARA 결과의 matched_rules 목록이 없다. 자유 reasons에서 규칙/대상을 복원하지 않는다.")
        return None
    if event["raw_score"] > 0 and isinstance(scope, str) and scope in _YARA_SCOPES and _valid_pid(evidence.get("pid")):
        notes.append("yara_pid 키는 PID+검사 범위다. 규칙별 사건 ID나 계정이 아니며 PID 재사용/여러 모듈 관측에 유의한다.")
        return f"yara_pid:{evidence['pid']}:{scope}"
    return None


def _executable_hash(event: Mapping[str, Any], notes: list[str]) -> None:
    evidence = event["evidence"]
    notes.append("실행 파일 SHA-256 카탈로그 일치 관측이다. 해당 실행 이미지 존재와 실제 핵 기능 활성화를 구분한다.")
    notes.append("raw_score는 일치가 있으면 1, 없으면 0인 검사 결과다. 일치 프로세스·카탈로그 ID 수로 다시 곱하지 않는다.")
    notes.append("matched_executables는 여러 프로세스의 목록일 수 있다. 첫 PID/첫 해시를 전체 Event의 단일 entity_key로 선택하지 않는다.")
    notes.append("일치 없는 부분/실패 검사는 Event 자체가 없을 수 있다. 중앙 무전송은 정상 0점이 아니며 하트비트와 별개로 해석한다.")
    matched = evidence.get("matched_executables")
    if event["raw_score"] > 0 and (not isinstance(matched, list) or not matched):
        notes.append("양수 해시 결과에 matched_executables 목록이 없다. 카탈로그 해시를 실행 이미지 해시로 대신하지 않는다.")
    if event["raw_score"] == 0 and evidence.get("coverage_complete") is False:
        notes.append("불완전 검사 0점은 생산자의 정상 무일치 전송 계약과 다르다. 확인된 정상으로 사용하지 않는다.")
    return None


def _memory(event: Mapping[str, Any], notes: list[str]) -> str | None:
    module, evidence = event["module"], event["evidence"]
    meta = evidence.get("meta")
    meta = meta if isinstance(meta, Mapping) else {}
    reasons = set(event["reasons"])
    notes.append("이 채널은 관측 시점/검사 구간의 평가다. 반복 양수는 독립 사건의 개수가 아니며 중앙에는 양수만 전송한다.")
    notes.append("NORMAL 상태의 약한 양수는 내부 등급 임계값 아래의 근거일 수 있다. NORMAL이라고 원점수를 0으로 바꾸지 않는다.")
    if meta.get("failed_checks") or meta.get("cdo_unreadable") or meta.get("no_live_instance"):
        notes.append("meta에 실패 검사/CDO 읽기 실패/미관측 인스턴스가 보고되었다. 남은 유효 근거를 보존하되 전체 정상으로 해석하지 않는다.")
    if any(key in evidence for key in ("address", "value", "module", "file")):
        notes.append("address/value/module/file은 설명을 포함한 평문일 수 있다. 문자열 파싱으로 함수·DLL·Pawn의 사건 키를 만들지 않는다.")

    known = _MEMORY_REASONS.get(module, {})
    for reason, note in known.items():
        if reason in reasons:
            notes.append(note)
    unknown = reasons - known.keys()
    if module == "value_tamper":
        notes.append("설정값을 아키타입/CDO와 비교한 관측이다. 정상 게임 설정 차이·유효한 기준선 여부를 추가 검증해야 한다.")
        fields = {reason.removeprefix("config_changed_") for reason in reasons if reason.startswith("config_changed_")}
        reviewed = _HIDE_FIELDS | _PAINT_FIELDS
        unknown = reasons - {"config_changed_" + name for name in reviewed}
        if fields & _HIDE_FIELDS:
            notes.append("숨기 관련 조사 필드의 기본값 차이 근거다. Hide Anywhere의 실제 값 패턴/행동과 동일 사건으로 자동 확정하지 않는다.")
        if fields & _PAINT_FIELDS:
            notes.append("칠하기 관련 조사 필드의 기본값 차이 근거다. AutoPaint의 실제 칠하기 행동과 구분한다.")
    if module == "filesystem":
        notes.append("파일 흔적은 게임 실행 전에도 관측 가능하다. 존재만으로 현재 핵 활성화·게임 동작을 확정하지 않는다.")
        if meta.get("ue4ss_manifest") == "broken":
            notes.append("런처 UE4SS 등록부를 읽지 못한 상태다. 우리 파일도 점수에 포함될 수 있어 운영 설정을 확인한다. 서버에서 이름만으로 면제하지 않는다.")
        if meta.get("exempt"):
            notes.append("생산자가 해시 일치로 제외한 UE4SS 근거가 남아 있다. 주석 목록을 새 위험 점수로 다시 가산하지 않는다.")
    if module == "injection" and "text_hash" in meta and "text_section_modified" not in reasons:
        notes.append(".text 비교 상태 설명이 있으며 기준 해시가 없을 수 있다. 실제 비교 성공/무결성을 설명 문자열만으로 추정하지 않는다.")
    if module in _RUNTIME_BOUNDS:
        bound = _RUNTIME_BOUNDS[module]
        notes.append(f"현재 {module}의 조사 상한은 {bound}점이다. 기존 공통 프로필 100과 다르며 프로필 갱신은 B와 협의한다.")
        if event["raw_score"] > bound:
            notes.append("현재 Runtime 상한을 벗어난 입력이다. 원점수를 자르지 않고 버전·사유를 확인한다.")
        notes.append("Runtime 메타의 Pawn/Controller 주소를 플레이어·계정·개별 사건의 안정 ID로 사용하지 않는다.")
    if unknown:
        notes.append("미분류 reason이 포함된다. 자유 문자열에서 핵 종류·새 중복 태그를 생성하거나 점수를 재계산하지 않는다.")
    if event["raw_score"] > 0 and not reasons:
        notes.append("양수에 reason 코드가 없다. 원점수를 보존하지만 원인/중복 후보를 추정하지 않는다.")
    if module in ("injection", "overlay_hook") and event["raw_score"] > 0 and _valid_pid(meta.get("target_pid")):
        notes.append("game_pid는 검사 대상 게임 프로세스 범위다. 외부 핵 주체/개별 후킹 사건 ID가 아니며 Whistle과 같은 PID만으로 중복을 확정하지 않는다.")
        return f"game_pid:{meta['target_pid']}"
    return None


def evaluate(event: Mapping[str, Any], baseline: SignalPreview) -> PolicyAnnotations:
    """Registry가 7필드 검증·baseline 분석을 완료한 뒤 호출하는 읽기 전용 함수."""
    module = event["module"]
    if module not in SUPPORTED_MODULES:
        raise ValueError("unsupported LocalGuard module")
    if baseline.module != module:
        raise ValueError("baseline module does not match the event")
    notes = [
        "이 정책은 원점수·상태를 보존하며 합산·가중치·최종 판정·자동 초기화를 수행하지 않는다.",
        "overlap_tags는 B와 이름·적용 조건을 합의하기 전까지 비워 둔다. 같은 PID/경로만으로 중복 사건을 확정하지 않는다.",
    ]
    if baseline.state == "MEASUREMENT_UNAVAILABLE":
        notes.append("ERROR/OFFLINE/measurement_valid=false는 정상 0점이나 과거 위험 해소가 아니다. 남은 근거로 entity/tag를 만들지 않는다.")
        return PolicyAnnotations(notes=tuple(notes))
    evidence = event["evidence"]
    if evidence.get("status") == "WARNING" or evidence.get("coverage_complete") is False:
        notes.append("부분 검사다. 확인된 근거는 보존하되 전체 정상으로 확대하지 않는다.")
    if baseline.state == "OUT_OF_AUDITED_RANGE":
        notes.append("공통 조사 상한을 벗어난 입력이다. 원점수를 자르지 않고 탐지기 버전·점수 계약을 확인한다.")
    if event["raw_score"] == 0 and evidence.get("status") != "NORMAL" and evidence.get("measurement_valid") is not True:
        notes.append("0점만으로 검사 성공/NORMAL을 추정하지 않는다.")
    if module in ("external_access", "module_integrity"):
        key = _external_access(event, notes)
    elif module == "localguard_yara":
        key = _yara(event, notes)
    elif module == "localguard_executable_hash":
        key = _executable_hash(event, notes)
    else:
        key = _memory(event, notes)
    return PolicyAnnotations(entity_key=key, notes=tuple(notes))
