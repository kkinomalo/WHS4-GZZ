"""실제 Windows API를 사용하는 module_integrity 종단간 스모크 테스트.

게임에는 연결하지 않는다. 이 스크립트가 만든 보조 Python 프로세스의 모듈
기준선을 저장한 뒤, 그 프로세스가 정상 Windows 시스템 DLL 하나를 로드하게
하고 LocalGuard가 추가 모듈 이벤트를 기록하는지 확인한다.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import struct
import subprocess
import sys
import threading
import time
from typing import Any

from ..common import get_windows_system_directory
from .module_sensor import ToolhelpModuleSensor
from .runner import ModuleIntegrityRunner


_HELPER_CODE = r"""
import ctypes
import sys

loaded_modules = []
print("READY", flush=True)
for raw_command in sys.stdin:
    command, separator, argument = raw_command.rstrip("\r\n").partition("\t")
    if command == "LOAD" and separator:
        try:
            # 검사 시점까지 DLL 객체를 유지해 언로드 가능성을 없앤다.
            loaded_modules.append(ctypes.WinDLL(argument))
        except Exception as error:
            print(f"ERROR\t{type(error).__name__}: {error}", flush=True)
        else:
            print("LOADED", flush=True)
    elif command == "EXIT":
        print("EXITING", flush=True)
        break
    else:
        print("ERROR\tunknown command", flush=True)
"""


def _system_dll_candidates() -> tuple[Path, ...]:
    system32 = get_windows_system_directory()
    return tuple(
        system32 / name
        for name in (
            "winhttp.dll",
            "wininet.dll",
            "dbghelp.dll",
            "cryptui.dll",
            "wlanapi.dll",
            "rasapi32.dll",
            "winmm.dll",
            "version.dll",
        )
    )


def _pick_unloaded_system_dll(pid: int) -> Path:
    snapshot = ToolhelpModuleSensor().capture(pid)
    loaded_names = {module.name.casefold() for module in snapshot.modules}
    for candidate in _system_dll_candidates():
        if candidate.is_file() and candidate.name.casefold() not in loaded_names:
            return candidate.resolve()
    raise RuntimeError("테스트용으로 아직 로드되지 않은 Windows 시스템 DLL을 찾지 못함")


def _send(helper: subprocess.Popen[str], command: str) -> None:
    if helper.stdin is None:
        raise RuntimeError("보조 프로세스 입력 파이프가 닫힘")
    helper.stdin.write(command + "\n")
    helper.stdin.flush()


def _read_reply(helper: subprocess.Popen[str], timeout_seconds: float = 10.0) -> str:
    if helper.stdout is None:
        raise RuntimeError("보조 프로세스 출력 파이프가 닫힘")
    replies: queue.Queue[str | BaseException] = queue.Queue(maxsize=1)

    def read_line() -> None:
        try:
            replies.put(helper.stdout.readline())
        except BaseException as error:
            replies.put(error)

    threading.Thread(target=read_line, daemon=True).start()
    try:
        item = replies.get(timeout=timeout_seconds)
    except queue.Empty as error:
        raise TimeoutError(
            f"보조 프로세스가 {timeout_seconds:g}초 안에 응답하지 않음"
        ) from error
    if isinstance(item, BaseException):
        raise RuntimeError(f"보조 프로세스 출력 읽기 실패: {item}") from item
    reply = item.strip()
    if not reply:
        return_code = helper.poll()
        raise RuntimeError(
            "보조 프로세스 응답이 없음"
            + (f" (exit={return_code})" if return_code is not None else "")
        )
    if reply.startswith("ERROR\t"):
        raise RuntimeError(f"보조 프로세스 DLL 로드 실패: {reply[6:]}")
    return reply


def _new_events(output_path: Path, previous_size: int) -> list[dict[str, Any]]:
    if not output_path.exists():
        return []
    payload = output_path.read_bytes()[previous_size:].decode("utf-8")
    return [json.loads(line) for line in payload.splitlines() if line.strip()]


def _stop_helper(helper: subprocess.Popen[str]) -> None:
    if helper.poll() is not None:
        return
    try:
        _send(helper, "EXIT")
        helper.wait(timeout=3)
    except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
        helper.terminate()
        try:
            helper.wait(timeout=3)
        except subprocess.TimeoutExpired:
            helper.kill()
            helper.wait(timeout=3)


def run_smoke_test(output_path: Path | None = None) -> tuple[Path, dict[str, Any]]:
    if os.name != "nt":
        raise RuntimeError("이 스모크 테스트는 Windows 전용임")
    if struct.calcsize("P") != 8:
        raise RuntimeError("64비트 Python으로 실행해야 64비트 대상 모듈을 열거할 수 있음")

    helper = subprocess.Popen(
        [sys.executable, "-I", "-u", "-c", _HELPER_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    try:
        if _read_reply(helper) != "READY":
            raise RuntimeError("보조 프로세스 준비 응답이 올바르지 않음")

        dll_path = _pick_unloaded_system_dll(helper.pid)
        if output_path is None:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = Path("logs") / f"module_integrity_smoke_{stamp}_{helper.pid}.jsonl"
        output_path = Path(output_path).expanduser().resolve()
        previous_size = output_path.stat().st_size if output_path.exists() else 0

        runner = ModuleIntegrityRunner(
            game_executable_name=Path(sys.executable).name,
            game_pid=helper.pid,
            session_id="module_smoke_001",
            player_id="local_test",
            output_path=output_path,
            audit_initial_snapshot=False,
        )

        baseline_report = runner.scan_once()
        if baseline_report.error:
            raise RuntimeError(f"기준선 수집 오류: {baseline_report.error}")
        if not baseline_report.game_found or not baseline_report.baseline_created:
            raise RuntimeError(f"기준선 생성 실패: {baseline_report}")

        _send(helper, f"LOAD\t{dll_path}")
        if _read_reply(helper) != "LOADED":
            raise RuntimeError("보조 프로세스 DLL 로드 응답이 올바르지 않음")

        detection_report = runner.scan_once()
        if detection_report.error:
            raise RuntimeError(f"DLL 추가 탐지 오류: {detection_report.error}")

        matching_events = [
            event
            for event in _new_events(output_path, previous_size)
            if event.get("session_id") == "module_smoke_001"
            and event.get("player_id") == "local_test"
            and event.get("module") == "external_access"
            and event.get("evidence", {}).get("submodule") == "module_integrity"
            and event.get("evidence", {}).get("change_type") == "added"
            and event.get("evidence", {}).get("target_pid") == helper.pid
            and str(event.get("evidence", {}).get("module_name", "")).casefold()
            == dll_path.name.casefold()
        ]
        if len(matching_events) != 1:
            raise RuntimeError(
                f"예상한 DLL 추가 이벤트가 정확히 1개가 아님: "
                f"module={dll_path.name}, matches={len(matching_events)}, "
                f"report={detection_report}"
            )
        repeat_offset = output_path.stat().st_size
        repeat_report = runner.scan_once()
        if repeat_report.error:
            raise RuntimeError(f"반복 스캔 오류: {repeat_report.error}")
        if repeat_report.emitted_detections != 0:
            raise RuntimeError(f"같은 DLL을 반복 탐지함: {repeat_report}")
        if _new_events(output_path, repeat_offset):
            raise RuntimeError("변화 없는 반복 스캔에서 새 JSON 이벤트가 기록됨")
        return output_path, matching_events[0]
    finally:
        _stop_helper(helper)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="게임을 건드리지 않는 LocalGuard module_integrity 스모크 테스트"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="결과 JSONL 경로. 생략하면 logs 아래에 시각·PID가 포함된 파일을 생성",
    )
    args = parser.parse_args()

    try:
        output_path, event = run_smoke_test(args.output)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    evidence = event["evidence"]
    print("PASS: module_integrity end-to-end smoke test")
    print(f"  target_pid: {evidence['target_pid']}")
    print(f"  detected_module: {evidence['module_name']}")
    print(f"  change_type: {evidence['change_type']}")
    print(f"  signature_status: {evidence['signature_status']}")
    print(f"  raw_score: {event['raw_score']}")
    print(f"  output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
