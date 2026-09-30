# LocalGuard external_access

외부 프로세스 접근 분석과 게임 내부 모듈 무결성 탐지기가 함께 쓰는 LocalGuard
구성이다. 두 탐지 결과는 각각의 로컬 JSONL에 먼저 기록하고, shared client가
설정돼 있으면 같은 7필드 결과를 각 모듈 전용 중앙 전송 대기열에도 넣는다.

```text
external_access/
├─ common/
│  ├─ models.py              # EXE/DLL 검사 결과와 게임 프로세스 식별자
│  ├─ detection_result.py    # 합의한 탐지 JSON 생성·검증
│  ├─ jsonl_writer.py        # 결과 한 건을 로컬 JSONL에 추가
│  ├─ process_locator.py     # 게임 PID 탐색·재실행 판별
│  ├─ artifact_inspector.py  # SHA-256·Authenticode·게시자 조회
│  └─ artifact_cache.py      # 파일이 안 바뀌었으면 검사 결과 재사용
├─ process_access/           # 위험한 게임 프로세스 핸들 관찰·점수화·JSONL 기록
├─ module_integrity/         # DLL 기준선·변화·신뢰 정보 탐지
└─ tests/
```

## 현재 결과 형식

```python
{
    "session_id": "session_20260915_001",
    "player_id": "player_042",
    "module": "external_access",
    "timestamp_ms": 507000,
    "evidence": {
        "submodule": "external_process",
        "access_mask": "0x00000020"
    },
    "reasons": ["Untrusted process has VM_WRITE access to the game"],
    "raw_score": 3,
}
```

`common/detection_result.py`가 위 형식을 검증하고,
`common/jsonl_writer.py`가 한 결과를 한 줄의 JSON으로 기록한다.

## 테스트

저장소 루트에서 실행한다. 아래 명령은 공통, process_access,
module_integrity 테스트를 모두 찾는다.

```powershell
py -3 -m unittest discover -s client/LocalGuard/external_access -t . -v
```

단위 테스트는 SHA-256, 캐시 무효화, 게임 PID 재시작 식별, JSONL 출력,
위험 권한 점수화, handle 수집 필터, 실행기 연결을 검증한다. 실제 게임 대상
handle 수집은 실환경에서 별도로 확인한다.

## 외부 프로세스 접근 분석 실행

게임을 실행한 뒤, 저장소 루트의 관리자 PowerShell에서 한 번만 관찰하려면
아래처럼 실행한다.

```powershell
py -3 -m client.LocalGuard.external_access.process_access.runner --game-exe PenguinHotel-Win64-Shipping.exe --session-id local_test_001 --player-id player_042 --once
```

반복 관찰은 `--once`를 빼고 실행한다. 위험 권한이 발견됐을 때만 기본 경로
`logs/external_access.jsonl`에 결과 한 줄이 기록된다. shared client는 `GZZ_TELEMETRY_URL`과
`GZZ_TELEMETRY_TOKEN` 환경 변수가 유효하면 같은 결과를 별도 outbox에 넣어 전송한다.
`queued`는 로컬 outbox 저장을 뜻하며 서버 저장 성공을 뜻하지 않는다. 중앙 수신 성공은
receiver가 준비된 뒤 `/api/detection` 종단 테스트로 확인해야 한다.

Launcher는 `external_access`와 `module_integrity`를 각각 독립된 상주 프로세스로
실행한다. 각 프로세스에 동일한 session/player/t0와 런처가 확인한 정확한 게임 PID를
전달하고 서로 다른 로컬 로그 및 outbox를 사용한다. 따라서 한 감시기가 종료돼도
다른 감시기를 막지 않으며, Launcher/Watchdog가 종료와 재시작 상태를 확인할 수 있다.

기존 7개 최상위 필드와 로컬 JSONL 기록은 유지한다. 결과를 JSONL에 기록한 다음
`send_detection()`을 호출하며, 모듈 종료 시 `flush_client()`와 `shutdown_client()`를
호출한다. 서버 전송은 차단·종료 결정을 하지 않는다.

## 게임 내부 모듈 무결성 실행

LocalGuard를 게임보다 먼저 실행한 뒤 64비트 Python에서 아래처럼 실행한다.

```powershell
py -3 -m client.LocalGuard.external_access.module_integrity.runner --game-exe PenguinHotel-Win64-Shipping.exe --session-id normal_001 --player-id player_042
```

첫 성공 스냅샷은 DLL 비교 기준선만 만들고 탐지 이벤트를 내지 않는다. 이후 새로
추가되거나 같은 경로에서 매핑 정보가 바뀐 DLL만 검사한다. DLL 파일의 SHA-256,
Authenticode 서명, 게시자를 공통 캐시로 조회하고, 정확한 이름+SHA-256 및 선택적인
경로·서명·게시자 조건이 모두 일치한 allowlist 항목만 제외한다. 결과 기본 경로는
`logs/module_integrity.jsonl`이다.

팀 Launcher로 두 담당 탐지기만 통합 실행하려면 아래처럼 실행한다. Launcher가 게임을
찾아 정확한 PID와 공통 시간축을 두 runner에 넘긴다.

```powershell
py -3 client/Launcher/main.py --only external_access,module_integrity `
  --session normal_001 --player player_042
```

센서/API 오류가 세 번 연속 발생하면 runner는 종료 코드 2로 끝난다. 프로세스만 살아
있고 실제 감시는 멈춘 상태를 정상으로 표시하지 않도록 Launcher/Watchdog가 이 종료를
감지하고 제한된 재시작 정책을 적용한다.

초기 점수는 새 DLL `+1`, 같은 경로의 매핑 정보 변경 `+1`, 미서명 `+1`, 유효하지
않은 서명 `+2`이다. 서명 조회 실패는 수집 한계일 수 있으므로 추가 점수를 주지 않는다.
이 값은 최종 밴 점수가 아니라 ReplayAnalyzer에서 조정할 원시 근거 점수다.

상세 구조와 한계는 [`module_integrity/README.md`](module_integrity/README.md)에,
발표용 평문은 [`module_integrity/STRUCTURE_PRESENTATION.txt`](module_integrity/STRUCTURE_PRESENTATION.txt)에
정리했다.

초기 점수 정책은 `PROCESS_VM_WRITE=2`, `PROCESS_VM_OPERATION=2`,
`PROCESS_CREATE_THREAD=3`이다. 미서명 또는 조회 불가 서명은 위험 handle과 결합할
때만 `+1`, 유효하지 않은 서명은 `+2`를 더한다. 실행 파일이 `TEMP`, `AppData`,
`Desktop`, `Downloads` 같은 사용자 쓰기 가능 위치에 있으면 약한 경로 근거로
`+1`을 더한다. 경로나 서명만으로는 탐지 결과를 만들지 않는다.

최신 Windows에서 kernel object 주소가 숨겨진 경우 후보 handle을 복제해
`GetProcessId`로 실제 대상이 게임인지 확인한다. 조회 전용 권한 복제를 먼저
시도하고, Windows가 이를 거부하는 handle만 원래 권한으로 잠깐 복제해 PID를
확인한 즉시 닫는다. 복제한 handle로 게임 메모리를 읽거나 쓰지는 않는다.

검토가 끝난 정상 프로세스는 `process_access/allowlist.json`에 실행 파일 이름과
SHA-256을 함께 등록한다. 이름만으로 예외 처리하거나 첫 실행 결과를 자동 등록하지
않는다. 게임 또는 Windows 업데이트로 해시가 바뀌면 다시 정상 여부를 확인한 뒤
목록을 갱신한다.

Windows 핵심 프로세스처럼 강한 예외가 필요한 항목은 이름과 SHA-256뿐 아니라
`executable_path`, `signature_status`, `publisher_contains`도 함께 지정한다. 네 조건을
모두 만족할 때만 정상 처리하므로, 같은 이름으로 위장하거나 서명이 깨진 파일은
예외 처리되지 않는다. Windows kernel `System`(PID 4)은 사용자 영역 실행 파일이
아니므로 handle 수집 단계에서 제외한다.

실게임 정상 환경, 직접 제작한 에임봇, CPU·메모리 측정 결과는
[`MEASUREMENTS.md`](MEASUREMENTS.md)에 정리한다.
