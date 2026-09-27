# LocalGuard module_integrity

게임 프로세스가 실행되는 동안 로드 DLL 목록의 변화를 읽기 전용으로 관찰한다.
직접 차단·종료·밴하지 않고 팀 공통 7필드 JSON 이벤트를 로컬에 기록한다.

## 구조

```text
ProcessLocator
  -> ToolhelpModuleSensor
  -> ModuleBaselineTracker
  -> ArtifactCache(ArtifactInspector)
  -> ModuleAllowlist
  -> ModuleIntegrityDetector
  -> append_detection_jsonl
```

- `module_sensor.py`: `CreateToolhelp32Snapshot`, `Module32FirstW`,
  `Module32NextW`로 DLL 이름·경로·base address·image size를 수집한다.
- `baseline.py`: 첫 성공 스냅샷을 기준선으로 만들고 이후 추가·제거·변경을 구분한다.
- `allowlist.py`: 정확한 DLL 이름+SHA-256을 필수로 비교하며 선택적으로 경로·서명·
  게시자 조건도 모두 검사한다.
- `detector.py`: 추가 또는 변경 DLL과 파일 신뢰 정보를 하나의 설명 가능한 이벤트로
  만든다.
- `runner.py`: 게임 탐색부터 JSONL 기록까지 순서대로 조립한다.

기준선은 목록 변화 비교 자료이지 자동 신뢰 목록이 아니다. 첫 스냅샷을 전부 새 DLL로
처리하면 정상 Windows·엔진 DLL이 대량 오탐되므로 기본 모드에서는 첫 스냅샷 자체를
이벤트로 만들지 않는다. 따라서 LocalGuard를 게임보다 먼저 실행해야 한다. 검토된
allowlist가 준비된 환경에서는 `--audit-initial-snapshot` 옵션으로 시작 목록도
검사할 수 있다. 이 옵션은 allowlist에 없는 초기 모듈을 모두 기록하므로 빈 목록
상태에서는 정상 DLL도 대량 기록된다.

수집 실패는 빈 DLL 목록으로 바꾸지 않는다. 마지막 성공 기준선을 유지해서 일시적인
권한 오류 뒤에 모든 DLL이 제거됐다가 다시 추가된 것처럼 보이는 오탐을 막는다. PID와
프로세스 생성 시각이 달라지면 게임 재실행으로 보고 이전 기준선을 폐기한다.

## 실행

관리자 PowerShell에서 저장소 루트로 이동한 뒤 실행한다.

```powershell
py -3 -m client.LocalGuard.external_access.module_integrity.runner `
  --game-exe PenguinHotel-Win64-Shipping.exe `
  --game-pid 12345 `
  --session-id normal_001 `
  --player-id player_042
```

검토된 `allowlist.json`에 항목이 있으면 초기 스냅샷 감사가 자동으로 켜진다. 빈
allowlist로 초기 감사를 시험하려면 `--audit-initial-snapshot`을 추가한다. 반대로
검토 목적으로 감사를 명시적으로 끄려면 `--skip-initial-audit`를 사용한다.

`--game-pid`에는 launcher가 확인한 정확한 게임 PID를 전달하는 것이 가장 안전하다.
생략한 경우 동명 프로세스가 둘 이상이면 임의의 첫 프로세스를 고르지 않고 오류로
보고한다. 고정 PID를 사용한 상태에서 게임이 재실행되면 launcher도 LocalGuard를 새
PID로 다시 실행해야 한다. 이름만 사용하는 모드는 동명 프로세스가 하나일 때 재실행을
따라가 새 기준선을 만든다.

한 번만 확인하려면 `--once`를 추가한다. 기본 간격은 3초, 출력은
`logs/module_integrity.jsonl`이다. `process_access`와 별도 프로세스로 실행할 때는
JSONL writer에 프로세스 간 잠금이 없으므로 서로 다른 출력 파일을 사용한다.

## 출력 예

```json
{
  "session_id": "esp_001",
  "player_id": "player_042",
  "module": "localguard",
  "timestamp_ms": 32500,
  "evidence": {
    "submodule": "module_integrity",
    "change_type": "added",
    "target_pid": 12345,
    "module_name": "unknown.dll",
    "module_path": "C:\\Temp\\unknown.dll",
    "base_address": "0x7FF800000000",
    "image_size": 245760,
    "allowlisted": false,
    "sha256": "...",
    "signature_status": "unsigned",
    "publisher": null
  },
  "reasons": [
    "Module appeared after the process baseline",
    "Module signature is unsigned"
  ],
  "raw_score": 2
}
```

## 점수와 allowlist

초기 raw score는 실측 후 ReplayAnalyzer에서 조정하기 위한 값이다.

- 실행 중 새 DLL: `+1`
- 같은 DLL 경로의 base address 또는 image size 변경: `+1`
- allowlist에 없는 초기 DLL(`--audit-initial-snapshot`): `+1`
- 미서명: `+1`
- 서명 신뢰 실패: `+2`
- 서명 조회 불가: 추가 점수 없음
- 정확한 allowlist 일치: 이벤트 억제
- DLL 제거만 관찰: 이벤트 없음

이름만 같다고 허용하지 않는다. `allowlist.json`에 최소 DLL 이름과 검토한 SHA-256을
넣어야 한다. 필요하면 `module_path`, `signature_status`, `publisher_contains` 조건을
추가한다. 첫 관찰 결과를 자동으로 allowlist에 넣지 않는다.

## 테스트

```powershell
py -3 -m unittest discover -s client/LocalGuard/external_access -t . -v
```

## 알려진 한계

- 기본 모드에서는 LocalGuard보다 먼저 주입된 DLL이 첫 동적 기준선에 포함될 수 있다.
  검토된 allowlist를 준비한 뒤 `--audit-initial-snapshot`으로 초기 목록도 감사한다.
- manual-map/reflective 방식처럼 정상 모듈 목록에 등록되지 않는 이미지는 Toolhelp
  스냅샷만으로 보이지 않을 수 있다.
- 폴링 사이에 로드됐다가 사라지는 짧은 DLL은 놓칠 수 있다.
- 같은 경로·image size·base address로 폴링 사이에 교체와 재로드가 모두 끝나면 목록
  차이가 없어 놓칠 수 있다. 이 경우 ETW image-load 이벤트나 주기적 내용 재검사가
  추가로 필요하다.
- 새 DLL 여러 개의 Authenticode를 처음 검사할 때는 현재 PowerShell 검사가 직렬로
  실행되어 다음 스캔이 늦어질 수 있다. 최종 통합에서는 WinVerifyTrust 직접 호출이나
  별도 검사 worker로 분리할 필요가 있다.
- 디스크 파일 해시는 현재 메모리 코드가 동일하다는 증거가 아니다. 메모리 내부 코드
  변조는 `memory_integrity` 담당 범위다.
- 32비트 Python에서 64비트 게임 모듈 열거가 실패할 수 있으므로 64비트 Python을
  사용해야 한다.
- `create_time` 조회가 불가능하고 같은 PID가 즉시 재사용되면 현재 공통 식별자만으로
  재실행을 구분하지 못할 수 있다.
