# LocalGuard module_integrity

게임 프로세스가 실행되는 동안 로드 DLL 목록의 변화를 읽기 전용으로 관찰한다.
직접 차단·종료·밴하지 않고 팀 공통 7필드 JSON 이벤트를 로컬에 먼저 기록한다.
`shared 0.2.0` 클라이언트 설정이 있으면 같은 이벤트를 중앙 전송 outbox에도 넣는다.

## 구조

```text
ProcessLocator
  -> ToolhelpModuleSensor
  -> ModuleBaselineTracker
  -> ArtifactCache(ArtifactInspector)
  -> ModuleAllowlist
  -> ModuleIntegrityDetector
  -> append_detection_jsonl
  -> shared 0.2.0 send_detection
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

Launcher는 이 모듈을 별도 `module_integrity` 프로세스로 실행한다. 공통 이벤트의
`module`도 `module_integrity`를 사용한다. 외부 핸들 채널 `external_access`와 중앙
최신 상태 키가 분리되며, `evidence.submodule="module_integrity"`도 유지한다.

## 실행

관리자 PowerShell에서 저장소 루트로 이동한 뒤 실행한다.

```powershell
py -3 -m client.LocalGuard.external_access.module_integrity.runner `
  --game-exe PenguinHotel-Win64-Shipping.exe `
  --game-pid 12345 `
  --game-root "C:\Program Files (x86)\Steam\steamapps\common\MECCHA CHAMELEON" `
  --session-id normal_001 `
  --player-id player_042 `
  --t0 1790912345.125
```

검토된 `allowlist.json`에 항목이 있으면 초기 스냅샷 감사가 자동으로 켜진다. 빈
allowlist로 초기 감사를 시험하려면 `--audit-initial-snapshot`을 추가한다. 반대로
검토 목적으로 감사를 명시적으로 끄려면 `--skip-initial-audit`를 사용한다.

`--game-pid`에는 launcher가 확인한 정확한 게임 PID를 전달하는 것이 가장 안전하다.
생략한 경우 동명 프로세스가 둘 이상이면 임의의 첫 프로세스를 고르지 않고 오류로
보고한다. 고정 PID를 사용한 상태에서 게임이 재실행되면 launcher도 LocalGuard를 새
PID로 다시 실행해야 한다. 이름만 사용하는 모드는 동명 프로세스가 하나일 때 재실행을
따라가 새 기준선을 만든다.

런처가 만든 `client/Launcher/logs/ue4ss_install.json`이 있으면 `--game-root`로
별도 확인한 설치 root와 manifest의 root가 일치하는 경우에만 DLL 항목을 읽는다.
각 DLL은 정확한 경로·이름·SHA-256이 현재 관측 파일과 모두 일치해야 예외 처리된다.
manifest 부재·손상·중복 key·경로 탈출·해시 불일치는 예외 없이 탐지 경로로 남는다.

휘파람 탐지기의 `ac_whistle_v10.dll`은 게임 폴더 밖의 안티치트 자체 관측
후크이므로 UE4SS 목록에 섞지 않는다. Launcher는 게임 관련 모듈을 시작하기 전에
`--self-hook`으로 명시된 파일을 `client/Launcher/logs/self_hook_manifest.json`에
별도로 기록한다. 폴더를 자동 검색하지 않으며, 오직 현재 검토된
`client/detectors/whistle-spoofing/native/whistle_hook/bin/Release/ac_whistle_v10.dll`
경로만 절대 경로와 SHA-256으로 기록한다. 이 목록도 현재 checkout root,
역할, 경로, 이름, 해시가 모두 맞아야 예외가 된다. 후크를 새로 빌드한 뒤 이미
Launcher가 실행 중이면 module_integrity를 재시작하기 전에 아래처럼 명시적으로
목록을 갱신한다.

```powershell
py -3 -m client.Launcher.self_hook_manifest --hook `
  "client/detectors/whistle-spoofing/native/whistle_hook/bin/Release/ac_whistle_v10.dll"
```

공격 실험용 `modules/whistle-spoofing/bin/whistle_v*.dll`은 승인 경로가 아니므로
이 목록에 들어가지 않는다.

게임 발견과 첫 기준선 생성만 한 번 확인하려면 `--once`를 추가한다. DLL 로드 전후의
변화 시험에는 `--once`를 사용하면 안 된다. 기본 간격은 3초, 출력은
`logs/module_integrity.jsonl`이다. `process_access`와 별도 프로세스로 실행할 때는
JSONL writer에 프로세스 간 잠금이 없으므로 서로 다른 출력 파일을 사용한다.

## 출력 예

```json
{
  "session_id": "esp_001",
  "player_id": "player_042",
  "module": "module_integrity",
  "timestamp_ms": 32500,
  "evidence": {
    "submodule": "module_integrity",
    "status": "SUSPICIOUS",
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

실행 진입점에서는 매 성공 스캔에 `raw_score=0`, `status=NORMAL`을 로컬 기록한다.
게임 프로세스가 없으면 `OFFLINE`, 프로세스 또는 모듈 열거가 실패하면 `ERROR`로
기록해 정상 표본과 관측 실패를 구분한다. 실제 추가·변경 DLL은 `SUSPICIOUS`다.
상태값은 최상위 필드를 늘리지 않고 `evidence.status`에 둔다.

중앙에는 양수 DLL 변화만 전송한다. 주기적인 0점 상태는 로컬 JSONL에만 남겨
한 번 수신된 양수 탐지가 다음 0점 상태로 즉시 덮어써지는 일을 막는다.

로컬 JSONL 기록이 성공한 뒤에만 `send_detection()`을 호출한다. `queued`는 shared
outbox 저장 성공이며 중앙 receiver의 수신 확인이 아니다. 종료할 때 `flush_client()`와
`shutdown_client()`를 호출하고, 서버 설정이 없거나 전송이 실패해도 로컬 관찰은 계속한다.

이름만 같다고 허용하지 않는다. `allowlist.json`에 최소 DLL 이름과 검토한 SHA-256을
넣어야 한다. 필요하면 `module_path`, `signature_status`, `publisher_contains` 조건을
추가한다. 첫 관찰 결과를 자동으로 allowlist에 넣지 않는다.

## 테스트

먼저 게임을 실행하지 않고 단위 테스트와 실제 Windows API 스모크 테스트를 실행한다.

```powershell
py -3 -c "import struct; print(struct.calcsize('P') * 8)"  # 결과가 64여야 함
py -3 -m unittest discover -s client/LocalGuard/external_access -t . -v
py -3 -m client.LocalGuard.external_access.module_integrity.smoke_test
```

스모크 테스트는 별도 Python 보조 프로세스를 만들고 그 프로세스에 아직 로드되지 않은
정상 Windows 시스템 DLL 하나를 로드한다. 그 전후 목록을 실제 Toolhelp API로 비교해
`added` 이벤트가 공통 JSON 형식으로 정확히 한 번 기록되는지 확인한다. 게임 프로세스나
게임 파일은 수정하지 않는다. 성공하면 `PASS`와 탐지 DLL, 점수, JSONL 저장 경로가
출력된다.

### 실제 게임 1: 정상 플레이 세션

게임 실행 후 정확한 PID를 확인하고 정상 세션부터 수집한다. 아래 `12345`는 조회된
실제 PID로 바꾼다.

```powershell
Get-CimInstance Win32_Process -Filter "Name='PenguinHotel-Win64-Shipping.exe'" |
  Select-Object ProcessId, ExecutablePath

py -3 -m client.LocalGuard.external_access.module_integrity.runner `
  --game-exe PenguinHotel-Win64-Shipping.exe `
  --game-pid 12345 `
  --session-id normal_module_001 `
  --player-id player_042 `
  --skip-initial-audit `
  --output logs\normal_module_001.jsonl
```

이 명령은 종료하지 말고 같은 runner를 계속 실행해야 한다. 첫 출력의
`baseline=True`가 기준선 생성이며, 그 뒤 같은 프로세스에서 발생한 DLL 변화가 탐지
대상이다. `--once`를 붙인 명령을 두 번 실행하면 두 번째 실행도 새 기준선을 만들기
때문에 전후 비교 테스트가 되지 않는다. 정상 세션은 5~10분 플레이하며 이벤트 수와
뒤늦게 로드된 정상 DLL을 기록한 후 `Ctrl+C`로 runner를 종료한다. 동적 DLL 변화가
없더라도 `status=NORMAL`, `raw_score=0` 표본이 JSONL에 남아야 한다. `OFFLINE`이나
`ERROR`를 정상 표본으로 계산하면 안 된다.

### 실제 게임 2: 승인된 DLL 양성 세션

정상 세션 runner를 종료한 뒤, 시험 DLL이 아직 로드되지 않은 같은 게임에서 새 세션으로
runner를 시작한다. 실제 PID는 정상 세션과 동일한지 다시 확인한다.

```powershell
py -3 -m client.LocalGuard.external_access.module_integrity.runner `
  --game-exe PenguinHotel-Win64-Shipping.exe `
  --game-pid 12345 `
  --session-id dll_module_001 `
  --player-id player_042 `
  --skip-initial-audit `
  --output logs\dll_module_001.jsonl
```

첫 `baseline=True`를 확인한 뒤 두 번째 관리자 PowerShell에서 사전에 코드·해시·진입점과
부작용을 확인한 무해한 x64 테스트 DLL을 승인된 loader나 게임의 공식/검토된 모드 로더로
로드한다. 출처와 동작을 확인하지 않은 저장소 내 DLL·인젝터는 실행하지 않는다. DLL은
기본 3초 폴링 주기의 두 배인 6초 이상 로드 상태를 유지한다. 첫 PowerShell에는
`added=1` 이상과 `emitted=1` 이상이 출력되어야 한다.

통합 UI의 테스트 버튼은 실제 DLL 로드를 보장하지 않으므로 양성 검증으로 사용하지
않는다. 저장소에 포함된 `smoke_test` 또는 팀이 사전에 검토한 테스트 DLL만 사용한다.
보안 제품이 파일을 격리한 경우 보안 기능을 끄거나 예외를 추가해 우회하지 않는다.

```powershell
Get-Content .\logs\dll_module_001.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Select-Object timestamp_ms, raw_score,
    @{Name="change_type"; Expression={$_.evidence.change_type}},
    @{Name="module_name"; Expression={$_.evidence.module_name}},
    @{Name="sha256"; Expression={$_.evidence.sha256}},
    @{Name="signature"; Expression={$_.evidence.signature_status}}
```

합격 조건은 대상 DLL의 `submodule=module_integrity`, `change_type=added`, 정확한 DLL
이름·경로·SHA-256이 공통 JSON 이벤트에 기록되는 것이다. 같은 DLL을 변화 없이 다음
주기에도 반복 기록하면 실패다. 시험이 끝나면 runner를 `Ctrl+C`로 종료하고 게임을
재시작해 깨끗한 상태로 되돌린다.

정상 플레이 중 뒤늦게 로드되는 정상 DLL도 있을 수 있으므로 이벤트가 나왔다는 사실만으로
치트를 확정하지 않는다. 경로·SHA-256·서명·게시자를 검토한 뒤 정상으로 확인된 정확한
파일만 allowlist 후보로 삼는다. 승인된 테스트 DLL이나 UE4SS 모드로 의심 세션을 시험할
때는 LocalGuard로 기준선을 먼저 만든 뒤 DLL을 로드하고, 결과의
`evidence.submodule=module_integrity`, `change_type=added`, DLL 해시·서명 정보가
기록되는지 확인한다. 동적 추가만 분리해서 시험할 때 allowlist에 항목이 있다면
`--skip-initial-audit`를 명시한다. 시험 DLL은 최소 두 번의 폴링 간격 동안 로드 상태를
유지해야 한다.

외부형 ESP는 게임 프로세스에 DLL을 로드하지 않을 수 있으므로 이 테스트의 대상이 아니다.
그 경우 외부 프로세스가 게임에 연 핸들과 접근 권한은 `process_access`에서 검증한다.

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
