# 중앙 서버 A 담당 탐지기 전송 규격 조사

> 최신 결과는 [9. 후속 조사·분석 함수 구현 및 A·B 합의](#9-후속-조사분석-함수-구현-및-ab-합의-2026-10-03)를 우선 참조함.
> 아래 1~8절은 최초 조사 당시 기록으로 보존함. runtime 점수 누락·ESP 제외·양수만 전송이라는 설명을 현재 구현 및 새 합의와 혼동하지 않도록 구분함.

조사일: 2026-10-02. 기준: 팀 `main`의 `f098b5d`에서 분기한 `feat/scoring-a-detector-policies`.

LocalGuard 계열, Whistle Spoofing, Hide Anywhere를 조사함. 사용자 요청에 따라 ESP는 조사 및 정책 구현 대상에서 제외함. 하트비트는 탐지 점수와 분리된 경로이므로 이번 점수 조사에서 제외함.

소스 확인과 기존 리플레이 검사, 입력값을 공급한 로컬 재현을 수행함. 게임 실행, 실제 네트워크 전송, 중앙 서버 수신 성공은 이번에 검증하지 않음. 기존 Scoring 공통 코드와 탐지기 코드는 변경하지 않음.

## 1. 실제 전송 이름과 점수

폴더명·런처 등록명과 이벤트의 `module` 값이 다를 수 있어 실제 생성 코드를 기준으로 조사함. 전송 방식은 로컬 기록과 중앙 전송을 구분하여 확인함.

| 실제 `module` | 현재 점수 구성 | 중앙 전송 조건 | 실행 주기 | 근거 |
|---|---|---|---|---|
| `external_access` | 위험 권한 2+2+3, 서명 최대 +2, 경로 +1. 생성되는 양수 점수는 2~10. VM_READ 단독은 이벤트 없음 | 허용목록에 없는 위험 접근이 관찰될 때, 원인 프로세스별 양수 이벤트 | 기본 3초 | `client/LocalGuard/external_access/process_access/access_rights.py:20`, `detector.py:28`, `detector.py:35`, `runner.py:213` |
| `localguard_yara` | 일치 규칙 점수의 최댓값. 기본 저장소 규칙은 모두 3점. 사용자 지정 규칙은 1~10점 허용 | 로컬은 검사 성공 시 0점도 기록. 중앙은 양수만 | 기본 YARA 검사 시작 간격 60초. 검사 소요에 따라 달라짐 | `client/LocalGuard/input_signature/yara_scanner.py:190`, `yara_scanner.py:244`, `yara_scanner.py:273`, `yara_scanner.py:503`, `replay_events.py:199` |
| `localguard_executable_hash` | 알려진 실행 파일 해시 일치가 하나 이상이면 1점, 아니면 0점. 일치 파일 수를 합산하지 않음 | 로컬은 완전 검사 또는 일치 발견 시 기록. 중앙은 양수만 | 기본 5초, 별도 모니터 스레드 | `client/LocalGuard/input_signature/hash_monitor.py:64`, `hash_monitor.py:71`, `hash_monitor.py:82`, `yara_scanner.py:497`, `replay_events.py:199` |
| `filesystem` | 파일·UE4SS·외부 Lua 모드 등의 규칙 점수 누적, 100점 상한 | 로컬은 0점/상태도 기록. 중앙은 양수만 | 런처는 검사 프로세스를 30초 주기로 실행. 독립 watch 기본 간격은 15초 | `client/LocalGuard/memory_integrity/detectors/filesystem.py:165`, `core/result.py:96`, `run_session.py:309`, `client/Launcher/modules.py:169` |
| `injection` | ProcessEvent 후킹 70, ExecFunction 후킹 70, .text 변조 60, 비신뢰 모듈 40. 누적 상한 100 | 위와 같음 | 위와 같음 | `client/LocalGuard/memory_integrity/detectors/injection.py:67`, `injection.py:149` |
| `value_tamper` | 변조된 설정 필드 종류마다 55점, 누적 상한 100 | 위와 같음 | 위와 같음 | `client/LocalGuard/memory_integrity/detectors/value_tamper.py:314` |
| `overlay_hook` | 비신뢰 인라인 후킹 60점, 오버레이 관련 후킹 +60점. 누적 상한 100 | 위와 같음 | 위와 같음 | `client/LocalGuard/memory_integrity/detectors/overlay_hook.py:289`, `overlay_hook.py:294` |
| `godmode_runtime` | **현재 소스는 근거를 추가해도 점수를 올리지 않으므로 0점** | 양수 조건을 통과하지 못하여 중앙 전송 없음 | 메모리 탐지기와 같이 실행 | `client/LocalGuard/memory_integrity/detectors/godmode_runtime.py:118`, `run_session.py:309` |
| `noclip_runtime` | **현재 소스는 근거를 추가해도 0점** | 위와 같음 | 위와 같음 | `client/LocalGuard/memory_integrity/detectors/noclip_runtime.py:107`, `run_session.py:309` |
| `aimbot_runtime` | **현재 소스는 근거를 추가해도 0점** | 위와 같음 | 메모리 탐지기와 같이 실행. 검사 한 번은 3초 동안 목표 60Hz로 회전값 수집 | `client/LocalGuard/memory_integrity/detectors/aimbot_runtime.py:14`, `aimbot_runtime.py:17`, `aimbot_runtime.py:220`, `run_session.py:309` |
| `whistle` | 관련 ExecFunction 후킹 60 / 기타 40, 캐릭터 vtable 후킹 60, 소리 교체 35. 누적 상한 100 | 메모리 탐지기와 같은 실행기를 사용하여 양수만 중앙 전송 | 런처 30초 주기, 독립 watch 기본 15초 | `client/detectors/whistle-spoofing/main.py:72`, `whistle.py:128`, `whistle.py:150`, `whistle.py:164`, `client/Launcher/modules.py:180` |
| `whistle_rpc` | 역할·사망·대상 위반 각각 60, 쿨다운·입력 부재 각각 40, 미분류 코드 30. 같은 코드의 발생 횟수는 점수에 곱하지 않음. 누적 상한 100 | 위와 같음. 런처/반복 경로는 새 로그 구간을 검사하여 양수만 보냄 | 위와 같음 | `client/detectors/whistle-spoofing/whistle_rpc.py:86`, `whistle_rpc.py:178`, `whistle_rpc.py:297`, `whistle_rpc.py:393` |
| `hide_anywhere` | 6개 고정값 조합 일치 시 3점. 미일치 시 `injected_module` + `viewport_hook`로 0~2점 | 설정된 ServerBridge가 있으면 0점 포함 매 평가 결과의 전송을 시도함. **현재 전송 호환 오류 존재** | 기본 1초. `--modules-only` 또는 메모리 관측기 초기화 실패 시 공통 이벤트 생성 경로가 실행되지 않음 | `client/detectors/Hide_anywhere_detector/mecha_detector_v9.py:66`, `mecha_detector_v9.py:85`, `mecha_logger.py:652`, `mecha_logger.py:774`, `mecha_logger.py:788` |

LocalGuard 등록표의 실제 이름은 `client/LocalGuard/memory_integrity/run_session.py:69`에서 확인함. 이벤트는 `core/result.py:367`에서 `res.detector`를 `module`로 사용함. `memory_integrity`, `input_signature`, `whistle_spoofing`이라는 런처 이름으로 중앙 정책을 등록하면 실제 이벤트 이름과 맞지 않음.

## 2. 중앙 점수 해석에 적용할 사항

### 2.1 양수만 전송하는 모듈

양수 전송을 확인한 모듈에서 마지막 이벤트는 마지막으로 관찰한 탐지 근거임. 이후 핵이 꺼졌거나 검사가 실패해도 중앙에 0점으로 갱신되지 않을 수 있음. 새 이벤트가 없다는 사실만으로 정상 상태, 계속 핵을 사용하는 상태 중 어느 쪽도 확정하지 않도록 해야 함. 점수의 유효 시간 및 유지·만료 기준은 B와 협의가 필요함.

메모리·휘파람 계열은 `run_session.py:309`의 양수 조건을 사용함. YARA·해시 계열은 `input_signature/replay_events.py:199`의 양수 조건을 사용함. 외부 접근은 `external_access/process_access/detector.py:37`에서 위험 권한이 없으면 이벤트 자체를 생성하지 않음.

### 2.2 ERROR/OFFLINE과 정상 0점

메모리·휘파람 로컬 결과의 `status`, `severity`, `window_id`, `sample_id`, 스캔 시간 등의 확장 필드는 `core/result.py:305`의 `to_shared_event()`가 `evidence` 안으로 이동시킴. Shared 최상위 7필드를 유지하면서 상태 정보를 보존함.

일반적인 0점 ERROR/OFFLINE은 양수 조건 때문에 중앙으로 전송되지 않음. 이미 양수 점수가 생긴 후 오류가 발생한 경우처럼 양수 ERROR가 전달되면 `evidence.status`를 우선 확인해야 함. 현재 B의 `policy.py:110`은 ERROR/OFFLINE을 `MEASUREMENT_UNAVAILABLE`로 구분함.

YARA는 읽기 실패·타임아웃을 정상 0점 이벤트로 생성하지 않음. 해시 검사는 일부 프로세스를 확인하지 못해도 일치가 확인되면 1점을 보낼 수 있으므로 `coverage_complete=false`를 함께 확인해야 함.

### 2.3 대상 식별과 중복 후보

| 모듈 | 실제로 있는 식별 근거 | 정책 작성 시 주의사항 | 중복 후보 태그 제안 — 아직 미확정 |
|---|---|---|---|
| `external_access` | `source_pid`, 선택적으로 `sha256`, `source_path` | 하나의 세션·플레이어·모듈 안에서도 여러 원인 프로세스가 있음. PID 재사용을 구분할 생성 시각이 이벤트에 없음. `(source_pid, sha256)`도 완전한 프로세스 수명 식별자는 아님 | `process_access`, 파일 해시가 있을 때 해시 계열과 비교 |
| `localguard_yara` | `pid`, `scope`, `matched_rules`, 선택적 `module_name` | 대상은 게임 프로세스일 수도 외부 Python일 수도 있음. PID와 scope를 함께 검토. 규칙명만으로 동일 사건 확정 불가 | 매칭 규칙·검사 범위별 후보 태그 |
| `localguard_executable_hash` | `matched_executables` 목록 안의 `pid`, `sha256`, `catalogue_ids` | 한 이벤트가 여러 실행 파일을 포함할 수 있어 임의로 첫 PID만 대표로 정하지 않음 | `known_executable_presence` |
| `filesystem` | `file`, `file_2` 등 여러 파일, `meta.game_dir`, `meta.ue4ss_manifest` | 파일 존재는 활성화 증거와 구분. 여러 파일을 하나의 사건으로 단정하지 않음. 최신 코드는 런처 설치 UE4SS의 manifest/해시 기반 제외를 포함함 | `artifact_presence` |
| `injection`, `overlay_hook`, `whistle` | 주소·모듈명·이유 코드, `meta.target_pid` | `target_pid`는 관찰 대상 게임 PID이며 원인 프로세스 PID가 아님. 같은 게임 PID만으로 중복 확정 불가 | 해당 이유 코드에 따라 `exec_function_hook`, `process_event_hook`, `inline_hook` |
| `value_tamper`, `hide_anywhere` | 설정 필드/값, Hide Anywhere v9의 세 가지 플래그 | Hide Anywhere의 설정 변조를 두 채널이 볼 수 있음. v9 공통 이벤트에는 Pawn 주소나 프로세스 수명 식별자가 없음 | `hide_value_pattern`, 설정 변조 관련 후보 |
| `godmode_runtime`, `noclip_runtime`, `aimbot_runtime` | 메타데이터의 Pawn/Controller 주소, 이유 코드 | 점수 미연결부터 확인 필요. 메모리 주소는 다른 라운드·프로세스 수명에서 재사용 가능 | 대응하는 `godmode`, `noclip`, `aimbot` 채널과의 중복 후보 |
| `whistle_rpc` | 이유 코드, `meta.log`, `meta.mode`, window 통계 | 후킹 상태를 보는 `whistle`과 RPC 위반을 보는 채널은 관측 의미가 다름. 원시 RPC의 사건 ID가 공통 이벤트에 없음 | `whistle_rpc_violation` |

위 태그는 B에게 검토를 요청할 후보임. 자동 감점·합산·중복 제거 규칙으로 확정하지 않음. 여러 독립 대상을 단일 `entity_key`로 어떻게 표현할지는 공통 인터페이스 및 저장 정책과 함께 협의해야 함.

## 3. 이번에 발견하고 재현한 문제

### 3.1 Hide Anywhere의 event_id가 Shared 규격과 맞지 않음

`server_bridge.py:20`은 `32자리 UUID hex:순번`을 전달함. `shared/schema.py:24`는 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 형식의 소문자 canonical UUID만 허용함. 실제 `validate_event_id()`에 연결하여 `ServerBridge.send()`를 실행하니 `server_enqueue_error / ValidationError`를 확인함.

기본 logger import 경로도 `mecha_logger.py:664`의 `detection_logger.logger`이므로 현재 저장소의 `shared.logger`와 맞추거나 실행 인자로 명시해야 함. `--server-config`를 지정해야 서버 전송기가 생성됨(`mecha_logger.py:724`). 런처의 현재 `modules.py`에는 Hide Anywhere 실행 항목이 없음.

이벤트 본문이 7필드 검사를 통과하는 것과 실제 outbox/서버에 도달하는 것은 별개임. 담당자에게 event_id 생성과 실행·설정 연결을 확인 요청해야 함.

### 3.2 세 가지 LocalGuard runtime 탐지기의 점수 연결 누락

실제 메모리를 읽지 않고 메모리 관측값 및 규칙 반환값을 공급하여 `scan()`을 실행함. Noclip은 충돌 비트가 꺼진 값, Godmode는 무적 상태값, Aimbot은 규칙 근거가 반환되는 상황을 사용함.

| 모듈 | 생성된 이유 코드 | 근거 개수 | `raw_score` | 변환 후 상태 | 양수 전송 조건 |
|---|---|---:|---:|---|---|
| `noclip_runtime` | `collision_bit_cleared` | 1 | 0 | `NORMAL` | 통과 못함 |
| `godmode_runtime` | `invincible_enabled`, `godmode_value_pattern` | 2 | 0 | `NORMAL` | 통과 못함 |
| `aimbot_runtime` | `control_rotation_pattern` | 1 | 0 | `NORMAL` | 통과 못함 |

각 구현이 reasons/evidence만 추가하고 `DetectorResult.add()`나 점수 대입을 호출하지 않기 때문임. 현재 상태를 정상이라고 해석하거나 서버에서 임의 점수를 부여하면 탐지기 의도와 달라질 수 있음. LocalGuard 담당자에게 점수 부여 계획과 관측 전용 여부를 확인해야 함. 이 세 모듈은 B 담당의 `godmode`, `noclip`, `aimbot`과 이름 및 경로가 다름.

### 3.3 Hide Anywhere의 세 번 확인 로직과 실제 점수 생성 경로가 다름

`mecha_detector_v9.py:37`에 3회 연속 확인하는 `Rule` 클래스는 존재함. 그러나 `mecha_logger.py:778`의 이벤트 생성 경로는 `make_common_event()`를 직접 호출하며 `Rule`을 사용하지 않음. 현재는 고정값 조합이 한 번 일치해도 바로 3점이 생성됨. 정책이나 문서에서 현재 동작을 3회 연속 확정으로 설명하면 안 됨.

### 3.4 Hide Anywhere 0점의 측정 유효성을 공통 이벤트에서 구분하기 어려움

`make_common_event()`는 값이 부족한 경우도 패턴 미일치로 처리함(`mecha_detector_v9.py:26`). 현재 공통 evidence는 세 가지 플래그만 있으므로 관측 실패·정상 미일치를 구분할 수 없음. 일부 필드의 읽기가 실패하면 `field()`가 이전 값을 유지할 수도 있음(`mecha_logger.py:303`). 따라서 모든 플래그가 0이라고 확정 정상으로 처리하거나 신선한 완전 측정이라고 가정하지 않도록 해야 함. 검사 유효성·신선도는 담당자에게 확인 필요함.

### 3.5 YARA 상한은 사용 규칙에 따라 달라짐

B의 `policy.py:68`은 현재 기본 규칙 기준으로 상한 3을 기록함. 기본 `repository_cheats.yar`의 규칙 점수는 모두 3이지만 scanner는 `--rules`를 추가할 수 있고 1~10점을 허용함(`yara_scanner.py:190`). 새 규칙으로 4점 이상이 생성되면 현재 B 코드는 `OUT_OF_AUDITED_RANGE`로 분류함. 버전·규칙 목록을 함께 공유하고 상한 변경이 필요한 경우 B와 협의해야 함.

## 4. 실제 리플레이 데이터 확인

`ReplayAnalyzer/replay-data`의 `events.jsonl`을 검사하되 `raw/`의 원시 로그는 제외함. ESP 이벤트 자체는 대상에서 제외함. ESP 테스트 폴더 등에 함께 기록된 LocalGuard 이벤트는 해당 LocalGuard 모듈의 기존 샘플로 집계함. 테스트 폴더 이름이 NORMAL/CHEAT여도 개별 모듈의 검사 성공을 보장하지 않으므로 이벤트 상태를 따로 확인함.

| 모듈 | 기존 기록 수 | 양수 | 0점 관측 | ERROR/OFFLINE 0점 | 원본 Shared 검증 |
|---|---:|---:|---:|---:|---|
| `filesystem` | 4 | 4 | 0 | 0 | 확장 필드 때문에 원본 거절, 변환 후 4건 통과 |
| `injection` | 48 | 44 | 4 | 0 | 원본 거절, 변환 후 48건 통과 |
| `value_tamper` | 48 | 42 | 6 | 0 | 원본 거절, 변환 후 48건 통과 |
| `whistle` | 40 | 1 | 39 | 0 | 원본 거절, 변환 후 40건 통과 |
| `whistle_rpc` | 40 | 0 | 0 | 40 | 원본 거절, 변환 후 40건 통과 |
| `hide_anywhere` | 147 | 89 | 58 | 0 | 본문 147건 통과. 측정 유효성·전송 성공은 별도 확인 필요 |
| `external_access`, YARA, 실행 파일 해시, `overlay_hook`, runtime 3종 | 0 | — | — | — | 이 리플레이 폴더에서 실전 샘플을 찾지 못함 |

합계 327건 중 확장 필드가 있는 180건을 실제 `to_shared_event()`로 변환하니 전부 7필드 검증을 통과함. **변환 함수를 사용하는 현재 코드의 형식 검증 결과이며, 기존 파일을 수정하거나 실제 서버에 재전송한 결과는 아님.**

`whistle_rpc` 40건이 모두 ERROR이므로 정상 동작/위반 점수 실전 샘플을 확보했다고 말할 수 없음. 후크 활성화 및 관측 성공 상태에서 새 로그를 확보해야 함.

### 실전 예시 위치

| 모듈 | 0점/정상 관측 예시 | 탐지 관측 예시 | 비고 |
|---|---|---|---|
| `filesystem` | 없음 | `ReplayAnalyzer/replay-data/whistle-spoofing/hack_001/events.jsonl:1` | 예전 UE4SS 자기 탐지 영향 가능. 최신 예외 처리 검증용으로 그대로 사용하지 않음 |
| `injection` | `ReplayAnalyzer/replay-data/normal/clean_002/events.jsonl:2` | `ReplayAnalyzer/replay-data/whistle-spoofing/hack_001/events.jsonl:2` | 로컬 확장 형식은 Shared용 변환 필요 |
| `value_tamper` | `ReplayAnalyzer/replay-data/normal/clean_002/events.jsonl:4` | `ReplayAnalyzer/replay-data/hide-anywhere/hide_hack_001/events.jsonl:2` | 로컬 확장 형식은 Shared용 변환 필요 |
| `whistle` | `ReplayAnalyzer/replay-data/normal/clean_002/events.jsonl:3` | `ReplayAnalyzer/replay-data/whistle-spoofing/hack_001/events.jsonl:3` | 탐지 예시 raw_score=100 |
| `whistle_rpc` | 성공한 0점 샘플 없음 | 위반 양수 샘플 없음 | `ReplayAnalyzer/replay-data/normal/wh_clean_004/events.jsonl:2`는 ERROR 예시이며 정상 예시가 아님 |
| `hide_anywhere` v9 | `ReplayAnalyzer/replay-data/hide-anywhere/hide_anywhere_003/events.jsonl:1` | 같은 파일 `:22` | 현재 세 플래그 구조. 0점/3점 예시 확보 |

Hide Anywhere `normal_001`, `hide_anywhere_002` 등의 예전 데이터는 실제 설정값·`matched_fields`·`consecutive_matches`를 기록하는 다른 형식임. 예를 들어 `hide_anywhere_002/events.jsonl:14`는 조합 일치 1회에 1점을 기록하지만 현재 v9 생성 함수는 조합 일치에 3점을 기록함. 필드와 점수 의미가 다른 버전을 섞어 임계치를 보정하지 않도록 구분함.

## 5. 확인된 JSON 예시

### 5.1 외부 접근: 입력값을 공급하여 현재 생성 함수로 재현한 예시

아래는 실전 캡처가 아닌 합성 입력 기반 예시임. VM_READ 단독 입력은 `None`을 반환하여 정상 0점 JSON이 생성되지 않음. 최대 점수 조합은 다음과 같이 생성되고 Shared 검사에 통과함.

```json
{
  "session_id": "audit_synthetic",
  "player_id": "audit_player",
  "module": "external_access",
  "timestamp_ms": 1000,
  "evidence": {
    "submodule": "external_process",
    "source_pid": 1234,
    "source_process": "example.exe",
    "source_path": "C:\\Users\\audit\\Desktop\\example.exe",
    "access_mask": "0x0000002A",
    "access_rights": ["PROCESS_VM_WRITE", "PROCESS_VM_OPERATION", "PROCESS_CREATE_THREAD"],
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "signature_status": "invalid",
    "publisher": null,
    "path_risk": "user_writable_location"
  },
  "reasons": [
    "External process opened PROCESS_VM_WRITE handle",
    "External process opened PROCESS_VM_OPERATION handle",
    "External process opened PROCESS_CREATE_THREAD handle",
    "Process executable signature is invalid",
    "Process executable is located in a user-writable directory"
  ],
  "raw_score": 10
}
```

### 5.2 Hide Anywhere: v9 형식의 기존 실전 캡처

`hide_anywhere_003/events.jsonl:1`과 `:22`에서 확인한 이벤트임. 0점 예시는 핵 테스트 시작 시점의 관측이며 전체 정상 플레이를 증명하지 않음.

```json
{"session_id":"hide_anywhere_003","player_id":"player_042","module":"hide_anywhere","timestamp_ms":40,"evidence":{"hide_value_pattern":0,"injected_module":0,"viewport_hook":0},"reasons":[],"raw_score":0}
```

```json
{"session_id":"hide_anywhere_003","player_id":"player_042","module":"hide_anywhere","timestamp_ms":21462,"evidence":{"hide_value_pattern":1,"injected_module":1,"viewport_hook":1},"reasons":["Hide Anywhere Value Pattern Matched","Injected Module Loaded","Viewport VTable Outside Main Image"],"raw_score":3}
```

다른 모듈의 전체 기존 이벤트는 다음 진단 스크립트의 `--examples`로 확인 가능함. 해당 출력은 소스 파일 경로·줄 번호·실전 캡처 여부·변환 적용 여부를 함께 출력함.

## 6. 이번에 추가한 재현 도구

`server/scoring/tools/audit_a_contracts.py`를 추가함. 저장소의 리플레이를 읽고 Shared 검사 결과를 출력하며 다음을 입력값/Mock으로 재현함. 파일 수정, 중앙 전송, 게임 프로세스 접근을 실행하지 않음.

1. 외부 접근 VM_READ 단독 입력에서 이벤트 미생성, 최대 점수 조합에서 10점 생성.
2. Hide Anywhere의 정상/패턴 조합에서 0점/3점 JSON 생성 및 본문 검증.
3. 실제 ServerBridge의 event_id를 Shared 검사에 연결하여 `ValidationError` 재현.
4. 세 runtime 탐지기의 근거 발견 후 0점/NORMAL 상태와 중앙 전송 조건 탈락 재현.
5. YARA/해시가 사용하는 `ReplaySession.emit()`에 0점·3점을 공급하면 로컬 기록 2건, 중앙 sink 전달 1건임을 확인.

실행 방법:

```powershell
python -B server/scoring/tools/audit_a_contracts.py
python -B server/scoring/tools/audit_a_contracts.py --examples
```

이 진단의 예상 오류 재현은 현재 코드의 문제를 확인하는 것이며, 해당 모듈이 운영 환경에서 정상 동작한다는 통과 판정이 아님.

진단 실행의 assertion을 모두 확인했고 기존 `test_policy`·`test_policy_contract` 22개 테스트도 통과함. 첫 제한 환경 실행은 임시 SQLite 폴더 접근 권한 때문에 실패하여 같은 테스트를 제한 밖에서 다시 실행한 결과임. 전체 Receiver/배포/실전 통합 테스트를 수행한 것은 아님.

```powershell
python -B -m unittest server.scoring.tests.test_policy server.scoring.tests.test_policy_contract
```

## 7. B 및 탐지기 담당자에게 공유할 사항

| 우선순위 | 확인·협의 사항 | 관련 담당 |
|---|---|---|
| 1 | Hide Anywhere의 canonical UUID, `shared.logger` 경로 및 실행 설정 연결 | Hide Anywhere 담당 / A 통합 |
| 1 | runtime 3종에 점수가 없는 이유 및 부여 계획. 의도한 관측 전용인지 확인 | LocalGuard runtime 담당 |
| 1 | `whistle_rpc` 후크 관측 성공 및 양수/성공 0점 실전 샘플 확보 | Whistle 담당 |
| 2 | 정확한 13개 module 중 활성 전송 가능한 항목을 정책에 등록. runtime은 미완료 상태를 명시 | A / B |
| 2 | 양수만 전송하는 모듈의 점수 유지·만료 기준 및 다중 원인 프로세스 저장 방식 | A / B |
| 2 | `overlap_tags` 이름, 코드/대상/시간의 조합으로 중복 후보를 비교하는 방법 | A / B |
| 2 | Hide Anywhere의 측정 유효성·실제 판정 경로·구버전 데이터 취급 | Hide Anywhere 담당 / A / B |
| 3 | 기본 YARA 상한 3과 추가 규칙 1~10점의 프로필 호환 | InputSignature 담당 / B |
| 3 | 부족한 정상·탐지 실전 샘플을 새 코드 버전에서 수집 | 각 탐지기 담당 / ReplayAnalyzer |

최종 위험도 가중치·임계값과 공통 파일 변경은 이번 조사에서 확정하지 않음. A 정책 파일과 테스트는 위 조사 결과를 기준으로 다음 단계에서 작성하며, 공통 등록 및 종합 점수는 B와 연결함.

## 8. 체크리스트

- [x] 최신 팀 main에서 A 작업 브랜치 생성 및 개인 fork에 push함.
- [x] ESP를 제외한 13개 실제 module 이름·점수 생성·중앙 전송 조건을 확인함.
- [x] 로컬 0점 기록과 중앙 양수 전송을 구분함.
- [x] 기존 리플레이 327건 검사와 180건 확장 형식 변환을 확인함.
- [x] 실전 예시와 합성 입력 재현을 구분하여 기록함.
- [x] Hide Anywhere event_id 오류와 runtime 3종 점수 누락을 로컬 재현함.
- [ ] 부족한 실전 정상·탐지 샘플을 수집해야 함.
- [ ] 발견한 탐지기 연결 문제를 담당자에게 공유하고 수정 방향을 확인해야 함.
- [ ] A 정책 파일 및 테스트를 구현해야 함.
- [ ] B의 Registry 등록과 Receiver → Scoring 실제 연결을 검증해야 함.
- [ ] 실제 중앙 서버 전송·재전송·중복 반영 방지 테스트를 수행해야 함.
- [ ] ESP는 코드가 올라온 뒤 별도 조사해야 함.

## 9. 후속 조사·분석 함수 구현 및 A·B 합의 (2026-10-03)

### 9.1 원래 업무 범위와 현재 산출물

인수인계 문서에서는 최종 점수 정책을 정하기 위해 실제 탐지 이벤트의 이름,
점수·전송 특성·대상 식별자·중복 가능성을 먼저 조사하도록 요청함.
조사만으로 끝나는 것이 아니라 공통 계약에 맞춘 읽기 전용
`evaluate(event, baseline) -> PolicyAnnotations` 함수와 단위 테스트도 A가 작성하도록 정함.

이에 LocalGuard·휘파람·Hide Anywhere·ESP 분석 함수와 테스트를 작성함.
이 함수는 원본 Event·raw_score·기존 SignalPreview를 유지하고 관측 범위와
해석 한계만 반환함. 최종 위험도·가중치·임계값·만료 시간·자동 감점은 구현하거나 확정하지 않음.
`overlap_tags` 이름·적용 조건이 미합의이므로 반환값은 비워 두고,
중복 후보는 이 문서와 개별 분석 문서에 남김.

| 범위 | 담당 | 현재 진행 상태 |
|---|---|---|
| 실제 전송 규격 조사·A 분석 함수·신규 테스트 | A | 별도 브랜치에 구현·push함 |
| 공통 Registry 등록·프로필·저장 구조·최종 통합 | 송희(B) | A 함수를 자동 등록하지 않음. 등록과 후속 통합이 필요함 |
| Receiver process() 연동 확인·공동 통합 테스트 | A / B | 이번 분석 테스트만으로 완료 처리하지 않음 |
| 탐지기 원본 전송 필터·측정 유효성 수정 | 각 탐지기 담당 | 요청 및 재검증이 필요함. A 분석 함수가 원본 문제를 고치지 않음 |

분석 함수 작성 당시 참조한 코드는 팀 main `bd66c6524b6dc8d50ded0c052191a70c8b4acf7c`,
PR #78 `f6bf7d1e1fb40774fff8c6fe64bfb23fef329f50`,
PR #79 `14b7c8ce0a70bed88e9e3daa89637ba797cc4dd4`임.
PR 코드를 검토한 사실과 팀 main에 병합·배포된 사실은 구분함.
작업 브랜치는 `feat/scoring-a-detector-policies`이며 A 분석 구현의 마지막 커밋은
`4c917b9`임. 이 절을 추가하는 문서 갱신 커밋은 별도로 남김.

### 9.2 이전 기록에서 달라진 사실

| 이전 기록 | 후속 확인 결과 | 남은 주의사항 |
|---|---|---|
| runtime 3종은 근거가 있어도 0점 | #74 이후 소스에 점수 연결이 있음. Godmode Runtime은 2+3 최대 5, Noclip Runtime은 1, Aimbot Runtime은 1점 | 공통 프로필의 일괄 상한 100과 실제 상한이 다르므로 B와 갱신 필요함 |
| ESP는 조사에서 제외함 | PR #79의 실제 이벤트 변환기·로컬 저장 파이프라인을 조사하고 `esp.py` 분석 함수를 작성함 | 현재 공통 ESP 프로필은 pending이며 최종 위험도·정규화 기준은 미확정임 |
| RPC Replay 40건은 모두 ERROR이며 성공 표본을 못 찾음 | 해당 Replay 40건이 ERROR인 것은 그대로임. 별도 measurements 폴더에는 정상 0점·위반 40점 기록이 존재함 | 옛 측정 형식이며 실제 중앙 전송 성공의 증거는 아님. 담당자가 최신 사설방 표본을 추가할 예정이라고 답변함 |
| 양수만 전송하므로 이전 점수 갱신 여부가 불명확함 | 상태형 결과는 정상 0점도 보내는 방향을 B와 합의함 | 합의와 탐지기 코드 반영·실제 수신 검증 완료는 다른 상태임 |

Runtime 근거는 `godmode_runtime.py:24`, `:148`, `noclip_runtime.py:16`, `:118`,
`aimbot_runtime.py:23`, `:234`에서 확인함.
Runtime의 약한 양수는 내부 20점 임계치 아래라 `status=NORMAL`일 수 있음.
NORMAL이라는 문자열만 보고 양수 raw_score를 0으로 바꾸지 않음.

RPC 별도 측정 예시는 `client/detectors/whistle-spoofing/measurements/rpc_clean_001.jsonl:4`,
`rpc_pi_002.jsonl:1`이며 분석 테스트에서만 Shared 7필드로 포장하여 검사함.
원본 캡처를 수정하거나 해당 폴더 전체를 정상 라벨로 판정하지 않음.

### 9.3 현재 A 분석 대상: 정확한 module 15개

아래 전송 특성은 참조한 코드 및 담당자 답변에서 확인한 동작임.
9.4절의 새 전송 합의가 모든 탐지기에 이미 반영됐다는 뜻은 아님.

| 실제 module / 구분 | raw_score 의미·상한 | 관측·전송 특성 및 중앙 분석 시 주의점 |
|---|---|---|
| external_access / external_process | 위험 핸들 보조 근거 합계, 최대 10 | 외부 프로세스별 양수 관측. 다중 PID를 최신 module 한 건으로 축약하지 않음 |
| module_integrity / module_integrity | 변화 기본 1 + 미서명 1 / invalid 2, 최대 3 | DLL 변화 채널. 양수 탐지만 중앙 전송하며 0점 상태는 로컬에 남김. external_access와 저장 키를 분리함 |
| localguard_yara | 매칭 규칙 점수의 최댓값. 기본 3, 사용자 규칙 1~10 | 현 전송 경로는 양수만. 규칙·scope·부분 검사·테스트 규칙을 보존함 |
| localguard_executable_hash | 일치 있으면 1, 없으면 0 | 현 전송 경로는 양수만. 여러 실행 파일 목록을 대표 PID 하나로 축약하지 않음 |
| filesystem | 파일 흔적별 점수, 상한 100 | 현재 상태/흔적 관측이며 활성 핵 실행의 증명은 아님 |
| injection | 후킹·코드 변조·신뢰 근거, 상한 100 | 현재 흔적 평가이며 실행 성공·특정 핵 사용으로 단정하지 않음 |
| value_tamper | 설정값 차이 종류별 55, 상한 100 | 기준선 유효성과 정상 설정 차이를 구분함 |
| overlay_hook | 관련 근거 60씩, 상한 100 | 렌더링 후킹 흔적과 실제 ESP 사용을 구분함 |
| godmode_runtime | 무적 플래그 2 + 상태 패턴 3, 최대 5 | 현재 메모리 상태이며 독립 Godmode의 신규 사건 증분 점수와 다름 |
| noclip_runtime | 충돌 비트 해제 1 | 현재 상태이며 벽 통과·지속 시간을 직접 증명하지 않음 |
| aimbot_runtime | 회전 패턴 1 | 관측 구간 평가이며 입력 부재·표적 수렴을 직접 증명하지 않음 |
| whistle | ExecFunction 40/60, vtable 60, 사운드 교체 35, 상한 100 | 흔적이 유지되면 반복되는 상태형 결과임. 반복 점수를 신규 사건으로 더하지 않음 |
| whistle_rpc | 역할·사망·대상 위반 60, 쿨다운·입력 부재 40, 코드별 합계 상한 100 | 런처 경로는 새 로그 구간 평가임. 상태형 snapshot이나 개별 호출 증분 계약과 구분함 |
| hide_anywhere | 패턴 3, 비패턴일 때 보조 신호 합계 0~2 | 반복 값 평가임. 최신 읽기 성공·3회 확인 완료를 세 플래그만으로 증명하지 못함 |
| esp | 개별 근거 1/2/3. 연결 근거 확장 시 합계가 3 초과할 수 있음 | 양수 관측 스트림. 로컬 0~100 의심도와 다르며 정상 0점 snapshot을 항상 생성하지 않음 |

external_access와 module_integrity는 서로 다른 중앙 module 상태로 저장함.
상세한 점수 근거·대상 범위·테스트 경로는 다음 문서에 정리함.

- [LocalGuard 분석](policies/LOCALGUARD_POLICY.md)
- [Whistle 분석](policies/WHISTLE_POLICY.md)
- [Hide Anywhere 분석](policies/HIDE_ANYWHERE_POLICY.md)
- [ESP 분석](policies/ESP_POLICY.md)

정상/탐지 실전 예시가 없는 module에는 임의의 합성 데이터를 실전 표본으로
채워 넣지 않음. 단위 테스트 fixture와 실제 생성기 호환성 검사는 구분하여 보고함.

### 9.4 담당자 답변과 이번 A·B 합의

휘파람·LocalGuard 2번 담당자는 Shared 0.2.0을 사용하여 127.0.0.1 가짜 수신기의
`/api/detection`에서 7필드와 evidence.status 보존을 확인했다고 답변함.
현재 양수만 보내고 0점·ERROR·OFFLINE은 로컬에 남긴다고 설명함.
이는 담당자의 검증 보고이며 A가 실제 운영 중앙 서버 수신을 확인한 결과는 아님.
런처 검사 주기는 30초라고 답변함. 내부 20/60점 등급은 탐지기의 등급이며
중앙의 최종 판정 임계값으로 확정한 수치가 아님.

상태형 탐지기의 정상 복귀를 중앙에서 알 수 없었던 문제가 있어 다음 방향을 B와 합의함.

1. 검사에 성공한 정상 0점도 중앙으로 전달하여 현재 상태를 갱신함.
2. ERROR/OFFLINE은 0점이어도 evidence.status를 보존하고 measurement unavailable로 구분함.
   검사 실패를 정상 복귀로 처리하지 않음. 실패 이후 현재 risk의 유지·만료·불명 표시는 후속 정책에서 구체화함.
3. heartbeat는 탐지기 생존 확인용으로 사용하며 개별 검사 NORMAL/ERROR/OFFLINE을 대신하지 않음.
4. whistle 같은 상태형 결과는 반복 양수를 누적하지 않고 latest snapshot으로 다룸.
   정상 0점은 해당 관측 범위의 현재 상태를 갱신하며 과거 탐지 history는 보존함.
5. whistle_rpc는 새 로그 구간의 이력으로 다루고 현재 risk에는 유효 구간 동안 반영하는 방향임.
   구체적 유효 시간·로그 cursor·실제 주기·재시작 중복 기준은 아직 미확정임.
6. 핸들/DLL 채널은 각각 external_access/module_integrity 이름을 사용해 최신값
   덮어쓰기를 제거함. 과거 형식은 읽기 호환만 유지함.

위 합의는 운영 반영 완료 보고가 아님. 전송 필터 변경과 서버 수신 검증이 필요함.
ESP의 양수 관측 스트림이나 DLL 변화 채널의 무변화 0점에 일반 상태형 초기화 규칙을
그대로 확장하지 않음. 각 정상 0점이 의미하는 관측 범위를 별도로 맞춰야 함.
최상위 7필드는 유지하며 추가 상태·구간·submodule 정보는 evidence 안에 둠.

### 9.5 남은 결함과 정책 결정에 필요한 자료

- Hide Anywhere의 canonical UUID 오류·기본 logger 경로·측정 유효성 부족·실패 후 캐시 유지 문제는
  참조 코드에서 남아 있음. 분석 함수의 주석을 추가한 것으로 해결 처리하지 않음.
- Rule 3회 확인과 실제 단일 평가 경로의 차이는 분석에 명시함. 몇 회 확인할지는 원본 담당의 의도와 별도로 협의함.
- ESP는 프로세스 접근·외부 창·DLL 관측을 분리함. 1/2/3 중앙 점수와 로컬 0~100 의심도를 혼용하지 않음.
  동일 원시 ID는 로컬에서 중복 처리하지만 새 ID의 같은 대상 관측은 중앙 Event가 다시 생성될 수 있음.
- LocalGuard/ESP의 같은 PID·DLL 경로·비슷한 reason을 동일 사건으로 자동 확정하지 않음.
  최초 조사 2.3절의 태그 후보는 검토안이며 공통 이름·성립 조건·실제 점수 조정은 B와 합의 필요함.
- 정상·핵 표본, 검사 실패 표본, 재시작·정상 복귀 표본을 확보한 후 최종 가중치·유효 시간·임계값을 정해야 함.

### 9.6 구현·검증·연결 상태

분석 함수와 단위 테스트는 커밋 `743ac8d`, `a158863`, `1cce229`, `5217e41`, `4c917b9`로 분리하여 push함.
네 분석 함수·공통 계약 테스트 127개가 통과함. 작업 브랜치 전체 Scoring 테스트 160개,
PR #79 참조 Scoring에 A 함수만 검색 경로로 추가한 회귀 테스트 197개,
ESP 실제 순수 생성기·로컬 파이프라인 호환성 검사 8개가 통과함.
테스트가 서로 겹치므로 개수를 합산하지 않음. 이는 실게임 탐지율·최종 점수 정확도·HTTPS ACK 검증이 아님.

공통 policy.py·storage.py·main.py·contract.py·policies/__init__.py는 A 함수 작업에서 변경하지 않음.
공통 Registry 등록과 최종 통합은 인수인계에서 정한 대로 송희(B)가 맡음.
현재 기본 Registry에 A 함수가 자동 적용된 것으로 설명하지 않음.
이번 문서 업로드 과정에서 원격 작업 브랜치가 `e95baf3`으로 갱신된 것을 확인함.
해당 원격 커밋에는 팀 main 병합과 PR #78·#79·#80의 병합 결과가 포함되어 있었음.
원격 변경을 force push로 덮지 않고 `d4117bf`에서 문서 커밋과 합침.
따라서 현재 작업 브랜치에는 module_integrity·ESP 실제 소스와 Godmode B 분석 함수가 포함됨.
공통 Registry는 Noclip·Aimbot·AutoPaint·Godmode만 등록하고 A 함수는 아직 미등록임.
A의 별도 점수·저장 변경을 추가한 것은 아니며 B 공통 코드는 원격 내용 그대로 유지함.
로컬에 남아 있던 audit_a_contracts.py의 별도 변경도 보존하고 문서 커밋에서 제외함.

이 병합 후 실제 작업 브랜치의 전체 Scoring 테스트 **201개**와 해당 브랜치의
실제 ESP 생성 경로 호환성 검사 **8개**가 통과함. 이전 160/197 수치는 위에
기록한 당시 브랜치·검색 경로 결합 검증의 결과로 구분함.
팀 main 대상 A 작업 PR 생성·병합과 실제 Receiver 통합 검증은 아직 별도 진행이 필요함.

#### 완료

- [x] 실제 module 14개 및 external_access 두 하위 채널을 조사함.
- [x] Runtime 점수 연결 후 상한·관측 의미를 확인함.
- [x] ESP 후속 소스 조사·분석 함수·호환성 검사를 수행함.
- [x] 공통 계약에 맞춘 네 분석 함수·테스트를 작성하고 작업 브랜치에 push함.
- [x] 0점·실패 상태·heartbeat의 역할과 B 담당 범위에 관한 합의를 문서에 추가함.
- [x] 원격의 팀 main 병합 변경을 보존하여 합치고 Scoring 201개·ESP 호환성 8개를 검증함.

#### 검증 필요

- [ ] 담당자의 정상 0점·ERROR/OFFLINE 전송 변경 후 실제 중앙 수신을 확인함.
- [ ] 최신 정상·핵·실패·재시작 표본을 확보하고 기존 캡처와 구분함.
- [ ] Receiver → Shared 기록 → Scoring 등록 함수가 실제로 호출되는지 공동 검증함.

#### 남은 작업 및 결정

- [ ] B가 Registry·프로필·submodule 저장 및 조회 구조를 연결함.
- [ ] A가 합의 후 필요한 분석 함수·테스트 수정 및 Receiver 연동 확인을 진행함.
- [ ] RPC 유효 시간·재시작 중복 기준과 ESP 반복 관측 처리 기준을 정함.
- [ ] 공통 overlap_tags 이름·적용 조건과 모듈 간 중복 분석을 맞춤.
- [ ] Hide Anywhere 원본 문제 수정 여부를 담당자와 재확인함.
- [ ] PR 제출 시 팀 main의 추가 변경을 다시 확인하고 A 작업 PR을 제출함.
- [ ] 데이터 검증을 바탕으로 최종 위험도·가중치·임계값을 별도로 확정함.
