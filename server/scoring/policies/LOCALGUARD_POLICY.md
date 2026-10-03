# LocalGuard 중앙 해석 정책 — A 담당

> 아래는 구현 당시 조사 기록임. 후속 상태와 정상 0점 전송 합의는 마지막 절 및
> [전체 조사 문서 9절](../A_DETECTOR_INVENTORY.md)을 우선 참조함.

## 1차 작업: 외부 접근 채널 분리

`localguard.evaluate(event, baseline)`은 Shared 7필드 Event와 기존 Scoring
점검 결과를 받아 `PolicyAnnotations`만 반환함. 원점수·등급·저장 내용·최종
판정을 수정하지 않음. 기본 Registry 등록은 B 담당과 협의 후 반영해야 함.

| module / evidence.submodule | 의미 | entity_key |
|---|---|---|
| external_access / external_process | 외부 프로세스의 위험 핸들 관측 | 양수·유효 PID인 경우 `external_process:<source_pid>` |
| module_integrity / module_integrity | DLL 추가·매핑 변경·초기 기준선 감사 | 양수·알려진 변화·유효 PID/절대 Windows 경로인 경우 `game_module:<target_pid>:<경로 SHA-256>` |
| 실패 관측·0점·미분류 채널 | 정상·위험 해소로 자동 변환하지 않음 | 없음 |

- 핸들 채널은 팀 main `bd66c6524b6dc8d50ded0c052191a70c8b4acf7c`의
  `client/LocalGuard/external_access/process_access/detector.py:27`,
  `runner.py:168`, `runner.py:251` 기준으로 확인함.
- DLL 채널은 아직 미병합인 PR #78의 head
  `f6bf7d1e1fb40774fff8c6fe64bfb23fef329f50` 기준임.
  `module_integrity/detector.py:37`, `:49`, `runner.py:348`, `:570`의
  전송 계약을 해석함. 탐지기 자체를 main에 병합하거나 수정한 것은 아님.
- 핸들의 NORMAL 0점은 이번 검사에 양수 결과가 없다는 의미임. DLL의 NORMAL
  0점은 새 의심 변화가 없다는 의미임. 이전 DLL이 제거되었다는 증거가 아님.
- DLL 키의 SHA-256은 정규화된 **경로 문자열**을 짧게 표현하는 수단임.
  파일 바이트 해시·악성 신뢰 판정·개별 DLL 로드 사건 ID로 사용하지 않음.
  경로를 실제 열거나 서버의 파일 시스템에서 조회하지 않음.
- 신규 DLL 이벤트는 `module_integrity`를 사용해 `external_access` 핸들 상태와
  최신 module 저장 키를 분리함. 과거 `external_access/module_integrity`
  이벤트는 읽기 호환만 유지함.
- overlap_tags는 합의 전까지 빈 tuple임. PID/경로의 일치만으로 중복 탐지를
  확정하거나 점수를 합산/감점하지 않음.

## 2차 작업: 시그니처·메모리 관측 확장

다음 9개 module을 추가함. Whistle 2개 채널은 별도 `whistle.py`에서 처리함.

| module | 이번 해석에서 구분한 것 | entity_key |
|---|---|---|
| localguard_yara | 규칙 일치 / 테스트 규칙 / 실제 핵 활성화, PID별 검사 범위, 규칙 점수 최댓값 | 양수·규칙 목록·유효 PID·조사한 scope가 있으면 `yara_pid:<pid>:<scope>` |
| localguard_executable_hash | 실행 이미지 카탈로그 일치 / 기능 활성화, 여러 실행 파일 목록, 부분 검사 | 단일 대상으로 축약하지 않음 |
| filesystem | 파일/로그 흔적 / 실제 로드·현재 행동, UE4SS 면제 목록·등록부 오류 | 없음 |
| injection | ProcessEvent·ExecFunction·.text·모듈 신뢰, 실패한 하위 검사 | 양수·유효 meta.target_pid면 `game_pid:<pid>` |
| overlay_hook | 비신뢰 인라인/렌더링 후킹 / 실제 ESP 사용 | 양수·유효 meta.target_pid면 `game_pid:<pid>` |
| value_tamper | 기준선과 설정값 차이, 숨기/칠하기 조사 필드, 미관측 클래스 | 없음 |
| godmode_runtime | 무적 플래그·체력 상태 패턴 / 피격 무효 사건별 점수 | 없음 |
| noclip_runtime | 충돌 비트 / 실제 벽 통과·지속 시간 | 없음 |
| aimbot_runtime | 회전 패턴 / 입력 없는 회전·표적 수렴·비가시 추적 | 없음 |

### 실제 코드에서 확인한 제한

- YARA의 `test_rule_match=true`는 테스트 규칙이 포함되었다는 뜻임. 운영
  탐지로 승격하거나 혼합 결과의 점수를 임의로 지우지 않고 주의사항을 남김.
  현재 기본 상한 3과 사용자 규칙 허용 상한 10의 차이는 B와 합의 필요함.
  `yara_scanner.py:235`, `:256`, `:273`의 실제 Event 생성 경로를 확인함.
- 해시 검사는 여러 `matched_executables`를 한 Event로 전달함. 첫 PID/첫 해시를
  대표 entity로 선택하지 않음. `catalogue_sha256`도 실행 이미지 해시가 아님.
  `hash_monitor.py:38`, `:70`의 생성 조건을 확인함. 부분 검사 중 확인된 일치는
  보존하되 부분 무일치/검사 실패를 전체 정상으로 취급하지 않음.
- YARA·해시·메모리 계열은 정상 0점을 로컬에 남겨도 현재 중앙에는 양수만
  전송함. `input_signature/replay_events.py:199`,
  `memory_integrity/run_session.py:309`에서 확인함. 무전송을 정상으로
  바꾸지 않음. 별도 하트비트 수신을 scoring 점수 Event로 합치지 않음.
- Runtime 현 점수 상한은 godmode 5, noclip 1, aimbot 1임. 각 탐지기의
  점수 상수와 단일 검사 내 사유 중복 억제 코드를 확인함. 기존 B 프로필의
  공통 상한 100은 이 함수에서 수정하지 않고 갱신 필요 사항으로 남김.
- 메모리 계열 내부 등급은 20점 미만을 NORMAL로 표시할 수 있음.
  `NORMAL + raw_score=1`을 오류나 정상 0점으로 덮어쓰지 않음.
  `core/result.py:305`의 실제 Shared 변환기로 합성 1점 결과를 검사함.
- 평문 `address/value/module/file`에는 설명이 붙어 있을 수 있어 사건 키를
  추출하지 않음. Runtime의 Pawn/Controller 주소를 안정된 player_id로
  사용하지 않음. 파일·메모리 검사 자체를 중앙 정책에서 다시 실행하지 않음.

## 테스트·연결

```powershell
python -B -m unittest server.scoring.tests.test_localguard_policy -v
```

테스트는 독립 Registry를 만들어 지원하는 10개 module을 등록함. 실게임 탐지율,
실제 중앙 HTTPS 수신, 최종 점수 정책, 운영 저장 분리를 검증한 것이 아님.
1차 검증: 외부 접근 정책 21개 + Whistle 25개 + 공통 계약 11개, 총 57개 통과함.

2차 검증(2026-10-03):

- LocalGuard 정책 46개 + Whistle 25개 + 공통 계약 11개: **82개 통과함**.
- 현재 작업 브랜치의 전체 Scoring 테스트: **115개 통과함**.
- 팀 main `bd66c65` 기반 Scoring 81개 + Whistle 25개 + LocalGuard 46개:
  **152개 통과함**. 별도 검토 checkout의 공통 코드를 불러오고 새 정책/테스트만
  모듈 검색 경로에 추가하여 검사함. 브랜치 병합이나 운영 등록 완료 의미가 아님.
- 기존 `hide_hack_001`, `clean_002` Replay의 filesystem/injection/value_tamper
  이벤트를 실제 `to_shared_event()`로 변환 후 해석함. 원본 캡처 파일은 변경하지
  않음. 과거 캡처 해석 검증이지 최신 탐지기 실게임 표본·서버 ACK 검증이 아님.
- DB 테스트는 임시 폴더 권한 제한 없이 실행함. 기존 FastAPI 테스트 환경에서
  httpx 관련 폐기 예정 경고가 발생했지만 테스트 실패는 없었음.

```python
from server.scoring.policies import localguard
for module in localguard.SUPPORTED_MODULES:
    registry.register(module, localguard.evaluate)
```

공통 `registry.py`, `contract.py`, `policy.py`, `storage.py`, `main.py`는 변경하지 않음.

## 남은 작업

- [x] 핸들/DLL 채널 분기와 원점수·실패 상태 보존 해석을 작성함.
- [x] YARA·해시·메모리/Runtime 9개 module의 주석·단위 테스트를 추가함.
- [x] 기존 캡처 변환 및 최신 B 코드와의 호환성을 검사함.
- [x] DLL 채널의 module 이름을 `module_integrity`로 분리해 최신 상태 충돌을 제거함.
- [ ] B와 외부 PID 다중 대상·positive-only 만료·관측 실패 처리를 합의해야 함.
- [ ] B와 Runtime/YARA 프로필 및 overlap_tags 계약을 맞춰야 함.
- [ ] B 담당 기본 Registry에 연결해야 함.
- [ ] Receiver → Shared 기록 → 실제 Scoring/중앙 HTTPS 수신을 공동 검증해야 함.
- [ ] 실게임 정상·핵 표본으로 가중치/최종 판정 정책을 별도로 정해야 함.

후속 A 정책 작성 대상은 Hide Anywhere와 ESP임. 원본 탐지기의 전송 문제 수정,
자기 탐지 예외 확정, 실게임 임계치 보정은 이번 정책 주석 작업과 구분함.

## 2026-10-03 후속 상태·담당 범위

Hide Anywhere와 ESP 분석 함수·테스트도 후속 커밋에서 구현함. 위의 미착수
설명은 2차 작업 당시 기록임. 네 파일 모두 공통 계약의 읽기 전용 분석이며
최종 점수 정책·저장 분리·Registry 연결 완료를 뜻하지 않음.

상태형 결과는 정상 0점도 전송하고 ERROR/OFFLINE은 정상과 구분하는 방향을
송희(B)와 합의함. heartbeat는 검사 결과를 대신하지 않음.
2번 런처 검사 주기 30초·Shared 0.2.0 가짜 수신기 성공은 담당자 보고로 확인함.
Runtime 3종의 실제 상한 5/1/1은 후속 소스에서도 확인함. 내부 0~100 등급
범위와 실제 단일 검사 점수 상한을 구분함.

external_access와 module_integrity는 별도 module 상태로 저장함. DLL 무변화
0점은 중앙으로 보내지 않고 로컬 상태에만 남기므로, 과거 탐지를 0점으로
덮어쓰지 않음. 변화 이력의 보존·만료 범위는 B와 계속 맞춰야 함.

공통 Registry 등록·프로필·저장 구조·최종 통합은 B 담당임.
A는 필요한 분석 함수·테스트 보완과 Receiver 연동 검증을 맡음.
최종 위험도·가중치·만료 시간이나 overlap_tags를 A가 임의로 확정하지 않음.
전송 필터 변경·공통 프로필 반영·실제 수신 성공은 아직 별도 확인이 필요함.

이번 문서 업로드 중 원격 `e95baf3`의 팀 main 병합을 보존하여 합침.
PR #78 module_integrity·PR #79 ESP는 현재 작업 브랜치에도 포함됨.
위의 미병합 표기는 최초 검토 시점의 기록임. 병합 후 전체 Scoring 테스트
201개가 통과했지만 공통 Registry의 A 함수 등록은 아직 수행하지 않음.
