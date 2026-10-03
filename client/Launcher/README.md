# Launcher

사용자가 LocalGuard·SelfDefense·KernelWatcher·탐지기·게임을 각각 찾아 실행하지
않도록, 이것 하나가 순서대로 켜고 상태를 보여주고 끝날 때 정리한다.

```bash
python client/Launcher/main.py
```

| 옵션 | 뜻 |
|---|---|
| `--session ID` | 세션 이름 (기본: 시각으로 자동 생성) |
| `--player ID` | 플레이어 식별자 (기본 `player_001`) |
| `--only a,b` | 그 모듈만 실행 |
| `--no-launch-game` | 게임은 내가 직접 켠다. 뜰 때까지 기다리기만 |
| `--wait-game SEC` | 게임을 기다리는 시간 (기본 180초) |
| `--status-every SEC` | 상태 화면 간격 (기본 10초) |
| `--self-hook DLL` | 이번 세션에 명시적으로 사용할 승인된 안티치트 관측 후크 |

커널 모듈을 쓰려면 **관리자 권한**으로 실행해야 한다. 아니면 그 모듈만 건너뛴다.

에임봇·오토페인트·노클립·갓모드 탐지기는 UE4SS 위에서 돈다. 런처가 그걸 어떻게 깔고
확인할지는 **[UE4SS.md](UE4SS.md)** 에 따로 정리했다(동효님 담당, 은지·성민님 요구사항 반영).

휘파람 탐지기의 `ac_whistle_v10.dll`은 게임 안에 의도적으로 넣는 안티치트 관측
후크라서 module_integrity가 핵 DLL로 오인하면 안 된다. 사용할 파일을 Launcher의
`--self-hook DLL`로 명시하면 게임 관련 모듈을 띄우기 직전에
`logs/self_hook_manifest.json`을 새로 만들고, 그 절대 경로와 SHA-256을 기록한다.
경로를 자동 검색하지 않으며 현재 검토된 v10의 정확한 빌드 출력 경로만 받는다.
UE4SS의 신뢰 루트는 게임 폴더이고
이 후크의 신뢰 루트는 현재 안티치트 checkout이므로 두 manifest는 합치지 않는다.
공격 실험용 `modules/whistle-spoofing/bin/`과 임의 버전 DLL은 승인 대상이 아니다.

```powershell
python client/Launcher/main.py --self-hook `
  "client/detectors/whistle-spoofing/native/whistle_hook/bin/Release/ac_whistle_v10.dll"
```

---

## 내 모듈을 붙이려면 — `modules.py` 에 한 줄

런처 본체(`main.py`, `process_manager.py`)는 건드릴 필요가 없다.

```python
Module(
    name="input_signature",
    owner="3번 (동효)",
    argv=[PY, "client/LocalGuard/input_signature/yara_scanner.py",
          "--session-id", "{session}", "--player-id", "{player}"],
    mode=CONTINUOUS,     # 또는 ONESHOT + every_s=30.0
    needs_game=True,
    needs_admin=False,
    restart=False,       # 되살리면 안 되는 모듈이면 (예: 세션 폴더를 exist_ok=False 로 만든다)
)
```

자리표시자 `{session}` `{player}` `{t0}` `{window}` `{game_bin}` `{telemetry}` 는 런처가 채운다.
`{game_bin}` 은 런처가 찾은 게임 실행 폴더(`...\Chameleon\Binaries\Win64`)다. UE4SS 모드가
쓰는 로그처럼 게임 폴더 아래 파일을 읽는 모듈은 경로를 박지 말고 이걸로 받는다
(예: `r"{game_bin}\ue4ss\Mods\DamageLogger\meccha_aim_telemetry.jsonl"`).
`{telemetry}` 는 `GZZ_TELEMETRY_URL` 이 설정돼 있으면 `managed`, 없으면 `off` 다. 서버 설정이
없을 때 시작을 거부하는 모듈(autopaint)에 쓴다.

PC 마다 있을 수도 없을 수도 있는 경로(게임 쪽 UE4SS 모드 폴더 등)를 넘겨야 하는데, 없는
경로를 주면 모듈이 시작을 거부한다면 `argv` 대신 `optional_paths` 에 적는다. 경로가 실제로
있을 때만 붙고, 없으면 빼고 띄운 뒤 상태 화면 비고에 `경로가 없어 뺌: <옵션>` 으로 남긴다.

```python
optional_paths=[("--lua-mod-dir", r"{game_bin}\ue4ss\Mods\GZZPaintObserver")],
```

| 항목 | 뜻 |
|---|---|
| `mode=CONTINUOUS` | 자기가 알아서 계속 돈다. 런처는 살아 있는지만 본다 |
| `mode=ONESHOT` + `every_s` | 한 번 돌고 끝난다. 런처가 그 주기로 다시 부른다 |
| `needs_game=False` | 게임보다 **먼저** 뜬다 (SelfDefense·KernelWatcher) |
| `needs_admin=True` | 관리자 권한이 없으면 건너뛴다 |

**실행 방식이 모듈마다 다르니 확인하고 적어야 한다.** 예를 들어 `external_access`
는 상대 import 를 써서 `python -m client.LocalGuard...` 로만 돌고, 직접 실행하면
`ImportError` 가 난다. `autopaint` 도 `python -m client.detectors.autopaint.main` 으로
띄운다 — 스크립트로 띄우면 레포 루트의 `shared` 를 못 찾는다. 등록하기 전에 그 명령을
손으로 한 번 돌려보는 게 빠르다.

### 주기 실행 모듈이라면 `{t0}` 를 꼭 받아 주세요

`ONESHOT` 은 실행할 때마다 새 프로세스다. 각자 자기 시작 시각을 기준으로
`timestamp_ms` 를 매기면 **실행이 바뀔 때마다 시각이 0 으로 되돌아가고**
ReplayAnalyzer 에서 타임라인이 깨진다. 그래서 런처가 세션 전체의 기준 시각을
`{t0}` 로 넘긴다. 받아서 기준으로 쓰면 된다
(`memory_integrity/run_session.py` 의 `--t0` 참고).

### 끌 때 정리 코드가 돌게 하려면 — 한 줄

런처는 끝낼 때 모듈에 **종료를 요청**하고(Ctrl+Break), 스스로 끝나기를 기다렸다가
(무리마다 최대 10초) 그래도 남은 것만 강제로 끈다. 파이썬 모듈은 시작부에 이 한 줄을
넣으면 그 요청이 `KeyboardInterrupt` 로 바뀌어, 이미 있는 `except KeyboardInterrupt`
와 `finally` 가 그대로 돈다.

```python
import signal
signal.signal(signal.SIGBREAK, signal.default_int_handler)
```

**manifest·세션 파일·마지막 전송처럼 끝날 때 닫아야 하는 게 있는 모듈은 꼭 넣어 주세요.**
없으면 윈도 기본 처리로 즉시 끝나서 예전 강제 종료와 같습니다(manifest 가 `RUNNING`
으로 남습니다). 나빠지는 건 없지만 좋아지지도 않습니다.

왜 Ctrl+C 가 아니라 Ctrl+Break 인가: 모듈마다 프로세스 그룹을 따로 두어야 하나씩
골라 끌 수 있는데, 윈도는 따로 둔 그룹에는 Ctrl+C 를 보낼 수 없게 막는다.
그 덕에 사용자가 런처 창에서 Ctrl+C 를 눌러도 모듈에 바로 가지 않는다. 런처가 받아서
**게임 관련 모듈 먼저, SelfDefense·KernelWatcher 는 나중에** 순서대로 끈다.

끝나면 런처가 누가 어떻게 끝났는지 보여준다.

```
  정리 결과: 요청 후 종료 5  /  강제 종료 1
    기본 처리로 끝남(정리 코드가 돌았는지 모름): aimbot
    요청은 갔는데 제때 안 끝남: kernel_watcher
```

"돌았는지 모름" 은 종료 코드가 `0xC000013A` 인 경우다. 한 줄이 없는 모듈도, 한 줄은
있지만 `KeyboardInterrupt` 를 잡지 않고 흘려보낸 모듈도 같은 코드로 끝나서 런처는
둘을 구분할 수 없다. 잡아서 `sys.exit(…)` 로 끝내면 이 표시가 사라진다.

**한계:** 런처가 콘솔 없이 떠 있으면(pythonw, 창 모드로 패키징한 exe) 요청을 못 보내고
바로 강제 종료로 넘어간다. `MecchaAntiCheat.exe` 로 묶을 때 콘솔 앱으로 묶어야 한다.

---

## 파일 나눔

| 파일 | 담당 | 하는 일 |
|---|---|---|
| `main.py` | 랑언 | 전체 순서 |
| `process_manager.py` | 랑언 | 실행·생존 확인·재시작·종료 |
| `registry.py` | 랑언 (워치독과 공용) | 등록부·잠금·재시작 규칙 |
| `modules.py` | 공용 | 모듈 등록표 |
| `ui.py` | **동효** | 상태 화면 (지금은 콘솔 표) |
| `game_launcher.py` | **동효** | 게임 찾기·실행 (지금은 최소 동작) |

동효님 두 파일은 **인터페이스만 맞춰서 최소 버전**을 채워뒀습니다. 런처가 돌아가야
다른 분들이 자기 모듈을 붙여볼 수 있어서 먼저 만든 것이고, 안을 통째로 바꾸셔도
`main.py` 는 손댈 필요가 없습니다. 지켜야 할 함수는 각 파일 맨 위에 적어뒀습니다.

`ui.render(rows, ctx)` 의 `rows` 한 줄:

```python
{"name": "memory_integrity", "owner": "2번 (재민·랑언)", "status": "RUNNING",
 "mode": "oneshot", "runs": 3, "restarts": 0, "started_by": "launcher",
 "last_code": 1, "uptime_s": 12.4,
 "detail": "의심 발견", "log": "...logs/memory_integrity.log"}
```

`status`: `MISSING` / `SKIPPED` / `PENDING` / `RUNNING` / `DONE` / `WARN` / `RESTART` / `FAILED` / `STOPPED`
(`RESTART` = 상주 모듈이 죽어서 되살리는 중)
서버 연결 상태는 `ctx["server"]` 로 들어갑니다(하트비트 붙이면 그 값만 채우면 됩니다).

---

## 재시작 — 런처와 워치독(4번)이 **둘 다** 한다

2026-09-29 성민님 제안으로, 죽은 상주 모듈(`CONTINUOUS`)은 런처도 되살리고 워치독도
되살린다. 따로 되살려도 충돌하지 않게 규칙은 전부 `registry.py` 한 곳에 있고,
**둘이 같은 함수 `registry.restart_if_dead()` 를 부른다.**

| 막는 문제 | 방법 |
|---|---|
| 같은 모듈이 두 번 뜬다 | 모듈마다 잠금. 잡은 쪽만 띄우고, 잡은 뒤 다시 봐서 상대가 이미 띄웠으면 이어받는다 |
| 워치독이 띄운 PID 를 아무도 모른다 | 누가 띄우든 `anticheat_pids.json` 에 적는다 |
| 런처가 끄는 걸 워치독이 되살린다 | 끌 때 `stopping` 을 먼저 켠다 |
| 런처가 비정상으로 죽어 `stopping` 을 못 켰다 | 등록부의 런처 PID 가 죽었으면 되살리지 않고 `orphaned` 를 돌려준다 |
| 둘이 따로 세서 한도가 두 배가 된다 | 재시작 횟수를 등록부에서 같이 센다 (5분에 5번, 간격 0/2/4/8/16초) |
| 띄운 뒤 등록을 못 하면 아무도 모르는 프로세스가 남는다 | 시도를 **띄우기 전에** 적고, 등록이 실패하면 방금 띄운 것을 끈다 |
| 런처를 두 개 띄우면 서로의 모듈을 죽인다 | 두 번째 런처는 시작 단계에서 막는다 (`LauncherAlreadyRunning`) |
| 런처가 강제 종료되면 그 세션 모듈이 영영 남는다 | 다음 런처가 시작할 때 지난 세션 모듈을 끄고 시작한다 |
| 등록부를 그 순간 못 읽어 살아 있는 모듈을 버린다 | 읽기를 다시 시도하고, 한 번 못 봤다고 포기하지 않는다 (5회) |
| 자기 보호를 거는 모듈을 죽은 줄 안다 | 핸들을 못 여는 이유가 **권한 없음이면 살아 있는 것으로 본다** |

잠금을 쥔 프로세스가 죽으면 OS 가 잠금을 풀어준다(msvcrt 바이트 잠금).

**워치독에서 쓰는 법** — 이 파일 하나만 가져다 쓰면 된다(표준 라이브러리만 씀).

```python
sys.path.insert(0, r"<레포>/client/Launcher")
import registry

for name in registry.restartable_names():
    status, pid, _ = registry.restart_if_dead(name, by="watchdog")
    # status: alive / restarted / backoff / gave_up / stopping / orphaned / skip
    # orphaned = 런처가 없다. 누가 런처를 죽였다면 그 자체가 보고할 거리다.
```

주기 실행(`ONESHOT`)은 끝나는 게 정상이라 워치독 대상이 아니다(`restartable=False`).
다만 비정상 종료(종료코드 0/1/2 밖)하면 런처가 다음 주기에 다시 부르고, 같은
한도를 넘으면 멈춘다. 되살리면 안 되는 상주 모듈은 `modules.py` 에서 `restart=False`.

시험(2026-09-29): 런처와 워치독 프로세스를 동시에 돌리며 모듈을 8번 죽였다.
런처 3번·워치독 5번 되살렸고, **두 개가 동시에 뜬 적은 한 번도 없었다.** 끈 뒤에는
워치독이 되살리지 않았고, 런처를 강제 종료하자 워치독은 `orphaned` 를 받았다.
실제 1번 `external_access` 를 게임 켠 상태에서 죽였을 때 런처가 되살렸다.

그 뒤 이 코드를 깨뜨리려는 관점으로 따로 검토해 결함 16건을 찾았고, 위 표의 아래 다섯 줄이
그때 나온 것이다. 등록부를 일부러 오래 붙잡고, 런처를 두 개 띄우고, 런처를 강제 종료하고,
등록부 읽기를 실패시키고, 핸들 권한을 막는 상황을 각각 재현해서 고친 뒤 다시 확인했다.

---

## 모듈 출력은 어디에

콘솔에 같이 찍으면 읽을 수 없고, 무엇보다 Windows 파이프 버퍼가 가득 차면
자식 프로세스가 멈춘다. 그래서 모듈마다 따로 보낸다.

```
client/Launcher/logs/<모듈>.log
```

실행할 때마다 헤더(`[launcher run #N] 시각` + `[cmd] 실제 명령`)를 남기므로, 안 붙을 때
그 파일을 보면 무슨 명령이 어떻게 실패했는지 바로 나온다. 되살렸을 때는
`[launcher restart 2/5]` / `[watchdog restart 3/5]` 처럼 누가 몇 번째로 되살렸는지 남는다. 탐지 결과 자체는
각 모듈이 원래 쓰던 자리(`logs/detection/` 등)에 그대로 쌓인다.

---

## 안 만들어진 모듈이 있어도 멈추지 않는다

2026-10-01 기준 `SelfDefense`(4번), `KernelWatcher`(5번) 는 등록된 경로에 코드가 없다.
런처는 이 모듈들을 `MISSING` 으로 보여주고 나머지를 계속 띄운다. 조용히 넘기지도
않는다 — 아직 안 만든 것과, 만들었는데 안 붙는 것은 원인이 다르기 때문이다.

---

## 안티치트가 자기 자신을 신고하지 않게 — `logs/anticheat_pids.json`

런처와 워치독은 자기가 띄운 프로세스 PID 를 이 파일(등록부)에 계속 갱신한다.

```json
{
  "launcher_pid": 42680, "launcher_create_time": 134051234567890123,
  "session_id": "run_002", "stopping": false,
  "modules": {"memory_integrity": 34400, "external_access": 33640},
  "entries": {"external_access": {"pid": 33640, "create_time": 134051234599990000,
              "started_by": "watchdog", "restartable": true, "restarts": [1790680000.1]}}
}
```

`modules` 는 예전 형식 그대로다(살아 있는 것만). 새로 쓰는 쪽은 `entries` 의
`create_time` 까지 보면 PID 재사용을 가려낼 수 있다. 전체 모양은 `registry.py` 맨 위.

**왜 필요한가.** `memory_integrity`·`whistle` 은 pymem 으로 게임 메모리를 읽는다.
처음엔 pymem 기본값대로 전체 권한(`0x001F3FFF`)으로 열어서 밖에서 보면 Cheat Engine 과
구분되지 않았고, 2026-09-27 첫 실전에서 은지님 `external_access` 가 우리 `python.exe` 를
`raw_score 8` 로 잡았다. 지금은 읽기 전용(`0x0410`, `memory_integrity/core/procopen.py`)
으로만 열어서 1번에 안 잡힌다. 다만 1번이 나중에 읽기 단독 핸들에도 점수를 주면 다시
잡히므로, 그때 "우리 프로세스" 를 가려낼 근거로 이 파일이 필요하다.

**allowlist 에 `python.exe` 를 넣는 것은 답이 아니다.** 이름+해시로 통과시키면
같은 파이썬으로 짠 핵도 전부 통과한다. "우리가 방금 띄운 이 PID" 만 빼는 것이 정확하다.

소비하는 쪽(1번 `external_access`, 4번 `SelfDefense`)은 이 파일을 읽고
`modules` 의 PID 와 `launcher_pid` 를 자기 판정에서 빼면 된다. 프로세스가 죽으면
PID 는 재사용되므로 **살아 있는 것만** 적고, 시작·종료할 때마다 다시 쓴다.
