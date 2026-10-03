"""모듈 프로세스의 실행·생존 확인·재시작·종료.

## 재시작 — 런처와 워치독(4번)이 **둘 다** 한다

2026-09-29 성민님 제안으로, 죽은 상주 모듈은 런처도 되살리고 워치독도 되살린다.
둘이 따로 되살려도 충돌하지 않도록 규칙은 전부 registry.py 한 곳에 있다.

    - 모듈마다 잠금을 잡은 쪽만 띄운다. 상대가 이미 되살렸으면 이어받는다
    - 누가 띄우든 등록부(logs/anticheat_pids.json)에 적는다
    - 재시작 한도(5분에 5번)와 간격(0/2/4/8/16초)을 둘이 같이 센다
    - 런처가 끌 때는 stopping 을 먼저 켜서, 워치독이 되살리지 않게 한다

런처는 자기가 띄운 것은 Popen 으로, 워치독이 띄운 것은 PID+생성 시각으로 지켜본다.
주기 실행(ONESHOT)은 "죽어서 되살리는 것" 이 아니라 원래 주기적으로 도는 검사다.
다만 비정상 종료하면 다음 주기에 다시 부르고, 같은 한도를 넘으면 멈춘다.

## 출력은 모듈마다 파일로 뺀다

모듈 7개가 한 콘솔에 같이 찍으면 읽을 수 없고, 무엇보다 파이프가 가득 차면
자식 프로세스가 멈춘다(Windows 파이프 버퍼는 몇 KB뿐이다). 그래서 각자
`client/Launcher/logs/<모듈>.log` 로 보낸다. 워치독이 되살려도 같은 파일에 이어 쓴다.
"""

import ctypes
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import registry
from modules import CONTINUOUS, GAME_DIR, ONESHOT, REPO, Module

LOG_DIR = registry.LOG_DIR

# 안티치트 자신이 띄운 프로세스 목록 = 등록부. 1번 external_access·커널 쪽이
# "우리 프로세스" 를 알아보는 근거이고, 4번 워치독이 무엇을 지켜볼지 아는 근거다.
# 자세한 모양은 registry.py 맨 위에 있다.
PID_FILE = registry.PID_FILE

# 상태값. ui.py 가 이걸 보고 화면을 그린다.
MISSING = "MISSING"        # 파일이 없다 = 아직 구현 전
SKIPPED = "SKIPPED"        # 조건이 안 맞아 건너뜀 (관리자 권한 등)
PENDING = "PENDING"        # 등록됐고 아직 시작 전 (게임을 기다리는 중)
RUNNING = "RUNNING"
DONE = "DONE"              # 한 번 돌고 정상 종료
WARN = "WARN"              # 돌긴 했는데 검사가 성립하지 않음 (종료코드 2)
RESTARTING = "RESTART"     # 상주 모듈이 죽었고 되살리는 중 (간격 대기 포함). 화면 칸 9자라 짧게
FAILED = "FAILED"          # 비정상 종료. 되살리지 않거나 한도를 넘었다
STOPPED = "STOPPED"        # 우리가 끝냈다

# Ctrl+C/Ctrl+Break 를 윈도 기본 처리로 받고 끝난 프로세스의 종료 코드.
STATUS_CONTROL_C_EXIT = 0xC000013A


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@dataclass
class ModuleState:
    module: Module
    status: str = PENDING
    proc: Optional[subprocess.Popen] = None   # 런처가 띄운 것
    adopted_pid: Optional[int] = None          # 워치독이 띄워서 이어받은 것
    adopted_ctime: int = 0
    started_by: str = ""
    started_at: float = 0.0
    last_code: Optional[int] = None
    runs: int = 0
    restarts: int = 0
    skips: int = 0             # 등록부에서 못 찾은 횟수. 한 번으로 포기하지 않는다
    crash_times: List[float] = field(default_factory=list)   # ONESHOT 비정상 종료 시각
    next_run_at: float = 0.0
    detail: str = ""
    log_path: str = ""

    @property
    def name(self) -> str:
        return self.module.name

    @property
    def pid(self) -> Optional[int]:
        if self.proc is not None:
            return self.proc.pid
        return self.adopted_pid

    def snapshot(self) -> dict:
        """ui.py 로 넘기는 한 줄 요약. **여기가 동효님과의 접점이다.**"""
        return {
            "name": self.name,
            "owner": self.module.owner,
            "status": self.status,
            "mode": self.module.mode,
            "runs": self.runs,
            "restarts": self.restarts,
            "started_by": self.started_by,
            "last_code": self.last_code,
            "uptime_s": (time.time() - self.started_at) if self.status == RUNNING else 0.0,
            "detail": self.detail,
            "log": self.log_path,
        }


class ProcessManager:
    def __init__(self, modules: List[Module], session: str, player: str,
                 t0: float, say=print):
        self.session = session
        self.player = player
        self.t0 = t0
        self.game_pid: Optional[int] = None
        self.say = say
        self.states: Dict[str, ModuleState] = {}
        os.makedirs(LOG_DIR, exist_ok=True)
        registry.begin_session(session)
        admin = is_admin()
        for m in modules:
            st = ModuleState(m)
            st.log_path = os.path.join(LOG_DIR, f"{m.name}.log")
            path = m.script_path()
            if path and not os.path.exists(path):
                # **없는 모듈을 조용히 넘기지 않는다.** 아직 안 만든 것과
                # 만들었는데 안 붙는 것은 원인이 완전히 다르다.
                st.status = MISSING
                st.detail = f"{os.path.relpath(path, REPO)} 없음 — {m.owner}"
            elif m.needs_admin and not admin:
                st.status = SKIPPED
                st.detail = "관리자 권한으로 실행해야 합니다"
            self.states[m.name] = st

    def set_game_pid(self, game_pid: int) -> None:
        if isinstance(game_pid, bool) or not isinstance(game_pid, int) or game_pid <= 0:
            raise ValueError("game_pid must be a positive integer")
        self.game_pid = game_pid

    def _restartable(self, st: ModuleState) -> bool:
        return st.module.mode == CONTINUOUS and st.module.restart

    # ── 실행 ───────────────────────────────────────────────────────────
    def start(self, name: str) -> bool:
        st = self.states[name]
        if st.status in (MISSING, SKIPPED):
            return False
        if st.proc is not None and st.proc.poll() is None:
            return True                      # 이미 돌고 있다

        ctx = {
            "session": self.session, "player": self.player,
            "t0": f"{self.t0:.3f}", "window": st.runs,
            "game_pid": self.game_pid,
            # 런처가 찾은 게임 실행 폴더(main.publish_game_dir 가 채운다). UE4SS 모드
            # 로그처럼 게임 폴더 아래 파일을 읽는 모듈에 넘긴다. 못 찾았으면 기본값.
            "game_bin": os.environ.get("GZZ_GAME_BIN") or GAME_DIR,
            "game_root": os.environ.get("GZZ_GAME_ROOT") or "",
            # 중앙 서버 설정이 있을 때만 전송한다. 없으면 로컬 기록만.
            "telemetry": "managed" if os.environ.get("GZZ_TELEMETRY_URL") else "off",
        }
        argv = st.module.resolved(ctx)
        skipped = st.module.missing_optional(ctx)
        cwd = st.module.cwd or REPO
        try:
            # 상주 모듈은 워치독과 같은 잠금 아래에서 띄운다. 워치독이 먼저 띄웠으면 이어받는다.
            with registry.lock("mod_" + name):
                live = registry.live_pid(name) if self._restartable(st) else None
                if live:
                    self._adopt(st, *live)
                    return True
                proc = registry.spawn(argv, cwd, st.log_path,
                                      note=f"launcher run #{st.runs + 1}")
                try:
                    registry.register(name, proc, by="launcher",
                                      restartable=self._restartable(st),
                                      argv=argv, cwd=cwd, log=st.log_path)
                except BaseException:
                    # 등록을 못 하면 방금 띄운 것을 남기지 않는다. 아무도 추적하지 못하고
                    # stop_all 도 모르는 프로세스가 되어 세션이 끝난 뒤에도 남는다.
                    registry._kill_proc(proc)
                    raise
        except Exception as e:
            if st.module.mode == ONESHOT and st.module.every_s:
                # 주기 검사는 일시적 실패 한 번으로 세션 끝까지 멈추면 안 된다.
                st.status = WARN
                st.detail = f"실행 실패: {e} — 다음 주기에 다시"
                st.next_run_at = time.time() + st.module.every_s
            else:
                st.status = FAILED
                st.detail = f"실행 실패: {e}"
            self.say(f"  ! {name} 실행 실패 — {e}")
            return False

        st.proc, st.adopted_pid, st.adopted_ctime = proc, None, 0
        st.status = RUNNING
        st.started_by = "launcher"
        st.started_at = time.time()
        st.runs += 1
        # 경로가 없어 뺀 옵션은 조용히 넘기지 않는다. 탐지 범위가 줄어든 채로 돈다.
        st.detail = ("경로가 없어 뺌: " + ", ".join(skipped)) if skipped else ""
        if skipped and st.runs == 1:
            self.say(f"  · {name}: {', '.join(skipped)} 경로가 없어 빼고 띄웁니다 "
                     f"(탐지 범위가 줄어듭니다)")
        return True

    def start_group(self, needs_game: bool) -> None:
        for st in self.states.values():
            if st.module.needs_game == needs_game and st.status == PENDING:
                self.start(st.name)

    def _adopt(self, st: ModuleState, pid: int, ctime: int) -> None:
        """워치독이 띄운 프로세스를 이어받는다. 새로 띄우지 않는다."""
        e = registry.entry(st.name) or {}
        st.proc = None
        st.adopted_pid, st.adopted_ctime = pid, ctime
        st.started_by = e.get("started_by", "watchdog")
        st.restarts = len(e.get("restarts", []))
        st.status = RUNNING
        st.started_at = time.time()
        st.detail = f"{st.started_by} 가 띄운 pid {pid} 를 이어받음"

    # ── 감시 ───────────────────────────────────────────────────────────
    def poll(self) -> None:
        """상태를 갱신하고, 죽은 상주 모듈을 되살리고, 주기 실행을 다시 부른다."""
        now = time.time()
        exited = False
        for st in self.states.values():
            if st.status == RUNNING:
                if st.proc is not None:
                    code = st.proc.poll()
                    if code is not None:
                        st.proc = None
                        st.last_code = code
                        exited = True
                        if st.module.mode == ONESHOT:
                            self._oneshot_exit(st, code, now)
                        else:
                            self._down(st, f"종료됨 (code {code})")
                elif st.adopted_pid and not registry.is_alive(st.adopted_pid, st.adopted_ctime):
                    st.adopted_pid, st.adopted_ctime = None, 0
                    exited = True
                    self._down(st, "이어받은 프로세스가 종료됨")

            if st.status == RESTARTING:
                self._try_restart(st)

            if (st.status in (DONE, WARN) and st.module.every_s
                    and st.next_run_at and now >= st.next_run_at):
                self.start(st.name)

        if exited:
            # 죽은 PID 를 등록부에 남겨 두지 않는다. 주기 검사는 30초에 한 번 도는데,
            # 그동안 modules 에 죽은 PID 가 있으면 1번이 엉뚱한 프로세스를 우리 것으로 본다.
            try:
                with registry.edit():
                    pass          # _save 가 살아 있는 것만으로 modules 를 다시 쓴다
            except Exception:
                pass

    def _oneshot_exit(self, st: ModuleState, code: int, now: float) -> None:
        # run_session.py 의 계약: 0 정상 / 1 의심 / 2 검사 실패 / 3 크래시.
        # 3 은 아래 비정상 종료 쪽으로 간다 — 크래시를 의심으로 세지 않는다.
        if code in (0, 1, 2):
            st.status = {0: DONE, 1: DONE, 2: WARN}[code]
            st.detail = {0: "정상", 1: "의심 발견", 2: "검사 실패"}[code]
        else:
            # 비정상 종료. 다음 주기에 다시 부르되, 상주 모듈과 같은 한도를 넘으면 멈춘다.
            st.crash_times = [t for t in st.crash_times if now - t < registry.WINDOW_S] + [now]
            if len(st.crash_times) >= registry.MAX_RESTARTS:
                st.status = FAILED
                st.detail = (f"비정상 종료 {len(st.crash_times)}회 "
                             f"({registry.WINDOW_S / 60:.0f}분 안) — 더 부르지 않음. 로그 확인")
                self.say(f"  ! {st.name} 이 계속 비정상 종료합니다. {st.log_path}")
                return
            st.status = WARN
            st.detail = f"비정상 종료 (code {code}) — 다음 주기에 다시"
        st.next_run_at = time.time() + st.module.every_s if st.module.every_s else 0.0

    def _down(self, st: ModuleState, why: str) -> None:
        if not self._restartable(st):
            st.status = FAILED
            st.detail = f"상주 모듈이 {why} — 재시작 안 함, 로그 확인"
            self.say(f"  ! {st.name} 이 멈췄습니다. {st.log_path}")
            return
        st.status = RESTARTING
        st.detail = f"{why} — 되살리는 중"
        self._try_restart(st)

    def _try_restart(self, st: ModuleState) -> None:
        try:
            status, pid, proc = registry.restart_if_dead(st.name, by="launcher")
        except Exception as e:
            st.detail = f"재시작 시도 실패: {e}"
            return
        if status == registry.RESTARTED:
            st.proc, st.adopted_pid, st.adopted_ctime = proc, None, 0
            st.restarts = len((registry.entry(st.name) or {}).get("restarts", []))
            st.status = RUNNING
            st.started_by = "launcher"
            st.started_at = time.time()
            st.runs += 1
            st.skips = 0
            st.detail = f"런처가 되살림 ({st.restarts}/{registry.MAX_RESTARTS})"
            self.say(f"  ~ {st.name} 을 되살렸습니다 (pid {pid})")
        elif status == registry.ALIVE:
            live = registry.live_pid(st.name)
            if live:
                self._adopt(st, *live)
        elif status == registry.BACKOFF:
            st.detail = "되살리기 전 대기 중 (연속 재시작 간격)"
        elif status == registry.GAVE_UP:
            st.status = FAILED
            st.detail = (f"재시작 한도 초과 ({registry.WINDOW_S / 60:.0f}분에 "
                         f"{registry.MAX_RESTARTS}회) — 로그 확인")
            self.say(f"  ! {st.name} 을 더 되살리지 않습니다. {st.log_path}")
        elif status == registry.SKIP:
            # 등록부를 그 순간 못 읽었을 수도 있다(상대가 파일을 바꿔 끼우는 중).
            # 한 번 못 봤다고 감시를 포기하면 멀쩡한 모듈을 세션 끝까지 버리게 된다.
            st.skips += 1
            if st.skips >= 5:
                st.status = FAILED
                st.detail = "등록부에서 찾을 수 없음 (5회 확인)"
                self.say(f"  ! {st.name} 을 등록부에서 찾을 수 없습니다.")
            else:
                st.detail = f"등록부 확인 실패 {st.skips}/5 — 다시 시도"
        # STOPPING 이면 아무것도 안 한다. 곧 stop_all 이 정리한다.

    def snapshot(self) -> List[dict]:
        return [self.states[n].snapshot() for n in self.states]

    def running_count(self) -> int:
        return sum(1 for s in self.states.values() if s.status == RUNNING)

    # ── 종료 ───────────────────────────────────────────────────────────
    def stop_all(self, grace_s: float = 10.0) -> Dict[str, List[str]]:
        """전부 끝낸다. 요청하고, 기다리고, 그래도 안 끝난 것만 강제로 끈다.

        예전에는 terminate() 로 끝냈다. 윈도에서 그건 TerminateProcess 라 모듈의
        finally·atexit 이 한 줄도 안 돈다. 기다리는 시간(grace)을 두긴 했지만 **이미
        죽인 뒤에** 기다리는 것이라 의미가 없었다. 그래서 input_signature 같은 모듈의
        manifest 가 RUNNING 으로 남았다(UE4SS.md 8번, 성민님 요구).

        자식은 모듈마다 별도 콘솔 프로세스 그룹이다(registry.spawn). 그래서 하나씩
        골라 Ctrl+Break 로 종료를 요청할 수 있다(은지님 9/29 #34 가 이 뼈대를 먼저
        넣었다. 여기에 순서·결과 보고·재입력 방지를 더했다).

        순서
          1. stopping 을 켠다         안 그러면 끄는 사이 워치독이 되살린다
          2. 진행 중인 재시작을 기다린다
          3. 게임 관련 모듈 먼저       탐지기가 먼저 정리를 끝내야 한다
             게임과 무관한 것 나중     SelfDefense·KernelWatcher 는 끝까지 지킨다
             무리마다: 종료 요청(Ctrl+Break) -> grace_s 까지 기다림 -> 남은 것만 강제
          4. 등록부에 남은 것 정리      워치독이 stopping 직전에 띄운 것

        grace_s 는 모듈 하나를 기다리는 기본 시간이다. 10초인 이유: 에임봇·
        external_access 가 끝날 때 중앙 전송을 flush(3초) + shutdown(5초) 한다. 서버가
        죽어 있으면 8초를 다 쓴다. 그보다 짧으면 비우는 도중에 강제로 끊게 된다.
        모듈이 Module.stop_grace_s 를 주면 그 값을 쓴다(input_signature 는 끊을 수 없는
        YARA 검사 한 번 때문에 더 길다). 각자 자기 시한이 오면 그 모듈만 강제로 끈다.
        보통은 1초 안에 끝나므로 이 시간을 다 기다리는 건 정리가 걸린 모듈이 있을 때뿐이다.

        종료하는 동안 런처는 Ctrl+C 를 무시한다. 급해서 한 번 더 누르면 기다리던
        중에 빠져나가 모듈이 고아로 남는다.

        돌려주는 값: {"graceful": [...], "forced": [...], "unsignaled": [...],
                      "defaulted": [...]}
          graceful    요청 후 스스로 끝남
          defaulted   graceful 중 윈도 기본 처리로 끝난 것(0xC000013A). 신호 처리
                      한 줄이 없는 모듈이 이렇게 끝나지만, 한 줄은 있고 KeyboardInterrupt
                      를 안 잡은 모듈도 같은 코드라 정리가 돌았는지는 모른다
          forced      요청은 갔는데 grace_s 안에 안 끝나 강제로 끔
          unsignaled  요청을 못 보내서 바로 강제로 끔 (콘솔이 없거나 다른 콘솔)
        """
        # 두 번째 Ctrl+C / Ctrl+Break 가 기다리는 도중 빠져나가게 하면 모듈이 고아로 남는다.
        sigs = [signal.SIGINT] + ([signal.SIGBREAK] if hasattr(signal, "SIGBREAK") else [])
        prev = {}
        for s in sigs:
            try:
                prev[s] = signal.signal(s, signal.SIG_IGN)
            except (ValueError, OSError):      # 메인 스레드가 아니면 못 바꾼다
                pass
        try:
            return self._stop_all(grace_s)
        finally:
            for s, h in prev.items():
                try:
                    signal.signal(s, h)
                except (ValueError, OSError):
                    pass

    def _stop_all(self, grace_s: float) -> Dict[str, List[str]]:
        try:
            registry.set_stopping()
        except Exception as e:
            self.say(f"  ! 등록부에 종료 표시를 못 했습니다: {e}")

        # 진행 중인 재시작이 끝나기를 기다린다. 되살리는 쪽은 모듈 잠금을 쥐고 있고,
        # 끝낼 때 stopping 을 다시 본다. 안 기다리면 그 프로세스가 등록 전 상태로 남아
        # 아무도 못 끄게 된다.
        for n in self.states:
            try:
                with registry.lock("mod_" + n, timeout=8):
                    pass
            except Exception:
                pass

        out: Dict[str, List[str]] = {"graceful": [], "forced": [], "unsignaled": []}
        game = [s for s in self.states.values() if s.module.needs_game]
        base = [s for s in self.states.values() if not s.module.needs_game]
        for group in (game, base):
            self._stop_group(group, grace_s, out)

        # 등록부에 남은 것까지 끈다. 워치독이 stopping 직전에 띄운 것이 있을 수 있다.
        for e in registry.load().get("entries", {}).values():
            registry.kill(e.get("pid"), e.get("create_time", 0))
        try:
            registry.end_session()
        except Exception:
            pass
        return out

    def _alive(self, st: ModuleState) -> bool:
        if st.proc is not None:
            return st.proc.poll() is None
        if st.adopted_pid:
            return registry.is_alive(st.adopted_pid, st.adopted_ctime)
        return False

    def _stop_group(self, group: List[ModuleState], grace_s: float,
                    out: Dict[str, List[str]]) -> None:
        live = [st for st in group if self._alive(st)]
        for st in group:
            if st not in live and st.status in (RUNNING, RESTARTING):
                st.status = STOPPED
        if not live:
            return

        # 이어받은 프로세스는 생성 시각까지 맞춰 본다(PID 재사용이면 남의 프로세스다).
        # 런처가 띄운 것은 Popen 을 쥐고 있어 재사용될 수 없으므로 시각을 안 넘긴다.
        sent = {st.name: registry.request_stop(
                    st.pid, None if st.proc is not None else st.adopted_ctime)
                for st in live}
        # 모듈마다 기다리는 시간이 다를 수 있다(Module.stop_grace_s). 한 모듈이 길다고
        # 다른 모듈의 강제 종료까지 미루지 않는다 — 각자 자기 시한이 오면 그때 끈다.
        # 요청을 못 보낸 모듈은 기다릴 이유가 없으니 바로 강제 종료 쪽으로 간다.
        start = time.time()
        allowed = {st.name: (st.module.stop_grace_s or grace_s) if sent[st.name] else 0.0
                   for st in live}
        pending = list(live)
        while pending:
            elapsed = time.time() - start
            still = []
            for st in pending:
                if not self._alive(st):
                    self._record_exit(st, out)
                elif elapsed >= allowed[st.name]:
                    self._force(st, sent[st.name], allowed[st.name], out)
                else:
                    still.append(st)
            pending = still
            if pending:
                time.sleep(0.1)

    def _finish(self, st: ModuleState) -> None:
        st.proc = None
        st.adopted_pid, st.adopted_ctime = None, 0
        if st.status in (RUNNING, RESTARTING):
            st.status = STOPPED

    def _record_exit(self, st: ModuleState, out: Dict[str, List[str]]) -> None:
        code = st.proc.returncode if st.proc is not None else None
        st.last_code = code
        if code is not None and (code & 0xFFFFFFFF) == STATUS_CONTROL_C_EXIT:
            # 윈도 기본 처리로 끝났다. 한 줄이 없는 모듈이 이렇게 끝나는데,
            # 한 줄은 있지만 KeyboardInterrupt 를 안 잡은 모듈도 코드가 같다.
            # 그래서 "정리가 안 돌았다" 고 단정하지 않고 모른다고 적는다.
            st.detail = "요청 후 종료 (기본 처리 — 정리 코드가 돌았는지 모름)"
            out.setdefault("defaulted", []).append(st.name)
        else:
            st.detail = "요청 후 종료" + (f" (code {code})" if code is not None else "")
        out["graceful"].append(st.name)
        self._finish(st)

    def _force(self, st: ModuleState, was_sent: bool, waited: float,
               out: Dict[str, List[str]]) -> None:
        # 여기까지 와야 강제로 끈다. 정리 코드는 안 돈다.
        if st.proc is not None:
            registry._kill_proc(st.proc)
        elif st.adopted_pid:
            registry.kill(st.adopted_pid, st.adopted_ctime)
        if was_sent:
            st.detail = f"강제 종료 — 요청 후 {waited:g}초 안에 안 끝남"
            out["forced"].append(st.name)
        else:
            st.detail = "강제 종료 — 종료 요청을 보내지 못함"
            out["unsignaled"].append(st.name)
        self.say(f"  - {st.name} {st.detail}")
        self._finish(st)
