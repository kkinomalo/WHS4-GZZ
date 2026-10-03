"""MECCHA 안티치트 런처.

사용자가 LocalGuard·SelfDefense·KernelWatcher·탐지기·게임을 각각 찾아 실행하지
않도록, 이것 하나가 순서대로 켜고 상태를 보여주고 끝날 때 정리한다.
나중에 MecchaAntiCheat.exe 로 패키징할 대상이다.

    python client/Launcher/main.py
    python client/Launcher/main.py --session test_001 --player rang_pc1
    python client/Launcher/main.py --no-launch-game     # 게임은 내가 직접 켠다
    python client/Launcher/main.py --only memory_integrity,whistle_spoofing

## 켜는 순서

    1. 게임과 무관한 것 먼저   SelfDefense, KernelWatcher
       게임이 뜨는 순간부터 보고 있어야 하므로 게임보다 앞선다.
    2. 게임
    3. 게임이 실제로 뜰 때까지 대기
    4. 게임이 있어야 의미가 있는 것   LocalGuard 3종, 핵별 탐지기
       게임이 없으면 이 모듈들은 OFFLINE 만 찍는다. 그건 "깨끗함"이 아니라
       "검사를 못 한 것"이라, 굳이 그 상태로 로그를 쌓지 않는다.
    5. 게임이 꺼지면 전부 정리

## 안 만들어진 모듈이 있어도 멈추지 않는다

지금(10/1) SelfDefense·KernelWatcher 는 등록된 경로에 코드가 없다. 없는 모듈에서
런처가 죽으면 다른 사람이 자기 것을 시험해볼 수 없다. **없으면 MISSING 으로
보여주고 나머지를 계속 띄운다.** 조용히 넘기지도 않는다 — 아직 안 만든 것과
만들었는데 안 붙는 것은 원인이 다르다.
"""

import argparse
import datetime
import hashlib
import os
import platform
import re
import shutil
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import game_launcher                                          # noqa: E402
import registry                                               # noqa: E402
import self_hook_manifest                                     # noqa: E402
import ui                                                     # noqa: E402
from modules import MODULES, REPO                              # noqa: E402
from process_manager import MISSING, RUNNING, ProcessManager, SKIPPED, is_admin  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PLAYER_FILE = os.path.join(HERE, "player_id.txt")

# 이름 규칙은 **받는 쪽 중에서 제일 좁은 것**에 맞춘다. 런처가 통과시켜 놓고
# 모듈 하나만 조용히 죽는 것보다, 시작할 때 다 같이 막히는 편이 낫다.
#   player : shared 는 [A-Za-z0-9_.-]{1,128}, input_signature 는 1~100자
#   session: input_signature 가 [A-Za-z0-9][A-Za-z0-9_-]{0,79} (점을 안 받는다)
PLAYER_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}\Z")
SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-]{0,79}\Z")


def resolve_player_id(given):
    """이 PC 의 player_id 를 정한다. (값, 어디서 왔는지, 처음 만들었는지)

    기본값을 `player_001` 하나로 두면 **모든 PC 가 같은 id 로 보낸다.** 표본이
    한 PC 에서 나왔는지 여러 PC 에서 나왔는지 구분할 수 없게 되는데, 그게 지금
    우리 측정의 제일 큰 구멍이라 기본값으로 둘 수가 없다.

    그래서 처음 실행할 때 이 PC 몫의 id 를 만들어 파일에 남긴다. 컴퓨터 이름을
    해시해서 쓴다 — PC 마다 다르고, 같은 PC 면 파일을 지워도 같은 값이 나오고,
    사람 이름이나 하드웨어 정보가 그대로 들어가지 않는다.
    (7번 송희님이 "실제 사용자명·개인정보는 player_id 에 넣지 말자" 고 했다.)

    알아보기 쉬운 이름을 쓰고 싶으면 파일을 고치거나 `--player` 를 주면 된다.
    그때도 사람 본명보다 팀에서 쓰는 짧은 호칭을 권한다.
    """
    if given:
        return given, "--player", False
    env = (os.environ.get("GZZ_PLAYER_ID") or "").strip()
    if env:
        return env, "GZZ_PLAYER_ID", False
    try:
        with open(PLAYER_FILE, encoding="utf-8") as f:
            saved = f.read().strip()
        if saved:
            return saved, os.path.relpath(PLAYER_FILE, REPO), False
    except FileNotFoundError:
        pass
    except OSError:
        pass
    node = platform.node() or "unknown"
    made = "pc_" + hashlib.sha256(node.encode("utf-8", "replace")).hexdigest()[:8]
    try:
        with open(PLAYER_FILE, "w", encoding="utf-8") as f:
            f.write(made + "\n")
    except OSError:
        # 파일을 못 써도 이번 실행은 그대로 간다. 컴퓨터 이름에서 나오는 값이라
        # 다음에 또 돌려도 같은 id 가 나온다.
        return made, "자동(저장 실패)", True
    return made, os.path.relpath(PLAYER_FILE, REPO), True


def existing_sessions(picked, session):
    """이 세션 이름으로 이미 쌓인 로그가 있는지 본다.

    주기 검사 모듈은 한 세션 안에서 여러 번 실행되므로 **누적 파일**에 쓴다
    (`--log-name`). 그래서 run_session.py 의 "같은 이름 거부" 가 걸리지 않는다.
    그대로 두면 런처를 같은 이름으로 두 번 돌렸을 때 두 실행이 한 파일에 섞이고,
    시각이 되돌아가 replay_export 가 **측정이 다 끝난 뒤에** 거부한다.
    실제로 첫 실전(run_001)에서 그렇게 됐다. 그래서 시작 전에 막는다.

    모듈마다 세션을 담는 모양이 다르다. 2번·휘파람은 `<세션>.jsonl` 파일이고,
    input_signature 는 `<세션>/` 폴더다(replay_events.py 가 `exist_ok=False` 로
    만들기 때문에 이미 있으면 **시작하자마자 죽는다**). 둘 다 본다.
    """
    found = []
    for m in picked:
        if not m.session_log_dir:
            continue
        base = os.path.join(REPO, m.session_log_dir)
        for p in (os.path.join(base, f"{session}.jsonl"), os.path.join(base, session)):
            if os.path.exists(p):
                found.append(os.path.relpath(p, REPO))
    return found


def preflight(pm, only):
    ui.line("=" * 76)
    ui.line("  MECCHA 안티치트 런처")
    ui.line("=" * 76)
    if not is_admin():
        ui.line("  ! 관리자 권한이 아닙니다. 커널 모듈은 건너뜁니다.")
    missing = [s for s in pm.states.values() if s.status == MISSING]
    if missing:
        ui.line("")
        ui.line("  아직 안 올라온 모듈 (런처는 그대로 진행합니다):")
        for s in missing:
            ui.line(f"    - {s.name:<18} {s.detail}")
    if only:
        ui.line(f"  --only: {', '.join(only)}")
    root = publish_game_dir()
    if root:
        ui.line(f"  게임 폴더: {root}")
    else:
        ui.line("  ! 게임 폴더를 못 찾았습니다. 스팀으로 띄우고, 게임이 뜨면 다시 봅니다.")
        ui.line("    직접 지정하려면 GZZ_GAME_DIR 환경변수를 쓰세요.")


def report_stop(ended):
    """누가 스스로 끝났고 누가 강제로 끝났는지 보여준다.

    강제로 끝난 모듈은 정리 코드가 안 돌았다. manifest 가 RUNNING 으로 남았을
    수 있으니, 그 세션 로그를 쓸 사람은 알아야 한다. 조용히 넘기지 않는다.
    """
    g, f, u = ended.get("graceful", []), ended.get("forced", []), ended.get("unsignaled", [])
    d = ended.get("defaulted", [])
    if not (g or f or u):
        return
    ui.line(f"  정리 결과: 요청 후 종료 {len(g)}  /  강제 종료 {len(f) + len(u)}")
    if d:
        ui.line(f"    기본 처리로 끝남(정리 코드가 돌았는지 모름): {', '.join(d)}")
    if f:
        ui.line(f"    요청은 갔는데 제때 안 끝남: {', '.join(f)}")
    if u:
        ui.line(f"    요청을 못 보냄(콘솔 없음 등): {', '.join(u)}")
    if d or f or u:
        ui.line("    위 모듈은 manifest 가 RUNNING 으로 남았을 수 있습니다. 모듈 시작부에")
        ui.line("    아래 한 줄이 있으면 Ctrl+Break 가 KeyboardInterrupt 로 바뀌어 finally 가 돕니다.")
        ui.line("      signal.signal(signal.SIGBREAK, signal.default_int_handler)")


def publish_game_dir(refresh=False):
    """찾은 게임 폴더를 자식 모듈들에게 환경변수로 알려준다.

    탐지기마다 게임 폴더를 따로 추측하고 있다 — filesystem 은 하드코딩 3줄,
    런처는 또 다른 한 줄이었다. 서로 다른 값을 쓰면 한쪽은 훑고 한쪽은 못 훑는다.
    런처가 이미 알고 있으니 알려주고, 자식은 환경을 물려받는다.

    게임이 뜬 뒤에 `refresh=True` 로 다시 부르면 프로세스에서 얻은 확실한
    경로로 갱신된다. 스팀 라이브러리 추정보다 그쪽이 정확하다.

    두 층을 다 내보낸다. 이름을 하나로 쓰면 받는 쪽마다 다른 층을 뜻하게 된다.
        GZZ_GAME_ROOT  ...\\MECCHA CHAMELEON                 (filesystem 이 훑는 층)
        GZZ_GAME_BIN   ...\\Chameleon\\Binaries\\Win64        (exe·UE4SS 가 있는 층)
    """
    if refresh:
        game_launcher._cache.clear()
    root = game_launcher.find_game_root()
    if root:
        os.environ["GZZ_GAME_ROOT"] = root
        os.environ["GZZ_GAME_BIN"] = game_launcher.find_game_dir()
    return root


def publish_self_hook_manifest(hooks):
    """Freeze exact hashes of approved observer hooks before detectors start.

    This manifest is intentionally separate from the UE4SS install manifest:
    observer hooks live under this repository, not under the game install root.
    Failure is visible but does not silently broaden the exception; the module
    integrity detector will then treat a later hook load as unreviewed.
    """
    try:
        data = self_hook_manifest.record(hooks)
    except (OSError, RuntimeError, ValueError) as error:
        # Do not let a stale manifest from an earlier session silently grant an
        # exception after this session's explicit selection failed validation.
        os.environ[self_hook_manifest.ENV_PATH] = str(
            self_hook_manifest.path_for().with_name("self_hook_manifest.invalid")
        )
        ui.line(
            "  ! 자체 관측 후크 manifest를 만들지 못했습니다: "
            f"{type(error).__name__}"
        )
        return None
    os.environ[self_hook_manifest.ENV_PATH] = str(self_hook_manifest.path_for())
    return data


def main(argv=None):
    # 런처도 모듈과 같은 약속을 지킨다 — Ctrl+Break 를 받으면 Ctrl+C 처럼 정리하고
    # 끝난다. 나중에 Dashboard 나 배치 스크립트가 런처를 끌 때 쓸 수 있는 문이다.
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, signal.default_int_handler)
        except (ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(description="MECCHA 안티치트 런처")
    ap.add_argument("--session", help="세션 id (기본: 시각으로 자동 생성)")
    ap.add_argument("--player", help="이 PC 의 player_id. 기본은 player_id.txt 를 읽고, "
                                     "없으면 컴퓨터 이름으로 하나 만들어 거기에 저장한다")
    ap.add_argument("--only", help="쉼표로 구분한 모듈 이름만 실행")
    ap.add_argument("--no-launch-game", action="store_true",
                    help="게임을 띄우지 않고, 이미 떠 있는 게임을 기다린다")
    ap.add_argument("--wait-game", type=float, default=180.0, metavar="SEC",
                    help="게임이 뜨기를 기다리는 시간 (기본 180초)")
    ap.add_argument("--status-every", type=float, default=10.0, metavar="SEC",
                    help="상태 화면을 몇 초마다 그릴지 (기본 10초)")
    ap.add_argument("--overwrite", action="store_true",
                    help="같은 세션 이름의 기존 로그를 지우고 다시 쓴다")
    ap.add_argument(
        "--self-hook",
        type=os.path.abspath,
        action="append",
        default=[],
        metavar="DLL",
        help=("이번 세션에 실제로 주입할 승인된 관측 후크 경로. "
              "현재 ac_whistle_v10.dll만 허용하며 반복 지정 가능"),
    )
    a = ap.parse_args(argv)

    session = a.session or ("ac_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    if not SESSION_RE.match(session):
        ui.line(f"세션 이름 '{session}' 은 쓸 수 없습니다.")
        ui.line("  영문·숫자로 시작하고, 영문·숫자·_·- 만 80자까지 (점은 안 됩니다).")
        ui.line("  input_signature 가 이 이름으로 폴더를 만들기 때문에 여기서 막습니다.")
        return 2

    player, player_src, player_made = resolve_player_id(a.player)
    if not PLAYER_RE.match(player):
        ui.line(f"player_id '{player}' 는 쓸 수 없습니다. ({player_src})")
        ui.line("  영문·숫자·_·.·- 만 64자까지. 중앙 전송(shared)이 이 규칙을 검사합니다.")
        return 2

    only = [s.strip() for s in a.only.split(",")] if a.only else None
    picked = [m for m in MODULES if not only or m.name in only]
    if only:
        unknown = set(only) - {m.name for m in MODULES}
        if unknown:
            ui.line(f"알 수 없는 모듈: {', '.join(sorted(unknown))}")
            ui.line(f"등록된 것: {', '.join(m.name for m in MODULES)}")
            return 2

    old = existing_sessions(picked, session)
    if old:
        if not a.overwrite:
            ui.line(f"세션 '{session}' 기록이 이미 있습니다:")
            for p in old:
                ui.line(f"    {p}")
            ui.line("새 --session 이름을 쓰세요. 지우고 다시 하려면 --overwrite.")
            return 2
        for p in old:
            full = os.path.join(REPO, p)
            shutil.rmtree(full) if os.path.isdir(full) else os.remove(full)
            ui.line(f"  지움: {p}")

    if player_made:
        ui.line(f"  이 PC 의 player_id 를 새로 만들었습니다: {player}")
        ui.line(f"    {player_src} 에 저장했습니다. 알아보기 쉬운 이름으로 바꿔도 됩니다.")

    # 세션 전체가 같은 시계를 쓴다. 주기 검사는 실행마다 새 프로세스라
    # 이걸 안 넘기면 시각이 매번 0 으로 되돌아가고 타임라인이 깨진다.
    t0 = time.time()
    try:
        pm = ProcessManager(picked, session, player, t0, say=ui.line)
    except registry.LauncherAlreadyRunning as e:
        ui.line(str(e))
        ui.line("먼저 뜬 런처를 끝내고 다시 실행하세요.")
        return 2
    preflight(pm, only)

    ctx = {"session": session, "game_pid": None, "server": "미연결"}
    code = 0
    try:
        ui.line("")
        ui.line("  [1/4] 게임과 무관한 모듈 시작")
        pm.start_group(needs_game=False)

        pid = game_launcher.find_game_pid()
        if pid is None and not a.no_launch_game:
            ui.line("  [2/4] 게임 실행")
            if not game_launcher.launch():
                ui.line("      게임을 띄우지 못했습니다. 직접 켜 주세요.")
        elif pid is not None:
            ui.line(f"  [2/4] 게임이 이미 떠 있습니다 (PID {pid})")

        if pid is None:
            ui.line(f"  [3/4] 게임을 기다리는 중 (최대 {a.wait_game:.0f}초)")
            pid = game_launcher.wait_for_game(a.wait_game)
        if pid is None:
            ui.line("  게임이 뜨지 않아 종료합니다. 게임을 켜고 다시 실행해 주세요.")
            return 2
        ctx["game_pid"] = pid
        pm.set_game_pid(pid)
        # 게임이 떴으니 이제 추정이 아니라 프로세스에서 경로를 얻을 수 있다.
        # 게임 관련 모듈을 띄우기 **전에** 갱신해야 그 값을 물려받는다.
        found = publish_game_dir(refresh=True)
        if found:
            ui.line(f"      게임 폴더: {found}")

        hook_manifest = publish_self_hook_manifest(a.self_hook)
        if hook_manifest and hook_manifest.get("hooks"):
            ui.line(
                "      안티치트 자체 관측 후크: "
                f"{len(hook_manifest['hooks'])}개 해시 등록"
            )

        ui.line("  [4/4] 게임 관련 모듈 시작")
        pm.start_group(needs_game=True)

        ui.line("")
        ui.line("  Ctrl+C 로 종료합니다. 게임이 꺼져도 자동으로 정리합니다.")
        last_draw = 0.0
        while True:
            pm.poll()
            if game_launcher.find_game_pid() is None:
                ui.line("")
                ui.line("  게임이 종료되었습니다. 모듈을 정리합니다.")
                break
            now = time.time()
            if now - last_draw >= a.status_every:
                ui.render(pm.snapshot(), ctx)
                last_draw = now
            time.sleep(0.5)
    except KeyboardInterrupt:
        ui.line("")
        ui.line("  중단합니다.")
    finally:
        # 이 안내 문구 때문에 정리가 막히면 안 된다. 여기서 예외가 나면 아래 stop_all 이
        # 안 불려 모듈이 전부 고아로 남는다(9/30 에 실제로 그렇게 됐다).
        try:
            # 게임 관련 무리를 다 끈 뒤에 나머지를 끄므로, 최악은 두 무리 최댓값의 합이다.
            running = [s for s in pm.states.values() if s.status == RUNNING]
            longest = sum(max([s.module.stop_grace_s or 10.0 for s in running
                               if s.module.needs_game == g] or [0.0]) for g in (True, False))
            ui.line(f"  모듈을 정리합니다. 다시 Ctrl+C 를 누르지 마세요 (길면 {longest:.0f}초쯤).")
        except Exception:
            ui.line("  모듈을 정리합니다. 다시 Ctrl+C 를 누르지 마세요.")
        ended = pm.stop_all()
        ui.render(pm.snapshot(), ctx)
        ui.line("")
        report_stop(ended)
        ui.line(f"  세션 {session} 종료. 모듈 로그: client/Launcher/logs/")

    # 런처 자체의 성공/실패만 돌려준다. 탐지 결과는 각 모듈 로그에 있다.
    failed = [s for s in pm.states.values()
              if s.status == "FAILED"]
    if failed:
        ui.line(f"  ! 비정상 종료한 모듈 {len(failed)}개: "
                + ", ".join(s.name for s in failed))
        code = 1
    return code


if __name__ == "__main__":
    sys.exit(main())
