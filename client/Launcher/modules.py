"""런처가 실행할 모듈 등록표.

**팀원이 자기 모듈을 런처에 붙이려면 이 파일에 한 줄만 추가하면 된다.**
런처 본체(main.py, process_manager.py)는 건드릴 필요가 없다.

등록표를 코드 밖으로 빼둔 이유는 하나다. 붙이는 사람과 돌리는 사람이 다르면
"내 모듈이 안 붙는다"는 말이 나오는데, 그때 고칠 곳이 한 군데여야 한다.

## 실행 방식이 모듈마다 다르다 — 확인하고 적은 것

  external_access   상대 import(`from ..common import`)를 써서 **`-m` 으로만** 돈다.
                    `python runner.py` 로 직접 실행하면 ImportError 가 난다.
  autopaint         `-m` 으로 띄운다. 스크립트로 띄우면 sys.path[0] 이 모듈 폴더라
                    레포 루트의 shared 를 못 찾고, 서버 설정이 있으면 시작을 거부한다.
                    `-m` 은 실행 위치(레포 루트)를 sys.path 에 넣어 준다.
  나머지            `python <경로>/main.py` 로 돈다. 파이썬이 스크립트 폴더를
                    sys.path[0] 에 넣어주기 때문에 자기 옆 모듈을 찾는다.

추측하지 않고 실제로 `--help` 를 돌려서 확인했다(2026-09-27).
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 이 파일은 client/Launcher/ 에 있다. 레포 루트는 두 단계 위.
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

GAME_EXE = "PenguinHotel-Win64-Shipping.exe"

# 게임 설치 위치의 **마지막 기본값**. 실제 탐색은 game_launcher.find_game_dir()
# 이 한다 (환경변수 -> 떠 있는 프로세스 -> 스팀 라이브러리 -> 이 값).
# 여기를 직접 쓰면 이 경로가 아닌 PC 에서 게임 폴더를 못 찾는다.
GAME_DIR = (r"C:\Program Files (x86)\Steam\steamapps\common"
            r"\MECCHA CHAMELEON\Chameleon\Binaries\Win64")

# 실행 방식
ONESHOT = "oneshot"        # 한 번 돌고 끝난다. 주기 검사는 런처가 다시 부른다
CONTINUOUS = "continuous"  # 자기가 알아서 계속 돈다


@dataclass
class Module:
    name: str
    owner: str                      # 누구 담당인지. 안 붙을 때 물어볼 사람
    # {session} {player} {t0} {window} {game_bin} {telemetry} 를 쓸 수 있다.
    # {telemetry} 는 GZZ_TELEMETRY_URL 이 있으면 "managed", 없으면 "off".
    argv: List[str]
    mode: str = CONTINUOUS
    cwd: Optional[str] = None       # None 이면 레포 루트
    needs_game: bool = True         # 게임이 떠 있어야 의미가 있는가
    needs_admin: bool = False       # 관리자 권한이 필요한가
    every_s: float = 0.0            # ONESHOT 을 몇 초마다 다시 부를지 (0 이면 한 번만)
    # CONTINUOUS 가 죽으면 되살릴지. 런처와 워치독이 둘 다 되살린다(registry.py).
    # 되살리면 안 되는 모듈(예: 한 번 적재하고 끝나야 하는 드라이버)이면 False.
    restart: bool = True
    # 끌 때 종료 요청 뒤 스스로 끝나기를 기다리는 시간(초). None 이면 런처 기본값
    # (process_manager.stop_all 의 grace_s, 10초). 정리 전에 끝나지 않는 긴 작업
    # (예: 끊을 수 없는 한 번의 YARA 검사)이 있는 모듈만 늘린다.
    stop_grace_s: Optional[float] = None
    # 이 모듈이 세션 로그(<세션>.jsonl)를 쓰는 폴더. 런처가 시작 전에
    # "그 세션 이름이 이미 있는지" 를 보려고 쓴다. 레포 루트 기준 상대경로.
    session_log_dir: str = ""
    # (옵션, 경로) — 자리표시자를 채운 경로가 실제로 있을 때만 argv 끝에 붙인다.
    # 게임 쪽 UE4SS 모드 폴더처럼 PC 마다 깔렸을 수도 안 깔렸을 수도 있는데,
    # 없는 경로를 넘기면 모듈이 시작을 거부하는 경우에 쓴다.
    optional_paths: List[Tuple[str, str]] = field(default_factory=list)
    note: str = ""

    @staticmethod
    def _fill(a: str, ctx: Dict[str, object]) -> str:
        for k, v in ctx.items():
            a = a.replace("{" + k + "}", str(v))
        return a

    def resolved(self, ctx: Dict[str, object]) -> List[str]:
        """자리표시자를 채운 실제 명령.

        `{window}` 는 실행할 때마다 달라지므로 시작 시점에 채운다.
        `{t0}` 는 세션 전체가 같은 시계를 쓰게 하려고 넘긴다 — 주기 검사는
        실행마다 새 프로세스라, 안 넘기면 시각이 매번 0 으로 되돌아간다.
        """
        out = [self._fill(a, ctx) for a in self.argv]
        for opt, path in self.optional_paths:
            p = self._fill(path, ctx)
            if os.path.exists(p):
                out += [opt, p]
        return out

    def missing_optional(self, ctx: Dict[str, object]) -> List[str]:
        """경로가 없어서 resolved() 가 뺀 옵션 이름들."""
        return [opt for opt, path in self.optional_paths
                if not os.path.exists(self._fill(path, ctx))]

    def script_path(self) -> Optional[str]:
        """존재 여부를 확인할 파일. `-m` 실행이면 모듈 경로로 바꿔 본다."""
        if "-m" in self.argv:
            mod = self.argv[self.argv.index("-m") + 1]
            return os.path.join(REPO, *mod.split(".")) + ".py"
        for a in self.argv[1:]:
            if a.endswith(".py"):
                return a if os.path.isabs(a) else os.path.join(REPO, a)
        return None


PY = sys.executable

# input_signature 의 YARA 검사 한 번 제한(초). 종료 요청은 진행 중인 검사가 끝나야
# 처리되므로(rules.match 는 중간에 못 끊는다) 끌 때 기다리는 시간도 이 값에 맞춘다.
# 동효님 실측: 평가 한 번에 20초~1분(9/30). 둘을 따로 바꾸면 검사 도중 강제 종료돼
# manifest 가 running 으로 남는다. 그래서 한 곳에서 같이 정한다.
YARA_TIMEOUT_S = 45

MODULES: List[Module] = [
    # ── 게임과 무관하게 먼저 뜨는 것 ────────────────────────────────────
    Module(
        name="self_defense",
        owner="4번 (성민)",
        argv=[PY, "client/SelfDefense/main.py"],
        needs_game=False,
        note="워치독·안티디버깅·자체 무결성. 진입점은 이 경로로 확정(2026-09-29 성민님)",
    ),
    Module(
        name="kernel_watcher",
        owner="5번 (찬준)",
        argv=[PY, "client/KernelWatcher/main.py"],
        needs_game=False,
        needs_admin=True,          # 드라이버를 올려야 한다
        note="커널 프로세스·드라이버 관측. 아직 폴더가 비어 있다",
    ),

    # ── 게임이 떠 있어야 하는 것 ────────────────────────────────────────
    Module(
        name="external_access",
        owner="1번 (은지·지완)",
        argv=[PY, "-m", "client.LocalGuard.external_access.process_access.runner",
              "--game-exe", GAME_EXE,
              "--session-id", "{session}", "--player-id", "{player}",
              # 은지님 #43 에서 받게 됐다. 안 넘기면 timestamp_ms 가 이 프로세스 시작
              # 기준이라 다른 모듈과 시간축이 갈린다.
              "--t0", "{t0}",
              "--output", "client/LocalGuard/external_access/logs/external_access.jsonl"],
        mode=CONTINUOUS,
        note="위험 핸들 감시. 상대 import 라 -m 으로만 돈다",
    ),
    Module(
        name="module_integrity",
        owner="1번 (지완)",
        argv=[PY, "-m", "client.LocalGuard.external_access.module_integrity.runner",
              "--game-exe", GAME_EXE, "--game-pid", "{game_pid}",
              "--session-id", "{session}", "--player-id", "{player}",
              "--t0", "{t0}",
              "--output", "client/LocalGuard/external_access/logs/module_integrity.jsonl"],
        mode=CONTINUOUS,
        optional_paths=[("--game-root", "{game_root}")],
        note="게임 DLL 기준선·추가·변경 감시. shared 0.2.0 공통 이벤트 전송",
    ),
    Module(
        name="input_signature",
        owner="3번 (동효)",
        argv=[PY, "client/LocalGuard/input_signature/yara_scanner.py",
              "--session-id", "{session}", "--player-id", "{player}",
              # 동효님 #51 부터 받는다. Event·하트비트·ON/OFF 표식이 런처 세션 시작
              # 기준으로 찍힌다. --seconds 는 여전히 이 검사기 자체 실행 시간이다.
              "--t0", "{t0}",
              "--timeout", str(YARA_TIMEOUT_S)],
        # 검사 한 번 + manifest 마무리(하트비트 전송 제한 3초 등) 여유.
        stop_grace_s=YARA_TIMEOUT_S + 10,
        # 세션 폴더를 exist_ok=False 로 만든다(replay_events.py ReplaySession).
        # 같은 --session-id 로 되살리면 반드시 FileExistsError 로 다시 죽어서,
        # 되살릴수록 재시작 예산만 태운다. 경로 설계가 바뀌면 True 로 되돌린다.
        restart=False,
        session_log_dir="client/LocalGuard/input_signature/sessions",
        # --auto-external-python 은 일부러 안 넘긴다. 그 옵션은 같은 세션의
        # python.exe 를 후보로 삼고 게임·자기자신·자기 부모만 빼기 때문에,
        # 런처가 띄운 다른 파이썬 탐지기를 검사 대상으로 잡는다(자기탐지).
        note="Raw Input 대조·YARA·해시. --seconds 기본 0 이라 끝까지 돈다",
    ),
    Module(
        name="memory_integrity",
        owner="2번 (재민·랑언)",
        argv=[PY, "client/LocalGuard/memory_integrity/run_session.py",
              "--session", "{session}", "--player", "{player}",
              "--log-name", "{session}", "--t0", "{t0}", "--window", "{window}"],
        mode=ONESHOT,
        every_s=30.0,
        session_log_dir="client/LocalGuard/memory_integrity/logs/detection",
        note="값 변조·코드 무결성·후킹. 한 번 스캔에 수 초~10초대라 주기 검사다",
    ),
    Module(
        name="whistle_spoofing",
        owner="휘파람 (랑언)",
        argv=[PY, "client/detectors/whistle-spoofing/main.py",
              "--session", "{session}", "--player", "{player}",
              "--log-name", "{session}", "--t0", "{t0}", "--window", "{window}"],
        mode=ONESHOT,
        every_s=30.0,
        session_log_dir="client/detectors/whistle-spoofing/logs/detection",
        note="휘파람 후킹 흔적 + 도발 RPC",
    ),
    Module(
        name="aimbot",
        owner="에임봇 (은지)",
        argv=[PY, "client/detectors/aimbot/main.py",
              "--session-id", "{session}", "--player-id", "{player}", "--from-end",
              "--t0", "{t0}",
              "--event-log", "client/detectors/aimbot/logs/detection/{session}.jsonl",
              # 기본값이 C:\Program Files (x86)\... 고정이라 게임이 다른 곳에 있으면
              # 영영 기다린다. 런처가 찾은 게임 폴더로 준다. DamageLogger Lua 는 #43 부터
              # 스크립트 위치 기준으로 <game_bin>\ue4ss\Mods\DamageLogger\ 에 써서
              # 이 경로와 파일 이름까지 같다.
              "--log-path", r"{game_bin}\ue4ss\Mods\DamageLogger\meccha_aim_telemetry.jsonl"],
        mode=CONTINUOUS,
        session_log_dir="client/detectors/aimbot/logs/detection",
        # 결과의 session_id/player_id 를 이 값으로 바꾸고 UE 값은 evidence 로 옮긴다.
        # 안 넘기면 UE 액터 경로가 player_id 에 들어가 중앙 전송이 로컬에서 거절된다.
        # --from-end: 텔레메트리 파일은 모드가 로드될 때만 비워져서 이전 게임 기록이
        # 남아 있을 수 있다. 처음부터 읽으면 그 기록이 지금 세션 이름으로 나가고,
        # 되살릴 때마다 같은 결과를 새 event_id 로 또 보낸다.
        note="UE4SS DamageLogger 텔레메트리",
    ),
    Module(
        name="esp",
        owner="ESP (지완)",
        argv=[PY, "client/detectors/esp/run.py", "--headless",
              "--session-id", "{session}", "--player-id", "{player}",
              "--t0", "{t0}", "--central-telemetry", "{telemetry}"],
        mode=CONTINUOUS,
        restart=False,
        session_log_dir="client/detectors/esp/data/sessions",
        note="외부 핸들·오버레이·로드 모듈 ESP 정황을 Sensor/Detector로 판정",
    ),
    Module(
        name="godmode",
        owner="GodMode (재민)",
        # 위치 인자로 넘긴다. main.py 가 argparse 없이 sys.argv[1], [2] 만 읽어서,
        # --session-id 같은 이름 인자를 주면 세션 이름이 '--session-id' 로 조용히
        # 나간다(shared 형식 검사도 통과한다, 9/30 실측). --t0 도 아직 못 받는다.
        # 재민님이 argparse·--t0 을 넣으면 에임봇처럼 이름 인자로 바꾼다.
        argv=[PY, "client/detectors/godmode/main.py", "{session}", "{player}"],
        mode=CONTINUOUS,
        # 텔레메트리 경로는 일부러 안 넘긴다. Lua 와 파이썬이 둘 다 기본값
        # %LOCALAPPDATA%\MECCHA-GZZ-godmode-telemetry.jsonl 을 쓴다.
        # GZZ_GODMODE_TELEMETRY_PATH 는 게임 프로세스 쪽 환경변수라 스팀으로 켰거나
        # 이미 떠 있는 게임에는 안 간다 — 런처가 파이썬 쪽에만 주면 둘이 갈라진다.
        # 시작할 때 파일 끝부터 읽어서(start_at_end) 이전 기록 재방출은 없다.
        #
        # 시작할 때 replay_exports/<세션>/ 의 events.jsonl·raw 를 비우고 시간도 0 부터
        # 다시 센다. 되살리면 그 세션 로컬 기록이 지워진다(9/30 실측 3줄 -> 0줄).
        restart=False,
        # 결과 폴더는 main.py 위치 기준 replay_exports/<세션>/ (gitignore). 같은 세션
        # 이름을 다시 쓰면 시작 전에 막는다.
        session_log_dir="client/detectors/godmode/replay_exports",
        note="UE4SS GodModeTelemetry JSONL 판정. 모드가 없어도 조용히 기다린다",
    ),
    Module(
        name="noclip",
        owner="Noclip (송희)",
        argv=[PY, "client/detectors/noclip/main.py",
              "--session-id", "{session}", "--player-id", "{player}",
              # 송희님 #46: 시작 전에 있던 CSV 행은 건너뛰고(이전 게임 기록 재방출 방지),
              # 시간은 런처 세션 기준으로 맞춘다.
              "--from-end", "--t0", "{t0}",
              # NoclipLogger Lua 가 #46 부터 스크립트 위치 기준으로
              # <game_bin>\ue4ss\Mods\NoclipLogger\noclip_log.csv 에 써서 이 경로와 같다.
              "--log-file", r"{game_bin}\ue4ss\Mods\NoclipLogger\noclip_log.csv",
              # 기본값이 실행 위치 기준이라 그대로면 레포 루트에 생긴다. 세션마다 따로 둔다.
              "--event-file", "client/Launcher/logs/noclip/{session}/events.jsonl",
              "--result-file", "client/Launcher/logs/noclip/{session}/detection_results.csv"],
        mode=CONTINUOUS,
        # --from-end 로 재방출은 막혔지만, 시작할 때 events.jsonl 을 여전히 비운다.
        # 되살리면 그 세션 로컬 기록이 지워진다. 이어쓰기로 바뀌면 True 로 되돌린다.
        restart=False,
        session_log_dir="client/Launcher/logs/noclip",
        note="UE4SS NoclipLogger CSV 를 읽어 점수로 판정",
    ),
    Module(
        name="autopaint",
        owner="AutoPaint (성민)",
        # -m 으로 띄워야 레포 루트의 shared 를 찾는다(맨 위 설명).
        argv=[PY, "-m", "client.detectors.autopaint.main",
              "--session-id", "{session}", "--player-id", "{player}",
              "--process-name", GAME_EXE,
              # 기본값 managed 는 서버 설정이 없으면 시작을 거부한다. 설정이 없을 때는
              # 다른 모듈처럼 로컬 기록만 하도록 off 를 준다.
              "--telemetry", "{telemetry}",
              # 기본값 logs/ 는 실행 위치 기준이라 그대로면 레포 루트에 생긴다.
              "--output-dir", "client/Launcher/logs/autopaint"],
        # GZZPaintObserver 가 안 깔린 PC 에서 이 옵션을 주면 시작을 거부한다
        # (Scripts/main.lua 확인). 빼면 행동 탐지 없이 DLL·런타임 검사만 한다.
        optional_paths=[("--lua-mod-dir", r"{game_bin}\ue4ss\Mods\GZZPaintObserver")],
        mode=CONTINUOUS,
        # <output-dir>/<세션>/ 을 exist_ok=False 로 만든다. 같은 세션으로 되살리면
        # FileExistsError 로 바로 다시 죽는다.
        restart=False,
        session_log_dir="client/Launcher/logs/autopaint",
        # --t0 는 아직 못 받는다. timestamp_ms 는 이 탐지기 자체 시작 기준이다.
        note="AutoPaint DLL·런타임 + GZZPaintObserver 행동 판정",
    ),
]


def by_name() -> Dict[str, Module]:
    return {m.name: m for m in MODULES}
