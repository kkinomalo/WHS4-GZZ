"""외부 process handle 수집·판정·로컬 JSONL 기록을 연결하는 실행기."""

import argparse
import os
import signal
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# The shared package is versioned under shared/GZZ-Shared-0.1.0 rather than
# installed as a top-level dependency. Put that package root first so
# ``import shared`` resolves to the team's shared client.
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
VERSIONED_SHARED_ROOT = REPOSITORY_ROOT / "shared" / "GZZ-Shared-0.1.0"
SHARED_PACKAGE_ROOT = (
    VERSIONED_SHARED_ROOT if (VERSIONED_SHARED_ROOT / "shared").is_dir()
    else REPOSITORY_ROOT
)
if str(SHARED_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_PACKAGE_ROOT))

from shared.config import ClientConfig
from shared.errors import SharedError
from shared.logger import configure_client, flush_client, send_detection, shutdown_client

from ..common import (
    ArtifactCache,
    ArtifactInspector,
    ProcessLocator,
    append_detection_jsonl,
)
from .allowlist import ProcessAllowlist
from .detector import ProcessAccessDetector
from .handle_sensor import ExternalHandleSensor, HandleSensorUnavailable
from .models import ExternalHandleObservation, ScanContext

Writer = Callable[[Path, Dict[str, Any]], None]


def _configure_shared_client() -> bool:
    """Configure the shared sender once; local detection can still run offline."""
    # Launcher는 모듈별 경로를 넘기지만 standalone 실행도 다른 탐지기와 같은
    # SQLite sender lock을 두고 충돌하지 않도록 이 모듈 전용 기본값을 둔다.
    os.environ.setdefault(
        "GZZ_TELEMETRY_OUTBOX",
        str(Path(__file__).resolve().parents[1] / "logs" / "outbox" / "external_access" / "client.sqlite3"),
    )
    try:
        configure_client(ClientConfig.from_env())
    except SharedError as error:
        # Do not print config values: they may contain the bearer token.
        print(f"[shared] client unavailable: {type(error).__name__}")
        return False
    return True


def _write_local_and_send(path: Path, result: Dict[str, Any]) -> None:
    """Keep the existing JSONL record, then enqueue the same 7-field result."""
    append_detection_jsonl(path, result)
    try:
        receipt = send_detection(result)
    except SharedError as error:
        print(f"[shared] detection not queued: {type(error).__name__}")
        return
    # A queued receipt means durable local outbox acceptance, not server delivery.
    print(f"[shared] detection {receipt.status}: {receipt.event_id}")


def _finish_shared_client() -> None:
    """Give queued detections a bounded chance to send, then close the worker."""
    try:
        delivered = flush_client(timeout=3)
        print(f"[shared] flush delivered={delivered}")
    except SharedError as error:
        print(f"[shared] flush failed: {type(error).__name__}")
    try:
        stopped = shutdown_client(timeout=5)
        print(f"[shared] shutdown complete={stopped}")
    except SharedError as error:
        print(f"[shared] shutdown failed: {type(error).__name__}")


@dataclass(frozen=True)
class ScanReport:
    game_found: bool
    observed_processes: int
    allowed_processes: int
    emitted_detections: int
    duration_ms: int
    error: Optional[str] = None


class ProcessAccessRunner:
    """한 번의 scan 또는 반복 scan을 수행하는 조립 계층.

    이 클래스는 차단·종료를 하지 않는다. 시스템 관찰값을 결과 JSON으로 바꿔
    로컬 파일에 추가하는 것만 담당한다.
    """

    def __init__(
        self,
        *,
        game_executable_name: str,
        game_pid: Optional[int] = None,
        session_id: str,
        player_id: str,
        output_path: Path,
        locator: Optional[ProcessLocator] = None,
        sensor: Optional[ExternalHandleSensor] = None,
        artifact_cache: Optional[ArtifactCache] = None,
        detector: Optional[ProcessAccessDetector] = None,
        allowlist: Optional[ProcessAllowlist] = None,
        writer: Writer = append_detection_jsonl,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        session_t0: Optional[float] = None,
    ) -> None:
        self._locator = locator or ProcessLocator(
            game_executable_name,
            expected_pid=game_pid,
            require_unique=True,
        )
        self._sensor = sensor or ExternalHandleSensor()
        self._artifact_cache = artifact_cache or ArtifactCache(ArtifactInspector())
        self._detector = detector or ProcessAccessDetector()
        self._allowlist = allowlist or ProcessAllowlist()
        self._session_id = session_id
        self._player_id = player_id
        self._output_path = Path(output_path)
        self._writer = writer
        self._clock = clock
        self._wall_clock = wall_clock
        self._session_t0 = session_t0
        self._started_at = clock()

    def scan_once(self) -> ScanReport:
        scan_started = self._clock()
        game = self._locator.find()
        if game is None:
            return ScanReport(False, 0, 0, 0, _elapsed_ms(scan_started, self._clock()))

        try:
            observations = self._sensor.scan(game)
        except HandleSensorUnavailable as error:
            return ScanReport(True, 0, 0, 0, _elapsed_ms(scan_started, self._clock()), str(error))

        timestamp_ms = self._timestamp_ms()
        context = ScanContext(self._session_id, self._player_id, timestamp_ms)
        emitted = 0
        allowed = 0
        for observation in observations:
            enriched = self._enrich_artifact(observation)
            if self._is_allowed(enriched):
                allowed += 1
                continue
            result = self._detector.evaluate(enriched, context)
            if result is None:
                continue
            # 스캔 성능 측정값은 판정 근거가 아니라 분석용 보조 정보다.
            result["evidence"]["scan_duration_ms"] = _elapsed_ms(scan_started, self._clock())
            self._writer(self._output_path, result)
            emitted += 1

        return ScanReport(
            game_found=True,
            observed_processes=len(observations),
            allowed_processes=allowed,
            emitted_detections=emitted,
            duration_ms=_elapsed_ms(scan_started, self._clock()),
        )

    def _timestamp_ms(self) -> int:
        """런처의 세션 시작 epoch가 있으면 모든 모듈과 같은 시간축을 쓴다."""
        if self._session_t0 is not None:
            return max(0, round((self._wall_clock() - self._session_t0) * 1000))
        return _elapsed_ms(self._started_at, self._clock())

    def _enrich_artifact(self, observation: ExternalHandleObservation) -> ExternalHandleObservation:
        if observation.source_path is None:
            return observation
        try:
            artifact = self._artifact_cache.inspect(observation.source_path)
        except OSError:
            # 삭제 경쟁·권한 부족으로 EXE를 읽지 못해도 위험 handle 관찰은 남긴다.
            return observation
        return replace(observation, artifact=artifact)

    def _is_allowed(self, observation: ExternalHandleObservation) -> bool:
        if observation.artifact is None or observation.artifact.sha256 is None:
            return False
        artifact = observation.artifact
        return (
            self._allowlist.find(
                observation.source_name,
                artifact.sha256,
                executable_path=artifact.path,
                signature_status=artifact.signature_status,
                publisher=artifact.publisher,
            )
            is not None
        )


def _elapsed_ms(started_at: float, now: float) -> int:
    return max(0, round((now - started_at) * 1000))


def _next_error_streak(current: int, report: ScanReport) -> int:
    """성공한 scan이 한 번이라도 나오면 연속 실패 횟수를 초기화한다."""
    return current + 1 if report.error else 0


def _enforce_error_limit(consecutive_errors: int, maximum: int) -> None:
    """감시 불능 상태를 Launcher/Watchdog가 알 수 있게 종료 코드 2로 끝낸다."""
    if consecutive_errors < maximum:
        return
    print(
        "sensor failed repeatedly; exiting so Launcher/Watchdog can "
        f"report and restart it ({consecutive_errors} consecutive errors)"
    )
    raise SystemExit(2)


def main() -> None:
    # 런처는 끌 때 Ctrl+Break를 보낸다. KeyboardInterrupt로 바꿔야 아래 finally(전송 flush)가 돈다.
    # (client/Launcher/README.md "끌 때 정리 코드가 돌게 하려면 — 한 줄")
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    parser = argparse.ArgumentParser(description="LocalGuard 외부 process handle 관찰기")
    parser.add_argument("--game-exe", required=True, help="예: PenguinHotel-Win64-Shipping.exe")
    parser.add_argument(
        "--game-pid",
        type=int,
        help="launcher가 확인한 정확한 게임 PID. 지정하면 동명 decoy 선택을 방지",
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--player-id", required=True)
    parser.add_argument(
        "--t0",
        type=float,
        help="런처 세션 시작 Unix epoch(초). 지정하면 timestamp_ms를 공통 세션 기준으로 맞춘다.",
    )
    parser.add_argument("--output", type=Path, default=Path("logs/external_access.jsonl"))
    parser.add_argument("--interval-ms", type=int, default=3000, help="반복 scan 주기 (기본 3000ms)")
    parser.add_argument(
        "--max-consecutive-errors",
        type=int,
        default=3,
        help="센서 오류가 연속으로 이 횟수 발생하면 비정상 종료해 런처가 감지 (기본 3)",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(__file__).with_name("allowlist.json"),
        help="검토된 정상 프로세스 이름+SHA-256 목록",
    )
    parser.add_argument("--once", action="store_true", help="한 번만 scan하고 종료")
    args = parser.parse_args()

    if args.interval_ms <= 0:
        raise SystemExit("--interval-ms는 0보다 커야 함")
    if args.max_consecutive_errors <= 0:
        raise SystemExit("--max-consecutive-errors는 0보다 커야 함")

    shared_ready = _configure_shared_client()
    try:
        runner = ProcessAccessRunner(
            game_executable_name=args.game_exe,
            game_pid=args.game_pid,
            session_id=args.session_id,
            player_id=args.player_id,
            output_path=args.output,
            allowlist=ProcessAllowlist.from_json(args.allowlist),
            writer=_write_local_and_send if shared_ready else append_detection_jsonl,
            session_t0=args.t0,
        )
        consecutive_errors = 0
        while True:
            started_at = time.monotonic()
            report = runner.scan_once()
            print(
                f"game_found={report.game_found} observed={report.observed_processes} "
                f"allowed={report.allowed_processes} "
                f"emitted={report.emitted_detections} duration_ms={report.duration_ms}"
                + (f" error={report.error}" if report.error else "")
            )
            consecutive_errors = _next_error_streak(consecutive_errors, report)
            _enforce_error_limit(consecutive_errors, args.max_consecutive_errors)
            if args.once:
                return
            time.sleep(max(0, args.interval_ms / 1000 - (time.monotonic() - started_at)))
    except KeyboardInterrupt:
        # 종료 요청은 정상 종료(0)로 끝낸다. 흘려보내면 0xC000013A라 런처가 "정리됐는지 모름"으로 본다.
        pass
    finally:
        if shared_ready:
            _finish_shared_client()


if __name__ == "__main__":
    main()
