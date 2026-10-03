"""게임 DLL 수집·기준선 비교·파일 검사·판정·JSONL 기록을 연결한다."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# shared 0.2.0 is installed directly under the repository root.
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from shared.config import ClientConfig
from shared.errors import SharedError
from shared.logger import configure_client, flush_client, send_detection, shutdown_client

from ..common import (
    ArtifactCache,
    ArtifactInspector,
    ProcessLocator,
    TargetProcess,
    append_detection_jsonl,
    build_detection_result,
)
from .allowlist import (
    DEFAULT_SELF_HOOK_MANIFEST_PATH,
    DEFAULT_UE4SS_MANIFEST_PATH,
    ModuleAllowlist,
)
from .baseline import ModuleBaselineTracker
from .detector import ModuleIntegrityDetector
from .models import (
    ModuleChange,
    ModuleObservation,
    ModuleSnapshot,
    ScanContext,
)
from .module_sensor import ModuleSensorUnavailable, ToolhelpModuleSensor


Writer = Callable[[Path, Dict[str, Any]], None]


def _configure_shared_client() -> bool:
    """Configure shared once while allowing local-only detection to continue."""
    try:
        configure_client(ClientConfig.from_env())
    except SharedError as error:
        # Configuration may include a bearer token, so only print the error type.
        print(f"[shared] client unavailable: {type(error).__name__}")
        return False
    return True


def _write_local_and_send(path: Path, result: Dict[str, Any]) -> None:
    """로컬에는 모두 남기고 양수 탐지만 중앙 전송 outbox에 넣는다."""
    append_detection_jsonl(path, result)
    if result["raw_score"] <= 0:
        return
    try:
        receipt = send_detection(result)
    except SharedError as error:
        print(f"[shared] detection not queued: {type(error).__name__}")
        return
    # queued means durable local outbox acceptance, not receiver acknowledgement.
    print(f"[shared] detection {receipt.status}: {receipt.event_id}")


def _finish_shared_client() -> None:
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


def _default_ue4ss_manifest_path() -> Path:
    configured = os.environ.get("GZZ_UE4SS_MANIFEST", "").strip()
    return Path(configured) if configured else DEFAULT_UE4SS_MANIFEST_PATH


def _default_game_root() -> Optional[Path]:
    configured = os.environ.get("GZZ_GAME_ROOT", "").strip()
    return Path(configured) if configured else None


def _default_self_hook_manifest_path() -> Path:
    configured = os.environ.get("GZZ_SELF_HOOK_MANIFEST", "").strip()
    return Path(configured) if configured else DEFAULT_SELF_HOOK_MANIFEST_PATH


def _load_allowlists(
    static_path: Path,
    ue4ss_manifest_path: Path,
    trusted_game_root: Optional[Path],
    self_hook_manifest_path: Path = DEFAULT_SELF_HOOK_MANIFEST_PATH,
    trusted_repository_root: Path = REPOSITORY_ROOT,
) -> tuple[ModuleAllowlist, bool]:
    """정적 목록, UE4SS DLL, 자체 관측 후크의 정확한 해시를 합친다.

    두 번째 반환값은 정적 검토 목록이 있어 초기 스냅샷 감사를 자동으로 켜도
    되는지를 나타낸다. PC별 UE4SS 예외만으로 초기 감사를 켜면 정상 시스템 DLL
    전체가 미검토 항목으로 기록되므로 동적 항목은 자동 활성화 조건에서 제외한다.
    """
    try:
        reviewed = ModuleAllowlist.from_json(static_path)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"[module_integrity] static allowlist unavailable: {type(error).__name__}")
        reviewed = ModuleAllowlist()
    ue4ss = (
        ModuleAllowlist.from_ue4ss_manifest(
            ue4ss_manifest_path,
            trusted_game_root=trusted_game_root,
        )
        if trusted_game_root is not None
        else ModuleAllowlist()
    )
    self_hooks = ModuleAllowlist.from_self_hook_manifest(
        self_hook_manifest_path,
        trusted_repository_root=trusted_repository_root,
    )
    if ue4ss.entries:
        print(f"[module_integrity] loaded UE4SS DLL exceptions: {len(ue4ss.entries)}")
    if self_hooks.entries:
        print(
            "[module_integrity] loaded anti-cheat observer hook exceptions: "
            f"{len(self_hooks.entries)}"
        )
    return reviewed.merged(ue4ss, self_hooks), bool(reviewed.entries)


@dataclass(frozen=True)
class ScanReport:
    game_found: bool
    baseline_created: bool
    initial_audit_performed: bool
    observed_modules: int
    added_modules: int
    removed_modules: int
    changed_modules: int
    allowed_modules: int
    emitted_detections: int
    duration_ms: int
    error: Optional[str] = None


@dataclass
class _PendingBatch:
    """부분 저장 실패 뒤 아직 기록하지 못한 결과와 확정 전 스냅샷."""

    snapshot: ModuleSnapshot
    baseline_created: bool
    observed_modules: int
    added_modules: int
    removed_modules: int
    changed_modules: int
    allowed_modules: int
    results: list[Dict[str, Any]]
    next_index: int = 0


class ModuleIntegrityRunner:
    """한 번 또는 반복해서 게임의 로드 DLL 변화를 관찰한다.

    게임을 종료하거나 DLL을 제거하지 않는다. 기본 모드는 첫 성공 스냅샷으로
    기준선을 만들며, 엄격한 초기 감사 옵션은 그 첫 목록도 allowlist와 대조한다.
    이후에는 새로 추가되거나 로드 정보가 바뀐 DLL만 판정한다.
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
        sensor: Optional[ToolhelpModuleSensor] = None,
        baseline: Optional[ModuleBaselineTracker] = None,
        artifact_cache: Optional[ArtifactCache] = None,
        detector: Optional[ModuleIntegrityDetector] = None,
        allowlist: Optional[ModuleAllowlist] = None,
        audit_initial_snapshot: Optional[bool] = None,
        writer: Writer = append_detection_jsonl,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        session_t0: Optional[float] = None,
        emit_status_events: bool = False,
    ) -> None:
        self._game_executable_name = game_executable_name
        self._locator = locator or ProcessLocator(
            game_executable_name,
            expected_pid=game_pid,
            require_unique=True,
        )
        self._sensor = sensor or ToolhelpModuleSensor()
        self._baseline = baseline or ModuleBaselineTracker()
        self._artifact_cache = artifact_cache or ArtifactCache(ArtifactInspector())
        self._detector = detector or ModuleIntegrityDetector()
        self._allowlist = allowlist or ModuleAllowlist()
        self._audit_initial_snapshot = (
            bool(self._allowlist.entries)
            if audit_initial_snapshot is None
            else bool(audit_initial_snapshot)
        )
        self._session_id = session_id
        self._player_id = player_id
        self._output_path = Path(output_path)
        self._writer = writer
        self._clock = clock
        self._wall_clock = wall_clock
        self._session_t0 = session_t0
        self._emit_status_events = bool(emit_status_events)
        self._started_at = clock()
        self._previous_target: Optional[TargetProcess] = None
        self._pending_batch: Optional[_PendingBatch] = None

    def scan_once(self) -> ScanReport:
        scan_started = self._clock()
        if self._pending_batch is not None:
            return self._flush_pending(scan_started)
        try:
            game = self._locator.find()
        except OSError as error:
            return self._write_status_and_report(
                scan_started,
                game_found=False,
                status="ERROR",
                error_code="PROCESS_ENUMERATION_FAILED",
                error=str(error),
            )
        if game is None:
            if self._previous_target is not None:
                self._baseline.reset(self._previous_target.pid)
            self._previous_target = None
            return self._write_status_and_report(
                scan_started,
                game_found=False,
                status="OFFLINE",
                error_code="GAME_PROCESS_NOT_FOUND",
            )

        if (
            self._previous_target is not None
            and ProcessLocator.was_restarted(self._previous_target, game)
        ):
            self._baseline.reset(self._previous_target.pid)
            # PID가 재사용된 경우 새 프로세스에 예전 PID 기준선이 남지 않게 한다.
            self._baseline.reset(game.pid)
            self._artifact_cache.clear()
        self._previous_target = game

        try:
            snapshot = self._sensor.capture(game.pid)
        except (ModuleSensorUnavailable, OSError) as error:
            # 실패를 빈 목록으로 바꾸지 않으므로 마지막 성공 기준선은 유지된다.
            return self._write_status_and_report(
                scan_started,
                game_found=True,
                status="ERROR",
                target_pid=game.pid,
                error_code="MODULE_SENSOR_UNAVAILABLE",
                error=str(error),
            )

        diff = self._baseline.compare(snapshot)
        if diff.baseline_created and not self._audit_initial_snapshot:
            report = self._write_status_and_report(
                scan_started,
                game_found=True,
                status="NORMAL",
                target_pid=game.pid,
                baseline_created=True,
                observed_modules=len(snapshot.modules),
            )
            if report.error is None:
                self._baseline.commit(snapshot)
            return report

        timestamp_ms = self._timestamp_ms_at(self._clock())
        context = ScanContext(
            session_id=self._session_id,
            player_id=self._player_id,
            timestamp_ms=timestamp_ms,
            target_pid=game.pid,
        )
        allowed = 0

        if diff.baseline_created:
            observations = [
                ModuleObservation(change_type="baseline_unreviewed", module=module)
                for module in snapshot.modules
            ]
        else:
            observations = [
                ModuleObservation(change_type="added", module=module)
                for module in diff.added
            ]
            observations.extend(
                self._changed_observation(change)
                for change in diff.changed
            )

        results = []
        for observation in observations:
            enriched = self._enrich_artifact(observation)
            if self._is_allowed(enriched):
                allowed += 1
                continue
            result = self._detector.evaluate(enriched, context)
            results.append(result)

        for result in results:
            result["evidence"].update(
                {
                    "scan_duration_ms": _elapsed_ms(scan_started, self._clock()),
                    "observed_modules": len(snapshot.modules),
                    "added_modules": len(diff.added),
                    "removed_modules": len(diff.removed),
                    "changed_modules": len(diff.changed),
                    "allowed_modules": allowed,
                }
            )

        if results:
            self._pending_batch = _PendingBatch(
                snapshot=snapshot,
                baseline_created=diff.baseline_created,
                observed_modules=len(snapshot.modules),
                added_modules=len(diff.added),
                removed_modules=len(diff.removed),
                changed_modules=len(diff.changed),
                allowed_modules=allowed,
                results=results,
            )
            return self._flush_pending(scan_started)

        report = self._write_status_and_report(
            scan_started,
            game_found=True,
            status="NORMAL",
            target_pid=game.pid,
            baseline_created=diff.baseline_created,
            initial_audit_performed=(
                diff.baseline_created and self._audit_initial_snapshot
            ),
            observed_modules=len(snapshot.modules),
            added_modules=len(diff.added),
            removed_modules=len(diff.removed),
            changed_modules=len(diff.changed),
            allowed_modules=allowed,
        )
        if report.error is None:
            self._baseline.commit(snapshot)
        return report

    def _timestamp_ms_at(self, monotonic_now: float) -> int:
        if self._session_t0 is not None:
            return max(0, round((self._wall_clock() - self._session_t0) * 1000))
        return _elapsed_ms(self._started_at, monotonic_now)

    def _write_status_and_report(
        self,
        scan_started: float,
        *,
        game_found: bool,
        status: str,
        target_pid: Optional[int] = None,
        error_code: Optional[str] = None,
        error: Optional[str] = None,
        baseline_created: bool = False,
        initial_audit_performed: bool = False,
        observed_modules: int = 0,
        added_modules: int = 0,
        removed_modules: int = 0,
        changed_modules: int = 0,
        allowed_modules: int = 0,
    ) -> ScanReport:
        scan_finished = self._clock()
        scan_end_ms = self._timestamp_ms_at(scan_finished)
        duration_ms = _elapsed_ms(scan_started, scan_finished)
        evidence: Dict[str, Any] = {
            "submodule": "module_integrity",
            "status": status,
            "target_process": self._game_executable_name,
            "target_pid": target_pid,
            "scan_duration_ms": duration_ms,
            "observed_modules": observed_modules,
            "added_modules": added_modules,
            "removed_modules": removed_modules,
            "changed_modules": changed_modules,
            "allowed_modules": allowed_modules,
            "baseline_created": baseline_created,
            "initial_audit_performed": initial_audit_performed,
        }
        if error_code is not None:
            evidence["error_code"] = error_code
        result = build_detection_result(
            session_id=self._session_id,
            player_id=self._player_id,
            module="module_integrity",
            timestamp_ms=scan_end_ms,
            evidence=evidence,
            reasons=[],
            raw_score=0,
        )
        write_error = error
        if self._emit_status_events:
            try:
                self._writer(self._output_path, result)
            except OSError as exc:
                write_error = f"탐지 결과 저장 실패: {exc}"
        return self._report(
            game_found,
            scan_started,
            baseline_created=baseline_created,
            initial_audit_performed=initial_audit_performed,
            observed_modules=observed_modules,
            added_modules=added_modules,
            removed_modules=removed_modules,
            changed_modules=changed_modules,
            allowed_modules=allowed_modules,
            error=write_error,
        )

    def _flush_pending(self, scan_started: float) -> ScanReport:
        pending = self._pending_batch
        if pending is None:
            raise RuntimeError("pending batch가 없음")

        emitted = 0
        while pending.next_index < len(pending.results):
            result = pending.results[pending.next_index]
            try:
                self._writer(self._output_path, result)
            except OSError as error:
                return self._report(
                    True,
                    scan_started,
                    baseline_created=pending.baseline_created,
                    initial_audit_performed=(
                        pending.baseline_created and self._audit_initial_snapshot
                    ),
                    observed_modules=pending.observed_modules,
                    added_modules=pending.added_modules,
                    removed_modules=pending.removed_modules,
                    changed_modules=pending.changed_modules,
                    allowed_modules=pending.allowed_modules,
                    emitted_detections=emitted,
                    error=f"탐지 결과 저장 실패: {error}",
                )
            pending.next_index += 1
            emitted += 1

        self._baseline.commit(pending.snapshot)
        self._pending_batch = None

        return self._report(
            True,
            scan_started,
            baseline_created=pending.baseline_created,
            initial_audit_performed=(
                pending.baseline_created and self._audit_initial_snapshot
            ),
            observed_modules=pending.observed_modules,
            added_modules=pending.added_modules,
            removed_modules=pending.removed_modules,
            changed_modules=pending.changed_modules,
            allowed_modules=pending.allowed_modules,
            emitted_detections=emitted,
        )

    @staticmethod
    def _changed_observation(change: ModuleChange) -> ModuleObservation:
        return ModuleObservation(
            change_type="changed",
            module=change.after,
            previous_base_address=change.before.base_address,
            previous_image_size=change.before.image_size,
        )

    def _enrich_artifact(self, observation: ModuleObservation) -> ModuleObservation:
        if observation.module.path is None:
            return ModuleObservation(
                change_type=observation.change_type,
                module=observation.module,
                inspection_error="full module path is unavailable",
                previous_base_address=observation.previous_base_address,
                previous_image_size=observation.previous_image_size,
            )
        try:
            artifact = self._artifact_cache.inspect(Path(observation.module.path))
        except OSError as error:
            # 열거 직후 언로드되거나 권한이 없어도 DLL 변화 관찰 자체는 보존한다.
            return ModuleObservation(
                change_type=observation.change_type,
                module=observation.module,
                inspection_error=str(error),
                previous_base_address=observation.previous_base_address,
                previous_image_size=observation.previous_image_size,
            )
        return ModuleObservation(
            change_type=observation.change_type,
            module=observation.module,
            artifact=artifact,
            previous_base_address=observation.previous_base_address,
            previous_image_size=observation.previous_image_size,
        )

    def _is_allowed(self, observation: ModuleObservation) -> bool:
        artifact = observation.artifact
        if artifact is None or artifact.sha256 is None:
            return False
        return (
            self._allowlist.find(
                observation.module.name,
                artifact.sha256,
                module_path=artifact.path,
                signature_status=artifact.signature_status,
                publisher=artifact.publisher,
            )
            is not None
        )

    def _report(
        self,
        game_found: bool,
        scan_started: float,
        *,
        baseline_created: bool = False,
        initial_audit_performed: bool = False,
        observed_modules: int = 0,
        added_modules: int = 0,
        removed_modules: int = 0,
        changed_modules: int = 0,
        allowed_modules: int = 0,
        emitted_detections: int = 0,
        error: Optional[str] = None,
    ) -> ScanReport:
        return ScanReport(
            game_found=game_found,
            baseline_created=baseline_created,
            initial_audit_performed=initial_audit_performed,
            observed_modules=observed_modules,
            added_modules=added_modules,
            removed_modules=removed_modules,
            changed_modules=changed_modules,
            allowed_modules=allowed_modules,
            emitted_detections=emitted_detections,
            duration_ms=_elapsed_ms(scan_started, self._clock()),
            error=error,
        )


def _elapsed_ms(started_at: float, now: float) -> int:
    return max(0, round((now - started_at) * 1000))


def main() -> None:
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    parser = argparse.ArgumentParser(description="LocalGuard 게임 DLL 무결성 관찰기")
    parser.add_argument("--game-exe", required=True, help="예: PenguinHotel-Win64-Shipping.exe")
    parser.add_argument(
        "--game-pid",
        type=int,
        help="launcher가 알고 있는 정확한 게임 PID. 지정하면 동명 decoy 선택을 방지",
    )
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--player-id", required=True)
    parser.add_argument(
        "--t0",
        type=float,
        help="런처 세션 시작 Unix epoch(초). 공통 timestamp_ms 기준으로 사용",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("logs/module_integrity.jsonl"),
        help="다른 runner와 동시에 쓸 때는 서로 다른 출력 파일을 사용",
    )
    parser.add_argument("--interval-ms", type=int, default=3000)
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(__file__).with_name("allowlist.json"),
    )
    parser.add_argument(
        "--ue4ss-manifest",
        type=Path,
        default=_default_ue4ss_manifest_path(),
        help="런처가 생성한 PC별 UE4SS 설치 해시 manifest",
    )
    parser.add_argument(
        "--game-root",
        type=Path,
        default=_default_game_root(),
        help="런처가 게임 프로세스와 별도로 확인한 설치 root",
    )
    parser.add_argument(
        "--self-hook-manifest",
        type=Path,
        default=_default_self_hook_manifest_path(),
        help="런처가 시작 전에 생성한 안티치트 자체 관측 후크 해시 manifest",
    )
    parser.add_argument("--once", action="store_true")
    initial_audit = parser.add_mutually_exclusive_group()
    initial_audit.add_argument(
        "--audit-initial-snapshot",
        dest="audit_initial_snapshot",
        action="store_true",
        help="첫 DLL 목록도 allowlist와 대조",
    )
    initial_audit.add_argument(
        "--skip-initial-audit",
        dest="audit_initial_snapshot",
        action="store_false",
        help="초기 allowlist가 있어도 첫 DLL 목록 감사를 명시적으로 생략",
    )
    parser.set_defaults(audit_initial_snapshot=None)
    args = parser.parse_args()

    if args.interval_ms <= 0:
        raise SystemExit("--interval-ms는 0보다 커야 함")

    shared_ready = _configure_shared_client()
    try:
        allowlist, auto_initial_audit = _load_allowlists(
            args.allowlist,
            args.ue4ss_manifest,
            args.game_root,
            args.self_hook_manifest,
            REPOSITORY_ROOT,
        )
        audit_initial_snapshot = (
            auto_initial_audit
            if args.audit_initial_snapshot is None
            else args.audit_initial_snapshot
        )
        runner = ModuleIntegrityRunner(
            game_executable_name=args.game_exe,
            game_pid=args.game_pid,
            session_id=args.session_id,
            player_id=args.player_id,
            output_path=args.output,
            allowlist=allowlist,
            audit_initial_snapshot=audit_initial_snapshot,
            writer=_write_local_and_send if shared_ready else append_detection_jsonl,
            session_t0=args.t0,
            emit_status_events=True,
        )
        while True:
            started_at = time.monotonic()
            report = runner.scan_once()
            print(
                f"game_found={report.game_found} baseline={report.baseline_created} "
                f"initial_audit={report.initial_audit_performed} "
                f"observed={report.observed_modules} added={report.added_modules} "
                f"removed={report.removed_modules} changed={report.changed_modules} "
                f"allowed={report.allowed_modules} emitted={report.emitted_detections} "
                f"duration_ms={report.duration_ms}"
                + (f" error={report.error}" if report.error else "")
            )
            if args.once:
                return
            time.sleep(max(0, args.interval_ms / 1000 - (time.monotonic() - started_at)))
    except KeyboardInterrupt:
        pass
    finally:
        if shared_ready:
            _finish_shared_client()


if __name__ == "__main__":
    main()
