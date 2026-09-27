"""게임 DLL 수집·기준선 비교·파일 검사·판정·JSONL 기록을 연결한다."""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from ..common import (
    ArtifactCache,
    ArtifactInspector,
    ProcessLocator,
    TargetProcess,
    append_detection_jsonl,
)
from .allowlist import ModuleAllowlist
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
    ) -> None:
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
            return self._report(False, scan_started, error=str(error))
        if game is None:
            if self._previous_target is not None:
                self._baseline.reset(self._previous_target.pid)
            self._previous_target = None
            return self._report(False, scan_started)

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
            return self._report(True, scan_started, error=str(error))

        diff = self._baseline.compare(snapshot)
        if diff.baseline_created and not self._audit_initial_snapshot:
            self._baseline.commit(snapshot)
            return self._report(
                True,
                scan_started,
                baseline_created=True,
                observed_modules=len(snapshot.modules),
            )

        timestamp_ms = _elapsed_ms(self._started_at, self._clock())
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
            result["evidence"]["scan_duration_ms"] = _elapsed_ms(
                scan_started, self._clock()
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

        self._baseline.commit(snapshot)

        return self._report(
            True,
            scan_started,
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

    runner = ModuleIntegrityRunner(
        game_executable_name=args.game_exe,
        game_pid=args.game_pid,
        session_id=args.session_id,
        player_id=args.player_id,
        output_path=args.output,
        allowlist=ModuleAllowlist.from_json(args.allowlist),
        audit_initial_snapshot=args.audit_initial_snapshot,
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


if __name__ == "__main__":
    main()
