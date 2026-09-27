"""성공한 DLL 스냅샷을 보관하고 다음 스냅샷과 비교한다."""

from __future__ import annotations

from typing import Iterable

from .models import (
    LoadedModule,
    ModuleChange,
    ModuleDiff,
    ModuleSnapshot,
    module_sort_key,
)


def _index_by_path(modules: Iterable[LoadedModule]) -> dict[str, LoadedModule]:
    indexed: dict[str, LoadedModule] = {}
    for module in modules:
        if not isinstance(module, LoadedModule):
            raise TypeError("모듈 목록에는 LoadedModule만 들어갈 수 있음")
        if module.identity in indexed:
            raise ValueError("같은 경로의 모듈을 중복 비교할 수 없음")
        indexed[module.identity] = module
    return indexed


def diff_module_snapshots(
    previous: ModuleSnapshot,
    current: ModuleSnapshot,
) -> ModuleDiff:
    """경로를 기준으로 추가·제거·로드 정보 변경을 분리한다."""
    if not isinstance(previous, ModuleSnapshot) or not isinstance(current, ModuleSnapshot):
        raise TypeError("previous와 current는 ModuleSnapshot이어야 함")
    if previous.pid != current.pid:
        raise ValueError("서로 다른 PID의 스냅샷은 비교할 수 없음")

    old = _index_by_path(previous.modules)
    new = _index_by_path(current.modules)
    added = tuple(
        sorted((new[key] for key in new.keys() - old.keys()), key=module_sort_key)
    )
    removed = tuple(
        sorted((old[key] for key in old.keys() - new.keys()), key=module_sort_key)
    )
    changed = tuple(
        ModuleChange(old[key], new[key])
        for key in sorted(old.keys() & new.keys())
        if (
            old[key].base_address != new[key].base_address
            or old[key].image_size != new[key].image_size
        )
    )
    return ModuleDiff(
        pid=current.pid,
        previous_captured_at=previous.captured_at,
        current_captured_at=current.captured_at,
        added=added,
        removed=removed,
        changed=changed,
    )


class ModuleBaselineTracker:
    """PID별 마지막 정상 수집본을 보관한다.

    센서 수집에 실패한 경우 ``observe``가 호출되지 않으므로 마지막 성공 기준선은
    그대로 남는다. 첫 성공 스냅샷은 비교 기준만 만들고 추가 DLL로 보고하지 않는다.
    """

    def __init__(self) -> None:
        self._previous_by_pid: dict[int, ModuleSnapshot] = {}

    def compare(self, snapshot: ModuleSnapshot) -> ModuleDiff:
        """현재 기준선과 비교하되 아직 기준선을 갱신하지 않는다."""
        if not isinstance(snapshot, ModuleSnapshot):
            raise TypeError("snapshot은 ModuleSnapshot이어야 함")
        previous = self._previous_by_pid.get(snapshot.pid)
        if previous is None:
            return ModuleDiff(
                pid=snapshot.pid,
                previous_captured_at=None,
                current_captured_at=snapshot.captured_at,
                baseline_created=True,
            )
        return diff_module_snapshots(previous, snapshot)

    def commit(self, snapshot: ModuleSnapshot) -> None:
        """관련 탐지 결과가 저장된 뒤 성공 스냅샷을 새 기준선으로 확정한다."""
        if not isinstance(snapshot, ModuleSnapshot):
            raise TypeError("snapshot은 ModuleSnapshot이어야 함")
        self._previous_by_pid[snapshot.pid] = snapshot

    def observe(self, snapshot: ModuleSnapshot) -> ModuleDiff:
        """비교와 확정을 한 번에 수행하는 순수 비교·테스트용 편의 메서드."""
        result = self.compare(snapshot)
        self.commit(snapshot)
        return result

    def reset(self, pid: int | None = None) -> None:
        if pid is None:
            self._previous_by_pid.clear()
            return
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid는 양의 정수여야 함")
        self._previous_by_pid.pop(pid, None)


__all__ = ["ModuleBaselineTracker", "diff_module_snapshots"]
