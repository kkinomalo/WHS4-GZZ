"""게임 프로세스 내부 DLL 관찰에 사용하는 값 객체."""

from __future__ import annotations

from dataclasses import dataclass
import math
import ntpath
from typing import Optional

from ..common.models import ArtifactInfo


def canonical_module_path(path: str) -> str:
    """Windows 경로를 DLL 스냅샷 비교용 식별자로 정규화한다."""
    if not isinstance(path, str):
        raise TypeError("path는 문자열이어야 함")
    value = path.strip().replace("/", "\\")
    if not value:
        raise ValueError("path는 비어 있을 수 없음")

    lowered = value.casefold()
    if lowered.startswith("\\\\?\\unc\\"):
        value = "\\\\" + value[8:]
    elif lowered.startswith("\\\\?\\"):
        value = value[4:]
    elif lowered.startswith("\\??\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


@dataclass(frozen=True)
class LoadedModule:
    """Toolhelp가 보고한 로드 모듈 한 개."""

    name: str
    path: Optional[str]
    base_address: int
    image_size: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name은 비어 있지 않은 문자열이어야 함")
        if self.path is not None:
            canonical_module_path(self.path)
        for field_name, value in (
            ("base_address", self.base_address),
            ("image_size", self.image_size),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name}는 0 이상의 정수여야 함")

    @property
    def identity(self) -> str:
        if self.path is None:
            return (
                "<path-unavailable>\\"
                + self.name.casefold()
                + f"@0x{self.base_address:X}"
            )
        return canonical_module_path(self.path)


def module_sort_key(module: LoadedModule) -> tuple[str, int, int]:
    return module.identity, module.base_address, module.image_size


@dataclass(frozen=True)
class ModuleSnapshot:
    """한 시점에 성공적으로 수집한 DLL 목록."""

    pid: int
    captured_at: float
    modules: tuple[LoadedModule, ...]

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("pid는 양의 정수여야 함")
        if (
            isinstance(self.captured_at, bool)
            or not isinstance(self.captured_at, (int, float))
            or not math.isfinite(float(self.captured_at))
            or self.captured_at < 0
        ):
            raise ValueError("captured_at은 0 이상의 유한한 숫자여야 함")

        modules = tuple(self.modules)
        if any(not isinstance(module, LoadedModule) for module in modules):
            raise TypeError("modules에는 LoadedModule만 들어갈 수 있음")
        normalized = tuple(sorted(modules, key=module_sort_key))
        identities = [module.identity for module in normalized]
        if len(identities) != len(set(identities)):
            raise ValueError("한 스냅샷에 같은 경로의 모듈이 중복될 수 없음")
        object.__setattr__(self, "captured_at", float(self.captured_at))
        object.__setattr__(self, "modules", normalized)


@dataclass(frozen=True)
class ModuleChange:
    """같은 경로에서 base address 또는 image size가 달라진 모듈."""

    before: LoadedModule
    after: LoadedModule

    def __post_init__(self) -> None:
        if self.before.identity != self.after.identity:
            raise ValueError("변경 모듈은 같은 경로를 가리켜야 함")


@dataclass(frozen=True)
class ModuleDiff:
    """두 번의 성공한 DLL 스냅샷 사이의 사실 변화."""

    pid: int
    previous_captured_at: Optional[float]
    current_captured_at: float
    added: tuple[LoadedModule, ...] = ()
    removed: tuple[LoadedModule, ...] = ()
    changed: tuple[ModuleChange, ...] = ()
    baseline_created: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)


@dataclass(frozen=True)
class ModuleObservation:
    """판정기에 전달하는 추가 또는 변경 DLL 관찰값."""

    change_type: str
    module: LoadedModule
    artifact: Optional[ArtifactInfo] = None
    inspection_error: Optional[str] = None
    previous_base_address: Optional[int] = None
    previous_image_size: Optional[int] = None

    def __post_init__(self) -> None:
        if self.change_type not in {"added", "changed", "baseline_unreviewed"}:
            raise ValueError(
                "change_type은 added, changed 또는 baseline_unreviewed여야 함"
            )


@dataclass(frozen=True)
class ScanContext:
    """공통 탐지 결과와 대상 프로세스를 연결하는 호출 시점 정보."""

    session_id: str
    player_id: str
    timestamp_ms: int
    target_pid: int
