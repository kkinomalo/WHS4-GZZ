"""Narrow process-relationship exceptions for known launcher behavior."""

from __future__ import annotations

import ntpath
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..core.context import ProcessTarget


_STEAM_EXECUTABLE = "steam.exe"
_DIRECT_MEMORY_RIGHTS = 0x0002 | 0x0008 | 0x0010 | 0x0020


def _normalized_windows_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value.strip()))


def installed_steam_executables() -> frozenset[str]:
    """Return Steam executables rooted in Windows' Steam installation records."""

    if os.name != "nt":
        return frozenset()
    try:
        import winreg
    except ImportError:
        return frozenset()

    candidates: set[str] = set()
    locations = (
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamExe", True),
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath", False),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Valve\Steam",
            "InstallPath",
            False,
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Valve\Steam",
            "InstallPath",
            False,
        ),
    )
    for hive, key, value_name, is_executable in locations:
        try:
            with winreg.OpenKey(hive, key) as handle:
                raw = winreg.QueryValueEx(handle, value_name)[0]
        except (OSError, TypeError):
            continue
        if not isinstance(raw, str) or not raw.strip():
            continue
        candidate = raw.strip() if is_executable else str(Path(raw.strip()) / _STEAM_EXECUTABLE)
        candidates.add(_normalized_windows_path(candidate))
    return frozenset(candidates)


class SteamExecutableVerifier:
    """Require both an installed Steam path and a valid Authenticode chain."""

    def __init__(
        self,
        identity_provider: Callable[[str], Mapping[str, Any]],
        *,
        executable_paths_provider: Callable[[], Iterable[str]] = installed_steam_executables,
    ) -> None:
        self._identity_provider = identity_provider
        self._paths_provider = executable_paths_provider

    def __call__(self, source_image: str) -> bool:
        if not isinstance(source_image, str) or not source_image.strip():
            return False
        try:
            installed = {
                _normalized_windows_path(str(path))
                for path in self._paths_provider()
                if isinstance(path, str) and path.strip()
            }
        except Exception:
            return False
        if _normalized_windows_path(source_image) not in installed:
            return False
        try:
            identity = self._identity_provider(source_image)
        except Exception:
            return False
        return (
            isinstance(identity, Mapping)
            and str(identity.get("signature_status", "")).casefold() == "trusted"
        )


def is_steam_launch_parent_access(
    *,
    target: ProcessTarget,
    source_pid: int | None,
    source_image: str | None,
    granted_access: int | None,
    observed_at: float,
    source_verified: bool = False,
    launch_window_seconds: float = 15.0,
) -> bool:
    """Recognize only Steam's direct, launch-time full-access child handle.

    A name or parent relationship is never sufficient on its own.  The caller
    must first prove that the exact source path is a registered Steam install and
    that Windows accepts its Authenticode chain.  A different PID/path, a later
    access, or a read-only access is still evaluated by the normal detector.  The
    parent creation timestamp must also predate the exact game instance, which
    prevents a reused parent PID from being trusted.
    """

    if (
        source_verified is not True
        or target.created_at is None
        or target.parent_pid is None
        or target.parent_created_at is None
        or target.parent_executable_path is None
        or source_pid != target.parent_pid
        or target.parent_created_at > target.created_at
        or not isinstance(source_image, str)
        or ntpath.basename(source_image).casefold() != _STEAM_EXECUTABLE
        or ntpath.normcase(ntpath.normpath(source_image))
        != ntpath.normcase(ntpath.normpath(target.parent_executable_path))
        or isinstance(granted_access, bool)
        or not isinstance(granted_access, int)
        or granted_access & _DIRECT_MEMORY_RIGHTS != _DIRECT_MEMORY_RIGHTS
    ):
        return False
    return target.created_at - 2.0 <= observed_at <= target.created_at + float(
        launch_window_seconds
    )


__all__ = [
    "SteamExecutableVerifier",
    "installed_steam_executables",
    "is_steam_launch_parent_access",
]
