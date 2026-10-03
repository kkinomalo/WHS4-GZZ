"""Small, defensive wrappers around the Windows process and window APIs.

The rest of the monitor consumes immutable Python values rather than raw
handles.  Every public discovery function treats an inaccessible or exited
process as ordinary churn and returns an empty/``None`` result instead of
letting a Win32 error terminate the monitoring loop.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import ntpath
import os
from typing import Iterable


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
GWL_EXSTYLE = -20

WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000


@dataclass(frozen=True, slots=True)
class Rect:
    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return max(0, self.right - self.left)

    @property
    def height(self) -> int:
        return max(0, self.bottom - self.top)

    @property
    def area(self) -> int:
        return self.width * self.height


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    image_path: str | None
    created_at: float | None = None
    parent_pid: int | None = None
    parent_created_at: float | None = None
    parent_image_path: str | None = None

    @property
    def name(self) -> str:
        return ntpath.basename(self.image_path or "")


@dataclass(frozen=True, slots=True)
class WindowInfo:
    hwnd: int
    pid: int
    title: str
    class_name: str
    rect: Rect
    ex_style: int
    visible: bool
    process_path: str | None = None

    @property
    def process_name(self) -> str:
        return ntpath.basename(self.process_path or "")


_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)

    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    )
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    _psapi.EnumProcesses.argtypes = (
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _psapi.EnumProcesses.restype = wintypes.BOOL

    _user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    _user32.IsWindowVisible.restype = wintypes.BOOL
    _user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
    _user32.GetWindowRect.restype = wintypes.BOOL
    _user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    _user32.GetWindowTextLengthW.restype = ctypes.c_int
    _user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    _user32.GetWindowTextW.restype = ctypes.c_int
    _user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    _user32.GetClassNameW.restype = ctypes.c_int

    _get_window_long_ptr = getattr(_user32, "GetWindowLongPtrW", None)
    if _get_window_long_ptr is None:  # 32-bit Python exports GetWindowLongW instead.
        _get_window_long_ptr = _user32.GetWindowLongW
    _get_window_long_ptr.argtypes = (wintypes.HWND, ctypes.c_int)
    _get_window_long_ptr.restype = ctypes.c_ssize_t

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _user32.EnumWindows.argtypes = (_WNDENUMPROC, wintypes.LPARAM)
    _user32.EnumWindows.restype = wintypes.BOOL

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = (
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * MAX_PATH),
        )

    _kernel32.Process32FirstW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_PROCESSENTRY32W),
    )
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_PROCESSENTRY32W),
    )
    _kernel32.Process32NextW.restype = wintypes.BOOL


def list_process_ids() -> list[int]:
    """Return a stable, sorted PID snapshot.

    ``EnumProcesses`` has no process-count call, so the buffer is grown until
    Windows reports that it was not completely filled.
    """

    if not _IS_WINDOWS:
        return []

    capacity = 1024
    for _ in range(8):
        buffer_type = wintypes.DWORD * capacity
        buffer = buffer_type()
        bytes_returned = wintypes.DWORD()
        try:
            ok = _psapi.EnumProcesses(
                buffer,
                ctypes.sizeof(buffer),
                ctypes.byref(bytes_returned),
            )
        except (OSError, ValueError):
            return []
        if not ok:
            return []

        count = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
        if count < capacity:
            return sorted({int(buffer[index]) for index in range(count)})
        capacity *= 2
    return sorted({int(pid) for pid in buffer})


def get_process_image_path(pid: int) -> str | None:
    """Return the full executable path for *pid*, or ``None`` if unavailable."""

    if not _IS_WINDOWS or isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None

    handle = None
    try:
        handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        size = wintypes.DWORD(32768)
        path_buffer = ctypes.create_unicode_buffer(size.value)
        if not _kernel32.QueryFullProcessImageNameW(
            handle, 0, path_buffer, ctypes.byref(size)
        ):
            return None
        return path_buffer.value[: size.value] or None
    except (OSError, ValueError):
        return None
    finally:
        if handle:
            try:
                _kernel32.CloseHandle(handle)
            except (OSError, ValueError):
                pass


def get_process_creation_time(pid: int) -> float | None:
    """Return process creation time as Unix seconds, or ``None``."""

    if not _IS_WINDOWS or isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None

    handle = None
    try:
        handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not _kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        ticks = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
        return ticks / 10_000_000.0 - 11_644_473_600.0
    except (OSError, ValueError):
        return None
    finally:
        if handle:
            try:
                _kernel32.CloseHandle(handle)
            except (OSError, ValueError):
                pass


def list_processes() -> list[ProcessInfo]:
    """Return process identifiers with best-effort full image paths."""

    return [ProcessInfo(pid, get_process_image_path(pid)) for pid in list_process_ids()]


def find_processes_by_name(executable_name: str) -> list[ProcessInfo]:
    """Case-insensitively find processes without opening every process.

    Toolhelp exposes executable basenames from one snapshot.  Full image-path
    lookup is then limited to exact-name matches, which keeps the 500 ms game
    presence poll inexpensive and avoids generating hundreds of process-handle
    operations per cycle.
    """

    wanted = ntpath.basename(str(executable_name)).casefold()
    if not wanted:
        return []
    if not _IS_WINDOWS:
        return [
            process for process in list_processes() if process.name.casefold() == wanted
        ]

    invalid_handle = ctypes.c_void_p(-1).value
    snapshot = None
    matches: list[tuple[int, str, int | None]] = []
    try:
        snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot or int(snapshot) == invalid_handle:
            return []
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = bool(_kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
        while ok:
            name = str(entry.szExeFile)
            if name.casefold() == wanted:
                parent_pid = int(entry.th32ParentProcessID)
                matches.append(
                    (int(entry.th32ProcessID), name, parent_pid if parent_pid > 0 else None)
                )
            ok = bool(_kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
    except (OSError, TypeError, ValueError):
        return []
    finally:
        if snapshot and int(snapshot) != invalid_handle:
            try:
                _kernel32.CloseHandle(snapshot)
            except (OSError, ValueError):
                pass

    return [
        ProcessInfo(
            pid,
            get_process_image_path(pid) or name,
            get_process_creation_time(pid),
            parent_pid,
            get_process_creation_time(parent_pid) if parent_pid is not None else None,
            get_process_image_path(parent_pid) if parent_pid is not None else None,
        )
        for pid, name, parent_pid in matches
    ]


def _window_text(hwnd: int) -> str:
    try:
        length = max(0, int(_user32.GetWindowTextLengthW(hwnd)))
        buffer = ctypes.create_unicode_buffer(length + 1)
        _user32.GetWindowTextW(hwnd, buffer, len(buffer))
        return buffer.value
    except (OSError, ValueError):
        return ""


def _window_class_name(hwnd: int) -> str:
    try:
        buffer = ctypes.create_unicode_buffer(256)
        _user32.GetClassNameW(hwnd, buffer, len(buffer))
        return buffer.value
    except (OSError, ValueError):
        return ""


def list_top_level_windows(*, visible_only: bool = True) -> list[WindowInfo]:
    """Return top-level windows, including rect and extended-style metadata.

    Processes and windows routinely disappear between individual API calls.
    Such entries are ignored or returned with ``process_path=None``.
    """

    if not _IS_WINDOWS:
        return []

    raw_windows: list[tuple[int, int, str, str, Rect, int, bool]] = []

    @_WNDENUMPROC
    def callback(hwnd: int, _lparam: int) -> bool:
        try:
            visible = bool(_user32.IsWindowVisible(hwnd))
            if visible_only and not visible:
                return True

            native_rect = wintypes.RECT()
            if not _user32.GetWindowRect(hwnd, ctypes.byref(native_rect)):
                return True
            rect = Rect(
                int(native_rect.left),
                int(native_rect.top),
                int(native_rect.right),
                int(native_rect.bottom),
            )
            if rect.area <= 0:
                return True

            pid = wintypes.DWORD()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            ex_style = int(_get_window_long_ptr(hwnd, GWL_EXSTYLE))
            raw_windows.append(
                (
                    int(hwnd),
                    int(pid.value),
                    _window_text(hwnd),
                    _window_class_name(hwnd),
                    rect,
                    ex_style,
                    visible,
                )
            )
        except (OSError, ValueError):
            pass
        return True

    try:
        if not _user32.EnumWindows(callback, 0):
            return []
    except (OSError, ValueError):
        return []

    path_cache: dict[int, str | None] = {}
    result: list[WindowInfo] = []
    for hwnd, pid, title, class_name, rect, ex_style, visible in raw_windows:
        if pid not in path_cache:
            path_cache[pid] = get_process_image_path(pid)
        result.append(
            WindowInfo(
                hwnd=hwnd,
                pid=pid,
                title=title,
                class_name=class_name,
                rect=rect,
                ex_style=ex_style,
                visible=visible,
                process_path=path_cache[pid],
            )
        )
    return result


def windows_for_pids(
    pids: Iterable[int], *, visible_only: bool = True
) -> list[WindowInfo]:
    """Return the top-level windows owned by any PID in *pids*."""

    wanted = {int(pid) for pid in pids}
    return [
        window
        for window in list_top_level_windows(visible_only=visible_only)
        if window.pid in wanted
    ]


__all__ = [
    "GWL_EXSTYLE",
    "MAX_PATH",
    "PROCESS_QUERY_LIMITED_INFORMATION",
    "TH32CS_SNAPPROCESS",
    "ProcessInfo",
    "Rect",
    "WS_EX_LAYERED",
    "WS_EX_NOACTIVATE",
    "WS_EX_TOOLWINDOW",
    "WS_EX_TOPMOST",
    "WS_EX_TRANSPARENT",
    "WindowInfo",
    "find_processes_by_name",
    "get_process_creation_time",
    "get_process_image_path",
    "list_process_ids",
    "list_processes",
    "list_top_level_windows",
    "windows_for_pids",
]
