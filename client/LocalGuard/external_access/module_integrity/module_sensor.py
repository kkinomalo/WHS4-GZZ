"""Windows Toolhelp API로 게임 프로세스의 로드 DLL 목록을 읽는다."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import ntpath
import os
import time
from typing import Callable, Iterable

from .models import LoadedModule, ModuleSnapshot, module_sort_key


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_MODULE_NAME32 = 255
MAX_PATH = 260
ERROR_NO_MORE_FILES = 18
ERROR_BAD_LENGTH = 24
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class ModuleSensorUnavailable(RuntimeError):
    """대상 프로세스의 모듈 목록을 신뢰성 있게 읽지 못한 경우."""

    def __init__(self, pid: int, operation: str, winerror: int | None = None) -> None:
        self.pid = int(pid)
        self.operation = str(operation)
        self.winerror = None if winerror is None else int(winerror)
        suffix = f" (WinError {self.winerror})" if self.winerror is not None else ""
        super().__init__(
            f"PID {self.pid} 모듈 목록을 읽을 수 없음: {self.operation}{suffix}"
        )


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


def _valid_pid(pid: int) -> int:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("pid는 양의 정수여야 함")
    return pid


def _handle_value(handle: object) -> int | None:
    if handle is None:
        return None
    if isinstance(handle, int):
        return handle
    return ctypes.cast(handle, ctypes.c_void_p).value


def _create_snapshot_handle(kernel32, pid: int, attempts: int = 4):
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    last_error: int | None = None
    for _ in range(attempts):
        ctypes.set_last_error(0)
        handle = kernel32.CreateToolhelp32Snapshot(flags, pid)
        if _handle_value(handle) not in (None, 0, INVALID_HANDLE_VALUE):
            return handle
        last_error = ctypes.get_last_error()
        if last_error != ERROR_BAD_LENGTH:
            break
    raise ModuleSensorUnavailable(pid, "CreateToolhelp32Snapshot", last_error)


def enumerate_process_modules(pid: int) -> tuple[LoadedModule, ...]:
    """대상 PID의 모듈을 읽는다. 대상 메모리를 수정하지 않는다."""
    pid = _valid_pid(pid)
    if os.name != "nt":
        raise ModuleSensorUnavailable(pid, "Windows 전용 센서")

    kernel32 = _kernel32()
    snapshot = _create_snapshot_handle(kernel32, pid)
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ctypes.set_last_error(0)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            error = ctypes.get_last_error()
            if error == ERROR_NO_MORE_FILES:
                return ()
            raise ModuleSensorUnavailable(pid, "Module32FirstW", error)

        modules: list[LoadedModule] = []
        while True:
            path = str(entry.szExePath).strip() or None
            name = str(entry.szModule).strip() or ntpath.basename(path or "")
            base_address = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
            modules.append(
                LoadedModule(
                    name=name,
                    path=path,
                    base_address=int(base_address),
                    image_size=int(entry.modBaseSize),
                )
            )

            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            ctypes.set_last_error(0)
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error != ERROR_NO_MORE_FILES:
                    raise ModuleSensorUnavailable(pid, "Module32NextW", error)
                break
        return tuple(sorted(modules, key=module_sort_key))
    finally:
        kernel32.CloseHandle(snapshot)


ModuleProvider = Callable[[int], Iterable[LoadedModule]]


class ToolhelpModuleSensor:
    """주입 가능한 provider를 사용해 시각이 포함된 모듈 스냅샷을 만든다."""

    def __init__(
        self,
        module_provider: ModuleProvider = enumerate_process_modules,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._module_provider = module_provider
        self._clock = clock

    def capture(self, pid: int) -> ModuleSnapshot:
        pid = _valid_pid(pid)
        return ModuleSnapshot(
            pid=pid,
            captured_at=self._clock(),
            modules=tuple(self._module_provider(pid)),
        )


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Module32FirstW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(MODULEENTRY32W),
    )
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(MODULEENTRY32W),
    )
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


__all__ = [
    "ERROR_BAD_LENGTH",
    "ERROR_NO_MORE_FILES",
    "LoadedModule",
    "ModuleSensorUnavailable",
    "ToolhelpModuleSensor",
    "enumerate_process_modules",
]
