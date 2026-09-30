"""EXE/DLL 파일의 SHA-256과 Windows Authenticode 정보를 조회한다."""

import ctypes
from ctypes import wintypes
import hashlib
import locale
import os
import subprocess
from pathlib import Path
from typing import Callable, Optional, Tuple

from .models import ArtifactInfo

SignatureReader = Callable[[Path], Tuple[str, Optional[str]]]


class ArtifactInspector:
    """파일 검사를 한 곳에 모아 EXE와 DLL이 같은 기준을 쓰게 한다."""

    def __init__(self, signature_reader: Optional[SignatureReader] = None) -> None:
        self._signature_reader = signature_reader or read_windows_authenticode

    def inspect(self, path: Path) -> ArtifactInfo:
        path = Path(path).expanduser().resolve()
        signature_status, publisher = self._signature_reader(path)
        return ArtifactInfo(
            path=path,
            sha256=calculate_sha256(path),
            signature_status=signature_status,
            publisher=publisher,
        )


def calculate_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """대용량 DLL도 한 번에 메모리에 올리지 않고 SHA-256을 계산한다."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_windows_system_directory() -> Path:
    """환경 변수나 PATH를 신뢰하지 않고 Windows 시스템 디렉터리를 반환한다."""
    if os.name != "nt":
        raise OSError("Windows 시스템 디렉터리는 Windows에서만 조회할 수 있음")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    if length >= len(buffer):
        raise OSError("Windows 시스템 디렉터리 경로가 버퍼보다 큼")
    system_directory = Path(buffer.value)
    if not system_directory.is_dir():
        raise OSError(f"Windows 시스템 디렉터리를 찾을 수 없음: {system_directory}")
    return system_directory.resolve()


def read_windows_authenticode(path: Path) -> Tuple[str, Optional[str]]:
    """Windows 서명 상태와 게시자를 조회한다.

    서명 조회 불가 자체는 치트 근거가 아니므로, 오류는 unknown으로 돌린다.
    """
    if os.name != "nt":
        return "unknown", None
    try:
        system_directory = get_windows_system_directory()
    except OSError:
        return "unknown", None
    powershell_root = system_directory / "WindowsPowerShell" / "v1.0"
    powershell_path = powershell_root / "powershell.exe"
    module_root = powershell_root / "Modules"
    security_manifest = (
        module_root
        / "Microsoft.PowerShell.Security"
        / "Microsoft.PowerShell.Security.psd1"
    )
    if not powershell_path.is_file() or not security_manifest.is_file():
        return "unknown", None
    script = (
        "& { $ErrorActionPreference = 'Stop'; "
        "Import-Module -Name $env:LOCALGUARD_SECURITY_MODULE -Force -ErrorAction Stop; "
        "$sig = Get-AuthenticodeSignature -LiteralPath $env:LOCALGUARD_ARTIFACT_PATH; "
        "Write-Output ([string]$sig.Status); "
        "if ($sig.SignerCertificate) { Write-Output ([string]$sig.SignerCertificate.Subject) } }"
    )
    child_environment = dict(os.environ)
    # Codex/PowerShell 7 같은 부모 프로세스의 PSModulePath를 물려받으면 Windows
    # PowerShell 5.1이 호환되지 않는 모듈을 먼저 선택할 수 있어 시스템 경로로 제한한다.
    child_environment.update(
        {
            "PSModulePath": str(module_root),
            "LOCALGUARD_ARTIFACT_PATH": str(path),
            "LOCALGUARD_SECURITY_MODULE": str(security_manifest),
        }
    )
    try:
        completed = subprocess.run(
            [
                str(powershell_path),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            timeout=15,
            env=child_environment,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown", None
    if completed.returncode != 0 or not completed.stdout.strip():
        return "unknown", None
    lines = completed.stdout.splitlines()
    status = lines[0].strip() if lines else "UnknownError"
    publisher = lines[1].strip() if len(lines) > 1 and lines[1].strip() else None
    if status == "Valid":
        return "trusted", publisher
    if status == "NotSigned":
        return "unsigned", None
    if status in {"HashMismatch", "NotTrusted"}:
        return "invalid", publisher
    return "unknown", publisher
