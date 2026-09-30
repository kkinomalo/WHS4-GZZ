"""external_access 내부에서 공유하는 값 객체."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class FileFingerprint:
    """내용 해시와 함께 캐시 무효화에 쓰는 파일 메타데이터."""

    path: Path
    size: int
    modified_time_ns: int


@dataclass(frozen=True)
class ArtifactInfo:
    """EXE와 DLL에 공통으로 적용되는 신뢰도 검사 결과."""

    path: Path
    sha256: Optional[str]
    # trusted | unsigned | invalid | unknown
    signature_status: str
    publisher: Optional[str]


@dataclass(frozen=True)
class TargetProcess:
    """PID 재사용을 구별할 수 있는 게임 프로세스 식별자."""

    pid: int
    executable_name: str
    executable_path: Optional[Path]
    create_time: Optional[float]
