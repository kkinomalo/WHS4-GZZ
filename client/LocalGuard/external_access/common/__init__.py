"""external_access 하위 탐지기들이 함께 쓰는 읽기 전용 도구."""

from .artifact_cache import ArtifactCache
from .artifact_inspector import ArtifactInspector, get_windows_system_directory
from .detection_result import build_detection_result, validate_detection_result
from .jsonl_writer import append_detection_jsonl
from .models import ArtifactInfo, FileFingerprint, TargetProcess
from .process_locator import AmbiguousTargetProcessError, ProcessLocator, describe_process

__all__ = [
    "ArtifactCache", "ArtifactInfo", "ArtifactInspector", "FileFingerprint",
    "AmbiguousTargetProcessError", "ProcessLocator", "TargetProcess",
    "append_detection_jsonl", "describe_process",
    "build_detection_result", "get_windows_system_directory",
    "validate_detection_result",
]
