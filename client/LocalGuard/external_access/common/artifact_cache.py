"""내용 해시로 검증한 Authenticode 결과를 재사용하는 메모리 캐시."""

from pathlib import Path
from threading import RLock
from typing import Dict, Tuple

from .artifact_inspector import ArtifactInspector, calculate_sha256
from .models import ArtifactInfo, FileFingerprint


class ArtifactCache:
    """파일 메타데이터와 실제 내용 해시가 모두 같을 때만 결과를 재사용한다.

    크기와 수정 시각만 사용하면 공격자가 같은 크기의 파일로 교체한 뒤 mtime을
    복원해 오래된 정상 서명 결과를 재사용하게 만들 수 있다. 따라서 캐시 조회 때도
    SHA-256은 다시 계산하고, 비용이 큰 Authenticode 결과만 안전하게 재사용한다.
    """

    def __init__(self, inspector: ArtifactInspector) -> None:
        self._inspector = inspector
        self._entries: Dict[Path, Tuple[FileFingerprint, ArtifactInfo]] = {}
        self._lock = RLock()

    def inspect(self, path: Path) -> ArtifactInfo:
        fingerprint = file_fingerprint(path)
        current_sha256 = calculate_sha256(fingerprint.path)
        with self._lock:
            cached = self._entries.get(fingerprint.path)
            if (
                cached
                and cached[0] == fingerprint
                and cached[1].sha256 == current_sha256
            ):
                return cached[1]
        inspected = self._inspector.inspect(fingerprint.path)
        # 검사 중 교체된 파일을 이전 메타데이터와 묶어 캐시하지 않는다.
        final_fingerprint = file_fingerprint(fingerprint.path)
        with self._lock:
            if final_fingerprint == fingerprint and inspected.sha256 == current_sha256:
                self._entries[fingerprint.path] = (fingerprint, inspected)
            else:
                self._entries.pop(fingerprint.path, None)
        return inspected

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def file_fingerprint(path: Path) -> FileFingerprint:
    path = Path(path).expanduser().resolve()
    metadata = path.stat()
    return FileFingerprint(path, metadata.st_size, metadata.st_mtime_ns)
