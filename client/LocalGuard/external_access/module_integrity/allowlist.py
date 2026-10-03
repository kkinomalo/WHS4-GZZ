"""검토가 끝난 정상 DLL을 정확한 이름과 SHA-256으로 예외 처리한다."""

from __future__ import annotations

import json
import ntpath
import os
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Iterable, Optional

from client.Launcher.self_hook_manifest import (
    DEFAULT_PATH as DEFAULT_SELF_HOOK_MANIFEST_PATH,
    load_verified as load_verified_self_hooks,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_UE4SS_MANIFEST_PATH = (
    REPOSITORY_ROOT / "client" / "Launcher" / "logs" / "ue4ss_install.json"
)
UE4SS_MANIFEST_VERSION = 1
MAX_UE4SS_MANIFEST_BYTES = 1024 * 1024
MAX_UE4SS_MANIFEST_FILES = 4096


@dataclass(frozen=True)
class ModuleAllowlistEntry:
    module_name: str
    sha256: str
    note: Optional[str] = None
    module_path: Optional[str] = None
    required_signature_status: Optional[str] = None
    publisher_contains: Optional[str] = None

    def matches(
        self,
        module_name: str,
        sha256: str,
        *,
        module_path: Optional[Path] = None,
        signature_status: Optional[str] = None,
        publisher: Optional[str] = None,
    ) -> bool:
        if self.module_name.casefold() != module_name.casefold():
            return False
        if self.sha256.casefold() != sha256.casefold():
            return False
        if self.module_path is not None:
            if module_path is None:
                return False
            if _normalize_windows_path(self.module_path) != _normalize_windows_path(module_path):
                return False
        if self.required_signature_status is not None:
            if (signature_status or "").casefold() != self.required_signature_status.casefold():
                return False
        if self.publisher_contains is not None:
            if self.publisher_contains.casefold() not in (publisher or "").casefold():
                return False
        return True


class ModuleAllowlist:
    def __init__(self, entries: Iterable[ModuleAllowlistEntry] = ()) -> None:
        self.entries = tuple(entries)

    @classmethod
    def from_json(cls, path: Path) -> "ModuleAllowlist":
        path = Path(path)
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("entries", []), list):
            raise ValueError("allowlist 최상위 형식은 entries 배열이어야 함")

        entries = []
        for index, item in enumerate(raw.get("entries", [])):
            if not isinstance(item, dict):
                raise ValueError(f"allowlist entries[{index}] 형식 오류")
            try:
                name = str(item["module_name"]).strip()
                sha256 = str(item["sha256"]).strip().lower()
            except KeyError as error:
                raise ValueError(f"allowlist entries[{index}] 필수 필드 누락") from error
            if not name or not _valid_sha256(sha256):
                raise ValueError(f"allowlist entries[{index}] 이름 또는 SHA-256 오류")
            entries.append(
                ModuleAllowlistEntry(
                    module_name=name,
                    sha256=sha256,
                    note=item.get("note"),
                    module_path=_optional_nonempty_string(item, "module_path", index),
                    required_signature_status=_optional_nonempty_string(
                        item, "signature_status", index
                    ),
                    publisher_contains=_optional_nonempty_string(
                        item, "publisher_contains", index
                    ),
                )
            )
        return cls(entries)

    @classmethod
    def from_ue4ss_manifest(
        cls,
        path: Path,
        *,
        trusted_game_root: Path,
    ) -> "ModuleAllowlist":
        """런처 manifest의 검토된 DLL 해시를 경로 고정 allowlist로 바꾼다.

        이 파일은 PC별 런타임 산출물이라 없거나 설치 도중 교체될 수 있다. 그런
        상태와 깨진 JSON, 알 수 없는 버전, 잘못된 경로·해시는 모두 빈 목록으로
        처리한다. manifest가 임의 경로를 신뢰 경계로 만들지 못하도록 런처가 별도로
        확인한 ``trusted_game_root``와 기록된 root가 같을 때만 사용한다. manifest에
        이름이 있다는 사실만으로는 허용하지 않으며, runner가 실제 관측 DLL의
        SHA-256을 계산한 뒤 여기 만든 정확한 경로와 함께 대조한다.
        """
        path = Path(path)
        try:
            trusted_root = Path(trusted_game_root).expanduser()
            if not trusted_root.is_absolute():
                return cls()
            trusted_root = trusted_root.resolve(strict=False)
            if path.stat().st_size > MAX_UE4SS_MANIFEST_BYTES:
                return cls()
            raw = json.loads(
                path.read_text(encoding="utf-8-sig"),
                object_pairs_hook=_object_without_duplicate_keys,
            )
        except (OSError, RuntimeError, UnicodeError, ValueError):
            return cls()

        if (
            not isinstance(raw, dict)
            or type(raw.get("version")) is not int
            or raw["version"] != UE4SS_MANIFEST_VERSION
        ):
            return cls()
        files = raw.get("files")
        game_root = raw.get("game_root")
        if not isinstance(files, dict) or len(files) > MAX_UE4SS_MANIFEST_FILES:
            return cls()
        if not isinstance(game_root, str) or not game_root.strip():
            return cls()

        try:
            recorded_root = Path(os.path.expandvars(game_root.strip())).expanduser()
            if not recorded_root.is_absolute():
                return cls()
            recorded_root = recorded_root.resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            return cls()
        if _normalize_windows_path(recorded_root) != _normalize_windows_path(trusted_root):
            return cls()

        candidates = {}
        conflicts = set()
        for relative_path, expected_hash in files.items():
            if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
                continue
            digest = expected_hash.strip().lower()
            if not _valid_sha256(digest):
                continue

            relative = _safe_manifest_relative_path(relative_path)
            if relative is None or relative.suffix.casefold() != ".dll":
                continue
            try:
                candidate = trusted_root.joinpath(*relative.parts).resolve(strict=False)
                candidate.relative_to(trusted_root)
            except (OSError, RuntimeError, ValueError):
                continue

            module_name = relative.name
            path_key = _normalize_windows_path(candidate)
            if path_key in conflicts:
                continue
            existing = candidates.get(path_key)
            if existing is not None:
                if existing.sha256 != digest:
                    conflicts.add(path_key)
                    candidates.pop(path_key, None)
                continue
            candidates[path_key] = ModuleAllowlistEntry(
                module_name=module_name,
                sha256=digest,
                module_path=str(candidate),
                note="Launcher UE4SS install manifest v1",
            )
        return cls(candidates.values())

    @classmethod
    def from_self_hook_manifest(
        cls,
        path: Path,
        *,
        trusted_repository_root: Path,
    ) -> "ModuleAllowlist":
        """Load Launcher-recorded observer hooks as exact path/hash exceptions.

        The Launcher manifest reader enforces the separate repository trust
        root, approved observer build directory, hook role, filename, absolute
        path and SHA-256 shape.  The module runner later hashes the observed DLL
        bytes and requires this exact path before suppressing the event.
        """
        hooks = load_verified_self_hooks(
            path,
            trusted_repository_root=trusted_repository_root,
        )
        return cls(
            ModuleAllowlistEntry(
                module_name=hook.path.name,
                sha256=hook.sha256,
                module_path=str(hook.path),
                note=f"Launcher self-hook manifest v1 ({hook.role})",
            )
            for hook in hooks
        )

    def merged(self, *others: "ModuleAllowlist") -> "ModuleAllowlist":
        entries = list(self.entries)
        for other in others:
            if not isinstance(other, ModuleAllowlist):
                raise TypeError("merged에는 ModuleAllowlist만 전달할 수 있음")
            entries.extend(other.entries)
        return ModuleAllowlist(entries)

    def find(
        self,
        module_name: str,
        sha256: str,
        *,
        module_path: Optional[Path] = None,
        signature_status: Optional[str] = None,
        publisher: Optional[str] = None,
    ) -> Optional[ModuleAllowlistEntry]:
        return next(
            (
                entry
                for entry in self.entries
                if entry.matches(
                    module_name,
                    sha256,
                    module_path=module_path,
                    signature_status=signature_status,
                    publisher=publisher,
                )
            ),
            None,
        )


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("manifest JSON object에 중복 key가 있음")
        result[key] = value
    return result


def _safe_manifest_relative_path(value: str) -> Optional[PureWindowsPath]:
    text = value.strip()
    if not text or "\x00" in text:
        return None
    relative = PureWindowsPath(text)
    if relative.is_absolute() or relative.drive or relative.root:
        return None
    for part in relative.parts:
        if part in {"", ".", ".."} or ":" in part or part != part.rstrip(" ."):
            return None
        device = part.split(".", 1)[0].casefold()
        if device in {"con", "prn", "aux", "nul"}:
            return None
        if len(device) == 4 and device[:3] in {"com", "lpt"} and device[3] in "123456789":
            return None
    return relative


def _optional_nonempty_string(item: dict, key: str, index: int) -> Optional[str]:
    value = item.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"allowlist entries[{index}].{key} 형식 오류")
    return value.strip()


def _normalize_windows_path(path: object) -> str:
    expanded = os.path.expandvars(str(path)).replace("/", "\\")
    lowered = expanded.casefold()
    if lowered.startswith("\\\\?\\unc\\"):
        expanded = "\\\\" + expanded[8:]
    elif lowered.startswith("\\\\?\\"):
        expanded = expanded[4:]
    elif lowered.startswith("\\??\\"):
        expanded = expanded[4:]
    return ntpath.normcase(ntpath.normpath(expanded))


__all__ = [
    "DEFAULT_SELF_HOOK_MANIFEST_PATH",
    "DEFAULT_UE4SS_MANIFEST_PATH",
    "ModuleAllowlist",
    "ModuleAllowlistEntry",
]
