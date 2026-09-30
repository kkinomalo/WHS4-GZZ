"""검토가 끝난 정상 DLL을 정확한 이름과 SHA-256으로 예외 처리한다."""

from __future__ import annotations

import json
import ntpath
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


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


__all__ = ["ModuleAllowlist", "ModuleAllowlistEntry"]
