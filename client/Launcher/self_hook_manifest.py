"""Launcher-owned manifest for anti-cheat DLLs intentionally loaded into the game.

This is deliberately separate from ``ue4ss_install.json``.  UE4SS files live
under the game install root, while observer hooks are build artifacts under the
anti-cheat repository.  Mixing both trust roots would either reject the hook or
make the game-root exception too broad.

The Launcher records only a hook path explicitly selected on its command line,
and that path must equal the reviewed observer build output.  There is no glob
or directory auto-discovery.  The consumer must still compare the observed
DLL's exact absolute path and SHA-256 with the manifest entry before suppressing
a detection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


VERSION = 1
ENV_PATH = "GZZ_SELF_HOOK_MANIFEST"
HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
DEFAULT_PATH = HERE / "logs" / "self_hook_manifest.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_HOOKS = 32

# This is the defensive observer DLL used by the whistle detector.  Do not add
# generic build/output folders here: doing so would allow a test cheat DLL to
# inherit the anti-cheat exception merely by being placed in the repository.
WHISTLE_OBSERVER_RELATIVE_PATH = Path(
    "client/detectors/whistle-spoofing/native/whistle_hook/bin/Release/"
    "ac_whistle_v10.dll"
)


@dataclass(frozen=True)
class VerifiedHook:
    role: str
    path: Path
    sha256: str


def path_for() -> Path:
    configured = os.environ.get(ENV_PATH, "").strip()
    return Path(configured) if configured else DEFAULT_PATH


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
        os.path.normpath(str(right))
    )


def _approved_hook(path: Path, repository_root: Path) -> Optional[str]:
    """Return the hook role only for the narrow, reviewed observer location."""
    try:
        resolved_root = Path(repository_root).resolve(strict=False)
        resolved = Path(path).resolve(strict=False)
        relative = resolved.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        return None

    if tuple(part.casefold() for part in relative.parts) != tuple(
        part.casefold() for part in WHISTLE_OBSERVER_RELATIVE_PATH.parts
    ):
        return None
    return "whistle_observer"


def record(
    hooks: Iterable[Path],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    output_path: Optional[Path] = None,
) -> dict:
    """Atomically write exact path/hash records for approved observer hooks."""
    raw_root = Path(repository_root)
    if not raw_root.is_absolute():
        raise ValueError("repository_root는 절대 경로여야 함")
    root = raw_root.resolve(strict=False)
    entries = []
    seen = set()
    for supplied in hooks:
        candidate = Path(supplied).resolve(strict=True)
        role = _approved_hook(candidate, root)
        if role is None:
            raise ValueError(f"approved self-hook path가 아님: {candidate}")
        key = os.path.normcase(os.path.normpath(str(candidate)))
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            {
                "role": role,
                "path": str(candidate),
                "sha256": sha256_of(candidate),
            }
        )
    entries.sort(key=lambda item: os.path.normcase(item["path"]))
    data = {
        "version": VERSION,
        "repository_root": str(root),
        "hooks": entries,
    }
    destination = Path(output_path) if output_path is not None else path_for()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)
    return data


def load_verified(
    path: Path,
    *,
    trusted_repository_root: Path,
) -> tuple[VerifiedHook, ...]:
    """Read a manifest through a fixed repository/path/name trust boundary."""
    manifest_path = Path(path)
    try:
        raw_trusted_root = Path(trusted_repository_root)
        if not raw_trusted_root.is_absolute():
            return ()
        trusted_root = raw_trusted_root.resolve(strict=False)
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            return ()
        raw = json.loads(
            manifest_path.read_text(encoding="utf-8-sig"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return ()

    if (
        not isinstance(raw, dict)
        or type(raw.get("version")) is not int
        or raw["version"] != VERSION
    ):
        return ()
    recorded_root = raw.get("repository_root")
    hooks = raw.get("hooks")
    if not isinstance(recorded_root, str) or not isinstance(hooks, list):
        return ()
    if len(hooks) > MAX_HOOKS:
        return ()
    try:
        manifest_root = Path(recorded_root).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return ()
    if not _same_path(manifest_root, trusted_root):
        return ()

    verified = {}
    conflicted = set()
    for item in hooks:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        raw_path = item.get("path")
        digest = item.get("sha256")
        if not all(isinstance(value, str) for value in (role, raw_path, digest)):
            continue
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            continue
        try:
            candidate = candidate.resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            continue
        approved_role = _approved_hook(candidate, trusted_root)
        normalized_digest = digest.strip().lower()
        if role != approved_role or not _valid_sha256(normalized_digest):
            continue
        key = os.path.normcase(os.path.normpath(str(candidate)))
        if key in conflicted:
            continue
        previous = verified.get(key)
        entry = VerifiedHook(role=role, path=candidate, sha256=normalized_digest)
        if previous is not None and previous != entry:
            conflicted.add(key)
            verified.pop(key, None)
            continue
        verified[key] = entry
    return tuple(verified[key] for key in sorted(verified))


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("self-hook manifest JSON object에 중복 key가 있음")
        result[key] = value
    return result


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="승인된 안티치트 관측 후크의 절대 경로·SHA-256 manifest 생성"
    )
    parser.add_argument(
        "--hook",
        type=Path,
        action="append",
        required=True,
        help="Launcher가 실제 관측용으로 선택할 ac_whistle_v10.dll 절대/상대 경로",
    )
    parser.add_argument("--output", type=Path, default=path_for())
    args = parser.parse_args()
    data = record(args.hook, output_path=args.output)
    print(f"self-hook manifest: {args.output} ({len(data['hooks'])} hook(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_PATH",
    "ENV_PATH",
    "REPOSITORY_ROOT",
    "VerifiedHook",
    "load_verified",
    "path_for",
    "record",
]
