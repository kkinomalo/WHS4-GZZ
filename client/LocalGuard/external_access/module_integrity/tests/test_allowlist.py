import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from client.LocalGuard.external_access.module_integrity.allowlist import ModuleAllowlist


class ModuleAllowlistTests(unittest.TestCase):
    def test_exact_name_and_hash_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.json"
            path.write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "module_name": "normal.dll",
                                "sha256": "a" * 64,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            allowlist = ModuleAllowlist.from_json(path)

        self.assertIsNotNone(allowlist.find("NORMAL.DLL", "a" * 64))
        self.assertIsNone(allowlist.find("normal.dll", "b" * 64))
        self.assertIsNone(allowlist.find("renamed.dll", "a" * 64))

    def test_optional_path_signature_and_publisher_are_all_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.json"
            path.write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "module_name": "plugin.dll",
                                "sha256": "c" * 64,
                                "module_path": "C:/Game/plugin.dll",
                                "signature_status": "trusted",
                                "publisher_contains": "Example Studio",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            allowlist = ModuleAllowlist.from_json(path)

        self.assertIsNotNone(
            allowlist.find(
                "plugin.dll",
                "c" * 64,
                module_path=Path(r"\\?\c:\game\PLUGIN.dll"),
                signature_status="trusted",
                publisher="CN=Example Studio, C=KR",
            )
        )
        self.assertIsNone(
            allowlist.find(
                "plugin.dll",
                "c" * 64,
                module_path=Path(r"C:\Temp\plugin.dll"),
                signature_status="trusted",
                publisher="CN=Example Studio, C=KR",
            )
        )

    def test_invalid_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.json"
            path.write_text(
                json.dumps(
                    {"entries": [{"module_name": "x.dll", "sha256": "short"}]}
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                ModuleAllowlist.from_json(path)

    def test_ue4ss_manifest_requires_exact_observed_path_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            game_root = Path(directory) / "game"
            dll = game_root / "Chameleon" / "Binaries" / "Win64" / "ue4ss" / "UE4SS.dll"
            dll.parent.mkdir(parents=True)
            dll.write_bytes(b"reviewed UE4SS fixture")
            digest = hashlib.sha256(dll.read_bytes()).hexdigest()
            manifest = Path(directory) / "ue4ss_install.json"
            manifest.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "game_root": str(game_root),
                        "files": {
                            "Chameleon/Binaries/Win64/ue4ss/UE4SS.dll": digest,
                            "Chameleon/Binaries/Win64/ue4ss/Mods/Test/main.lua": "b" * 64,
                        },
                    }
                ),
                encoding="utf-8",
            )

            allowlist = ModuleAllowlist.from_ue4ss_manifest(
                manifest,
                trusted_game_root=game_root,
            )

        self.assertEqual(len(allowlist.entries), 1)
        self.assertIsNotNone(
            allowlist.find("ue4ss.dll", digest, module_path=dll.resolve())
        )
        self.assertIsNone(
            allowlist.find("ue4ss.dll", "f" * 64, module_path=dll.resolve())
        )
        self.assertIsNone(
            allowlist.find(
                "ue4ss.dll",
                digest,
                module_path=Path(directory) / "elsewhere" / "UE4SS.dll",
            )
        )

    def test_ue4ss_manifest_rejects_path_escape_and_invalid_records(self):
        with tempfile.TemporaryDirectory() as directory:
            game_root = Path(directory) / "game"
            game_root.mkdir()
            manifest = Path(directory) / "ue4ss_install.json"
            manifest.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "game_root": str(game_root),
                        "files": {
                            "../outside.dll": "a" * 64,
                            "C:/Temp/absolute.dll": "b" * 64,
                            "safe/bad-hash.dll": "short",
                            "safe/not-a-dll.txt": "c" * 64,
                            "safe/value-object.dll": {"sha256": "d" * 64},
                            "safe/hook.dll:stream": "e" * 64,
                            "safe/CON.dll": "f" * 64,
                            "\\rooted.dll": "1" * 64,
                        },
                    }
                ),
                encoding="utf-8",
            )

            allowlist = ModuleAllowlist.from_ue4ss_manifest(
                manifest,
                trusted_game_root=game_root,
            )

        self.assertEqual(allowlist.entries, ())

    def test_ue4ss_manifest_absence_and_format_errors_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.json"
            self.assertEqual(
                ModuleAllowlist.from_ue4ss_manifest(
                    missing,
                    trusted_game_root=root,
                ).entries,
                (),
            )

            broken = root / "broken.json"
            broken.write_text("{not-json", encoding="utf-8")
            self.assertEqual(
                ModuleAllowlist.from_ue4ss_manifest(
                    broken,
                    trusted_game_root=root,
                ).entries,
                (),
            )

            unsupported = root / "unsupported.json"
            unsupported.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "game_root": str(root),
                        "files": {"hook.dll": "a" * 64},
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                ModuleAllowlist.from_ue4ss_manifest(
                    unsupported,
                    trusted_game_root=root,
                ).entries,
                (),
            )

    def test_ue4ss_manifest_cannot_choose_a_different_trusted_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / "trusted-game"
            claimed = root / "claimed-game"
            trusted.mkdir()
            claimed.mkdir()
            manifest = root / "ue4ss_install.json"
            manifest.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "game_root": str(claimed),
                        "files": {"hook.dll": "a" * 64},
                    }
                ),
                encoding="utf-8",
            )

            allowlist = ModuleAllowlist.from_ue4ss_manifest(
                manifest,
                trusted_game_root=trusted,
            )

        self.assertEqual(allowlist.entries, ())

    def test_ue4ss_manifest_rejects_duplicate_keys_and_non_integer_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"version":1,"game_root":'
                + json.dumps(str(root))
                + ',"files":{"hook.dll":"'
                + "a" * 64
                + '","hook.dll":"'
                + "b" * 64
                + '"}}',
                encoding="utf-8",
            )
            self.assertEqual(
                ModuleAllowlist.from_ue4ss_manifest(
                    duplicate,
                    trusted_game_root=root,
                ).entries,
                (),
            )

            boolean_version = root / "boolean-version.json"
            boolean_version.write_text(
                json.dumps(
                    {
                        "version": True,
                        "game_root": str(root),
                        "files": {"hook.dll": "a" * 64},
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                ModuleAllowlist.from_ue4ss_manifest(
                    boolean_version,
                    trusted_game_root=root,
                ).entries,
                (),
            )

    def test_self_hook_manifest_requires_approved_path_and_exact_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hook = (
                root
                / "client"
                / "detectors"
                / "whistle-spoofing"
                / "native"
                / "whistle_hook"
                / "bin"
                / "Release"
                / "ac_whistle_v10.dll"
            )
            hook.parent.mkdir(parents=True)
            hook.write_bytes(b"reviewed observer hook")
            digest = hashlib.sha256(hook.read_bytes()).hexdigest()
            manifest = root / "self_hook_manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "repository_root": str(root),
                        "hooks": [
                            {
                                "role": "whistle_observer",
                                "path": str(hook.resolve()),
                                "sha256": digest,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            allowlist = ModuleAllowlist.from_self_hook_manifest(
                manifest,
                trusted_repository_root=root,
            )

            self.assertIsNotNone(
                allowlist.find(
                    hook.name,
                    digest,
                    module_path=hook.resolve(),
                )
            )
            self.assertIsNone(
                allowlist.find(
                    hook.name,
                    "f" * 64,
                    module_path=hook.resolve(),
                )
            )
            self.assertIsNone(
                allowlist.find(
                    hook.name,
                    digest,
                    module_path=root / "elsewhere" / hook.name,
                )
            )


if __name__ == "__main__":
    unittest.main()
