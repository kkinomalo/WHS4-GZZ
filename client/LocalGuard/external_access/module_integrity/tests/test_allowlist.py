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


if __name__ == "__main__":
    unittest.main()
