import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys


LAUNCHER_DIR = Path(__file__).resolve().parents[1]
if str(LAUNCHER_DIR) not in sys.path:
    sys.path.insert(0, str(LAUNCHER_DIR))

import self_hook_manifest  # noqa: E402


class SelfHookManifestTests(unittest.TestCase):
    @staticmethod
    def _approved_hook(root: Path, name: str = "ac_whistle_v10.dll") -> Path:
        hook = (
            root
            / "client"
            / "detectors"
            / "whistle-spoofing"
            / "native"
            / "whistle_hook"
            / "bin"
            / "Release"
            / name
        )
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_bytes(b"anti-cheat observer hook fixture")
        return hook

    def test_explicit_selection_records_only_approved_observer_with_exact_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = self._approved_hook(root)
            output = root / "runtime" / "self_hook_manifest.json"

            data = self_hook_manifest.record(
                [approved],
                repository_root=root,
                output_path=output,
            )
            verified = self_hook_manifest.load_verified(
                output,
                trusted_repository_root=root,
            )

            self.assertEqual(len(data["hooks"]), 1)
            self.assertEqual(len(verified), 1)
            self.assertEqual(verified[0].role, "whistle_observer")
            self.assertEqual(verified[0].path, approved.resolve())
            self.assertEqual(
                verified[0].sha256,
                hashlib.sha256(approved.read_bytes()).hexdigest(),
            )

    def test_record_rejects_non_observer_paths_and_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "modules" / "whistle-spoofing" / "whistle_v15.dll"
            outside.parent.mkdir(parents=True)
            outside.write_bytes(b"test cheat")
            wrong_name = self._approved_hook(root, "arbitrary.dll")
            future_version = self._approved_hook(root, "ac_whistle_v99.dll")

            for candidate in (outside, wrong_name, future_version):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(ValueError):
                        self_hook_manifest.record(
                            [candidate],
                            repository_root=root,
                            output_path=root / "manifest.json",
                        )

    def test_no_explicit_selection_does_not_auto_approve_existing_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._approved_hook(root)
            output = root / "manifest.json"

            data = self_hook_manifest.record(
                [],
                repository_root=root,
                output_path=output,
            )

            self.assertEqual(data["hooks"], [])
            self.assertEqual(
                self_hook_manifest.load_verified(
                    output,
                    trusted_repository_root=root,
                ),
                (),
            )

    def test_reader_rejects_root_mismatch_and_tampered_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = self._approved_hook(root)
            output = root / "manifest.json"
            self_hook_manifest.record(
                [approved],
                repository_root=root,
                output_path=output,
            )

            other_root = root / "other"
            other_root.mkdir()
            self.assertEqual(
                self_hook_manifest.load_verified(
                    output,
                    trusted_repository_root=other_root,
                ),
                (),
            )

            raw = json.loads(output.read_text(encoding="utf-8"))
            raw["hooks"][0]["role"] = "arbitrary_hook"
            output.write_text(json.dumps(raw), encoding="utf-8")
            self.assertEqual(
                self_hook_manifest.load_verified(
                    output,
                    trusted_repository_root=root,
                ),
                (),
            )

    def test_reader_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "manifest.json"
            output.write_text(
                '{"version":1,"version":1,"repository_root":'
                + json.dumps(str(root))
                + ',"hooks":[]}',
                encoding="utf-8",
            )
            self.assertEqual(
                self_hook_manifest.load_verified(
                    output,
                    trusted_repository_root=root,
                ),
                (),
            )

    def test_reader_does_not_accept_tampered_v99_manifest_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            future_version = self._approved_hook(root, "ac_whistle_v99.dll")
            output = root / "manifest.json"
            output.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "repository_root": str(root),
                        "hooks": [
                            {
                                "role": "whistle_observer",
                                "path": str(future_version),
                                "sha256": hashlib.sha256(
                                    future_version.read_bytes()
                                ).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                self_hook_manifest.load_verified(
                    output,
                    trusted_repository_root=root,
                ),
                (),
            )


if __name__ == "__main__":
    unittest.main()
