import unittest
from pathlib import Path

from client.LocalGuard.external_access.common.models import ArtifactInfo
from client.LocalGuard.external_access.module_integrity.detector import (
    ModuleIntegrityDetector,
)
from client.LocalGuard.external_access.module_integrity.models import (
    LoadedModule,
    ModuleObservation,
    ScanContext,
)


class ModuleIntegrityDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = ModuleIntegrityDetector()
        self.context = ScanContext("esp_001", "player_042", 32500, 1234)
        self.module = LoadedModule("extra.dll", r"C:\Temp\extra.dll", 0x1000, 4096)

    def test_added_unsigned_module_uses_common_seven_field_format(self):
        observation = ModuleObservation(
            change_type="added",
            module=self.module,
            artifact=ArtifactInfo(
                path=Path(r"C:\Temp\extra.dll"),
                sha256="a" * 64,
                signature_status="unsigned",
                publisher=None,
            ),
        )

        result = self.detector.evaluate(observation, self.context)

        self.assertEqual(
            set(result),
            {
                "session_id",
                "player_id",
                "module",
                "timestamp_ms",
                "evidence",
                "reasons",
                "raw_score",
            },
        )
        self.assertEqual(result["module"], "module_integrity")
        self.assertEqual(result["evidence"]["submodule"], "module_integrity")
        self.assertEqual(result["evidence"]["status"], "SUSPICIOUS")
        self.assertEqual(result["evidence"]["submodule"], "module_integrity")
        self.assertEqual(result["raw_score"], 2)
        self.assertIn("Module appeared after the process baseline", result["reasons"])
        self.assertIn("Module signature is unsigned", result["reasons"])

    def test_changed_invalid_module_is_weighted_more_strongly(self):
        observation = ModuleObservation(
            change_type="changed",
            module=self.module,
            artifact=ArtifactInfo(
                path=Path(r"C:\Temp\extra.dll"),
                sha256="b" * 64,
                signature_status="invalid",
                publisher="CN=Unknown",
            ),
            previous_base_address=0x500,
            previous_image_size=2048,
        )

        result = self.detector.evaluate(observation, self.context)

        self.assertEqual(result["raw_score"], 3)
        self.assertEqual(result["evidence"]["previous_base_address"], "0x500")
        self.assertEqual(result["evidence"]["previous_image_size"], 2048)

    def test_unknown_inspection_does_not_add_unproven_signature_score(self):
        observation = ModuleObservation(
            change_type="added",
            module=self.module,
            inspection_error="file disappeared",
        )

        result = self.detector.evaluate(observation, self.context)

        self.assertEqual(result["raw_score"], 1)
        self.assertEqual(result["evidence"]["signature_status"], "unknown")
        self.assertEqual(result["evidence"]["inspection_error"], "file disappeared")


if __name__ == "__main__":
    unittest.main()
