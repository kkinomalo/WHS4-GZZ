import unittest

from anti_esp.core.context import ProcessTarget
from anti_esp.sensors.process_relationships import (
    SteamExecutableVerifier,
    is_steam_launch_parent_access,
)


class ProcessRelationshipTests(unittest.TestCase):
    def test_steam_verifier_requires_registered_path_and_trusted_signature(self):
        official = r"C:\Program Files (x86)\Steam\steam.exe"
        verifier = SteamExecutableVerifier(
            lambda _path: {"signature_status": "trusted"},
            executable_paths_provider=lambda: (official,),
        )
        rejected_signature = SteamExecutableVerifier(
            lambda _path: {"signature_status": "rejected"},
            executable_paths_provider=lambda: (official,),
        )

        self.assertTrue(verifier(official.upper()))
        self.assertFalse(verifier(r"C:\Temp\steam.exe"))
        self.assertFalse(rejected_signature(official))

    def test_parent_name_and_relationship_without_verification_are_not_enough(self):
        fake_steam = r"C:\Temp\steam.exe"
        target = ProcessTarget(
            77,
            r"C:\Game\game.exe",
            created_at=100.0,
            parent_pid=22,
            parent_created_at=50.0,
            parent_executable_path=fake_steam,
        )

        self.assertFalse(
            is_steam_launch_parent_access(
                target=target,
                source_pid=22,
                source_image=fake_steam,
                granted_access=0x3A,
                observed_at=101.0,
            )
        )
        self.assertTrue(
            is_steam_launch_parent_access(
                target=target,
                source_pid=22,
                source_image=fake_steam,
                granted_access=0x3A,
                observed_at=101.0,
                source_verified=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
