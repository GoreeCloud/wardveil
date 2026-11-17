"""Negative admission tests for the read-only local ClamAV host audit."""
import copy
from datetime import datetime, timezone
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
source = ROOT / "tools" / "clamav" / "audit_local.py"
spec = importlib.util.spec_from_file_location("clamav_audit_local", source)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

NOW = datetime(2026, 11, 17, 21, 0, tzinfo=timezone.utc)
VERSION = "ClamAV 1.5.4/28186/Tue Nov 17 06:30:05 2026"
DATABASE = ("File: /var/lib/clamav/daily.cld\n"
            "Build time: 17 Nov 2026 06:30 +0000\n"
            "Version: 28186\nSignatures: 355871\nVerification OK.\n")


def snapshot():
    return {
        "Name": "/" + audit.CONTAINER,
        "RestartCount": 0,
        "State": {"Status": "running", "Health": {"Status": "healthy"}},
        "Config": {"Image": audit.IMAGE, "User": "clamav"},
        "HostConfig": {
            "Memory": 4 * 1024**3, "PidsLimit": 64, "Privileged": False,
            "ReadonlyRootfs": True, "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"], "PortBindings": {},
            "Binds": None,
        },
        "NetworkSettings": {
            "Networks": {audit.NETWORK: {}},
            "Ports": {"3310/tcp": None, "7357/tcp": None},
        },
        "Mounts": [{
            "Type": "volume", "Name": audit.VOLUME,
            "Destination": "/var/lib/clamav",
        }],
    }


class AuditTests(unittest.TestCase):
    def verify(self, obj=None, engine=VERSION, database=DATABASE, updater=True):
        return audit.audit_snapshot(snapshot() if obj is None else obj,
                                    engine, database, updater, NOW)

    def test_genuine_signed_current_private_daemon(self):
        result = self.verify()
        self.assertEqual(result["state"], "READY")
        self.assertEqual(result["engine_daily_version"], 28186)
        self.assertEqual(result["verified_disk_daily_version"], 28186)
        self.assertGreater(result["daily_age_hours"], 0)
        self.assertEqual(result["reasons"], [])

    def test_missing_updater_and_stale_loaded_signatures_fail_closed(self):
        self.assertIn("SIGNATURE_UPDATER_NOT_RUNNING",
                      self.verify(updater=False)["reasons"])
        self.assertIn("SIGNATURE_GENERATION_MISMATCH",
                      self.verify(engine=VERSION.replace("28186", "28184"))["reasons"])

    def test_forged_unverified_and_expired_database_fail_closed(self):
        self.assertIn("SIGNATURE_VERIFICATION_FAILED",
                      self.verify(database=DATABASE.replace("Verification OK.", ""))["reasons"])
        expired = DATABASE.replace("17 Nov 2026", "10 Nov 2026")
        self.assertIn("SIGNATURES_TOO_OLD",
                      self.verify(database=expired)["reasons"])
        future = DATABASE.replace("17 Nov 2026", "22 Nov 2026")
        self.assertIn("FUTURE_SIGNATURE_BUILD_TIME",
                      self.verify(database=future)["reasons"])

    def test_public_port_wrong_image_host_mount_and_privilege_are_rejected(self):
        cases = [
            ("HOST_PORT_PUBLISHED", ("HostConfig", "PortBindings"), {"3310/tcp": [{"HostPort": "3310"}]}),
            ("IMAGE_DIGEST_MISMATCH", ("Config", "Image"), "clamav/clamav:latest"),
            ("UNSAFE_EXECUTION_IDENTITY", ("Config", "User"), "root"),
            ("RESOURCE_LIMIT_MISMATCH", ("HostConfig", "Memory"), 2 * 1024**3),
            ("UNEXPECTED_FILESYSTEM_MOUNT", ("HostConfig", "Binds"), ["/home:/data"]),
            ("UNEXPECTED_NETWORK_ATTACHMENT", ("NetworkSettings", "Networks"),
             {audit.NETWORK: {}, "untrusted-shared": {}}),
        ]
        for expected, path, value in cases:
            with self.subTest(expected=expected):
                state = copy.deepcopy(snapshot())
                state[path[0]][path[1]] = value
                self.assertIn(expected, self.verify(obj=state)["reasons"])

    def test_denies_malformed_signature_metadata(self):
        for bad in [
            DATABASE.replace("Version: 28186", "Version: 0"),
            DATABASE.replace("Version: 28186", "Version: 28186\nVersion: 28186"),
            DATABASE.replace("Build time: 17 Nov", "Build time: 40 Nov"),
            DATABASE.replace("Build time: 17 Nov", "Build time: 17 Foo"),
            DATABASE.replace("Verification OK.", "Verification OK.\nVerification OK."),
        ]:
            with self.subTest(bad=bad[:80]):
                self.assertEqual(self.verify(database=bad)["state"], "UNREADY")


if __name__ == "__main__":
    unittest.main()
