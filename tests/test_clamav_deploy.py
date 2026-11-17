"""Fail-closed source admission for Wardveil's non-public ClamAV Compose backend."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILE = ROOT / "deploy" / "clamav" / "compose.yaml"
EXPECTED_DIGEST = "sha256:ed2ee243029c1f3c2e13c1eadd835fbca239bbbb80bbde06627f7676a17314f2"


class PrivateClamavComposeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = FILE.read_text(encoding="utf-8")
        pinned_image = "image: docker.io/clamav/clamav:1.5.4@" + EXPECTED_DIGEST
        if pinned_image not in source:
            raise AssertionError("reviewed official image digest is missing")
        # Compose is required. Never fall back to line-based YAML guesses.
        result = subprocess.run(
            ["docker", "compose", "-f", str(FILE), "config", "--format", "json"],
            cwd=ROOT, capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode:
            raise AssertionError("Docker Compose parse failed: "
                                 + result.stderr[:700])
        cls.config = json.loads(result.stdout)

    def test_exactly_one_private_backend(self):
        self.assertEqual(self.config["name"], "wardveil-clamav")
        services = self.config["services"]
        self.assertEqual(set(services), {"clamd"})
        svc = services["clamd"]
        self.assertFalse(svc.get("ports"))
        self.assertFalse(svc.get("expose"))
        self.assertFalse(svc.get("network_mode"))
        self.assertFalse(svc.get("privileged", False))
        self.assertEqual(svc["pull_policy"], "never")
        self.assertEqual(svc["platform"], "linux/amd64")
        self.assertIn("@" + EXPECTED_DIGEST, svc["image"])

    def test_no_host_data_or_expanded_privileges(self):
        svc = self.config["services"]["clamd"]
        self.assertTrue(svc["read_only"])
        self.assertEqual(svc["user"], "clamav")
        self.assertEqual(svc["entrypoint"], ["/init-unprivileged"])
        self.assertEqual(svc["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", svc["security_opt"])
        self.assertLessEqual(int(svc["mem_limit"]), 2 * 1024**3)
        self.assertLessEqual(int(svc["pids_limit"]), 64)
        self.assertLessEqual(float(svc["cpus"]), 2.0)
        self.assertTrue(all(v["type"] == "volume"
                            and v["target"] == "/var/lib/clamav"
                            and v["source"] == "signatures"
                            for v in svc.get("volumes", [])))
        self.assertEqual(len(svc["volumes"]), 1)

    def test_network_and_signature_egress_are_intentional(self):
        svc = self.config["services"]["clamd"]
        self.assertEqual(set(svc["networks"]), {"signature-egress"})
        network = self.config["networks"]["signature-egress"]
        self.assertEqual(network["driver"], "bridge")
        self.assertFalse(network.get("attachable", False))
        self.assertFalse(network.get("internal", False))
        self.assertEqual(svc["environment"]["CLAMAV_NO_MILTERD"], "true")
        check = svc["healthcheck"]["test"]
        self.assertEqual(check[0], "CMD-SHELL")
        self.assertIn("sigtool --info /var/lib/clamav/daily.cld", check[1])
        self.assertIn("clamdscan --version", check[1])
        self.assertIn('test "$$loaded" = "$$disk"', check[1])
        self.assertEqual(set(self.config["volumes"]), {"signatures"})

    def test_health_gate_fails_closed_for_unloaded_or_unverified_signatures(self):
        # Compose escapes $ as $$; Docker supplies a single $ to the shell.
        check = self.config['services']['clamd']['healthcheck']['test']
        command = check[1].replace('$$', '$')
        tools = {
            'clamdcheck.sh': '#!/bin/sh\nexit "${MOCK_CLAMD_EXIT:-1}"\n',
            'sigtool': ('#!/bin/sh\nprintf "Version: %s\\n" "$MOCK_DISK_VERSION"\n'
                        'if [ "$MOCK_SIG_VERIFIED" = 1 ]; then printf "Verification OK.\\n"; fi\n'),
            'clamdscan': '#!/bin/sh\nprintf "ClamAV 1.5.4/%s/test\\n" "$MOCK_LOADED_VERSION"\n',
        }
        with tempfile.TemporaryDirectory(prefix='wardveil-clamav-health-') as tmp:
            for name, script in tools.items():
                path = pathlib.Path(tmp) / name
                path.write_text(script, encoding='utf-8')
                path.chmod(0o700)
            cases = [
                ('matching', '28186', '28186', '1', '0', True),
                ('stale_loaded_engine', '28186', '28184', '1', '0', False),
                ('unverified_database', '28186', '28186', '0', '0', False),
                ('unavailable_engine', '28186', '28186', '1', '1', False),
            ]
            for name, disk, loaded, verified, daemon_exit, should_pass in cases:
                with self.subTest(name=name):
                    env = dict(os.environ,
                               PATH=tmp + os.pathsep + os.environ.get('PATH', ''),
                               MOCK_DISK_VERSION=disk, MOCK_LOADED_VERSION=loaded,
                               MOCK_SIG_VERIFIED=verified, MOCK_CLAMD_EXIT=daemon_exit)
                    result = subprocess.run(['sh', '-c', command], env=env,
                                            capture_output=True, text=True,
                                            check=False, timeout=10)
                    self.assertEqual(result.returncode == 0, should_pass,
                                     f'{name}: {result.stderr[:250]}')



if __name__ == "__main__":
    unittest.main()
