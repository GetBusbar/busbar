#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Hermetic NONRELEASE signing checks. No Cloud KMS call or release key is used.

The one ephemeral P-256 test key remains in process memory and shell pipes. Temporary
directories contain only public keys, test messages, signatures and mocked command receipts.
"""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "openssl is required for the NONRELEASE fixture")
class SigningWrappers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # NONRELEASE fixture only. Never persist or print the private bytes.
        generated = subprocess.run(
            [OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            capture_output=True,
        )
        if generated.returncode:
            raise RuntimeError("could not create the ephemeral NONRELEASE fixture")
        cls.private_pem = generated.stdout.decode("ascii")
        public = subprocess.run(
            [OPENSSL, "pkey", "-pubout"], input=generated.stdout, capture_output=True
        )
        if public.returncode:
            raise RuntimeError("could not derive the NONRELEASE public fixture")
        cls.public_pem = public.stdout

    @classmethod
    def tearDownClass(cls):
        cls.private_pem = None
        cls.public_pem = None

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="busbar-NONRELEASE-sign-wrapper-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.message = self.root / "NONRELEASE message.txt"
        self.message.write_bytes(b"NONRELEASE signing wrapper fixture\n")
        self.signature = self.root / "NONRELEASE signature.der"
        self.env = {
            k: v for k, v in os.environ.items()
            if k not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"}
            and not k.startswith("BUSBAR_")
        }

    def invoke(self, script, *arguments, extra=None, trace=False):
        env = {**self.env, **(extra or {})}
        return subprocess.run(
            ["bash", *(["-x"] if trace else []), str(SCRIPTS / script), *map(str, arguments)],
            cwd=self.root, env=env, capture_output=True,
        )

    def assert_signed(self, result):
        self.assertEqual(result.returncode, 0, "NONRELEASE signer must succeed")
        self.assertFalse(self.private_pem.encode() in result.stdout + result.stderr,
                         "private fixture must not appear in output")
        public = self.root / "NONRELEASE public.pem"
        public.write_bytes(self.public_pem)
        verified = subprocess.run(
            [OPENSSL, "dgst", "-sha256", "-verify", str(public),
             "-signature", str(self.signature), str(self.message)], capture_output=True,
        )
        self.assertEqual(verified.returncode, 0, "NONRELEASE signature must verify")
        self.assertEqual(stat.S_IMODE(self.signature.stat().st_mode), 0o600)

    def test_environment_signer_produces_a_valid_der_signature(self):
        self.assert_signed(self.invoke("sign-key-env.sh", self.message, self.signature,
                                       extra={"BUSBAR_RELEASE_SIGNER_KEY": self.private_pem}))

    def test_shell_tracing_does_not_disclose_the_environment_key(self):
        result = self.invoke("sign-key-env.sh", self.message, self.signature, trace=True,
                             extra={"BUSBAR_RELEASE_SIGNER_KEY": self.private_pem})
        self.assert_signed(result)
        self.assertFalse(b"BEGIN PRIVATE KEY" in result.stdout + result.stderr,
                         "tracing must stop before reading the key")

    def test_retired_legacy_environment_variable_is_never_a_fallback(self):
        result = self.invoke("sign-key-env.sh", self.message, self.signature,
                             extra={"BUSBAR_SIGN_KEY": "NONRELEASE legacy sentinel"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.signature.exists())

    def test_malformed_pem_is_refused_without_echoing_its_contents(self):
        sentinel = b"NONRELEASE-invalid-PEM-sentinel"
        result = self.invoke("sign-key-env.sh", self.message, self.signature, trace=True,
                             extra={"BUSBAR_RELEASE_SIGNER_KEY": sentinel.decode()})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sentinel in result.stdout + result.stderr)

    def test_relative_input_starting_with_a_dash_is_a_filename(self):
        dash_message = self.root / "-NONRELEASE-input"
        dash_message.write_bytes(self.message.read_bytes())
        self.assert_signed(self.invoke("sign-key-env.sh", dash_message.name, self.signature,
                                       extra={"BUSBAR_RELEASE_SIGNER_KEY": self.private_pem}))

    def mock_command(self, name, body):
        directory = self.root / "mock bin"
        directory.mkdir(exist_ok=True)
        command = directory / name
        command.write_text("#!/usr/bin/env python3\n" + body)
        command.chmod(0o700)
        return {"PATH": str(directory) + os.pathsep + self.env.get("PATH", "")}

    def test_openssl_gets_the_key_only_through_its_pipe(self):
        mocked = self.mock_command("openssl", """import os, pathlib, sys
assert 'BUSBAR_RELEASE_SIGNER_KEY' not in os.environ
assert '_busbar_signer_pem' not in os.environ
args = sys.argv[1:]
key = pathlib.Path(args[args.index('-sign') + 1]).read_bytes()
assert key.startswith(b'-----BEGIN PRIVATE KEY-----')
assert all('PRIVATE KEY' not in arg for arg in args)
pathlib.Path(args[args.index('-out') + 1]).write_bytes(b'NONRELEASE mock signature')
""")
        result = self.invoke("sign-key-env.sh", self.message, self.signature,
                             extra={**mocked, "BUSBAR_RELEASE_SIGNER_KEY": self.private_pem}, trace=True)
        self.assertEqual(result.returncode, 0, "OpenSSL must receive an unexported pipe key")
        self.assertFalse(b"BEGIN PRIVATE KEY" in result.stdout + result.stderr)

    def kms_mock(self):
        return self.mock_command("gcloud", """import json, pathlib, sys
args = sys.argv[1:]
pathlib.Path('NONRELEASE-gcloud-argv.json').write_text(json.dumps(args))
out = next(arg.split('=', 1)[1] for arg in args if arg.startswith('--signature-file='))
pathlib.Path(out).write_bytes(b'NONRELEASE mock KMS binary signature\\x00\\xff')
""")

    def test_kms_uses_explicit_project_location_and_default_root_without_key_export(self):
        result = self.invoke("sign-kms.sh", self.message, self.signature, extra={
            **self.kms_mock(), "BUSBAR_KMS_PROJECT": "NONRELEASE-project",
            "BUSBAR_KMS_LOCATION": "NONRELEASE-location",
        })
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads((self.root / "NONRELEASE-gcloud-argv.json").read_text()), [
            "kms", "asymmetric-sign", "--project=NONRELEASE-project",
            "--location=NONRELEASE-location", "--keyring=busbar-plugin-signing",
            "--key=busbar-plugins-root", "--version=1", "--digest-algorithm=sha256",
            f"--input-file={self.message}", f"--signature-file={self.signature}",
        ])
        self.assertEqual(self.signature.read_bytes(), b"NONRELEASE mock KMS binary signature\x00\xff")

    def test_kms_keyring_key_and_version_overrides_are_passed_as_single_arguments(self):
        result = self.invoke("sign-kms.sh", self.message, self.signature, extra={
            **self.kms_mock(), "BUSBAR_KMS_PROJECT": "NONRELEASE-project",
            "BUSBAR_KMS_LOCATION": "NONRELEASE-location", "BUSBAR_KMS_KEYRING": "test ring",
            "BUSBAR_KMS_KEY": "test root", "BUSBAR_KMS_VERSION": "7",
        })
        self.assertEqual(result.returncode, 0)
        args = json.loads((self.root / "NONRELEASE-gcloud-argv.json").read_text())
        for expected in ["--keyring=test ring", "--key=test root", "--version=7"]:
            self.assertIn(expected, args)
        self.assertNotIn("--skip-integrity-verification", args)

    def test_kms_never_infers_missing_project_or_location(self):
        for values in [{}, {"BUSBAR_KMS_PROJECT": "NONRELEASE-project"}]:
            result = self.invoke("sign-kms.sh", self.message, self.signature,
                                 extra={**self.kms_mock(), **values})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "NONRELEASE-gcloud-argv.json").exists())

    def test_kms_failure_status_is_preserved(self):
        mocked = self.mock_command("gcloud", "raise SystemExit(23)\n")
        result = self.invoke("sign-kms.sh", self.message, self.signature, extra={
            **mocked, "BUSBAR_KMS_PROJECT": "NONRELEASE-project",
            "BUSBAR_KMS_LOCATION": "NONRELEASE-location",
        })
        self.assertEqual(result.returncode, 23)

    def test_both_wrappers_refuse_missing_inputs_wrong_arity_and_input_overwrite(self):
        original = self.message.read_bytes()
        for script in ["sign-kms.sh", "sign-key-env.sh"]:
            for arguments in [(), (self.root / "missing", self.signature),
                              (self.root, self.signature), (self.message, self.message)]:
                self.assertNotEqual(self.invoke(script, *arguments).returncode, 0)
            hardlink = self.root / (script + ".input-alias")
            os.link(self.message, hardlink)
            self.assertNotEqual(self.invoke(script, self.message, hardlink).returncode, 0)
        self.assertEqual(self.message.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
