import base64
import builtins
import pathlib
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from normalize_update_signing_key import (
    ED25519_PRIVATE_KEY_LEN,
    PKCS8_ED25519_DER_PREFIX,
    normalize_signing_key,
    _private_key_marker,
    pem_from_pkcs8_der,
    pkcs8_der_from_raw_private_key,
    pkcs8_der_from_seed,
)


class NormalizeUpdateSigningKeyTests(unittest.TestCase):
    def test_accepts_multiline_pem(self) -> None:
        seed = bytes(range(32))
        pem = pem_from_pkcs8_der(pkcs8_der_from_seed(seed))
        self.assertEqual(normalize_signing_key(pem), pem)

    def test_unescapes_single_line_pem(self) -> None:
        seed = bytes(range(32))
        pem = pem_from_pkcs8_der(pkcs8_der_from_seed(seed))
        escaped = pem.strip().replace("\n", "\\n")
        self.assertEqual(normalize_signing_key(escaped), pem)

    def test_pkcs8_pem_does_not_require_cryptography_import(self) -> None:
        seed = bytes(range(32))
        pem = pem_from_pkcs8_der(pkcs8_der_from_seed(seed))
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.startswith("cryptography"):
                raise ModuleNotFoundError(name)
            return original_import(name, globals, locals, fromlist, level)

        with mock.patch("builtins.__import__", side_effect=guarded_import):
            self.assertEqual(normalize_signing_key(pem), pem)

    def test_converts_hex_seed_to_pkcs8_pem(self) -> None:
        seed = bytes(range(32))
        normalized = normalize_signing_key(seed.hex())
        self.assertEqual(normalized, pem_from_pkcs8_der(pkcs8_der_from_seed(seed)))

    def test_converts_base64_seed_to_pkcs8_pem(self) -> None:
        seed = bytes(range(32))
        secret = base64.b64encode(seed).decode("ascii")
        normalized = normalize_signing_key(secret)
        self.assertEqual(normalized, pem_from_pkcs8_der(pkcs8_der_from_seed(seed)))

    def test_converts_hex_raw_private_key_to_pkcs8_pem(self) -> None:
        raw_private_key = bytes(range(ED25519_PRIVATE_KEY_LEN))
        normalized = normalize_signing_key(raw_private_key.hex())
        self.assertEqual(
            normalized,
            pem_from_pkcs8_der(pkcs8_der_from_raw_private_key(raw_private_key)),
        )

    def test_converts_base64_raw_private_key_to_pkcs8_pem(self) -> None:
        raw_private_key = bytes(range(ED25519_PRIVATE_KEY_LEN))
        secret = base64.b64encode(raw_private_key).decode("ascii")
        normalized = normalize_signing_key(secret)
        self.assertEqual(
            normalized,
            pem_from_pkcs8_der(pkcs8_der_from_raw_private_key(raw_private_key)),
        )

    def test_accepts_base64_pkcs8_der(self) -> None:
        der = PKCS8_ED25519_DER_PREFIX + bytes(range(32))
        secret = base64.b64encode(der).decode("ascii")
        normalized = normalize_signing_key(secret)
        self.assertEqual(normalized, pem_from_pkcs8_der(der))

    def test_converts_openssh_private_key_to_pkcs8_pem(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        openssh = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        pkcs8 = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        self.assertEqual(normalize_signing_key(openssh), pkcs8)

    def test_converts_base64_openssh_private_key_to_pkcs8_pem(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        openssh = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pkcs8 = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        self.assertEqual(normalize_signing_key(base64.b64encode(openssh).decode("ascii")), pkcs8)

    def test_rejects_unknown_format(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported update-signing secret"):
            normalize_signing_key("definitely-not-a-private-key")

    def test_generated_pem_uses_expected_markers(self) -> None:
        seed = bytes(range(32))
        pem = pem_from_pkcs8_der(pkcs8_der_from_seed(seed))
        self.assertTrue(pem.startswith(f"{_private_key_marker('BEGIN')}\n"))
        self.assertTrue(pem.endswith(f"{_private_key_marker('END')}\n"))


if __name__ == "__main__":
    unittest.main()
