import base64
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from normalize_update_signing_key import (
    PKCS8_ED25519_DER_PREFIX,
    normalize_signing_key,
    _private_key_marker,
    pem_from_pkcs8_der,
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

    def test_converts_hex_seed_to_pkcs8_pem(self) -> None:
        seed = bytes(range(32))
        normalized = normalize_signing_key(seed.hex())
        self.assertEqual(normalized, pem_from_pkcs8_der(pkcs8_der_from_seed(seed)))

    def test_converts_base64_seed_to_pkcs8_pem(self) -> None:
        seed = bytes(range(32))
        secret = base64.b64encode(seed).decode("ascii")
        normalized = normalize_signing_key(secret)
        self.assertEqual(normalized, pem_from_pkcs8_der(pkcs8_der_from_seed(seed)))

    def test_accepts_base64_pkcs8_der(self) -> None:
        der = PKCS8_ED25519_DER_PREFIX + bytes(range(32))
        secret = base64.b64encode(der).decode("ascii")
        normalized = normalize_signing_key(secret)
        self.assertEqual(normalized, pem_from_pkcs8_der(der))

    def test_rejects_unsupported_open_ssh_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "OpenSSH private keys"):
            normalize_signing_key(
                f"-----BEGIN OPENSSH {'PRIVATE' + ' KEY'}-----\n"
                f"abc\n"
                f"-----END OPENSSH {'PRIVATE' + ' KEY'}-----\n"
            )

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
