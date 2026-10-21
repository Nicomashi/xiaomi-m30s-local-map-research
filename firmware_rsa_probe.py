"""Offline public-key check for the RSA block in an owned firmware archive.

Run with uv --with pycryptodome. No network, flashing or robot access.
Only PKCS#1 type-1 message recovery is checked: this is the documented
Dreame firmware hypothesis, not a claim that every firmware uses it.
Recovered message bytes and keys are never printed or written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import unittest
from pathlib import Path

from Crypto.PublicKey import RSA

MAX_KEY_BYTES = 16384


def recover_message(signature: bytes, public_key: bytes) -> bytes | None:
    if len(public_key) > MAX_KEY_BYTES:
        raise ValueError("public-key file too large")
    key = RSA.import_key(public_key)
    if key.has_private():
        raise ValueError("expected a public key; private keys are unnecessary")
    size = key.size_in_bytes()
    if len(signature) != size or not 128 <= size <= 1024:
        return None
    value = int.from_bytes(signature, "big")
    if value >= key.n:
        return None
    block = pow(value, key.e, key.n).to_bytes(size, "big")
    if not block.startswith(b"\x00\x01"):
        return None
    stop = block.find(b"\x00", 2)
    # RSA_public_decrypt with PKCS#1 signature padding requires at least
    # eight FF bytes. A 00 01 prefix alone is not evidence of a valid key.
    if stop < 10 or block[2:stop] != b"\xff" * (stop - 2):
        return None
    return block[stop + 1:]


def check_key(signature: bytes, public_key: bytes) -> dict:
    key = RSA.import_key(public_key)
    message = recover_message(signature, public_key)
    return {
        "public_key_sha256": hashlib.sha256(
            key.public_key().export_key(format="DER")).hexdigest(),
        "bits": key.size_in_bits(),
        "pkcs1_type1_valid": message is not None,
        "recovered_message_bytes": len(message) if message is not None else None,
        "firmware_decrypted": False,
    }


class PublicKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = RSA.generate(2048)
        cls.public = cls.private.public_key().export_key()

    def sign_block(self, block: bytes) -> bytes:
        return pow(int.from_bytes(block, "big"), self.private.d,
                   self.private.n).to_bytes(256, "big")

    def test_valid_message_is_recovered_without_disclosure(self):
        message = b"synthetic-passphrase-for-test-only"
        block = b"\x00\x01" + b"\xff" * (253 - len(message)) + b"\x00" + message
        sig = self.sign_block(block)
        self.assertEqual(recover_message(sig, self.public), message)
        result = check_key(sig, self.public)
        self.assertTrue(result["pkcs1_type1_valid"])
        self.assertFalse(result["firmware_decrypted"])
        self.assertNotIn(message.decode(), json.dumps(result))

    def test_invalid_padding_and_out_of_range_are_rejected(self):
        for block in [b"\x00\x01\xff\x00" + b"x" * 252,
                      b"\x00\x01" + b"x" * 253 + b"\x00",
                      b"\x00\x02" + b"x" * 253 + b"\x00"]:
            self.assertIsNone(recover_message(self.sign_block(block), self.public))
        self.assertIsNone(recover_message(b"\xff" * 256, self.public))
        self.assertIsNone(recover_message(b"short", self.public))

    def test_private_key_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "public key"):
            recover_message(b"\x00" * 256, self.private.export_key())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--public-key", type=Path, action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner().run(
            unittest.defaultTestLoader.loadTestsFromTestCase(PublicKeyTests))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if not args.signature or not args.public_key:
        parser.error("--signature and at least one --public-key are required")
    if args.signature.stat().st_size > 1024:
        parser.error("unexpected RSA block size")
    signature = args.signature.read_bytes()
    rows = []
    for path in args.public_key:
        if path.stat().st_size > MAX_KEY_BYTES:
            parser.error("public-key file too large")
        rows.append(check_key(signature, path.read_bytes()))
    print(json.dumps({"offline_only": True, "candidates": rows}))


if __name__ == "__main__":
    main()
