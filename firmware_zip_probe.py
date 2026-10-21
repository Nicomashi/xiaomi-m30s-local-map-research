"""Offline firmware archive inspection; no network or robot access.

Run through uv. Recovered keys remain in private bkcrack logs; this script
prints only progress and validates decoded archives against the original CRCs.
The Salted__ prefix used by the experiment is a hypothesis until verified.
Reference: https://github.com/kimci86/bkcrack
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

EXPECTED_MD5 = "f9b53e46142ad4075c4734b65228ea09"
ALLOWED_ENTRIES = {"update.img_enc", "random_signed"}
MAX_FILE_BYTES = 128 * 1024 * 1024


def inspect_archive(path: Path, expected_md5: str | None = None) -> dict:
    digest = hashlib.md5(path.read_bytes()).hexdigest()
    if expected_md5 is not None and digest != expected_md5:
        raise ValueError("firmware checksum differs from official metadata")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != 2 or {x.filename for x in entries} != ALLOWED_ENTRIES:
            raise ValueError("unexpected firmware archive entries")
        if any(x.file_size > MAX_FILE_BYTES for x in entries):
            raise ValueError("unexpected expanded size")
        return {
            "bytes": path.stat().st_size,
            "md5": digest,
            "entries": [{
                "name": x.filename, "bytes": x.file_size,
                "packed_bytes": x.compress_size, "compression": x.compress_type,
                "encrypted": bool(x.flag_bits & 1), "crc32": f"{x.CRC:08x}",
            } for x in entries],
        }


def cipher_prefix(path: Path, length: int = 64) -> bytes:
    """Copy encrypted bytes, including the 12-byte ZipCrypto header.

    Useful for reproducing the same offline calculation on another owned PC
    without transferring the entire firmware or any account credentials.
    """
    inspect_archive(path)
    with zipfile.ZipFile(path) as archive, path.open("rb") as stream:
        info = archive.getinfo("update.img_enc")
        if not info.flag_bits & 1 or info.compress_type != zipfile.ZIP_DEFLATED:
            raise ValueError("expected a ZipCrypto/deflate entry")
        stream.seek(info.header_offset)
        header = stream.read(30)
        if header[:4] != b"PK\x03\x04":
            raise ValueError("invalid local ZIP header")
        name_bytes, extra_bytes = struct.unpack_from("<HH", header, 26)
        stream.seek(name_bytes + extra_bytes, 1)
        result = stream.read(length)
        if len(result) != length:
            raise ValueError("truncated ciphertext")
        return result


def validate_decoded(original: Path, decoded: Path) -> dict:
    """A reported key is not success: require original sizes and both CRCs."""
    reference = inspect_archive(original)
    expected = {x["name"]: (x["bytes"], x["crc32"]) for x in reference["entries"]}
    try:
        candidate = inspect_archive(decoded)
        if any(x["encrypted"] for x in candidate["entries"]):
            return {"verified": False, "reason": "archive still encrypted"}
        actual = {x["name"]: (x["bytes"], x["crc32"]) for x in candidate["entries"]}
        if expected != actual:
            return {"verified": False, "reason": "entry metadata changed"}
        with zipfile.ZipFile(decoded) as archive:
            bad = archive.testzip()
            if bad is not None:
                return {"verified": False, "reason": "CRC mismatch"}
            image = archive.read("update.img_enc")
        return {
            "verified": True, "entry_count": 2,
            "inner_openssl_header": image.startswith(b"Salted__"),
            "inner_bytes": len(image), "inner_sha256": hashlib.sha256(image).hexdigest(),
        }
    except (ValueError, RuntimeError, zipfile.BadZipFile, zlib.error, EOFError):
        return {"verified": False, "reason": "invalid decoded archive"}


def safe_progress(log: Path) -> dict:
    content = log.read_text(errors="replace")
    progress = re.findall(r"([0-9.]+) % \((\d+) / (\d+)\)", content)
    checkpoints = re.findall(r"--continue-attack (\d+)", content)
    result = {
        "key_candidate_reported": bool(re.search(
            r"(?m)^[0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}\s*$", content)),
        "checkpoint": int(checkpoints[-1]) if checkpoints else None,
        "search_exhausted": "100.0 %" in content and "Could not find the keys." in content,
    }
    if progress:
        percent, done, total = progress[-1]
        result.update(percent=float(percent), done=int(done), total=int(total))
        # A completed reduction stage is not a completed key search.
        result["search_exhausted"] &= int(done) == int(total)
    return result


class ArchiveTests(unittest.TestCase):
    def make_archive(self, path: Path):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("update.img_enc", b"Salted__" + b"\0" * 32)
            archive.writestr("random_signed", b"s" * 256)

    def test_requires_both_original_crcs(self):
        with tempfile.TemporaryDirectory() as root:
            original, decoded = Path(root) / "original.zip", Path(root) / "decoded.zip"
            self.make_archive(original)
            decoded.write_bytes(original.read_bytes())
            self.assertTrue(validate_decoded(original, decoded)["verified"])
            raw = bytearray(decoded.read_bytes())
            raw[raw.index(b"Salted__") + 1] ^= 1
            decoded.write_bytes(raw)
            self.assertFalse(validate_decoded(original, decoded)["verified"])

    def test_checksum_and_entry_name_guards(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "firmware.zip"
            self.make_archive(path)
            with self.assertRaisesRegex(ValueError, "checksum"):
                inspect_archive(path, "0" * 32)
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("../outside", "invalid")
            with self.assertRaisesRegex(ValueError, "entries"):
                inspect_archive(path)

    def test_progress_does_not_disclose_keys_or_confuse_reduction(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "attack.log"
            path.write_text("100.0 % (6 / 6)\r5.0 % (50 / 1000)\n"
                            "Operation interrupted by user.\nCould not find the keys.\n"
                            "You may resume the attack with the option: --continue-attack 49\n"
                            "abcdef01 abcdef02 abcdef03\n")
            result = safe_progress(path)
            self.assertEqual(result["checkpoint"], 49)
            self.assertFalse(result["search_exhausted"])
            self.assertTrue(result["key_candidate_reported"])
            self.assertNotIn("abcdef01", json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", type=Path, help="Original official OTA image")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--decoded", type=Path)
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[__file__])
    elif args.log:
        print(json.dumps(safe_progress(args.log)))
    elif args.decoded:
        if not args.firmware:
            parser.error("--firmware is required with --decoded")
        print(json.dumps(validate_decoded(args.firmware, args.decoded)))
    else:
        if not args.firmware:
            parser.error("--firmware is required")
        print(json.dumps(inspect_archive(args.firmware, EXPECTED_MD5), indent=2))
