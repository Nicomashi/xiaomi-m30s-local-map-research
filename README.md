# Xiaomi M30 S: local-map research

Open research into fully local Home Assistant map access for **Xiaomi Mijia M30 S**, model `xiaomi.vacuum.d103cn`, stock firmware **4.5.6_1409**.

**Status: incomplete. This is not a working cloud-free integration, a rooting tool, or a flashable firmware.** The tested Home Assistant setup still requires the vendor cloud for complete maps. Restart recovery, packet-gap recovery and a fresh map without cloud access have not passed acceptance testing.

## What is confirmed

- Authenticated local miIO commands can read state and control the robot.
- Token-encrypted LAN subscriptions deliver real map delta (`P`) frames, including while the robot's internet access is blocked.
- A complete initial snapshot (`I` frame), reliable recovery of missing frames, and the new map's room segmentation have **not** been obtained locally. A cached map plus deltas is insufficient to claim independence from the cloud.
- The outer ZipCrypto layer of the official OTA image was recovered offline with [bkcrack](https://github.com/kimci86/bkcrack). Both original entry sizes and CRCs were verified after decoding.
- The inner `update.img_enc` remains encrypted. It begins with the OpenSSL `Salted__` header; `random_signed` is a 256-byte block. The documented Dreame signed-random-password scheme is a hypothesis for the inner step, not yet verified on this model.
- The public Allwinner Tina SDK demo OTA key does not validate that RSA block. The RSA certificate found in the published miIO helper is a TLS CA certificate and does not validate it either. No compatible vendor OTA public key has been found.

No firmware was written to the robot during this analysis. Model-specific root access without opening the robot has not been demonstrated.

## Help wanted: public OTA key / stock unpacker

See [the technical request](PUBLIC_KEY_REQUEST.md), published as [Dustcloud issue #356](https://github.com/dgiese/dustcloud/issues/356). A compatible **public** `/etc/publickey.pem`, `/etc/OTA_Key_pub.pem`, or stock `/ava/script/ota_unpack.sh` could enable further offline analysis. Compatibility must be checked against this exact OTA image; the filename alone is not evidence.

Please do not upload private signing keys, Xiaomi passwords/tokens, device identity/calibration backups, private logs or home maps. A public key or a reference to a published stock script is enough for the current question.

## Firmware format evidence

| Item | Verified value |
| --- | --- |
| Official image size | 46,012,176 bytes |
| Official image MD5 | `f9b53e46142ad4075c4734b65228ea09` |
| `update.img_enc` size / CRC32 | 46,004,512 / `73bcd290` |
| `update.img_enc` SHA256 | `44783797af5c78a1e6e6071eb1bb3eebf39c6ba9ec146e53b6d0f23d17f9a771` |
| `random_signed` size / CRC32 | 256 / `9f42a67a` |
| `random_signed` SHA256 | `c7da21eb2e716db3c9fa156ebec66e1d0b93f73cffe00effa1eee09bea4d26cc` |

The outer-layer experiment used the expected OpenSSL header within a deflate stored block as known plaintext. Success was accepted only after both original ZIP CRCs matched. Recovered ZipCrypto key material and vendor firmware are not distributed here.

## Offline tools

Python dependencies are isolated with [uv](https://docs.astral.sh/uv/). Neither tool connects to a network or a robot, runs firmware code, or flashes anything.

```sh
uv sync --group dev
uv run python firmware_zip_probe.py --self-test
uv run python firmware_rsa_probe.py --self-test
uv run ruff check firmware_zip_probe.py firmware_rsa_probe.py
```

Inspect an independently obtained original image and check a decoded outer ZIP:

```sh
uv run python firmware_zip_probe.py --firmware /path/to/official.bin
uv run python firmware_zip_probe.py --firmware /path/to/official.bin --decoded /path/to/decoded.zip
```

Check a candidate public RSA key against a local copy of `random_signed`:

```sh
uv run python firmware_rsa_probe.py --signature /path/to/random_signed --public-key /path/to/candidate.pem
```

The RSA tool checks modulus range and strict PKCS#1 type-1 padding. It rejects private-key inputs and never prints or saves the recovered message. A valid RSA block alone is **not** proof that the inner firmware was decrypted; the result keeps `firmware_decrypted: false`.

Tests use synthetic ZIP/RSA data and need no firmware, device or credentials. Six tests and Ruff passed locally before this initial publication. The real outer ZIP was also checked separately; it is not a test fixture in this repository.

## Scope and sources

This repository contains original offline verification tools and documentation. It contains no vendor firmware, decompiled vendor code, account credentials, network configuration, household captures or derived paid-card code. MIT covers the original tools and documentation only; linked third-party projects retain their own licences.

Primary references:

- [bkcrack](https://github.com/kimci86/bkcrack)
- [Dennis Giese, Nullcon Goa 2023: IoT Hacking 101](https://dontvacuum.me/talks/NULLconGoa2023/Nullcon-101-IoT-Reversing.pdf), firmware format on slide 65
- [Dustbuilder public scripts](https://github.com/dgiese/dustbuilder-script-public)
- [Robotinfo by Dennis Giese](https://github.com/dgiese/robotinfo)
- [Allwinner Tina SDK public demo OTA key](https://github.com/lindenis-org/lindenis-v536-package/blob/1d13dff9a11e981e24db16d801ca21cb8018da6a/allwinner/tina-upgrade/OTA_Key_pub.pem)

## По-русски

Исследование автономной карты для M30 S. Управление и частичные изменения карты по LAN подтверждены, но полного снимка и восстановления карты без облака пока нет. Внешний архив прошивки распакован с проверкой обоих CRC; внутренний образ ещё зашифрован. Нужен совместимый открытый ключ или штатный распаковщик. Это исследовательские инструменты, а не готовый плагин и не прошивка.
