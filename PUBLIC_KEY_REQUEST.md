# Xiaomi M30 S / xiaomi.vacuum.d103cn 4.5.6_1409: public OTA key or unpacker for offline analysis

Hello,

I am investigating fully local map access for my own Xiaomi Mijia M30 S,
model xiaomi.vacuum.d103cn, running stock firmware 4.5.6_1409. The goal is
Home Assistant map support without the vendor cloud or opening the robot.

The official OTA image is 46,012,176 bytes, MD5
f9b53e46142ad4075c4734b65228ea09 (verified against Xiaomi metadata).
I recovered the outer ZipCrypto layer using bkcrack and verified the sizes
and CRCs of both original archive entries:
- update.img_enc: 46,004,512 bytes, CRC32 73bcd290; begins with Salted__.
- random_signed: 256 bytes, CRC32 9f42a67a.

This appears consistent with the signed-random-password scheme described
in Dennis Giese's Nullcon Goa 2023 presentation, but I do not have the
matching public key or stock unpacker to confirm the inner step.
The public Allwinner Tina SDK demo OTA key does not validate this RSA block.

Is there a published PUBLIC key (/etc/publickey.pem and/or
/etc/OTA_Key_pub.pem), a stock /ava/script/ota_unpack.sh, or a compatible
model reference that can be used to unpack this image offline?
I am asking for a public verification/recovery key, not a private signing
key, account credentials, or device identity/calibration data.

No firmware has been flashed or modified on the robot. This is currently
file analysis only. Any software-only installation/root path would still
need separate model/firmware-specific verification.

References:
https://dontvacuum.me/talks/NULLconGoa2023/Nullcon-101-IoT-Reversing.pdf
https://github.com/kimci86/bkcrack
