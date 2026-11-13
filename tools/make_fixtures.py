"""生成 ZipPwn 测试样本（已知口令），用于端到端验证。

刻意手写成 ZIP 字节流，不依赖任何第三方加密库：
  * zc_stored.zip   ZipCrypto + stored
  * zc_deflate.zip  ZipCrypto + deflate
  * aes256.zip      WinZip AES-256 (AE-3)
  * kpa_twin.zip    ZipCrypto 加密条目 + 同名未加密孪生条目（已知明文攻击素材）
  * wordlist.txt    含正确口令的字典

用法: python tools/make_fixtures.py [输出目录]
"""

from __future__ import annotations

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from zippwn.engine.crypto import AES, CRC_TAB_INT  # noqa: E402


# ------------------------------------------------------------ ZipCrypto
def _zc_update(k0: int, k1: int, k2: int, c: int):
    k0 = CRC_TAB_INT[(k0 ^ c) & 0xFF] ^ (k0 >> 8)
    k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    k2 = CRC_TAB_INT[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8)
    return k0, k1, k2


def zc_encrypt(password: bytes, plain: bytes) -> bytes:
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for c in password:
        k0, k1, k2 = _zc_update(k0, k1, k2, c)
    out = bytearray()
    for b in plain:
        t = (k2 | 2) & 0xFFFF
        ks = ((t * (t ^ 1)) >> 8) & 0xFF
        out.append(b ^ ks)
        k0, k1, k2 = _zc_update(k0, k1, k2, b)
    return bytes(out)


# ------------------------------------------------------------ WinZip AES
def aes_zip_encrypt(password: bytes, plain: bytes, strength: int = 3):
    key_len = {1: 16, 2: 24, 3: 32}[strength]
    salt_len = {1: 8, 2: 12, 3: 16}[strength]
    salt = os.urandom(salt_len)
    import hashlib

    dk = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * key_len + 2)
    enc_key, auth_key, pv = dk[:key_len], dk[key_len:2 * key_len], dk[2 * key_len:]

    cipher = AES(enc_key)
    ct = bytearray()
    ctr = 1
    for off in range(0, len(plain), 16):
        ks = cipher.encrypt_block(ctr.to_bytes(16, "little"))
        chunk = plain[off:off + 16]
        for i, b in enumerate(chunk):
            ct.append(b ^ ks[i])
        ctr += 1

    import hmac

    auth = hmac.new(auth_key, bytes(ct), hashlib.sha1).digest()[:10]
    return salt, pv, bytes(ct), auth, key_len


# ------------------------------------------------------------ ZIP 写入
def write_zip(path: str, entries: list[dict]) -> None:
    """entries: name, flags, method, crc, csize, usize, extra, payload"""
    out = bytearray()
    cd = bytearray()
    for e in entries:
        name = e["name"].encode()
        extra = e.get("extra", b"")
        lho = len(out)
        out += struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04", 20, e["flags"], e["method"], 0x5000, 0x5621,
            e["crc"], e["csize"], e["usize"], len(name), len(extra),
        )
        out += name + extra + e["payload"]

        cd += struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02", 20, 20, e["flags"], e["method"], 0x5000, 0x5621,
            e["crc"], e["csize"], e["usize"], len(name), len(extra), 0,
            0, 0, 0, lho,
        )
        cd += name + extra

    cd_off = len(out)
    out += cd
    out += struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0,
                       len(entries), len(entries), len(cd), cd_off, 0)
    with open(path, "wb") as f:
        f.write(out)


def blob(n: int, seed: bytes) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += seed + str(i).encode()
        i += 1
    return bytes(out[:n])


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "tests", "fixtures")
    os.makedirs(outdir, exist_ok=True)

    # ---- 1. ZipCrypto + stored ----
    pw1 = b"Tr0ub4dor&3"
    content = blob(4096, b"secret-line-")
    crc = zlib.crc32(content) & 0xFFFFFFFF
    hdr = bytearray(os.urandom(12))
    hdr[11] = (crc >> 24) & 0xFF
    body = zc_encrypt(pw1, bytes(hdr) + content)
    write_zip(os.path.join(outdir, "zc_stored.zip"), [{
        "name": "reports/q4.csv", "flags": 0x1, "method": 0,
        "crc": crc, "csize": len(body), "usize": len(content), "payload": body,
    }])

    # ---- 2. ZipCrypto + deflate ----
    pw2 = b"sunshine2024"
    raw = blob(20000, b"deflate-payload-")
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed = comp.compress(raw) + comp.flush()
    crc2 = zlib.crc32(raw) & 0xFFFFFFFF
    hdr2 = bytearray(os.urandom(12))
    hdr2[11] = (crc2 >> 24) & 0xFF
    body2 = zc_encrypt(pw2, bytes(hdr2) + packed)
    write_zip(os.path.join(outdir, "zc_deflate.zip"), [{
        "name": "logs/app.log", "flags": 0x1, "method": 8,
        "crc": crc2, "csize": len(body2), "usize": len(raw), "payload": body2,
    }])

    # ---- 3. WinZip AES-256 ----
    pw3 = b"Passw0rd!"
    raw3 = blob(30000, b"aes-payload-")
    comp3 = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed3 = comp3.compress(raw3) + comp3.flush()
    crc3 = zlib.crc32(raw3) & 0xFFFFFFFF
    salt, pv, ct, auth, klen = aes_zip_encrypt(pw3, packed3, 3)
    extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 8)
    payload3 = salt + pv + ct + auth
    write_zip(os.path.join(outdir, "aes256.zip"), [{
        "name": "vault/finance.xlsx", "flags": 0x1, "method": 99,
        "crc": crc3, "csize": len(payload3), "usize": len(raw3),
        "extra": extra, "payload": payload3,
    }])

    # ---- 4. 已知明文：同名孪生明文条目 ----
    pw4 = b"twin-pass"
    name = "public/notice.txt"
    twin = b"CONFIDENTIAL//INTERNAL-ONLY//DO-NOT-DISTRIBUTE//2026-Q4\n" * 12
    crc4 = zlib.crc32(twin) & 0xFFFFFFFF
    hdr4 = bytearray(os.urandom(12))
    hdr4[11] = (crc4 >> 24) & 0xFF
    body4 = zc_encrypt(pw4, bytes(hdr4) + twin)
    write_zip(os.path.join(outdir, "kpa_twin.zip"), [
        {"name": name, "flags": 0x0, "method": 0, "crc": crc4,
         "csize": len(twin), "usize": len(twin), "payload": twin},
        {"name": name, "flags": 0x1, "method": 0, "crc": crc4,
         "csize": len(body4), "usize": len(twin), "payload": body4},
    ])

    # ---- 5. 字典 ----
    words = ["123456", "password", "qwerty", "letmein", "admin", "iloveyou",
             "monkey", "dragon", "sunshine", "princess", "football", "charlie",
             "Tr0ub4dor&3", "sunshine2024", "Passw0rd!", "twin-pass",
             "P@ssw0rd", "welcome1", "abc12345", "zzzzzzzz"]
    with open(os.path.join(outdir, "wordlist.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(words) + "\n")

    print(f"fixtures -> {os.path.abspath(outdir)}")
    for n in sorted(os.listdir(outdir)):
        p = os.path.join(outdir, n)
        print(f"  {n:20s} {os.path.getsize(p):>8d} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
