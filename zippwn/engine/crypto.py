"""底层密码学原语。零外部依赖（仅标准库；numpy 为可选加速）。

包含：
  * CRC32 表（ZipCrypto 流密码状态推进）
  * AES 128/192/256（key expansion + 单块加解密）
  * WinZip-AES 专用 CTR 模式（小端 128 位计数器，从 1 开始）
  * PBKDF2-HMAC-SHA1 / SHA256 薄封装（走 hashlib 的 C 实现）

numpy 说明：核心引擎已迁移到 C++，Python 侧只剩测试样本生成器在用本模块。
CRC_TAB（numpy 数组）仅为历史向量化路径保留，未安装 numpy 时自动降级为 None，
因此 `tools/make_fixtures.py` 在纯净 Python 环境下也能跑（CI 无需装 numpy）。
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

try:  # numpy 可选：没有也能跑，只是拿不到向量化用的 CRC_TAB
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]

# ============================================================ CRC32
def _build_crc_table_int() -> list[int]:
    tab: list[int] = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        tab.append(c)
    return tab


CRC_TAB_INT: list[int] = _build_crc_table_int()

# 向量化路径用的 numpy 视图；无 numpy 时为 None
CRC_TAB = None
if np is not None:
    CRC_TAB = np.array(CRC_TAB_INT, dtype=np.uint32)


def crc32(data: bytes, crc: int = 0) -> int:
    """标准 CRC32（IEEE 802.3）。"""
    c = crc ^ 0xFFFFFFFF
    for b in data:
        c = CRC_TAB_INT[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# ============================================================ AES
def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if (p & 0x80) else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = (q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX: list[int] = _build_sbox()
INV_SBOX: list[int] = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r & 0xFF


_MUL2 = [_gmul(i, 2) for i in range(256)]
_MUL3 = [_gmul(i, 3) for i in range(256)]
_MUL9 = [_gmul(i, 9) for i in range(256)]
_MUL11 = [_gmul(i, 11) for i in range(256)]
_MUL13 = [_gmul(i, 13) for i in range(256)]
_MUL14 = [_gmul(i, 14) for i in range(256)]


class AES:
    """最小可用 AES，块固定 16 字节。只用于单候选确认/解密，不追求吞吐。"""

    __slots__ = ("nr", "rk")

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16/24/32 bytes")
        self.nr = {16: 10, 24: 12, 32: 14}[len(key)]
        self.rk = self._expand(key)

    def _expand(self, key: bytes) -> list[list[int]]:
        nk = len(key) // 4
        nr = self.nr
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        rounds: list[list[int]] = []
        for r in range(nr + 1):
            flat: list[int] = []
            for c in range(4):
                flat.extend(w[4 * r + c])
            rounds.append(flat)
        return rounds

    def encrypt_block(self, block) -> bytes:
        s = [block[i] ^ self.rk[0][i] for i in range(16)]
        for rnd in range(1, self.nr):
            s = self._mix(self._sub_shift(s))
            s = [s[i] ^ self.rk[rnd][i] for i in range(16)]
        s = self._sub_shift(s)
        s = [s[i] ^ self.rk[self.nr][i] for i in range(16)]
        return bytes(s)

    def decrypt_block(self, block) -> bytes:
        s = [block[i] ^ self.rk[self.nr][i] for i in range(16)]
        for rnd in range(self.nr - 1, 0, -1):
            shifted = self._inv_shift(s)
            s = [INV_SBOX[shifted[i]] ^ self.rk[rnd][i] for i in range(16)]
            s = self._inv_mix(s)
        shifted = self._inv_shift(s)
        s = [INV_SBOX[shifted[i]] ^ self.rk[0][i] for i in range(16)]
        return bytes(s)

    @staticmethod
    def _sub_shift(s: list[int]) -> list[int]:
        t = [SBOX[b] for b in s]
        out = [0] * 16
        for row in range(4):
            for col in range(4):
                out[4 * col + row] = t[4 * ((col + row) % 4) + row]
        return out

    @staticmethod
    def _inv_shift(s: list[int]) -> list[int]:
        out = [0] * 16
        for row in range(4):
            for col in range(4):
                out[4 * col + row] = s[4 * ((col - row) % 4) + row]
        return out

    @staticmethod
    def _mix(s: list[int]) -> list[int]:
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _MUL2[a0] ^ _MUL3[a1] ^ a2 ^ a3
            out[4 * c + 1] = a0 ^ _MUL2[a1] ^ _MUL3[a2] ^ a3
            out[4 * c + 2] = a0 ^ a1 ^ _MUL2[a2] ^ _MUL3[a3]
            out[4 * c + 3] = _MUL3[a0] ^ a1 ^ a2 ^ _MUL2[a3]
        return out

    @staticmethod
    def _inv_mix(s: list[int]) -> list[int]:
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            out[4 * c + 0] = _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3]
            out[4 * c + 1] = _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3]
            out[4 * c + 2] = _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3]
            out[4 * c + 3] = _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3]
        return out


# ================================================= WinZip AES CTR
def ctr_xor(key: bytes, data: bytes, nonce_start: int = 1) -> bytes:
    """WinZip AES CTR：密钥流 = AES_Encrypt(小端 128 位计数器)，计数器从 1 起。"""
    cipher = AES(key)
    out = bytearray(len(data))
    ctr = nonce_start
    for off in range(0, len(data), 16):
        ks = cipher.encrypt_block(ctr.to_bytes(16, "little"))
        chunk = data[off:off + 16]
        for i in range(len(chunk)):
            out[off + i] = chunk[i] ^ ks[i]
        ctr += 1
    return bytes(out)


# ================================================= PBKDF2 / HMAC
def pbkdf2_sha1(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, salt, iterations, dklen)


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def hmac_sha1(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha1).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()
