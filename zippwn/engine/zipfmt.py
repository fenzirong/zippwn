"""压缩包结构解析：定位加密条目、抽取破解所需的全部参数。

支持 / 识别：
  * ZIP + ZipCrypto（传统 PKZIP 流密码）
  * ZIP + WinZip AES（AE-1 / AE-2 / AE-3，额外字段 0x9901）
  * ZIP + Zip64（尺寸走 0x0001 额外字段）
  * RAR4 / RAR5 / 7z —— 仅做格式识别与「外挂后端」路由，不在此解析加密体

字段语义与本地文件头（LFH）/ 中央目录（CD）逐字节对齐；参考 unzip 的
process.c、7-Zip 的 ZipIn.cpp、hashcat 的 zip2john 输出约定。
"""

from __future__ import annotations

import mmap
import os
import struct
from dataclasses import dataclass, field

SIG_LFH = b"PK\x03\x04"
SIG_CD = b"PK\x01\x02"
SIG_EOCD = b"PK\x05\x06"
SIG_Z64_LOC = b"PK\x06\x07"
SIG_Z64_EOCD = b"PK\x06\x06"
SIG_RAR4 = b"Rar!\x1a\x07\x00"
SIG_RAR5 = b"Rar!\x1a\x07\x01\x00"
SIG_7Z = b"7z\xbc\xaf\x27\x1c"

AES_SALT_LEN = {1: 8, 2: 12, 3: 16}
AES_KEY_LEN = {1: 16, 2: 24, 3: 32}

ENC_NONE = "none"
ENC_ZIPCRYPTO = "zipcrypto"
ENC_WINZIP_AES = "winzip-aes"


@dataclass
class Entry:
    """一个 ZIP 条目 + 其加密参数。"""

    name: str
    flags: int = 0
    method: int = 0
    crc32: int = 0
    csize: int = 0
    usize: int = 0
    lho: int = 0
    dostime: int = 0
    aes_strength: int = 0       # 0=none, 1=AE-1(128), 2=AE-2(192), 3=AE-3(256)
    aes_version: int = 0
    aes_vendor: bytes = b""
    real_method: int = 0
    data_offset: int = 0
    enc_kind: str = ENC_NONE
    check_byte: int = -1        # ZipCrypto 12 字节头第 12 字节期望值
    enc_header: bytes = b""     # ZipCrypto 12 字节加密头
    salt: bytes = b""
    pv: bytes = b""             # 2 字节口令校验值
    ct_head: bytes = b""        # AES 密文前 16 字节
    auth_code: bytes = b""      # AES 末 10 字节 HMAC
    body_len: int = 0           # 密文体长度
    is_dir: bool = False

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & 0x1) or self.aes_strength > 0

    @property
    def key_len(self) -> int:
        return AES_KEY_LEN.get(self.aes_strength, 0)

    @property
    def salt_len(self) -> int:
        return AES_SALT_LEN.get(self.aes_strength, 0)

    def describe_enc(self) -> str:
        if self.enc_kind == ENC_ZIPCRYPTO:
            return "ZipCrypto (传统 PKZIP 流密码)"
        if self.enc_kind == ENC_WINZIP_AES:
            return f"WinZip AES-{self.key_len * 8} (AE-{self.aes_strength})"
        return "未加密"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "method": self.method if self.aes_strength == 0 else self.real_method,
            "crc32": f"{self.crc32:08x}",
            "csize": self.csize,
            "usize": self.usize,
            "enc": self.enc_kind,
            "enc_desc": self.describe_enc(),
            "aes_strength": self.aes_strength,
            "key_len": self.key_len,
            "is_dir": self.is_dir,
        }


@dataclass
class ArchiveInfo:
    path: str
    format: str = "unknown"
    entries: list[Entry] = field(default_factory=list)
    comment: bytes = b""
    errors: list[str] = field(default_factory=list)
    _buf: object = None

    def close(self) -> None:
        buf = self._buf
        self._buf = None
        if buf is not None:
            try:
                buf.close()
            except Exception:
                pass

    def __enter__(self) -> "ArchiveInfo":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def encrypted_entries(self) -> list[Entry]:
        return [e for e in self.entries if e.encrypted and not e.is_dir]

    @property
    def data(self):
        return self._buf

    def read(self, off: int, n: int) -> bytes:
        if self._buf is None or off < 0:
            return b""
        return bytes(self._buf[off:off + max(0, n)])

    def summary(self) -> dict:
        enc = self.encrypted_entries
        kinds = sorted({e.enc_kind for e in enc})
        return {
            "path": self.path,
            "format": self.format,
            "format_desc": {
                "zip": "ZIP", "rar4": "RAR4 (RAR 2.x-4.x)",
                "rar5": "RAR5", "7z": "7-Zip",
            }.get(self.format, "未知"),
            "entries_total": len(self.entries),
            "entries_encrypted": len(enc),
            "enc_kinds": kinds,
            "enc_desc": " / ".join(sorted({e.describe_enc() for e in enc})) or "无加密条目",
            "native_cpu": bool(enc) and self.format == "zip"
            and all(k in (ENC_ZIPCRYPTO, ENC_WINZIP_AES) for k in kinds),
            "errors": self.errors,
            "files": [e.to_dict() for e in self.entries[:300]],
        }


# --------------------------------------------------------------- 内部工具
def _read_extra(extra: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    p = 0
    while p + 4 <= len(extra):
        hid, hlen = struct.unpack_from("<HH", extra, p)
        p += 4
        out[hid] = extra[p:p + hlen]
        p += hlen
    return out


def _find_eocd(buf) -> int:
    size = len(buf)
    tail_start = max(0, size - 65557 - 22)
    chunk = bytes(buf[tail_start:size])
    idx = chunk.rfind(SIG_EOCD)
    while idx != -1:
        if idx + 22 <= len(chunk):
            return tail_start + idx
        idx = chunk.rfind(SIG_EOCD, 0, idx)
    return -1


def _parse_zip(buf, info: ArchiveInfo) -> None:
    eocd = _find_eocd(buf)
    if eocd < 0:
        info.errors.append("未找到 EOCD，可能不是标准 ZIP 或被截断")
        return
    (_s, _disk, _cdd, _nd, n_total, cd_size, cd_off,
     clen) = struct.unpack_from("<4sHHHHIIH", buf, eocd)
    info.comment = bytes(buf[eocd + 22:eocd + 22 + clen])

    if n_total == 0xFFFF or cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        loc = eocd - 20
        if loc >= 0 and bytes(buf[loc:loc + 4]) == SIG_Z64_LOC:
            z64_off = struct.unpack_from("<Q", buf, loc + 8)[0]
            if bytes(buf[z64_off:z64_off + 4]) == SIG_Z64_EOCD:
                n_total = struct.unpack_from("<Q", buf, z64_off + 32)[0]
                cd_size = struct.unpack_from("<Q", buf, z64_off + 40)[0]
                cd_off = struct.unpack_from("<Q", buf, z64_off + 48)[0]

    p = cd_off
    end = min(len(buf), cd_off + cd_size) if cd_size else len(buf)
    count = 0
    while p + 46 <= end and bytes(buf[p:p + 4]) == SIG_CD:
        (flags, method, dtime, _ddate, crc, csize, usize, nlen, elen,
         clen2, _dstart, _iattr, _eattr, lho) = struct.unpack_from(
            "<HHHHIIIHHHHHII", buf, p + 8)
        name = bytes(buf[p + 46:p + 46 + nlen]).decode("utf-8", "replace")
        extra = bytes(buf[p + 46 + nlen:p + 46 + nlen + elen])
        ex = _read_extra(extra)
        if 0x0001 in ex and (csize == 0xFFFFFFFF or usize == 0xFFFFFFFF
                             or lho == 0xFFFFFFFF):
            z = ex[0x0001]
            q = 0
            if usize == 0xFFFFFFFF and q + 8 <= len(z):
                usize = struct.unpack_from("<Q", z, q)[0]; q += 8
            if csize == 0xFFFFFFFF and q + 8 <= len(z):
                csize = struct.unpack_from("<Q", z, q)[0]; q += 8
            if lho == 0xFFFFFFFF and q + 8 <= len(z):
                lho = struct.unpack_from("<Q", z, q)[0]; q += 8

        e = Entry(name=name, flags=flags, method=method, crc32=crc,
                  csize=csize, usize=usize, lho=lho, dostime=dtime,
                  real_method=method, is_dir=name.endswith("/"))
        if 0x9901 in ex:
            z = ex[0x9901]
            if len(z) >= 7:
                ver, vendor, strength, rmethod = struct.unpack_from("<H2sBH", z, 0)
                e.aes_version = ver
                e.aes_vendor = vendor
                e.aes_strength = strength if strength in (1, 2, 3) else 0
                e.real_method = rmethod
        info.entries.append(e)
        count += 1
        p += 46 + nlen + elen + clen2
        if n_total and count >= n_total:
            break

    for e in info.entries:
        if e.is_dir:
            continue
        if e.lho + 30 > len(buf) or bytes(buf[e.lho:e.lho + 4]) != SIG_LFH:
            info.errors.append(f"{e.name}: 本地文件头缺失")
            continue
        nlen2, elen2 = struct.unpack_from("<HH", buf, e.lho + 26)
        e.data_offset = e.lho + 30 + nlen2 + elen2
        if not e.encrypted:
            continue
        if e.aes_strength:
            sl = e.salt_len
            e.salt = bytes(buf[e.data_offset:e.data_offset + sl])
            e.pv = bytes(buf[e.data_offset + sl:e.data_offset + sl + 2])
            body_off = e.data_offset + sl + 2
            e.body_len = max(0, e.csize - sl - 2 - 10)
            e.ct_head = bytes(buf[body_off:body_off + 16])
            e.auth_code = bytes(buf[e.data_offset + e.csize - 10:
                                   e.data_offset + e.csize])
            e.enc_kind = ENC_WINZIP_AES
        else:
            e.enc_header = bytes(buf[e.data_offset:e.data_offset + 12])
            if len(e.enc_header) < 12:
                info.errors.append(f"{e.name}: 加密头不足 12 字节")
                continue
            e.check_byte = (e.dostime >> 8) & 0xFF if (e.flags & 0x8) \
                else (e.crc32 >> 24) & 0xFF
            e.enc_kind = ENC_ZIPCRYPTO
            e.body_len = max(0, e.csize - 12)


def parse_archive(path: str) -> ArchiveInfo:
    """打开并解析压缩包。调用方负责 close()（或使用 with）。"""
    info = ArchiveInfo(path=path)
    if not os.path.isfile(path):
        info.errors.append(f"文件不存在: {path}")
        return info
    f = open(path, "rb")
    try:
        if os.fstat(f.fileno()).st_size == 0:
            info.errors.append("空文件")
            return info
        buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    finally:
        f.close()
    info._buf = buf

    head = bytes(buf[:8])
    if head.startswith(SIG_RAR5):
        info.format = "rar5"
    elif head.startswith(SIG_RAR4):
        info.format = "rar4"
    elif head.startswith(SIG_7Z):
        info.format = "7z"
    elif head.startswith(SIG_LFH) or head.startswith(SIG_EOCD):
        info.format = "zip"
        _parse_zip(buf, info)
    else:
        info.format = "unknown"
        info.errors.append("无法识别的容器格式")
    return info


# --------------------------------------------------- 已知明文（漏洞攻击素材）
PLAINTEXT_PROFILES: dict[str, bytes] = {
    "PNG 头": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "JPEG 头(SOI+APP0)": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00",
    "PDF 1.4": b"%PDF-1.4\r\n%\xe2\xe3\xcf\xd3\r\n",
    "PDF 1.7": b"%PDF-1.7\r\n%\xe2\xe3\xcf\xd3\r\n",
    "GIF89a": b"GIF89a",
    "ZIP 本地头": SIG_LFH,
    "OOXML content types":
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
    "Word document.xml":
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">',
    "Excel sheet1.xml":
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
    "SQLite3": b"SQLite format 3\x00",
    "7z 头": SIG_7Z,
    "RAR5 头": SIG_RAR5,
    "PE/DOS MZ": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
}

_EXT_PROFILE = {
    ".png": "PNG 头",
    ".jpg": "JPEG 头(SOI+APP0)",
    ".jpeg": "JPEG 头(SOI+APP0)",
    ".pdf": "PDF 1.4",
    ".docx": "ZIP 本地头",
    ".xlsx": "ZIP 本地头",
    ".pptx": "ZIP 本地头",
    ".zip": "ZIP 本地头",
    ".sqlite": "SQLite3",
    ".db": "SQLite3",
    ".exe": "PE/DOS MZ",
    ".dll": "PE/DOS MZ",
}


def harvest_known_plaintext(info: ArchiveInfo) -> list[dict]:
    """产出可直接喂给已知明文攻击的素材。

    三个来源（按攻击力降序）：
      1. 未加密的同名孪生条目 —— 明文完全已知
      2. 条目扩展名推断的文件魔数（要求条目为 stored/method 0）
      3. 内置结构模板
    """
    out: list[dict] = []
    enc = [e for e in info.entries if e.encrypted and not e.is_dir]
    plain = [e for e in info.entries if not e.encrypted and not e.is_dir]
    by_name = {e.name: e for e in plain}

    for e in enc:
        twin = by_name.get(e.name)
        if twin and twin.usize > 0 and twin.method == 0:
            body = info.read(twin.data_offset, min(twin.usize, 65536))
            if len(body) >= 12:
                out.append({
                    "label": f"孪生未加密条目 · {e.name}",
                    "entry": e.name, "offset": 0, "data_len": len(body),
                    "confidence": 1.0, "preview": body[:32].hex(),
                    "_bytes": body,
                })

    for e in enc:
        if e.method != 0:
            continue          # 压缩流的明文与压缩器实现相关，不做魔数猜测
        prof = _EXT_PROFILE.get(os.path.splitext(e.name.lower())[1])
        if not prof:
            continue
        data = PLAINTEXT_PROFILES[prof]
        if len(data) >= 12:
            out.append({
                "label": f"{prof} @ {e.name}",
                "entry": e.name, "offset": 0, "data_len": len(data),
                "confidence": 0.75, "preview": data[:32].hex(),
                "_bytes": data,
            })

    out.sort(key=lambda r: (-r["confidence"], -r["data_len"]))
    return out
