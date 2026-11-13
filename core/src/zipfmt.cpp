// ============================================================================
//  ZIP 容器解析：定位加密条目，抽取 ZipCrypto / WinZip-AES 破解所需的全部参数
//
//  逐字段对齐 PKWARE APPNOTE：
//    EOCD(0x06054b50) -> 中央目录(0x02014b50) -> 本地文件头(0x04034b50)
//    Zip64: EOCD64 定位器(0x07064b50) + EOCD64(0x06064b50) + 额外字段 0x0001
//    WinZip AES: 额外字段 0x9901 = ver(2) "AE"(2) strength(1) real_method(2)
//
//  ZipCrypto 的 12 字节加密头之后才是数据；其第 12 字节期望值为
//    flags.bit3 ? (dosTime >> 8) & 0xFF : (crc32 >> 24) & 0xFF
//  这是 PKZIP 传统加密唯一的完整性锚点，也是 1/256 误报率的来源。
// ============================================================================
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "zpwn.hpp"

namespace zpwn {

static constexpr uint32_t SIG_LFH = 0x04034b50;
static constexpr uint32_t SIG_CD = 0x02014b50;
static constexpr uint32_t SIG_EOCD = 0x06054b50;
static constexpr uint32_t SIG_EOCD64 = 0x06064b50;
static constexpr uint32_t SIG_EOCD64_LOC = 0x07064b50;

static inline uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

int Entry::key_len() const {
    switch (aes_strength) {
        case 1: return 16;
        case 2: return 24;
        case 3: return 32;
        default: return 0;
    }
}

int Entry::salt_len() const {
    switch (aes_strength) {
        case 1: return 8;
        case 2: return 12;
        case 3: return 16;
        default: return 0;
    }
}

std::string Entry::enc_desc() const {
    switch (enc) {
        case EncKind::ZipCrypto: return "ZipCrypto (传统 PKZIP 流密码)";
        case EncKind::WinZipAes: {
            char b[64];
            std::snprintf(b, sizeof b, "WinZip AES-%d (AE-%d)", key_len() * 8, aes_strength);
            return b;
        }
        default: return "未加密";
    }
}

std::vector<const Entry*> Archive::encrypted() const {
    std::vector<const Entry*> v;
    for (const auto& e : entries)
        if (e.enc != EncKind::None && !e.is_dir) v.push_back(&e);
    return v;
}

const uint8_t* Archive::at(uint64_t off, size_t n) const {
    if (off > raw.size() || raw.size() - off < n) return nullptr;
    return raw.data() + off;
}

std::string Archive::format_desc() const {
    if (format == "zip") return "ZIP";
    if (format == "rar4") return "RAR 2.x-4.x (RAR4)";
    if (format == "rar5") return "RAR5";
    if (format == "7z") return "7-Zip";
    return "未知容器";
}

// 解析额外字段，返回指定 header id 的负载（找不到返回 nullptr）
static bool find_extra(const uint8_t* ex, size_t exlen, uint16_t want,
                       const uint8_t** out, size_t* outlen) {
    size_t p = 0;
    while (p + 4 <= exlen) {
        const uint16_t id = rd16(ex + p);
        const size_t len = rd16(ex + p + 2);
        p += 4;
        if (p + len > exlen) break;
        if (id == want) {
            *out = ex + p;
            *outlen = len;
            return true;
        }
        p += len;
    }
    return false;
}

static bool load_file(const std::string& path, std::vector<uint8_t>& out, std::string& err) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) { err = "无法读取文件大小: " + ec.message(); return false; }
    if (size == 0) { err = "文件为空"; return false; }
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = "无法打开文件"; return false; }
    out.resize((size_t)size);
    f.read(reinterpret_cast<char*>(out.data()), (std::streamsize)size);
    if (!f) { err = "读取文件失败"; return false; }
    return true;
}

bool parse_archive(const std::string& path, Archive& out, std::string& err) {
    out = Archive{};
    out.path = path;
    if (!load_file(path, out.raw, err)) return false;

    const uint8_t* d = out.raw.data();
    const size_t n = out.raw.size();

    auto starts = [&](size_t off, uint32_t sig) {
        return off + 4 <= n && rd32(d + off) == sig;
    };

    // ---- 格式判定 ----
    if (n >= 7 && std::memcmp(d, "Rar!\x1a\x07\x00", 7) == 0) { out.format = "rar4"; return true; }
    if (n >= 8 && std::memcmp(d, "Rar!\x1a\x07\x01\x00", 8) == 0) { out.format = "rar5"; return true; }
    if (n >= 6 && std::memcmp(d, "7z\xbc\xaf\x27\x1c", 6) == 0) { out.format = "7z"; return true; }

    // ---- 找 EOCD（从尾部回扫）----
    size_t eocd = SIZE_MAX;
    const size_t back = n > 66000 ? n - 66000 : 0;
    for (size_t i = n; i-- > back;) {
        if (i + 4 <= n && rd32(d + i) == SIG_EOCD && i + 22 <= n) { eocd = i; break; }
    }
    if (eocd == SIZE_MAX) {
        out.format = starts(0, SIG_LFH) ? "zip" : "unknown";
        out.errors.push_back("未找到 EOCD：压缩包可能被截断或是自解压格式");
        return out.format == "zip";
    }
    out.format = "zip";

    uint64_t total_entries = rd16(d + eocd + 10);
    uint64_t cd_size = rd32(d + eocd + 12);
    uint64_t cd_off = rd32(d + eocd + 16);

    if (total_entries == 0xFFFF || cd_off == 0xFFFFFFFF || cd_size == 0xFFFFFFFF) {
        if (eocd >= 20 && rd32(d + eocd - 20) == SIG_EOCD64_LOC) {
            const uint64_t z64 = rd64(d + eocd - 20 + 8);
            if (z64 + 56 <= n && rd32(d + z64) == SIG_EOCD64) {
                total_entries = rd64(d + z64 + 32);
                cd_size = rd64(d + z64 + 40);
                cd_off = rd64(d + z64 + 48);
            }
        }
    }
    if (cd_off >= n) {
        out.errors.push_back("中央目录偏移越界");
        return true;
    }

    // ---- 遍历中央目录 ----
    size_t p = (size_t)cd_off;
    const size_t cd_end = (cd_size && cd_off + cd_size <= n) ? (size_t)(cd_off + cd_size) : n;
    uint64_t guard = 0;
    while (p + 46 <= cd_end && rd32(d + p) == SIG_CD) {
        Entry e;
        e.flags = rd16(d + p + 8);
        e.method = rd16(d + p + 10);
        e.dostime = rd16(d + p + 12);
        e.crc = rd32(d + p + 16);
        e.csize = rd32(d + p + 20);
        e.usize = rd32(d + p + 24);
        const uint16_t nlen = rd16(d + p + 28);
        const uint16_t elen = rd16(d + p + 30);
        const uint16_t clen = rd16(d + p + 32);
        e.lho = rd32(d + p + 42);

        if (p + 46 + nlen + elen + clen > cd_end) {
            out.errors.push_back("中央目录条目越界，停止解析");
            break;
        }
        e.name.assign(reinterpret_cast<const char*>(d + p + 46), nlen);
        const uint8_t* ex = d + p + 46 + nlen;
        e.real_method = e.method;
        e.is_dir = !e.name.empty() && e.name.back() == '/';

        const uint8_t* z = nullptr;
        size_t zlen = 0;
        if (find_extra(ex, elen, 0x0001, &z, &zlen) &&
            (e.csize == 0xFFFFFFFFull || e.usize == 0xFFFFFFFFull || e.lho == 0xFFFFFFFFull)) {
            size_t q = 0;
            if (e.usize == 0xFFFFFFFFull && q + 8 <= zlen) { e.usize = rd64(z + q); q += 8; }
            if (e.csize == 0xFFFFFFFFull && q + 8 <= zlen) { e.csize = rd64(z + q); q += 8; }
            if (e.lho == 0xFFFFFFFFull && q + 8 <= zlen) { e.lho = rd64(z + q); q += 8; }
        }
        if (find_extra(ex, elen, 0x9901, &z, &zlen) && zlen >= 7) {
            e.aes_version = rd16(z);
            // z[2..3] 是供应商 "AE"
            const int strength = z[4];
            e.aes_strength = (strength >= 1 && strength <= 3) ? strength : 0;
            e.real_method = rd16(z + 5);
        }
        out.entries.push_back(e);
        ++guard;
        p += 46 + nlen + elen + clen;
        if (total_entries && guard >= total_entries) break;
    }

    if (out.entries.empty()) out.errors.push_back("中央目录未解析出任何条目");

    // ---- 逐条补本地文件头与加密参数 ----
    for (auto& e : out.entries) {
        if (e.is_dir) continue;
        if (e.lho + 30 > n || rd32(d + e.lho) != SIG_LFH) {
            out.errors.push_back(e.name + ": 本地文件头缺失或损坏");
            continue;
        }
        const uint16_t nlen2 = rd16(d + e.lho + 26);
        const uint16_t elen2 = rd16(d + e.lho + 28);
        e.data_offset = e.lho + 30 + nlen2 + elen2;
        if (e.data_offset > n) {
            out.errors.push_back(e.name + ": 数据偏移越界");
            continue;
        }
        const bool flag_enc = (e.flags & 0x1) != 0;

        if (e.aes_strength > 0) {
            const int sl = e.salt_len();
            if (e.data_offset + sl + 2 + 10 > n) {
                out.errors.push_back(e.name + ": AES 参数区越界");
                continue;
            }
            e.salt.assign(d + e.data_offset, d + e.data_offset + sl);
            e.pv.assign(d + e.data_offset + sl, d + e.data_offset + sl + 2);
            const uint64_t body_off = e.data_offset + sl + 2;
            const uint64_t tail_off = e.data_offset + e.csize;
            e.body_len = e.csize > (uint64_t)(sl + 2 + 10) ? e.csize - (uint64_t)(sl + 2 + 10) : 0;
            if (body_off + 16 <= n) e.ct_head.assign(d + body_off, d + body_off + 16);
            if (tail_off <= n && tail_off >= 10)
                e.auth_code.assign(d + tail_off - 10, d + tail_off);
            e.enc = EncKind::WinZipAes;
        } else if (flag_enc) {
            if (e.data_offset + 12 > n) {
                out.errors.push_back(e.name + ": ZipCrypto 加密头不足 12 字节");
                continue;
            }
            std::memcpy(e.enc_header, d + e.data_offset, 12);
            e.check_byte = (e.flags & 0x8) ? ((e.dostime >> 8) & 0xFF) : ((e.crc >> 24) & 0xFF);
            e.enc = EncKind::ZipCrypto;
            e.body_len = e.csize > 12 ? e.csize - 12 : 0;
        }
    }
    return true;
}

// --------------------------------------------------------- 已知明文素材采集
namespace {
struct Magic {
    const char* ext;
    const char* label;
    const char* hex;
    size_t hexlen;
};
}  // namespace

static std::vector<uint8_t> from_hex(const std::string& h) {
    std::vector<uint8_t> v;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        const int a = val(h[i]), b = val(h[i + 1]);
        if (a < 0 || b < 0) break;
        v.push_back((uint8_t)((a << 4) | b));
    }
    return v;
}

std::vector<PlainPair> harvest_plaintext(const Archive& ar) {
    std::vector<PlainPair> out;
    const auto encs = ar.encrypted();

    // 1) 孪生未加密条目：同一条目名同时存在明文副本 -> 明文完全已知
    for (const Entry* e : encs) {
        for (const auto& pl : ar.entries) {
            if (pl.enc != EncKind::None || pl.is_dir) continue;
            if (pl.name != e->name || pl.usize == 0) continue;
            const size_t take = (size_t)std::min<uint64_t>(pl.usize, 65536);
            const uint8_t* b = ar.at(pl.data_offset, take);
            if (b && take >= 12) {
                PlainPair p;
                p.label = "孪生未加密条目 · " + e->name;
                p.entry = e->name;
                p.offset = 0;
                p.data.assign(b, b + take);
                p.confidence = 1.0;
                out.push_back(std::move(p));
            }
        }
    }

    // 2) 扩展名魔数（仅对 stored 条目成立：压缩流的明文依赖压缩器实现）
    struct P { const char* ext; const char* label; const char* hex; };
    static const P prof[] = {
        {".png", "PNG 头", "89504e470d0a1a0a0000000d49484452"},
        {".jpg", "JPEG SOI+APP0", "ffd8ffe000104a46494600010100000100010000"},
        {".jpeg", "JPEG SOI+APP0", "ffd8ffe000104a46494600010100000100010000"},
        {".pdf", "PDF 1.4", "255044462d312e340d0a25e2e3cfd30d0a"},
        {".sqlite", "SQLite3", "53514c69746520666f726d6174203300"},
        {".db", "SQLite3", "53514c69746520666f726d6174203300"},
        {".zip", "ZIP 本地头", "504b0304"},
        {".docx", "ZIP 本地头", "504b0304"},
        {".xlsx", "ZIP 本地头", "504b0304"},
        {".pptx", "ZIP 本地头", "504b0304"},
    };
    for (const Entry* e : encs) {
        if (e->method != 0 || e->enc != EncKind::ZipCrypto) continue;
        std::string lower = e->name;
        for (auto& c : lower) c = (char)tolower((unsigned char)c);
        for (const auto& p : prof) {
            const size_t el = std::strlen(p.ext);
            if (lower.size() >= el && lower.compare(lower.size() - el, el, p.ext) == 0) {
                auto data = from_hex(p.hex);
                if (data.size() >= 12) {
                    PlainPair pp;
                    pp.label = std::string(p.label) + " @ " + e->name;
                    pp.entry = e->name;
                    pp.offset = 0;
                    pp.data = std::move(data);
                    pp.confidence = 0.75;
                    out.push_back(std::move(pp));
                }
                break;
            }
        }
    }

    std::stable_sort(out.begin(), out.end(), [](const PlainPair& a, const PlainPair& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.data.size() > b.data.size();
    });
    return out;
}

}  // namespace zpwn
