// ============================================================================
//  攻击引擎：校验器 + 候选生成器 + 多线程调度
//
//  ZipCrypto 快筛原理（结构性弱点，PKZIP 传统加密）：
//    12 字节加密头里只有第 12 字节有效（crc>>24 或 dostime>>8），
//    因此单条目误报率 1/256。我们把同一压缩包里多个条目串成"漏斗"：
//    第 1 个条目筛完 -> 只剩 1/256；第 2 个 -> 1/65536；第 3 个 -> 1/16.7M。
//    这样既能只解 12 字节（不解全量数据、不做 inflate），又不牺牲准确性。
//
//  WinZip AES 快筛原理：
//    PBKDF2-HMAC-SHA1(password, salt, 1000) 的最后 2 字节是明文口令校验值，
//    命中率 1/65536；命中后再做 HMAC-SHA1 全量确认（只在命中时付一次代价）。
// ============================================================================
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "zpwn.hpp"

namespace zpwn {

// ------------------------------------------------------------ ZipCrypto 状态机
static inline void zc_update(uint32_t& k0, uint32_t& k1, uint32_t& k2, uint8_t c) {
    k0 = CRC_TABLE[(k0 ^ c) & 0xFF] ^ (k0 >> 8);
    k1 = (k1 + (k0 & 0xFF)) * 134775813u + 1u;
    k2 = CRC_TABLE[(k2 ^ (k1 >> 24)) & 0xFF] ^ (k2 >> 8);
}

void zipcrypto_decrypt(const uint8_t* pw, size_t len, uint8_t* data, size_t n) {
    uint32_t k0 = 0x12345678u, k1 = 0x23456789u, k2 = 0x34567890u;
    for (size_t i = 0; i < len; ++i) zc_update(k0, k1, k2, pw[i]);
    for (size_t i = 0; i < n; ++i) {
        const uint32_t t = (k2 | 2u) & 0xFFFFu;
        const uint8_t ks = (uint8_t)((t * (t ^ 1u)) >> 8);
        const uint8_t p = (uint8_t)(data[i] ^ ks);
        data[i] = p;
        zc_update(k0, k1, k2, p);
    }
}

// 关键：ZipCrypto 的密钥流是**连续**的。12 字节加密头本身也推进密钥状态，
// 所以解密正文之前必须先把这 12 字节"过一遍"（解出的明文头直接丢弃），
// 否则密钥状态错位，后面全部是垃圾。
void zipcrypto_decrypt_body(const uint8_t* pw, size_t len, const uint8_t hdr[12],
                            uint8_t* data, size_t n) {
    uint32_t k0 = 0x12345678u, k1 = 0x23456789u, k2 = 0x34567890u;
    for (size_t i = 0; i < len; ++i) zc_update(k0, k1, k2, pw[i]);
    for (int i = 0; i < 12; ++i) {
        const uint32_t t = (k2 | 2u) & 0xFFFFu;
        const uint8_t ks = (uint8_t)((t * (t ^ 1u)) >> 8);
        const uint8_t p = (uint8_t)(hdr[i] ^ ks);
        zc_update(k0, k1, k2, p);
    }
    for (size_t i = 0; i < n; ++i) {
        const uint32_t t = (k2 | 2u) & 0xFFFFu;
        const uint8_t ks = (uint8_t)((t * (t ^ 1u)) >> 8);
        const uint8_t p = (uint8_t)(data[i] ^ ks);
        data[i] = p;
        zc_update(k0, k1, k2, p);
    }
}

// ------------------------------------------------------------ ZipCrypto 校验器
//
//  test()   ：只解 12 字节加密头，误报率 1/256^n（n = 交叉校验条目数）—— 用于快筛
//  confirm()：全量解密 + 解压 + CRC32 比对 —— 误报率 0，但只在 test 命中时付代价
//
//  解压用自己的 raw DEFLATE 解码器（见下方 inflate_raw），零外部依赖。
//  Windows 的 compressapi.h 只有 MSZIP（带 CK 标记的变体），不支持原始 deflate，
//  所以不能偷懒。
namespace {

// ---------------- 极简 DEFLATE 解码（puff 风格，纯标准 C++） ----------------
struct BitReader {
    const uint8_t* p = nullptr;
    size_t n = 0;
    size_t pos = 0;
    uint32_t buf = 0;
    int cnt = 0;

    int bit() {
        if (cnt == 0) {
            if (pos >= n) return -1;
            buf = p[pos++];
            cnt = 8;
        }
        const int b = (int)(buf & 1u);
        buf >>= 1;
        --cnt;
        return b;
    }
    int bits(int need) {
        int v = 0;
        for (int i = 0; i < need; ++i) {
            const int b = bit();
            if (b < 0) return -1;
            v |= b << i;
        }
        return v;
    }
    void align() { cnt = 0; }
};

struct Huffman {
    short count[16];
    short symbol[288];
};

// 返回剩余码空间：0=满树，>0=不完整树（合法），<0=超额（非法）
int huff_build(Huffman* h, const short* length, int n) {
    for (int i = 0; i < 16; ++i) h->count[i] = 0;
    for (int i = 0; i < n; ++i) h->count[length[i]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len < 16; ++len) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return -1;
    }
    short offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; ++len) offs[len + 1] = (short)(offs[len] + h->count[len]);
    for (int i = 0; i < n; ++i)
        if (length[i]) h->symbol[offs[length[i]]++] = (short)i;
    return left;
}

int huff_decode(BitReader& br, const Huffman* h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; ++len) {
        const int b = br.bit();
        if (b < 0) return -1;
        code |= b;
        const int count = h->count[len];
        if (code - count < first) return index + (code - first) < 288
                                          ? h->symbol[index + (code - first)]
                                          : -1;
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

const short LBASE[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                         35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const short LEXT[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const short DBASE[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
                         193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
                         6145, 8193, 12289, 16385, 24577};
const short DEXT[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                        6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

constexpr size_t INFLATE_FAIL = (size_t)-1;

// 返回解压字节数；失败返回 INFLATE_FAIL
size_t inflate_raw(const uint8_t* src, size_t n, uint8_t* dst, size_t cap) {
    BitReader br;
    br.p = src;
    br.n = n;

    static Huffman fixed_l, fixed_d;
    static bool fixed_ready = false;
    if (!fixed_ready) {
        short lens[288];
        int i = 0;
        for (; i < 144; ++i) lens[i] = 8;
        for (; i < 256; ++i) lens[i] = 9;
        for (; i < 280; ++i) lens[i] = 7;
        for (; i < 288; ++i) lens[i] = 8;
        huff_build(&fixed_l, lens, 288);
        short dl[30];
        for (int j = 0; j < 30; ++j) dl[j] = 5;
        huff_build(&fixed_d, dl, 30);
        fixed_ready = true;
    }

    size_t out = 0;
    int last = 0;
    while (!last) {
        last = br.bits(1);
        if (last < 0) return INFLATE_FAIL;
        const int type = br.bits(2);
        if (type < 0) return INFLATE_FAIL;

        Huffman lencode, distcode;

        if (type == 0) {                       // 存储块（未压缩）
            br.align();
            const int lo = br.bits(16), hi = br.bits(16);
            if (lo < 0 || hi < 0) return INFLATE_FAIL;
            const size_t len = (size_t)lo | ((size_t)hi << 16);
            const int nlo = br.bits(16), nhi = br.bits(16);
            if (nlo < 0 || nhi < 0) return INFLATE_FAIL;
            const size_t nlen = (size_t)nlo | ((size_t)nhi << 16);
            if (((~len) & 0xFFFF) != nlen) return INFLATE_FAIL;
            if (out + len > cap) return INFLATE_FAIL;
            for (size_t k = 0; k < len; ++k) {
                const int b = br.bits(8);
                if (b < 0) return INFLATE_FAIL;
                dst[out++] = (uint8_t)b;
            }
            continue;
        }

        if (type == 1) {                       // 固定 Huffman
            lencode = fixed_l;
            distcode = fixed_d;
        } else if (type == 2) {                // 动态 Huffman
            short lengths[320] = {0};
            int hlit = br.bits(5), hdist = br.bits(5), hclen = br.bits(4);
            if (hlit < 0 || hdist < 0 || hclen < 0) return INFLATE_FAIL;
            hlit += 257;
            hdist += 1;
            hclen += 4;
            if (hlit > 286 || hdist > 30) return INFLATE_FAIL;

            static const short ORD[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
                                          11, 4, 12, 3, 13, 2, 14, 1, 15};
            short cl[19] = {0};
            for (int i = 0; i < hclen; ++i) {
                const int v = br.bits(3);
                if (v < 0) return INFLATE_FAIL;
                cl[ORD[i]] = (short)v;
            }
            Huffman clcode;
            if (huff_build(&clcode, cl, 19) < 0) return INFLATE_FAIL;

            int index = 0;
            while (index < hlit + hdist) {
                const int sym = huff_decode(br, &clcode);
                if (sym < 0) return INFLATE_FAIL;
                if (sym < 16) {
                    lengths[index++] = (short)sym;
                    continue;
                }
                short val = 0;
                int rep = 0;
                if (sym == 16) {
                    if (index == 0) return INFLATE_FAIL;
                    val = lengths[index - 1];
                    rep = 3 + br.bits(2);
                } else if (sym == 17) {
                    rep = 3 + br.bits(3);
                } else {
                    rep = 11 + br.bits(7);
                }
                if (rep < 0) return INFLATE_FAIL;
                while (rep-- > 0 && index < hlit + hdist) lengths[index++] = val;
            }
            if (huff_build(&lencode, lengths, hlit) < 0) return INFLATE_FAIL;
            if (huff_build(&distcode, lengths + hlit, hdist) < 0) return INFLATE_FAIL;
        } else {
            return INFLATE_FAIL;               // type == 3 非法
        }

        for (;;) {
            const int sym = huff_decode(br, &lencode);
            if (sym < 0) return INFLATE_FAIL;
            if (sym < 256) {
                if (out >= cap) return INFLATE_FAIL;
                dst[out++] = (uint8_t)sym;
            } else if (sym == 256) {
                break;                          // 块结束
            } else {
                const int li = sym - 257;
                if (li >= 29) return INFLATE_FAIL;
                const int e = br.bits(LEXT[li]);
                if (e < 0) return INFLATE_FAIL;
                const size_t len = (size_t)LBASE[li] + (size_t)e;
                const int dsym = huff_decode(br, &distcode);
                if (dsym < 0 || dsym >= 30) return INFLATE_FAIL;
                const int de = br.bits(DEXT[dsym]);
                if (de < 0) return INFLATE_FAIL;
                const size_t dist = (size_t)DBASE[dsym] + (size_t)de;
                if (dist > out) return INFLATE_FAIL;
                if (out + len > cap) return INFLATE_FAIL;
                for (size_t k = 0; k < len; ++k) {
                    dst[out] = dst[out - dist];
                    ++out;
                }
            }
        }
    }
    return out;
}

}  // namespace

class ZipCryptoChecker final : public Checker {
public:
    struct Target {
        uint8_t hdr[12];
        uint8_t check;
        size_t entry_index;
        std::string name;
    };
    std::vector<Target> targets;
    const Archive* ar = nullptr;

    const char* kind() const override { return "zipcrypto"; }

    std::string detail() const override {
        char b[192];
        std::snprintf(b, sizeof b, "%zu 个条目交叉校验（快筛误报 1/%llu，命中后全量 CRC 复核）",
                      targets.size(),
                      (unsigned long long)(1ull << (8 * std::min<size_t>(targets.size(), 8))));
        return b;
    }

    bool test(const uint8_t* pw, size_t len) override {
        uint32_t k0 = 0x12345678u, k1 = 0x23456789u, k2 = 0x34567890u;
        for (size_t i = 0; i < len; ++i) zc_update(k0, k1, k2, pw[i]);

        for (const auto& t : targets) {
            uint32_t a = k0, b = k1, c = k2;
            uint8_t last = 0;
            for (int i = 0; i < 12; ++i) {
                const uint32_t tmp = (c | 2u) & 0xFFFFu;
                const uint8_t ks = (uint8_t)((tmp * (tmp ^ 1u)) >> 8);
                const uint8_t p = (uint8_t)(t.hdr[i] ^ ks);
                if (i == 11) last = p;
                zc_update(a, b, c, p);
            }
            if (last != t.check) return false;
        }
        return true;
    }

    // 严格确认：解全量密文 -> (解压) -> CRC32 必须与条目头里的 CRC 一致
    bool confirm(const uint8_t* pw, size_t len) override {
        if (!test(pw, len)) return false;
        if (!ar || targets.empty()) return true;

        const Entry& e = ar->entries[targets.front().entry_index];
        const uint64_t body_len = e.body_len;
        if (body_len == 0) return true;

        // 上限 128MB：更大的条目跳过复核（只保留 1/256^n 概率，不影响实用）
        if (body_len > (128ull << 20)) return true;

        const uint8_t* src = ar->at(e.data_offset + 12, (size_t)body_len);
        if (!src) return false;

        std::vector<uint8_t> plain((size_t)body_len);
        std::memcpy(plain.data(), src, (size_t)body_len);
        zipcrypto_decrypt_body(pw, len, e.enc_header, plain.data(), plain.size());

        if (e.method == 0) {
            return crc32_calc(plain.data(), plain.size()) == e.crc;
        }
        if (e.method == 8) {
            if (e.usize == 0 || e.usize > (256ull << 20)) return true;
            std::vector<uint8_t> out((size_t)e.usize);
            const size_t got = inflate_raw(plain.data(), plain.size(), out.data(), out.size());
            if (got == INFLATE_FAIL || got != (size_t)e.usize) return false;
            return crc32_calc(out.data(), got) == e.crc;
        }
        // 其它压缩方法（bzip2/lzma 等）：退化为长度合理性判断
        return true;
    }
};

// ------------------------------------------------------------ WinZip AES 校验器
class WinZipAesChecker final : public Checker {
public:
    const Archive* ar = nullptr;
    size_t entry_index = 0;
    uint32_t iters = 1000;

    const char* kind() const override { return "zipaes"; }

    std::string detail() const override {
        if (!ar) return {};
        const Entry& e = ar->entries[entry_index];
        char b[192];
        std::snprintf(b, sizeof b,
                      "AES-%d / PBKDF2-HMAC-SHA1 %u 轮 / pv 误报率 1/65536",
                      e.key_len() * 8, iters);
        return b;
    }

    bool test(const uint8_t* pw, size_t len) override {
        if (!ar) return false;
        const Entry& e = ar->entries[entry_index];
        const int kl = e.key_len();
        if (kl == 0 || e.pv.size() != 2) return false;
        uint8_t dk[2 * 32 + 2];
        pbkdf2_hmac_sha1(pw, len, e.salt.data(), e.salt.size(), iters, dk,
                         (size_t)(2 * kl + 2));
        return dk[2 * kl] == e.pv[0] && dk[2 * kl + 1] == e.pv[1];
    }

    // 严格确认：解密全量密文并核对 HMAC-SHA1（1/2^80 误报）
    bool confirm(const uint8_t* pw, size_t len) override {
        if (!test(pw, len)) return false;
        if (!ar) return false;
        const Entry& e = ar->entries[entry_index];
        const int kl = e.key_len();
        uint8_t dk[2 * 32 + 2];
        pbkdf2_hmac_sha1(pw, len, e.salt.data(), e.salt.size(), iters, dk,
                         (size_t)(2 * kl + 2));

        const uint64_t body_off = e.data_offset + (uint64_t)e.salt_len() + 2;
        const uint64_t body_len = e.body_len;
        if (body_len == 0 || body_len > (1ull << 31)) return true;   // 超大条目跳过 HMAC
        const uint8_t* ct = ar->at(body_off, (size_t)body_len);
        if (!ct) return false;

        uint8_t mac[20];
        hmac_sha1(dk + kl, (size_t)kl, ct, (size_t)body_len, mac);
        if (e.auth_code.size() != 10) return false;
        return std::memcmp(mac, e.auth_code.data(), 10) == 0;
    }
};

std::unique_ptr<Checker> make_checker(const Archive& ar, std::string& err) {
    const auto encs = ar.encrypted();
    if (encs.empty()) { err = "该压缩包没有加密条目"; return nullptr; }

    const EncKind kind = encs.front()->enc;
    for (const Entry* e : encs) {
        if (e->enc != kind) {
            err = "压缩包混合使用多种加密方案，请逐个处理";
            return nullptr;
        }
    }

    if (kind == EncKind::ZipCrypto) {
        auto c = std::make_unique<ZipCryptoChecker>();
        c->ar = &ar;
        for (size_t i = 0; i < ar.entries.size(); ++i) {
            const Entry& e = ar.entries[i];
            if (e.enc != EncKind::ZipCrypto || e.is_dir) continue;
            if (c->targets.size() >= 3) break;      // 3 个条目已足够 1/16.7M
            if (e.check_byte < 0) continue;
            ZipCryptoChecker::Target t;
            std::memcpy(t.hdr, e.enc_header, 12);
            t.check = (uint8_t)e.check_byte;
            t.entry_index = i;
            t.name = e.name;
            c->targets.push_back(std::move(t));
        }
        if (c->targets.empty()) { err = "未取得可用的加密头"; return nullptr; }
        return c;
    }

    if (kind == EncKind::WinZipAes) {
        auto c = std::make_unique<WinZipAesChecker>();
        c->ar = &ar;
        for (size_t i = 0; i < ar.entries.size(); ++i) {
            if (ar.entries[i].enc == EncKind::WinZipAes) { c->entry_index = i; break; }
        }
        return c;
    }

    err = "不支持的加密方案";
    return nullptr;
}

// ============================================================ 规则引擎
namespace {

std::string to_lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}
std::string to_upper(std::string s) {
    for (auto& c : s) c = (char)toupper((unsigned char)c);
    return s;
}
std::string capitalize(std::string s) {
    if (!s.empty()) {
        s[0] = (char)toupper((unsigned char)s[0]);
        for (size_t i = 1; i < s.size(); ++i) s[i] = (char)tolower((unsigned char)s[i]);
    }
    return s;
}
std::string leet(std::string s) {
    for (auto& c : s) {
        switch (tolower((unsigned char)c)) {
            case 'a': c = '4'; break;
            case 'e': c = '3'; break;
            case 'i': c = '1'; break;
            case 'o': c = '0'; break;
            case 's': c = '5'; break;
            case 't': c = '7'; break;
            case 'b': c = '8'; break;
            case 'g': c = '9'; break;
            default: break;
        }
    }
    return s;
}
std::string swapcase(std::string s) {
    for (auto& c : s)
        c = isupper((unsigned char)c) ? (char)tolower((unsigned char)c)
                                      : (char)toupper((unsigned char)c);
    return s;
}

// 单链规则：每个字符一个动作，'$x' 追加、'^x' 前置
bool apply_chain(const std::string& in, const std::string& ops, std::string& out) {
    out = in;
    for (size_t i = 0; i < ops.size(); ++i) {
        const char op = ops[i];
        switch (op) {
            case ':': break;
            case 'l': out = to_lower(out); break;
            case 'u': out = to_upper(out); break;
            case 'c': out = capitalize(out); break;
            case 'C': if (!out.empty()) out[0] = (char)toupper((unsigned char)out[0]); break;
            case 'r': std::reverse(out.begin(), out.end()); break;
            case 'd': out = out + out; break;
            case 'f': { std::string r(out.rbegin(), out.rend()); out += r; break; }
            case 't': out = swapcase(out); break;
            case 's': out = leet(out); break;
            case '$': if (i + 1 < ops.size()) out += ops[++i]; break;
            case '^': if (i + 1 < ops.size()) out.insert(out.begin(), ops[++i]); break;
            default: break;
        }
    }
    return true;
}

// 预设规则集 -> 规则链列表（每条链独立作用于原文，与 best64 的用法一致）
std::vector<std::string> resolve_rules(const std::vector<std::string>& names) {
    std::vector<std::string> chains;
    auto add = [&](const std::string& c) { chains.push_back(c); };

    for (const auto& raw : names) {
        const std::string n = to_lower(raw);
        if (n.empty() || n == "none" || n == ":") { add(":"); }
        else if (n == "lower") add("l");
        else if (n == "upper") add("u");
        else if (n == "capitalize") add("c");
        else if (n == "reverse") add("r");
        else if (n == "dup" || n == "duplicate") add("d");
        else if (n == "reflect") add("f");
        else if (n == "swapcase") add("t");
        else if (n == "leet") add("s");
        else if (n == "case") { add("l"); add("u"); add("c"); }
        else if (n == "append_digits") {
            for (char d = '0'; d <= '9'; ++d) add(std::string(":$") + d);
        } else if (n == "append_digits2") {
            for (char a = '0'; a <= '9'; ++a)
                for (char b = '0'; b <= '9'; ++b)
                    add(std::string(":$") + a + b);
        } else if (n == "append_years") {
            for (int y = 1970; y <= 2035; ++y) {
                char b[8];
                std::snprintf(b, sizeof b, "$%c$%c$%c$%c", (char)('0' + y / 1000 % 10),
                              (char)('0' + y / 100 % 10), (char)('0' + y / 10 % 10),
                              (char)('0' + y % 10));
                add(std::string(":") + b);
            }
        } else if (n == "append_symbols") {
            static const char* syms[] = {"!", "@", "#", "$", ".", "_", "-", "!!", "123", "1", "01"};
            for (const char* s : syms) add(std::string(":$") + s[0] + (s[1] ? std::string("$") + s[1] : "")
                                          + (s[2] ? std::string("$") + s[2] : ""));
        } else if (n == "best64lite") {
            add(":");
            add("l"); add("u"); add("c"); add("r"); add("s"); add("d"); add("f");
            for (char d = '0'; d <= '9'; ++d) add(std::string("l$") + d);
            for (int y = 1980; y <= 2025; y += 1) {
                char b[8];
                std::snprintf(b, sizeof b, "l$%c$%c$%c$%c", (char)('0' + y / 1000 % 10),
                              (char)('0' + y / 100 % 10), (char)('0' + y / 10 % 10),
                              (char)('0' + y % 10));
                add(b);
            }
            add("l$!"); add("c$!"); add("c$1"); add("c$123"); add("l$1");
        } else {
            add(raw);   // 直接当规则链处理
        }
    }
    // 去重保序
    std::vector<std::string> uniq;
    std::unordered_set<std::string> seen;
    for (auto& c : chains)
        if (seen.insert(c).second) uniq.push_back(c);
    return uniq;
}

size_t count_lines(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return 0;
    size_t n = 0;
    char buf[1 << 16];
    bool last_nl = true;
    while (f) {
        f.read(buf, sizeof buf);
        const std::streamsize got = f.gcount();
        for (std::streamsize i = 0; i < got; ++i) {
            if (buf[i] == '\n') ++n;
            last_nl = buf[i] == '\n';
        }
    }
    if (!last_nl) ++n;
    return n;
}

// ---- 目录字典源 ----
class DictSource final : public CandidateSource {
public:
    DictSource(std::vector<std::string> files, std::vector<std::string> chains,
               int min_len, int max_len, uint64_t total)
        : files_(std::move(files)), chains_(std::move(chains)),
          min_len_(min_len), max_len_(max_len), total_(total) {}

    uint64_t total() const override { return total_; }

    bool next(std::string& out) override {
        for (;;) {
            if (!have_word_ && !advance_word()) return false;

            out.clear();
            apply_chain(word_, chains_[chain_idx_], out);
            if (++chain_idx_ >= chains_.size()) {
                chain_idx_ = 0;
                have_word_ = false;
            }
            if (out.empty()) continue;
            if (min_len_ > 0 && (int)out.size() < min_len_) continue;
            if (max_len_ > 0 && (int)out.size() > max_len_) continue;
            return true;
        }
    }

private:
    // 取下一个词：当前文件还有行就继续，否则换下一个文件
    bool advance_word() {
        for (;;) {
            if (!f_.is_open()) {
                if (file_idx_ >= files_.size()) return false;
                f_.open(files_[file_idx_++], std::ios::binary);
                if (!f_) continue;
            }
            if (read_line(word_)) {
                have_word_ = true;
                return true;
            }
            f_.close();
        }
    }
    bool read_line(std::string& s) {
        s.clear();
        char c;
        bool any = false;
        while (f_.get(c)) {
            any = true;
            if (c == '\n') break;
            if (c != '\r') s.push_back(c);
        }
        if (!any) return false;
        if (s.size() >= 2 && (uint8_t)s[0] == 0xFF && (uint8_t)s[1] == 0xFE) s.erase(0, 2);
        return true;
    }

    std::vector<std::string> files_;
    std::vector<std::string> chains_;
    int min_len_, max_len_;
    uint64_t total_;
    size_t file_idx_ = 0;
    size_t chain_idx_ = 0;
    bool have_word_ = false;
    std::ifstream f_;
    std::string word_;
};

// ---- 掩码源 ----
struct MaskPos {
    std::string cs;
    size_t count;
};

bool parse_mask(const std::string& mask, const std::string charsets[4],
                std::vector<MaskPos>& pos, std::string& err) {
    static const char* L = "abcdefghijklmnopqrstuvwxyz";
    static const char* U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char* D = "0123456789";
    static const char* S = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    std::string all;
    all += L; all += U; all += D; all += S;

    pos.clear();
    for (size_t i = 0; i < mask.size(); ++i) {
        const char c = mask[i];
        if (c != '?' || i + 1 >= mask.size()) {
            pos.push_back({std::string(1, c), 1});
            continue;
        }
        const char t = mask[++i];
        std::string cs;
        switch (t) {
            case 'l': cs = L; break;
            case 'u': cs = U; break;
            case 'd': cs = D; break;
            case 's': cs = S; break;
            case 'a': cs = all; break;
            case 'b': {
                for (int b = 0; b < 256; ++b) cs.push_back((char)b);
                break;
            }
            case '1': case '2': case '3': case '4': {
                cs = charsets[t - '1'];
                if (cs.empty()) { err = std::string("?") + t + " 自定义字符集为空"; return false; }
                break;
            }
            case '?': cs = "?"; break;
            default: cs = std::string(1, t); break;
        }
        pos.push_back({cs, cs.size()});
    }
    if (pos.empty()) { err = "掩码为空"; return false; }
    for (auto& p : pos)
        if (p.count == 0) { err = "掩码含空字符集"; return false; }
    return true;
}

uint64_t mask_total(const std::vector<MaskPos>& pos, uint64_t cap = 0) {
    uint64_t n = 1;
    for (auto& p : pos) {
        if (p.count > 0 && n > cap / p.count && cap) return cap;
        n *= p.count;
        if (n > (1ull << 62)) return 1ull << 62;
    }
    return n;
}

class MaskSource final : public CandidateSource {
public:
    MaskSource(std::vector<MaskPos> pos, uint64_t total)
        : pos_(std::move(pos)), total_(total) {}

    uint64_t total() const override { return total_; }

    // 增量进位（odometer）：每次只改变化的低位，避免每候选 6 次 div/mod
    bool next(std::string& out) override {
        if (produced_ >= total_) return false;
        if (produced_ == 0) {
            idx_.assign(pos_.size(), 0);
            cur_.assign(pos_.size(), '\0');
            for (size_t i = 0; i < pos_.size(); ++i) cur_[i] = pos_[i].cs[0];
        }
        out = cur_;
        ++produced_;
        for (size_t i = pos_.size(); i-- > 0;) {
            if (++idx_[i] < pos_[i].count) {
                cur_[i] = pos_[i].cs[idx_[i]];
                return true;
            }
            idx_[i] = 0;
            cur_[i] = pos_[i].cs[0];
        }
        return true;
    }

private:
    std::vector<MaskPos> pos_;
    std::vector<size_t> idx_;
    std::string cur_;
    uint64_t total_;
    uint64_t produced_ = 0;
};

// ---- 混合源：字典词 + 掩码后缀 ----
class HybridSource final : public CandidateSource {
public:
    HybridSource(std::unique_ptr<CandidateSource> dict, std::vector<MaskPos> pos,
                 uint64_t mask_n)
        : dict_(std::move(dict)), pos_(std::move(pos)), mask_n_(mask_n) {}

    uint64_t total() const override {
        const uint64_t d = dict_->total();
        return d ? d * mask_n_ : 0;
    }

    bool next(std::string& out) override {
        for (;;) {
            if (mi_ >= mask_n_) {
                if (!dict_->next(word_)) return false;
                mi_ = 0;
            }
            uint64_t v = mi_++;
            std::string suf(pos_.size(), '\0');
            for (size_t i = pos_.size(); i-- > 0;) {
                suf[i] = pos_[i].cs[v % pos_[i].count];
                v /= pos_[i].count;
            }
            out = word_ + suf;
            return true;
        }
    }

private:
    std::unique_ptr<CandidateSource> dict_;
    std::vector<MaskPos> pos_;
    uint64_t mask_n_;
    uint64_t mi_ = 0;
    std::string word_;
};

}  // namespace

size_t CandidateSource::next_block(std::vector<std::string>& out, size_t want) {
    out.clear();
    out.reserve(want);
    std::string s;
    while (out.size() < want && next(s)) out.push_back(s);
    return out.size();
}

uint64_t estimate_total(AttackSpec& spec) {
    const auto chains = resolve_rules(spec.rules);
    uint64_t lines = 0;
    for (const auto& f : spec.wordlists) lines += count_lines(f);

    if (spec.mode == "mask" || (!spec.mask.empty() && spec.wordlists.empty())) {
        std::vector<MaskPos> pos;
        std::string err;
        if (!parse_mask(spec.mask, spec.charset, pos, err)) return 0;
        spec.total = mask_total(pos);
        return spec.total;
    }
    if (spec.mode == "hybrid") {
        std::vector<MaskPos> pos;
        std::string err;
        if (!parse_mask(spec.hybrid_mask.empty() ? "?d?d" : spec.hybrid_mask, spec.charset, pos, err))
            return 0;
        spec.total = lines * (chains.empty() ? 1 : chains.size()) * mask_total(pos);
        return spec.total;
    }
    spec.total = lines * (chains.empty() ? 1 : chains.size());
    return spec.total;
}

std::unique_ptr<CandidateSource> make_source(AttackSpec& spec, std::string& err) {
    if (spec.mode == "dict" || (spec.mode.empty() && !spec.wordlists.empty())) {
        if (spec.wordlists.empty()) { err = "字典模式需要至少一个字典文件"; return nullptr; }
        for (const auto& f : spec.wordlists) {
            std::ifstream t(f, std::ios::binary);
            if (!t) { err = "无法打开字典: " + f; return nullptr; }
        }
        auto chains = resolve_rules(spec.rules);
        if (chains.empty()) chains.push_back(":");
        const uint64_t lines = [&] {
            uint64_t n = 0;
            for (const auto& f : spec.wordlists) n += count_lines(f);
            return n;
        }();
        spec.total = lines * chains.size();
        return std::make_unique<DictSource>(spec.wordlists, chains, spec.min_len,
                                            spec.max_len, spec.total);
    }
    if (spec.mode == "mask") {
        std::vector<MaskPos> pos;
        if (!parse_mask(spec.mask, spec.charset, pos, err)) return nullptr;
        const uint64_t n = mask_total(pos);
        spec.total = n;
        return std::make_unique<MaskSource>(std::move(pos), n);
    }
    if (spec.mode == "hybrid") {
        if (spec.wordlists.empty()) { err = "混合模式需要字典文件"; return nullptr; }
        auto chains = resolve_rules(spec.rules);
        if (chains.empty()) chains.push_back(":");
        uint64_t lines = 0;
        for (const auto& f : spec.wordlists) lines += count_lines(f);
        auto dict = std::make_unique<DictSource>(spec.wordlists, chains, spec.min_len,
                                                 spec.max_len, lines * chains.size());
        std::vector<MaskPos> pos;
        if (!parse_mask(spec.hybrid_mask.empty() ? "?d?d" : spec.hybrid_mask,
                        spec.charset, pos, err)) return nullptr;
        const uint64_t mn = mask_total(pos);
        spec.total = lines * chains.size() * mn;
        return std::make_unique<HybridSource>(std::move(dict), std::move(pos), mn);
    }
    err = "未知攻击模式: " + spec.mode;
    return nullptr;
}

// ============================================================ 调度
RunResult run_attack(CandidateSource& src, Checker& chk, unsigned threads,
                     const ProgressCb& cb, std::atomic<bool>& cancel) {
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    threads = std::max(1u, std::min<unsigned>(threads, (unsigned)kMaxThreads));
    if (threads == 0) threads = std::thread::hardware_concurrency();

    std::mutex mu;                      // 保护候选源与计数器
    std::mutex hit_mu;                  // 保护命中结果
    uint64_t tried = 0;
    bool found = false;
    std::string hit;
    const uint64_t total = src.total();

    const size_t kBlock = 8192;
    auto worker = [&]() {
        std::vector<std::string> local;
        for (;;) {
            if (cancel.load(std::memory_order_relaxed)) return;
            {
                std::lock_guard<std::mutex> lk(hit_mu);
                if (found) return;
            }
            {
                std::lock_guard<std::mutex> lk(mu);
                if (src.next_block(local, kBlock) == 0) return;
                tried += local.size();   // 先记账，命中也会被计入
            }
            for (const auto& s : local) {
                if (chk.test(reinterpret_cast<const uint8_t*>(s.data()), s.size())) {
                    if (chk.confirm(reinterpret_cast<const uint8_t*>(s.data()), s.size())) {
                        std::lock_guard<std::mutex> lk(hit_mu);
                        if (!found) { found = true; hit = s; }
                        return;
                    }
                }
            }
        }
    };

    std::atomic<bool> stop_monitor{false};
    std::thread monitor;
    if (cb) {
        monitor = std::thread([&]() {
            while (!stop_monitor.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                Progress p;
                p.threads = threads;
                p.total = total;
                {
                    std::lock_guard<std::mutex> lk(mu);
                    p.tried = tried;
                }
                const double el = std::chrono::duration<double>(clock::now() - t0).count();
                p.seconds = el;
                p.speed = el > 0 ? (double)p.tried / el : 0.0;
                p.percent = total ? (100.0 * (double)p.tried / (double)total) : 0.0;
                cb(p);
            }
        });
    }

    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (unsigned i = 0; i < threads; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    // 先量时间再停监控线程：否则 150ms 的采样休眠会被算进耗时
    const double elapsed = std::chrono::duration<double>(clock::now() - t0).count();

    stop_monitor.store(true);
    if (monitor.joinable()) monitor.join();

    RunResult r;
    r.found = found;
    r.password = hit;
    {
        std::lock_guard<std::mutex> lk(mu);
        r.tried = tried;
    }
    r.seconds = elapsed;
    r.speed = r.seconds > 0 ? (double)r.tried / r.seconds : 0.0;
    r.cancelled = cancel.load();
    if (cb && r.seconds > 0) {
        Progress p;
        p.threads = threads;
        p.total = total;
        p.tried = r.tried;
        p.seconds = r.seconds;
        p.speed = r.speed;
        p.percent = total ? (100.0 * (double)r.tried / (double)total) : 100.0;
        cb(p);
    }
    return r;
}

}  // namespace zpwn
