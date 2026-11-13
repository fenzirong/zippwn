// ============================================================================
//  密码学原语：CRC32 / SHA-1 / HMAC-SHA1 / PBKDF2-HMAC-SHA1 / AES(仅加密)
//
//  AES 只需要加密方向：WinZip AES 用 CTR 模式，解密 = 明文 XOR AES_Enc(ctr)，
//  因此不需要 InvSubBytes / InvMixColumns，代码量与出错面减半。
//
//  所有实现都带官方向量自测（crypto_self_test），构建后必须全绿再谈性能。
// ============================================================================
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <string>

#include "zpwn.hpp"

namespace zpwn {

// ---------------------------------------------------------------- CRC32
uint32_t CRC_TABLE[256];
static bool g_crc_ready = false;

static void build_crc() {
    if (g_crc_ready) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        CRC_TABLE[i] = c;
    }
    g_crc_ready = true;
}

struct CrcInit {
    CrcInit() { build_crc(); }
};
static CrcInit g_crc_init;

uint32_t crc32_calc(const void* data, size_t n, uint32_t crc) {
    build_crc();
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t c = crc ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = CRC_TABLE[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------- SHA-1
static inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_block(uint32_t h[5], const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    }
    for (int i = 16; i < 80; ++i)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
        uint32_t tmp = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void Sha1Ctx::init() {
    h[0] = 0x67452301u; h[1] = 0xEFCDAB89u; h[2] = 0x98BADCFEu;
    h[3] = 0x10325476u; h[4] = 0xC3D2E1F0u;
    total = 0;
    fill = 0;
}

void Sha1Ctx::update(const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    total += n;
    while (n > 0) {
        size_t take = std::min<size_t>(64 - fill, n);
        std::memcpy(buf + fill, p, take);
        fill += take;
        p += take;
        n -= take;
        if (fill == 64) {
            sha1_block(h, buf);
            fill = 0;
        }
    }
}

void Sha1Ctx::final(uint8_t out[20]) {
    uint64_t bits = total * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (fill != 56) update(&zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    update(len, 8);
    for (int i = 0; i < 5; ++i) {
        out[4 * i + 0] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(h[i]);
    }
}

void sha1(const void* data, size_t n, uint8_t out[20]) {
    Sha1Ctx c;
    c.init();
    c.update(data, n);
    c.final(out);
}

void hmac_sha1(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen,
               uint8_t out[20]) {
    uint8_t k[64] = {0};
    if (keylen > 64) sha1(key, keylen, k);
    else std::memcpy(k, key, keylen);

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5C);
    }
    uint8_t inner[20];
    Sha1Ctx c;
    c.init();
    c.update(ipad, 64);
    c.update(msg, msglen);
    c.final(inner);

    Sha1Ctx o;
    o.init();
    o.update(opad, 64);
    o.update(inner, 20);
    o.final(out);
}

// PBKDF2 走内联 HMAC：把 ipad/opad 的 SHA-1 压缩前状态算一次，避免每轮重复。
void pbkdf2_hmac_sha1(const uint8_t* pw, size_t pwlen, const uint8_t* salt,
                      size_t saltlen, uint32_t iters, uint8_t* out, size_t outlen) {
    if (iters == 0) iters = 1;

    uint8_t k[64] = {0};
    if (pwlen > 64) sha1(pw, pwlen, k);
    else std::memcpy(k, pw, pwlen);

    Sha1Ctx ipad_ctx, opad_ctx;
    ipad_ctx.init();
    opad_ctx.init();
    uint8_t pad64[64];
    for (int i = 0; i < 64; ++i) pad64[i] = (uint8_t)(k[i] ^ 0x36);
    ipad_ctx.update(pad64, 64);
    for (int i = 0; i < 64; ++i) pad64[i] = (uint8_t)(k[i] ^ 0x5C);
    opad_ctx.update(pad64, 64);

    const uint32_t blocks = (uint32_t)((outlen + 19) / 20);
    for (uint32_t b = 1; b <= blocks; ++b) {
        uint8_t u[20], t[20];
        uint8_t be[4] = {(uint8_t)(b >> 24), (uint8_t)(b >> 16),
                         (uint8_t)(b >> 8), (uint8_t)b};

        Sha1Ctx c = ipad_ctx;
        c.update(salt, saltlen);
        c.update(be, 4);
        c.final(u);
        {
            Sha1Ctx o = opad_ctx;
            o.update(u, 20);
            o.final(u);
        }
        std::memcpy(t, u, 20);

        for (uint32_t i = 1; i < iters; ++i) {
            Sha1Ctx ci = ipad_ctx;
            ci.update(u, 20);
            ci.final(u);
            Sha1Ctx co = opad_ctx;
            co.update(u, 20);
            co.final(u);
            for (int j = 0; j < 20; ++j) t[j] ^= u[j];
        }
        size_t off = (b - 1) * 20;
        size_t n = std::min<size_t>(20, outlen - off);
        std::memcpy(out + off, t, n);
    }
}

// ---------------------------------------------------------------- AES
static uint8_t g_sbox[256];
static uint8_t g_rsbox[256];
static bool g_aes_ready = false;

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static void build_aes() {
    if (g_aes_ready) return;
    uint8_t p = 1, q = 1;
    do {
        p = (uint8_t)(p ^ ((p << 1) & 0xFF) ^ ((p & 0x80) ? 0x1B : 0x00));
        q ^= (uint8_t)(q << 1);
        q ^= (uint8_t)(q << 2);
        q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        auto rotl = [](uint8_t x, int n) {
            return (uint8_t)((x << n) | (x >> (8 - n)));
        };
        g_sbox[p] = (uint8_t)(q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63);
    } while (p != 1);
    g_sbox[0] = 0x63;
    for (int i = 0; i < 256; ++i) g_rsbox[g_sbox[i]] = (uint8_t)i;
    g_aes_ready = true;
}

void aes_set_encrypt_key(AesKey& k, const uint8_t* key, int keylen) {
    build_aes();
    const int nk = keylen / 4;
    if (nk != 4 && nk != 6 && nk != 8) { k.rounds = 0; return; }
    k.rounds = nk + 6;
    const int total = 4 * (k.rounds + 1);

    std::memcpy(k.rk, key, (size_t)keylen);
    uint8_t rcon = 1;
    for (int i = nk; i < total; ++i) {
        uint8_t t[4];
        std::memcpy(t, k.rk + 4 * (i - 1), 4);
        if (i % nk == 0) {
            const uint8_t t0 = t[0];
            t[0] = (uint8_t)(g_sbox[t[1]] ^ rcon);
            t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]];
            t[3] = g_sbox[t0];
            rcon = xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (int j = 0; j < 4; ++j) t[j] = g_sbox[t[j]];
        }
        for (int j = 0; j < 4; ++j)
            k.rk[4 * i + j] = (uint8_t)(k.rk[4 * (i - nk) + j] ^ t[j]);
    }
}

void aes_encrypt_block(const AesKey& k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = (uint8_t)(in[i] ^ k.rk[i]);

    for (int r = 1; r <= k.rounds; ++r) {
        uint8_t t[16];
        for (int c = 0; c < 4; ++c)
            for (int row = 0; row < 4; ++row)
                t[4 * c + row] = g_sbox[s[4 * ((c + row) & 3) + row]];

        if (r != k.rounds) {
            for (int c = 0; c < 4; ++c) {
                const uint8_t a0 = t[4 * c], a1 = t[4 * c + 1];
                const uint8_t a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                s[4 * c + 0] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
                s[4 * c + 1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
                s[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
                s[4 * c + 3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
            }
        } else {
            std::memcpy(s, t, 16);
        }
        const uint8_t* rk = k.rk + 16 * r;
        for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
    }
    std::memcpy(out, s, 16);
}

void aes_ctr_winzip(const uint8_t* key, int keylen, uint8_t* data, size_t n,
                    uint64_t ctr0) {
    AesKey k;
    aes_set_encrypt_key(k, key, keylen);
    uint64_t ctr = ctr0;
    for (size_t off = 0; off < n; off += 16) {
        uint8_t block[16] = {0};
        for (int i = 0; i < 8; ++i) block[i] = (uint8_t)(ctr >> (8 * i));
        uint8_t ks[16];
        aes_encrypt_block(k, block, ks);
        const size_t take = std::min<size_t>(16, n - off);
        for (size_t i = 0; i < take; ++i) data[off + i] ^= ks[i];
        ++ctr;
    }
}

// ---------------------------------------------------------------- 自测
static std::string hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 15]; }
    return s;
}

int crypto_self_test(std::string& report) {
    int fails = 0;
    auto check = [&](const char* name, const std::string& got, const char* want) {
        const bool ok = (got == want);
        if (!ok) ++fails;
        report += std::string(ok ? "[ OK ] " : "[FAIL] ") + name;
        if (!ok) report += "  got=" + got + " want=" + want;
        report += "\n";
    };

    // CRC32
    char buf[32];
    std::snprintf(buf, sizeof buf, "%08x", crc32_calc("123456789", 9));
    check("CRC32(\"123456789\")", buf, "cbf43926");

    // SHA-1
    uint8_t d[20];
    sha1("abc", 3, d);
    check("SHA1(\"abc\")", hex(d, 20), "a9993e364706816aba3e25717850c26c9cd0d89d");
    sha1("", 0, d);
    check("SHA1(\"\")", hex(d, 20), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    // PBKDF2-HMAC-SHA1 (RFC 6070)
    uint8_t dk[25];
    pbkdf2_hmac_sha1((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, dk, 20);
    check("PBKDF2-SHA1 it=1", hex(dk, 20), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    pbkdf2_hmac_sha1((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 2, dk, 20);
    check("PBKDF2-SHA1 it=2", hex(dk, 20), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    pbkdf2_hmac_sha1((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 4096, dk, 20);
    check("PBKDF2-SHA1 it=4096", hex(dk, 20), "4b007901b765489abead49d926f721d065a429c1");

    // AES-128 (FIPS-197 C.1)
    {
        uint8_t key[16], pt[16], ct[16];
        for (int i = 0; i < 16; ++i) key[i] = (uint8_t)i;
        const uint8_t p[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        std::memcpy(pt, p, 16);
        AesKey k;
        aes_set_encrypt_key(k, key, 16);
        aes_encrypt_block(k, pt, ct);
        check("AES-128 FIPS-197", hex(ct, 16), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }
    // AES-256 (FIPS-197 C.3)
    {
        uint8_t key[32], ct[16];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        const uint8_t p[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t pt[16];
        std::memcpy(pt, p, 16);
        AesKey k;
        aes_set_encrypt_key(k, key, 32);
        aes_encrypt_block(k, pt, ct);
        check("AES-256 FIPS-197", hex(ct, 16), "8ea2b7ca516745bfeafc49904b496089");
    }
    return fails;
}

}  // namespace zpwn
