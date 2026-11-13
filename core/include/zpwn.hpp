// ============================================================================
//  ZipPwn 内核公共接口（C++20，零外部依赖，仅 Windows SDK）
//
//  设计参考:
//    * PKWARE APPNOTE 6.3.x        —— ZIP 容器与 ZipCrypto 传统加密
//    * WinZip AES 规范 (AE-1/2/3)  —— PBKDF2-HMAC-SHA1 + AES-CTR + HMAC-SHA1
//    * Biham & Kocher, "A Known Plaintext Attack on the PKZIP Stream Cipher"
//    * bkcrack / pkcrack           —— 已知明文密钥恢复的项目形态
//    * hashcat                     —— GPU 内核后端（-m 172xx / 13600）
// ============================================================================
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace zpwn {

inline constexpr const char* kVersion = "0.4.0";
inline constexpr int kMaxThreads = 256;

// ============================================================ crypto
extern uint32_t CRC_TABLE[256];   // 进程启动时由 CrcInit 填充
uint32_t crc32_calc(const void* data, size_t n, uint32_t crc = 0);

struct Sha1Ctx {
    uint32_t h[5]{};
    uint64_t total = 0;
    uint8_t buf[64]{};
    size_t fill = 0;
    void init();
    void update(const void* data, size_t n);
    void final(uint8_t out[20]);
};

void sha1(const void* data, size_t n, uint8_t out[20]);
void hmac_sha1(const uint8_t* key, size_t keylen, const uint8_t* msg, size_t msglen,
               uint8_t out[20]);
void pbkdf2_hmac_sha1(const uint8_t* pw, size_t pwlen, const uint8_t* salt,
                      size_t saltlen, uint32_t iters, uint8_t* out, size_t outlen);

struct AesKey {
    uint8_t rk[240]{};   // 15 轮 × 16 字节
    int rounds = 0;
};
void aes_set_encrypt_key(AesKey& k, const uint8_t* key, int keylen);
void aes_encrypt_block(const AesKey& k, const uint8_t in[16], uint8_t out[16]);

// WinZip AES 的 CTR：密钥流 = AES_Enc(key, 小端 128 位计数器)，计数器从 1 起
void aes_ctr_winzip(const uint8_t* key, int keylen, uint8_t* data, size_t n,
                    uint64_t ctr0 = 1);

// 自测：FIPS-197 / RFC 3174 / RFC 6070 官方向量；返回失败项数
int crypto_self_test(std::string& report);

// ============================================================ ZIP 结构
enum class EncKind { None, ZipCrypto, WinZipAes };

struct Entry {
    std::string name;
    uint16_t flags = 0;
    uint16_t method = 0;
    uint32_t crc = 0;
    uint64_t csize = 0;
    uint64_t usize = 0;
    uint64_t lho = 0;
    uint16_t dostime = 0;
    int aes_strength = 0;     // 0=none 1=AE-1(128) 2=AE-2(192) 3=AE-3(256)
    int aes_version = 0;
    uint16_t real_method = 0;
    uint64_t data_offset = 0;
    EncKind enc = EncKind::None;
    int check_byte = -1;
    uint8_t enc_header[12]{};
    std::vector<uint8_t> salt, pv, ct_head, auth_code;
    uint64_t body_len = 0;
    bool is_dir = false;

    int key_len() const;
    int salt_len() const;
    std::string enc_desc() const;
};

struct Archive {
    std::string path;
    std::string format = "unknown";
    std::vector<Entry> entries;
    std::vector<uint8_t> raw;
    std::vector<std::string> errors;

    std::vector<const Entry*> encrypted() const;
    const uint8_t* at(uint64_t off, size_t n) const;
    std::string format_desc() const;
};

bool parse_archive(const std::string& path, Archive& out, std::string& err);

struct PlainPair {
    std::string label;
    std::string entry;
    uint64_t offset = 0;
    std::vector<uint8_t> data;
    double confidence = 0.0;
};
std::vector<PlainPair> harvest_plaintext(const Archive& ar);

// ============================================================ 校验器
class Checker {
public:
    virtual ~Checker() = default;
    // 快筛：返回 true 表示“可能是口令”（ZipCrypto 误报率 1/256^n）
    virtual bool test(const uint8_t* pw, size_t len) = 0;
    // 严格确认；默认等同快筛
    virtual bool confirm(const uint8_t* pw, size_t len) { return test(pw, len); }
    virtual const char* kind() const = 0;
    virtual std::string detail() const { return {}; }
};

std::unique_ptr<Checker> make_checker(const Archive& ar, std::string& err);

// ============================================================ 候选生成
struct AttackSpec {
    std::string mode = "dict";   // dict | mask | hybrid
    std::vector<std::string> wordlists;
    std::vector<std::string> rules;
    std::string mask;            // ?l?u?d?s?a + 自定义 ?1..?4
    std::string hybrid_mask;     // dict 打头 + 后缀掩码
    std::string charset[4];      // ?1..?4
    int min_len = 0;
    int max_len = 0;
    uint64_t total = 0;
};

uint64_t estimate_total(AttackSpec& spec);

class CandidateSource {
public:
    virtual ~CandidateSource() = default;
    virtual bool next(std::string& out) = 0;
    virtual uint64_t total() const { return 0; }
    virtual size_t next_block(std::vector<std::string>& out, size_t want);
};

std::unique_ptr<CandidateSource> make_source(AttackSpec& spec, std::string& err);

// ============================================================ 调度
struct Progress {
    uint64_t tried = 0;
    uint64_t total = 0;
    double speed = 0.0;      // 候选/秒
    unsigned threads = 0;
    double seconds = 0.0;
    double percent = 0.0;
};
using ProgressCb = std::function<void(const Progress&)>;

struct RunResult {
    bool found = false;
    std::string password;
    uint64_t tried = 0;
    double seconds = 0.0;
    bool cancelled = false;
    double speed = 0.0;
};

RunResult run_attack(CandidateSource& src, Checker& chk, unsigned threads,
                     const ProgressCb& cb, std::atomic<bool>& cancel);

// ============================================================ 漏洞攻击 / 已知明文
struct KpaResult {
    bool ok = false;
    std::string note;
    std::vector<uint8_t> keystream;
    size_t plain_len = 0;
    std::string entry;
};

// 用已知明文对（明文 P 与密文 C 的对应区间）提取 ZipCrypto 密钥流 K = P ^ C
KpaResult extract_keystream(const Archive& ar, const PlainPair& pair);

// 结构性弱点与可行攻击路线评估（信息泄露 / 误报率 / 预期成本）
std::string attack_surface_report(const Archive& ar, const std::vector<PlainPair>& pairs);

// ============================================================ GPU 后端
struct GpuInfo {
    bool available = false;
    std::string exe;
    std::string version;
    std::string note;
    std::vector<std::string> devices;
};
GpuInfo probe_hashcat(const std::string& hint = "");

struct GpuRun {
    bool found = false;
    std::string password;
    std::string log;
    std::string mode;
};
GpuRun run_hashcat(const Archive& ar, AttackSpec& spec, const std::string& exe,
                   const ProgressCb& cb, std::atomic<bool>& cancel);

// 导出 hashcat 可识别的 hash 串；失败返回空
std::string export_hash(const Archive& ar, std::string* mode, std::string* err);

}  // namespace zpwn
