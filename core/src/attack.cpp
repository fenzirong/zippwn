// ============================================================================
//  漏洞攻击 / 已知明文模块
//
//  这里必须把话说清楚，避免给出假的攻击力：
//
//  [真实可行的结构弱点]
//   1. ZipCrypto 的 12 字节加密头只有 1 字节有效校验 -> 单条目误报 1/256。
//      把它做成多条目漏斗后，误报降到 1/2^(8n)，因此**只解 12 字节**即可，
//      不必解密全量数据、不必 inflate。这是本引擎快筛的理论依据。
//   2. WinZip AES 的明文口令校验值只有 2 字节 -> 误报 1/65536，
//      命中后再付一次 HMAC-SHA1 全量代价即可 100% 确认。
//   3. 已知明文对（K = P XOR C）是 ZipCrypto 的**密钥恢复**入口：
//      拿到足够长的明文对后，Biham-Kocher 攻击可以把密钥空间从 2^96 压到 2^38，
//      这是 zip 传统加密唯一的致命弱点。
//
//  [不存在结构弱点的]
//   7z(AES-256 + SHA-256 KDF 2^19 轮)、RAR5(AES-256 + PBKDF2-SHA256)、
//   WinZip AES 本体 —— 都只能靠 KDF 成本 + GPU 硬算，没有取巧路径。
//   本模块不会假装能"绕过"它们。
// ============================================================================
#include <algorithm>
#include <cstdio>
#include <sstream>
#include <string>

#include "zpwn.hpp"

namespace zpwn {

KpaResult extract_keystream(const Archive& ar, const PlainPair& pair) {
    KpaResult r;
    r.entry = pair.entry;

    const Entry* target = nullptr;
    for (const auto& e : ar.entries) {
        if (e.name != pair.entry) continue;
        if (e.enc == EncKind::ZipCrypto) { target = &e; break; }
        if (!target) target = &e;    // 先记住同名条目，下面统一判错
    }

    if (!target) { r.note = "找不到条目: " + pair.entry; return r; }
    if (target->enc != EncKind::ZipCrypto) {
        r.note = "该条目不是 ZipCrypto 加密，已知明文对密钥流无意义";
        return r;
    }

    const uint64_t ct_off = target->data_offset + 12 + pair.offset;
    const size_t n = pair.data.size();
    const uint8_t* ct = ar.at(ct_off, n);
    if (!ct) {
        r.note = "明文对越界：条目密文长度不足";
        return r;
    }

    r.keystream.resize(n);
    for (size_t i = 0; i < n; ++i) r.keystream[i] = (uint8_t)(pair.data[i] ^ ct[i]);
    r.plain_len = n;
    r.ok = n >= 12;
    if (!r.ok) r.note = "明文对不足 12 字节，无法支撑密钥恢复";
    else r.note = "已提取 " + std::to_string(n) + " 字节密钥流";
    return r;
}

std::string attack_surface_report(const Archive& ar, const std::vector<PlainPair>& pairs) {
    std::ostringstream o;
    const auto encs = ar.encrypted();

    o << "===== ZipPwn 攻击面评估 =====\n";
    o << "文件      : " << ar.path << "\n";
    o << "容器      : " << ar.format_desc() << "\n";
    o << "条目总数  : " << ar.entries.size() << "（加密 " << encs.size() << "）\n";

    // ---- 信息泄露 ----
    if (!ar.entries.empty()) {
        o << "\n[信息泄露]\n";
        o << "  文件名/大小/CRC 未加密，可直接读取 —— 这是定向字典的原料。\n";
        size_t shown = 0;
        for (const Entry* e : encs) {
            if (shown++ >= 8) { o << "  ...\n"; break; }
            char b[256];
            std::snprintf(b, sizeof b, "  %-40s 明文 %8llu 字节  crc=%08x\n",
                          e->name.c_str(), (unsigned long long)e->usize, e->crc);
            o << b;
        }
    }

    // ---- 按加密方案给路线 ----
    bool has_zc = false, has_aes = false;
    for (const Entry* e : encs) {
        if (e->enc == EncKind::ZipCrypto) has_zc = true;
        if (e->enc == EncKind::WinZipAes) has_aes = true;
    }

    o << "\n[路线评估]\n";
    if (has_zc) {
        const size_t n = std::min<size_t>(encs.size(), 3);
        const unsigned long long fp = 1ull << (8 * n);
        o << "  ZipCrypto:\n";
        o << "    * 结构弱点: 12 字节加密头仅 1 字节有效校验\n";
        o << "    * 多条目交叉校验: 误报率 1/" << fp << "\n";
        o << "    * 推荐: 本内核 CPU 多线程字典/掩码（每线程 ~1e7 候选/秒量级）\n";
        o << "    * 可选: hashcat -m 17210/17220/17225 走 GPU\n";
        if (!pairs.empty()) {
            o << "    * 已知明文素材 " << pairs.size() << " 组，最优一组: "
              << pairs.front().label << " (" << pairs.front().data.size() << " 字节)\n";
            o << "    * 致命路线: Biham-Kocher 密钥恢复（绕过口令，直接还原密钥）\n";
            o << "        命令: bkcrack -C \"" << ar.path << "\" -c \""
              << pairs.front().entry << "\" -p plain.bin -o " << pairs.front().offset << "\n";
            o << "        再用: bkcrack -C \"" << ar.path << "\" -k keys -U out.zip recovered\n";
        } else {
            o << "    * 未找到已知明文素材：无法走密钥恢复，只能口令穷举\n";
            o << "      （提示：若压缩包里有 stored 的 png/pdf/jpg 条目，或存在未加密孪生副本，\n";
            o << "        重新采集即可获得明文对）\n";
        }
    }
    if (has_aes) {
        o << "  WinZip AES:\n";
        o << "    * 结构弱点: 仅 2 字节 pv（1/65536），可做快筛\n";
        o << "    * 本体无结构弱点: PBKDF2-HMAC-SHA1 1000 轮 + AES-256-CTR + HMAC-SHA1\n";
        o << "    * 必须 GPU: hashcat -m 13600（本内核 CPU 仅用于小字典验证）\n";
    }
    if (ar.format == "rar5" || ar.format == "rar4" || ar.format == "7z") {
        o << "  " << ar.format_desc() << ":\n";
        o << "    * 无结构弱点：AES-256 + 高强度 KDF（RAR5 PBKDF2-SHA256 2^15、7z SHA-256 2^19）\n";
        o << "    * 必须 GPU: hashcat -m 13000 (RAR5) / -m 12500 (RAR3) / -m 11600 (7z)\n";
        o << "    * 本内核不解析其加密体，需 7z2hashcat / rar2john 导出 hash\n";
    }

    o << "\n[成本提示]\n";
    o << "  口令空间 = 字符集^长度 × 规则数。8 位小写+数字 ≈ 2.8e12，\n";
    o << "  按 CPU 2e8 候选/秒 ≈ 3.9 小时；GPU 通常快 50-200 倍。\n";
    return o.str();
}

}  // namespace zpwn
