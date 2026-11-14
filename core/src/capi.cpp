// ============================================================================
//  C ABI 导出层（给 GUI / 其它语言用）
//
//  Python 侧用 ctypes 直接加载 zippwn.dll：
//    lib = ctypes.CDLL("zippwn.dll")
//    lib.zpwn_crack(path, cfg, buf, 256, cb, None, ct.byref(flag))
//
//  cfg 是扁平的 "k=v;k=v" 串，不引入 JSON 解析依赖：
//    mode=dict;dicts=a.txt,b.txt;rules=best64lite;threads=16;min=0;max=0
//    mode=mask;mask=?l?l?l?d?d;threads=16
//    mode=hybrid;dicts=a.txt;hybrid=?d?d
// ============================================================================
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "zpwn.hpp"

#ifdef _WIN32
#define ZPWN_API extern "C" __declspec(dllexport)
#else
#define ZPWN_API extern "C"
#endif

namespace {

std::string cfg_get(const std::string& cfg, const char* key) {
    const std::string k = std::string(key) + "=";
    size_t start = 0;
    while (start <= cfg.size()) {
        const size_t end = cfg.find(';', start);
        const std::string item = cfg.substr(start, end == std::string::npos
                                                       ? std::string::npos
                                                       : end - start);
        if (item.rfind(k, 0) == 0) return item.substr(k.size());
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> v;
    std::string cur;
    for (char c : s) {
        if (c == ',') { if (!cur.empty()) v.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!cur.empty()) v.push_back(cur);
    return v;
}

void json_escape(const std::string& in, std::string& out) {
    out.clear();          // 复用同一个 buffer 时必须先清空，否则会拼接出坏 JSON
    out.push_back('"');
    for (unsigned char c : in) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    out += b;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    out.push_back('"');
}

int copy_out(const std::string& s, char* buf, size_t cap) {
    if (!buf || cap == 0) return (int)s.size();
    const size_t n = std::min(cap - 1, s.size());
    std::memcpy(buf, s.data(), n);
    buf[n] = '\0';
    return (int)s.size();
}

zpwn::AttackSpec spec_from_cfg(const std::string& cfg) {
    zpwn::AttackSpec sp;
    sp.mode = cfg_get(cfg, "mode");
    if (sp.mode.empty()) sp.mode = "dict";
    sp.wordlists = split_csv(cfg_get(cfg, "dicts"));
    sp.rules = split_csv(cfg_get(cfg, "rules"));
    sp.mask = cfg_get(cfg, "mask");
    sp.hybrid_mask = cfg_get(cfg, "hybrid");
    for (int i = 0; i < 4; ++i) {
        const std::string key = "cs" + std::to_string(i + 1);
        sp.charset[i] = cfg_get(cfg, key.c_str());
    }
    const std::string mn = cfg_get(cfg, "min"), mx = cfg_get(cfg, "max");
    if (!mn.empty()) sp.min_len = std::atoi(mn.c_str());
    if (!mx.empty()) sp.max_len = std::atoi(mx.c_str());
    return sp;
}

}  // namespace

ZPWN_API const char* zpwn_version() { return zpwn::kVersion; }

ZPWN_API int zpwn_selftest(char* buf, size_t cap) {
    std::string rep;
    const int fails = zpwn::crypto_self_test(rep);
    return copy_out(rep, buf, cap) + fails * 1000000;
}

// 返回 JSON：容器与条目信息
ZPWN_API int zpwn_info(const char* path, char* buf, size_t cap) {
    zpwn::Archive ar;
    std::string err;
    if (!path || !zpwn::parse_archive(path, ar, err))
        return copy_out("{\"ok\":false,\"error\":\"parse failed\"}", buf, cap);

    std::ostringstream o;
    o << "{\"ok\":true,\"path\":";
    std::string esc;
    json_escape(ar.path, esc);
    o << esc;
    o << ",\"format\":\"" << ar.format << "\",\"format_desc\":";
    json_escape(ar.format_desc(), esc);
    o << esc;
    o << ",\"entries\":" << ar.entries.size();
    o << ",\"encrypted\":" << ar.encrypted().size();
    o << ",\"native_cpu\":" << ((ar.format == "zip") ? "true" : "false");

    o << ",\"files\":[";
    bool first = true;
    for (const auto& e : ar.entries) {
        if (e.is_dir) continue;
        if (!first) o << ",";
        first = false;
        o << "{\"name\":";
        json_escape(e.name, esc);
        o << esc << ",\"usize\":" << e.usize << ",\"csize\":" << e.csize
          << ",\"enc\":\"" << (e.enc == zpwn::EncKind::ZipCrypto ? "zipcrypto"
                                : e.enc == zpwn::EncKind::WinZipAes ? "winzip-aes" : "none")
          << "\",\"enc_desc\":";
        json_escape(e.enc_desc(), esc);
        o << esc << ",\"method\":" << (e.aes_strength ? e.real_method : e.method)
          << ",\"key_len\":" << e.key_len() << "}";
    }
    o << "],\"errors\":[";
    first = true;
    for (const auto& s : ar.errors) {
        if (!first) o << ",";
        first = false;
        json_escape(s, esc);
        o << esc;
    }
    o << "]}";
    return copy_out(o.str(), buf, cap);
}

ZPWN_API int zpwn_report(const char* path, char* buf, size_t cap) {
    zpwn::Archive ar;
    std::string err;
    if (!path || !zpwn::parse_archive(path, ar, err))
        return copy_out("解析失败", buf, cap);
    const auto pairs = zpwn::harvest_plaintext(ar);
    return copy_out(zpwn::attack_surface_report(ar, pairs), buf, cap);
}

ZPWN_API int zpwn_pairs(const char* path, char* buf, size_t cap) {
    zpwn::Archive ar;
    std::string err;
    if (!path || !zpwn::parse_archive(path, ar, err))
        return copy_out("[]", buf, cap);
    const auto pairs = zpwn::harvest_plaintext(ar);
    std::ostringstream o;
    o << "[";
    bool first = true;
    std::string esc;
    for (const auto& p : pairs) {
        if (!first) o << ",";
        first = false;
        o << "{\"label\":";
        json_escape(p.label, esc);
        o << esc << ",\"entry\":";
        json_escape(p.entry, esc);
        o << esc << ",\"offset\":" << p.offset << ",\"len\":" << p.data.size()
          << ",\"confidence\":" << p.confidence << "}";
    }
    o << "]";
    return copy_out(o.str(), buf, cap);
}

typedef void (*zpwn_progress_fn)(unsigned long long tried, unsigned long long total,
                                 double speed, void* user);

ZPWN_API int zpwn_crack(const char* path, const char* cfg, char* out, size_t cap,
                        zpwn_progress_fn cb, void* user, int* cancel_flag) {
    zpwn::Archive ar;
    std::string err;
    if (!path || !zpwn::parse_archive(path, ar, err)) return copy_out("解析失败", out, cap);

    std::string cerr;
    auto checker = zpwn::make_checker(ar, cerr);
    if (!checker) return copy_out(cerr, out, cap);

    zpwn::AttackSpec sp = spec_from_cfg(cfg ? cfg : "");
    std::string serr;
    auto src = zpwn::make_source(sp, serr);
    if (!src) return copy_out(serr, out, cap);

    const std::string ts = cfg_get(cfg ? cfg : "", "threads");
    unsigned threads = ts.empty() ? std::thread::hardware_concurrency()
                                  : (unsigned)std::atoi(ts.c_str());

    std::atomic<bool> cancel{false};
    zpwn::ProgressCb pcb;
    if (cb) {
        pcb = [&](const zpwn::Progress& p) {
            cb(p.tried, p.total, p.speed, user);
            if (cancel_flag && *cancel_flag) cancel.store(true);
        };
    }

    const auto r = zpwn::run_attack(*src, *checker, threads, pcb, cancel);
    if (r.found) return copy_out(r.password, out, cap);
    return 0;
}

ZPWN_API void zpwn_set_hashcat_path(const char* path) {
    zpwn::set_hashcat_path(path ? std::string(path) : std::string());
}

ZPWN_API int zpwn_gpu_info(char* buf, size_t cap) {
    const auto g = zpwn::probe_hashcat();
    std::ostringstream o;
    o << "{\"available\":" << (g.available ? "true" : "false") << ",\"exe\":";
    std::string esc;
    json_escape(g.exe, esc);
    o << esc << ",\"version\":";
    json_escape(g.version, esc);
    o << esc << ",\"note\":";
    json_escape(g.note, esc);
    o << esc << ",\"devices\":[";
    bool first = true;
    for (const auto& d : g.devices) {
        if (!first) o << ",";
        first = false;
        json_escape(d, esc);
        o << esc;
    }
    o << "]}";
    return copy_out(o.str(), buf, cap);
}

ZPWN_API int zpwn_gpu_crack(const char* path, const char* cfg, char* out, size_t cap) {
    zpwn::Archive ar;
    std::string err;
    if (!path || !zpwn::parse_archive(path, ar, err)) return copy_out("解析失败", out, cap);

    const auto g = zpwn::probe_hashcat();
    if (!g.available) return copy_out("未找到 hashcat", out, cap);

    zpwn::AttackSpec sp = spec_from_cfg(cfg ? cfg : "");
    std::atomic<bool> cancel{false};
    const auto r = zpwn::run_hashcat(ar, sp, g.exe, nullptr, cancel);
    if (r.found) return copy_out(r.password, out, cap);
    return copy_out(r.log, out, cap);
}

ZPWN_API int zpwn_export_hash(const char* path, char* out, size_t cap) {
    zpwn::Archive ar;
    std::string err;
    if (!path || !zpwn::parse_archive(path, ar, err)) return copy_out("解析失败", out, cap);
    std::string mode, herr;
    const std::string h = zpwn::export_hash(ar, &mode, &herr);
    if (h.empty()) return copy_out(herr, out, cap);
    return copy_out(h, out, cap);
}
