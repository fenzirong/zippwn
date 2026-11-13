// ============================================================================
//  ZipPwn 命令行入口
//
//  zippwn selftest                       密码学官方向量自测
//  zippwn info     <archive>             容器/条目/加密方案
//  zippwn report   <archive>             攻击面评估 + 已知明文素材
//  zippwn crack    <archive> [选项]      口令恢复（CPU 多线程）
//  zippwn gpuinfo                        探测 hashcat 与 GPU 设备
//  zippwn hash     <archive>             导出 hashcat 可用的 hash 串
//  zippwn gpucrack <archive> [选项]      GPU 字典攻击
//
//  crack 选项:
//    --mode dict|mask|hybrid   攻击模式
//    --dict a.txt,b.txt        字典（逗号分隔）
//    --rules best64lite,leet   规则集
//    --mask ?l?l?l?l?d?d       掩码
//    --hybrid ?d?d             混合模式后缀掩码
//    --threads N               线程数（默认 CPU 逻辑核数）
//    --min N --max N           口令长度过滤
//    --pot file               断点/命中记录（追加写入）
// ============================================================================
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "zpwn.hpp"

namespace {
std::atomic<bool> g_cancel{false};

void on_sigint(int) { g_cancel.store(true); }

void usage() {
    std::puts(
        "ZipPwn " "0.4.0" " —— 压缩包口令恢复 / 取证工作台\n"
        "\n"
        "用法:\n"
        "  zippwn selftest                     密码学官方向量自测\n"
        "  zippwn info     <archive>           容器 / 条目 / 加密方案\n"
        "  zippwn report   <archive>           攻击面评估 + 已知明文素材\n"
        "  zippwn crack    <archive> [选项]    口令恢复（CPU 多线程）\n"
        "  zippwn gpuinfo                      探测 hashcat 与 GPU 设备\n"
        "  zippwn hash     <archive>           导出 hashcat hash 串\n"
        "  zippwn gpucrack <archive> [选项]    GPU 字典攻击\n"
        "\n"
        "crack / gpucrack 选项:\n"
        "  --mode dict|mask|hybrid   --dict a.txt,b.txt   --rules best64lite,leet\n"
        "  --mask ?l?l?l?l?d?d       --hybrid ?d?d        --threads N\n"
        "  --min N --max N           --pot file.pot\n");
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> v;
    std::string cur;
    for (char c : s) {
        if (c == sep) { if (!cur.empty()) v.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!cur.empty()) v.push_back(cur);
    return v;
}

std::string fmt_num(double v) {
    char b[64];
    if (v >= 1e9) std::snprintf(b, sizeof b, "%.2f G", v / 1e9);
    else if (v >= 1e6) std::snprintf(b, sizeof b, "%.2f M", v / 1e6);
    else if (v >= 1e3) std::snprintf(b, sizeof b, "%.2f K", v / 1e3);
    else std::snprintf(b, sizeof b, "%.0f ", v);
    return b;
}

struct Opts {
    zpwn::AttackSpec spec;
    unsigned threads = 0;
    std::string pot;
};

bool parse_opts(int argc, char** argv, int from, Opts& o) {
    for (int i = from; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "缺少参数值: %s\n", name);
                return {};
            }
            return argv[++i];
        };
        if (a == "--mode") o.spec.mode = need("--mode");
        else if (a == "--dict") o.spec.wordlists = split(need("--dict"), ',');
        else if (a == "--rules") o.spec.rules = split(need("--rules"), ',');
        else if (a == "--mask") o.spec.mask = need("--mask");
        else if (a == "--hybrid") o.spec.hybrid_mask = need("--hybrid");
        else if (a == "--threads") o.threads = (unsigned)std::atoi(need("--threads").c_str());
        else if (a == "--min") o.spec.min_len = std::atoi(need("--min").c_str());
        else if (a == "--max") o.spec.max_len = std::atoi(need("--max").c_str());
        else if (a == "--pot") o.pot = need("--pot");
        else { std::fprintf(stderr, "未知选项: %s\n", a.c_str()); return false; }
    }
    if (o.threads == 0) o.threads = std::thread::hardware_concurrency();
    if (o.threads == 0) o.threads = 8;
    return true;
}

void print_progress(const zpwn::Progress& p) {
    std::printf("\r  ");
    if (p.total) {
        std::printf("%llu/%llu %6.2f%%", (unsigned long long)p.tried,
                    (unsigned long long)p.total, p.percent);
    } else {
        std::printf("%llu 候选", (unsigned long long)p.tried);
    }
    std::printf("   %s候选/秒   %.1fs   ", fmt_num(p.speed).c_str(), p.seconds);
    std::fflush(stdout);
}

void append_pot(const std::string& pot, const std::string& pw) {
    if (pot.empty()) return;
    if (FILE* f = std::fopen(pot.c_str(), "ab")) {
        std::fprintf(f, "%s\n", pw.c_str());
        std::fclose(f);
    }
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    std::signal(SIGINT, on_sigint);
    const std::string cmd = argv[1];

    // ---------------- selftest ----------------
    if (cmd == "selftest") {
        std::string rep;
        const int fails = zpwn::crypto_self_test(rep);
        std::fputs(rep.c_str(), stdout);
        std::printf("\n结果: %s（失败 %d 项）\n", fails ? "FAIL" : "PASS", fails);
        return fails ? 2 : 0;
    }

    if (cmd == "gpuinfo") {
        const auto g = zpwn::probe_hashcat();
        std::printf("hashcat 可用 : %s\n", g.available ? "是" : "否");
        if (g.available) {
            std::printf("路径         : %s\n", g.exe.c_str());
            std::printf("版本         : %s\n", g.version.c_str());
            for (size_t i = 0; i < g.devices.size(); ++i)
                std::printf("设备 #%zu      : %s\n", i + 1, g.devices[i].c_str());
        }
        if (!g.note.empty()) std::printf("备注         : %s\n", g.note.c_str());
        return 0;
    }

    if (argc < 3) { usage(); return 1; }
    const std::string path = argv[2];

    // ---------------- info ----------------
    if (cmd == "info") {
        zpwn::Archive ar;
        std::string err;
        if (!zpwn::parse_archive(path, ar, err)) {
            std::fprintf(stderr, "解析失败: %s\n", err.c_str());
            return 1;
        }
        std::printf("文件     : %s\n", ar.path.c_str());
        std::printf("容器     : %s\n", ar.format_desc().c_str());
        std::printf("条目     : %zu（加密 %zu）\n", ar.entries.size(), ar.encrypted().size());
        std::puts("");
        int shown = 0;
        for (const auto& e : ar.entries) {
            if (e.is_dir) continue;
            if (shown++ >= 60) { std::puts("  ..."); break; }
            std::printf("  %-44s %10llu B  %s\n", e.name.c_str(),
                        (unsigned long long)e.usize, e.enc_desc().c_str());
        }
        if (!ar.errors.empty()) {
            std::puts("\n警告:");
            for (const auto& s : ar.errors) std::printf("  - %s\n", s.c_str());
        }
        return 0;
    }

    // ---------------- report ----------------
    if (cmd == "report") {
        zpwn::Archive ar;
        std::string err;
        if (!zpwn::parse_archive(path, ar, err)) {
            std::fprintf(stderr, "解析失败: %s\n", err.c_str());
            return 1;
        }
        const auto pairs = zpwn::harvest_plaintext(ar);
        std::fputs(zpwn::attack_surface_report(ar, pairs).c_str(), stdout);
        if (!pairs.empty()) {
            std::puts("\n[已知明文素材]");
            for (const auto& p : pairs) {
                std::printf("  %.2f  %-46s %5zu 字节  %s\n", p.confidence, p.label.c_str(),
                            p.data.size(), p.entry.c_str());
                const auto k = zpwn::extract_keystream(ar, p);
                if (k.ok) std::printf("        密钥流前 8 字节: ");
                if (k.ok) {
                    for (int i = 0; i < 8 && i < (int)k.keystream.size(); ++i)
                        std::printf("%02x", k.keystream[i]);
                    std::printf("  （%s）\n", k.note.c_str());
                }
            }
        }
        return 0;
    }

    // ---------------- hash ----------------
    if (cmd == "hash") {
        zpwn::Archive ar;
        std::string err;
        if (!zpwn::parse_archive(path, ar, err)) {
            std::fprintf(stderr, "解析失败: %s\n", err.c_str());
            return 1;
        }
        std::string mode, herr;
        const std::string h = zpwn::export_hash(ar, &mode, &herr);
        if (h.empty()) {
            std::fprintf(stderr, "%s\n", herr.c_str());
            return 2;
        }
        std::printf("mode=%s\n%s\n", mode.c_str(), h.c_str());
        return 0;
    }

    // ---------------- crack ----------------
    if (cmd == "crack" || cmd == "gpucrack") {
        zpwn::Archive ar;
        std::string err;
        if (!zpwn::parse_archive(path, ar, err)) {
            std::fprintf(stderr, "解析失败: %s\n", err.c_str());
            return 1;
        }
        Opts o;
        if (!parse_opts(argc, argv, 3, o)) return 1;

        if (cmd == "gpucrack") {
            const auto g = zpwn::probe_hashcat();
            if (!g.available) {
                std::fprintf(stderr, "未找到 hashcat：%s\n", g.note.c_str());
                return 2;
            }
            std::printf("GPU 后端: %s\n", g.exe.c_str());
            const auto r = zpwn::run_hashcat(ar, o.spec, g.exe, print_progress, g_cancel);
            std::printf("\n%s\n", r.log.c_str());
            if (r.found) {
                std::printf("命中口令: %s\n", r.password.c_str());
                append_pot(o.pot, r.password);
                return 0;
            }
            return 3;
        }

        std::string cerr;
        auto checker = zpwn::make_checker(ar, cerr);
        if (!checker) {
            std::fprintf(stderr, "无法破解: %s\n", cerr.c_str());
            const auto pairs = zpwn::harvest_plaintext(ar);
            std::fputs(zpwn::attack_surface_report(ar, pairs).c_str(), stderr);
            return 2;
        }
        std::string serr;
        auto src = zpwn::make_source(o.spec, serr);
        if (!src) {
            std::fprintf(stderr, "候选生成失败: %s\n", serr.c_str());
            return 2;
        }

        std::printf("容器   : %s\n", ar.format_desc().c_str());
        std::printf("方案   : %s\n", checker->detail().c_str());
        std::printf("模式   : %s   线程: %u   候选总数: %llu\n", o.spec.mode.c_str(),
                    o.threads, (unsigned long long)o.spec.total);
        std::fflush(stdout);

        const auto r = zpwn::run_attack(*src, *checker, o.threads, print_progress, g_cancel);
        std::printf("\n");
        std::printf("已尝试 : %llu 个候选\n", (unsigned long long)r.tried);
        std::printf("耗时   : %.2f 秒（%.2f M候选/秒）\n", r.seconds, r.speed / 1e6);
        if (r.found) {
            std::printf("命中   : %s\n", r.password.c_str());
            append_pot(o.pot, r.password);
            return 0;
        }
        std::printf("结果   : 未命中%s\n", r.cancelled ? "（已中断）" : "");
        return r.cancelled ? 130 : 3;
    }

    usage();
    return 1;
}
