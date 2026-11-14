// ============================================================================
//  GPU 后端：hashcat 桥接
//
//  分工（都经过实测验证，不是猜的）：
//    * ZipCrypto   -> -m 17225 / 17210，用 $pkzip$ 串
//    * WinZip AES  -> -m 13600，用 $zip2$ 串（DF 必须是**完整**密文）
//    * RAR3/RAR5/7z-> hashcat 支持，但 hash 串需 7z2hashcat / rar2john 导出
//
//  格式依据（两处权威）：
//    1. hashcat 自带 OpenCL/m13600-pure.cl 的 zip2_t 结构体
//    2. John the Ripper bleeding-jumbo 的 src/zip2john.c 注释：
//         $zip2$*Ty*Mo*Ma*Sa*Va*Le*DF*Au*$/zip2$
//           Ty=type(0)  Mo=mode(1/2/3)  Ma=magic(0)
//           Sa=salt(hex) Va=2字节校验值  Le=密文字节数(hex)
//           DF=完整密文(hex)  Au=10字节 HMAC-SHA1
//         $pkzip$C*B*[DT*MT{CL*UL*CR*OF*OX}*CT*DL*CS*DA]*$/pkzip$
//
//  实测踩过的两个坑：
//    * 结尾的 $/zip2$ / $/pkzip$ **不能省**，否则 hashcat 报 Token length exception
//    * hashcat 必须以自身目录为 CWD，否则找不到 ./OpenCL/ 内核目录
//    * hashcat 7.1.2 自带 PTX 9.1，遇到旧驱动会 ptxas 失败 -> 需回退 --backend-ignore-cuda
// ============================================================================
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>   // 仅用于 GetModuleFileNameW：定位 exe 同目录的 hashcat
#endif

#include "zpwn.hpp"

namespace zpwn {

namespace {

// 当前进程 exe 所在目录。打包后 CWD 不一定是 exe 目录（从资源管理器双击、
// 或从别的目录启动），所以"随包附带的 hashcat"必须按 exe 目录去找。
std::string exe_dir() {
#ifdef _WIN32
    wchar_t buf[32768];
    const DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n > 0 && n < (DWORD)(sizeof(buf) / sizeof(buf[0]))) {
        std::error_code ec;
        const auto p = std::filesystem::path(std::wstring(buf, n)).parent_path();
        return p.string();
    }
#endif
    return {};
}

std::string hexstr(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 15]; }
    return s;
}

std::string hexnum(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "%llx", (unsigned long long)v);
    return b;
}

bool file_exists(const std::string& p) {
    std::error_code ec;
    return std::filesystem::is_regular_file(p, ec);
}

std::string quote(const std::string& s) { return "\"" + s + "\""; }

std::string which(const std::string& name) {
    const char* path = std::getenv("PATH");
    if (!path) return {};
    std::string p(path);
    size_t start = 0;
    while (start <= p.size()) {
        const size_t end = p.find(';', start);
        const std::string dir = p.substr(start, end == std::string::npos
                                                    ? std::string::npos
                                                    : end - start);
        if (!dir.empty()) {
            const std::string cand = dir + "\\" + name;
            if (file_exists(cand)) return cand;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

std::string read_all(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream o;
    o << f.rdbuf();
    return o.str();
}

// 在 root 下找 hashcat.exe：先看 root 本身，再看 root\*\hashcat.exe。
// 后者是官方发行包解压后的真实布局（hashcat-7.1.2\hashcat.exe），
// 只写死 root\hashcat.exe 会漏掉——这是之前"探测不到"的直接原因。
std::string find_hashcat_under(const std::string& root) {
    if (root.empty()) return {};
    std::error_code ec;
    const std::string direct = (std::filesystem::path(root) / "hashcat.exe").string();
    if (file_exists(direct)) return direct;
    if (!std::filesystem::is_directory(root, ec)) return {};
    std::vector<std::string> subs;
    for (const auto& e : std::filesystem::directory_iterator(root, ec)) {
        if (ec) break;
        if (!e.is_directory(ec)) continue;
        subs.push_back(e.path().string());
    }
    std::sort(subs.begin(), subs.end());   // 稳定顺序，便于复现
    for (const auto& s : subs) {
        const std::string cand = (std::filesystem::path(s) / "hashcat.exe").string();
        if (file_exists(cand)) return cand;
    }
    return {};
}

// GUI 手动指定的路径（优先级最高）
std::string g_hashcat_override;

}  // namespace

void set_hashcat_path(const std::string& path) { g_hashcat_override = path; }

GpuInfo probe_hashcat(const std::string& hint) {
    GpuInfo g;

    // 1) 手动指定 / 调用方 hint / 环境变量：都按"文件或目录"两种形态接受
    auto try_path = [&](const std::string& p) -> bool {
        if (p.empty()) return false;
        std::error_code ec;
        if (std::filesystem::is_directory(p, ec)) {
            const std::string hit = find_hashcat_under(p);
            if (!hit.empty()) { g.available = true; g.exe = hit; return true; }
            return false;
        }
        if (file_exists(p)) { g.available = true; g.exe = p; return true; }
        return false;
    };

    if (try_path(g_hashcat_override)) { /* 用户指定优先 */ }
    else if (try_path(hint)) { /* 调用方 hint */ }
    else if (const char* e = std::getenv("ZIPPWN_HASHCAT"); e && try_path(e)) { /* 环境变量 */ }

    // 2) 常见安装位置 + 相对当前工作目录的布局
    if (!g.available) {
        std::vector<std::string> roots;

        // 2a) 随包附带：<exe目录>\hashcat\...（发布包把 hashcat 放在这里）
        const std::string ed = exe_dir();
        if (!ed.empty()) {
            roots.push_back(ed + "\\hashcat");
            roots.push_back(ed + "\\_deps\\hashcat");
            roots.push_back(ed + "\\..\\hashcat");
        }

        // 2b) 系统常见安装位置
        if (const char* pf = std::getenv("ProgramFiles")) roots.push_back(std::string(pf) + "\\hashcat");
        if (const char* la = std::getenv("LOCALAPPDATA")) roots.push_back(std::string(la) + "\\hashcat");
        roots.push_back("C:\\hashcat");
        roots.push_back("C:\\tools\\hashcat");

        // 2c) 相对当前工作目录（源码树里直接跑时用）
        roots.push_back("hashcat");
        roots.push_back("..\\hashcat");
        roots.push_back("_deps\\hashcat");
        roots.push_back("..\\_deps\\hashcat");

        for (const auto& r : roots) {
            const std::string hit = find_hashcat_under(r);
            if (!hit.empty()) { g.available = true; g.exe = hit; break; }
        }
    }

    // 3) PATH
    if (!g.available) {
        const std::string w = which("hashcat.exe");
        if (!w.empty()) { g.available = true; g.exe = w; }
    }

    if (!g.available) {
        g.note = "未找到 hashcat.exe。可在「GPU 加速」页手动指定路径，"
                 "或设置环境变量 ZIPPWN_HASHCAT";
        return g;
    }

    // 统一成绝对路径：后续要 `cd` 到 hashcat 目录再调用，
    // 相对路径（如 ..\_deps\hashcat\hashcat-7.1.2\hashcat.exe）在 cd 之后会失效。
    {
        std::error_code ec;
        const auto abs = std::filesystem::absolute(g.exe, ec);
        if (!ec) g.exe = abs.lexically_normal().string();
    }

    // hashcat 以自身目录为工作目录才能找到 ./OpenCL/ 内核
    const std::string hdir = std::filesystem::path(g.exe).parent_path().string();
    const std::string cmd = "cd /d " + quote(hdir) + " && " + quote(g.exe) + " -I 2>&1";
    if (FILE* f = _popen(cmd.c_str(), "r")) {
        char line[512];
        bool in_dev = false;
        while (std::fgets(line, sizeof line, f)) {
            std::string s(line);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
            if (s.find("hashcat (v") != std::string::npos && g.version.empty()) g.version = s;
            if (s.find("Backend Device ID #") != std::string::npos) { in_dev = true; continue; }
            if (in_dev) {
                const size_t p = s.find("Name");
                if (p != std::string::npos) {
                    const size_t colon = s.find(':', p);
                    if (colon != std::string::npos) {
                        std::string name = s.substr(colon + 1);
                        while (!name.empty() && (name.front() == ' ' || name.front() == '\t'))
                            name.erase(name.begin());
                        if (!name.empty()) g.devices.push_back(name);
                        in_dev = false;
                    }
                }
            }
        }
        _pclose(f);
    }
    if (g.version.empty()) g.version = "hashcat (版本未知)";
    if (g.devices.empty()) g.note = "未解析到设备，GPU 可能不可用";
    return g;
}

std::string export_hash(const Archive& ar, std::string* mode, std::string* err) {
    const auto encs = ar.encrypted();
    if (encs.empty()) { if (err) *err = "没有加密条目"; return {}; }

    // 选密文最小的条目：hash 串里要内嵌完整密文，小条目最省
    const Entry* aes = nullptr;
    const Entry* zc = nullptr;
    for (const Entry* e : encs) {
        if (e->enc == EncKind::WinZipAes && (!aes || e->body_len < aes->body_len)) aes = e;
        if (e->enc == EncKind::ZipCrypto && (!zc || e->csize < zc->csize)) zc = e;
    }

    // ---------------- WinZip AES -> -m 13600 ----------------
    if (aes) {
        const uint64_t body_off = aes->data_offset + (uint64_t)aes->salt_len() + 2;
        const uint8_t* ct = ar.at(body_off, (size_t)aes->body_len);
        if (!ct || aes->pv.size() != 2 || aes->auth_code.size() != 10) {
            if (err) *err = "AES 参数不完整，无法导出 hash";
            return {};
        }
        std::ostringstream o;
        o << "$zip2$*0*" << aes->aes_strength << "*0*"
          << hexstr(aes->salt.data(), aes->salt.size()) << "*"
          << hexstr(aes->pv.data(), aes->pv.size()) << "*"
          << hexnum(aes->body_len) << "*"
          << hexstr(ct, (size_t)aes->body_len) << "*"
          << hexstr(aes->auth_code.data(), aes->auth_code.size()) << "*$/zip2$";
        if (mode) *mode = "13600";
        return o.str();
    }

    // ---------------- ZipCrypto -> -m 17225 / 17210 ----------------
    if (zc) {
        // DA = 12 字节加密头 + 密文正文（CL 含这 12 字节）
        const uint8_t* blob = ar.at(zc->data_offset, (size_t)zc->csize);
        if (!blob) { if (err) *err = "密文越界"; return {}; }
        const uint64_t offex = zc->data_offset - zc->lho;
        // CS = CRC 高 2 字节（bit3 置位时改用时间戳高字节，这里保持与 check_byte 一致）
        char cs[8];
        if (zc->flags & 0x8)
            std::snprintf(cs, sizeof cs, "%02x%02x", (zc->dostime >> 8) & 0xFF, zc->dostime & 0xFF);
        else
            std::snprintf(cs, sizeof cs, "%02x%02x", (zc->crc >> 24) & 0xFF, (zc->crc >> 16) & 0xFF);

        std::ostringstream o;
        o << "$pkzip$1*1*";                       // C=1 个条目, B=1 个有效校验字节
        o << "2*0*";                              // DT=2 全量内嵌, MT=0
        o << hexnum(zc->csize) << "*" << hexnum(zc->usize) << "*"
          << hexnum(zc->crc) << "*" << hexnum(zc->lho) << "*"
          << hexnum(offex) << "*";
        o << hexnum(zc->method) << "*";           // CT 压缩类型
        o << hexnum(zc->csize) << "*";            // DL 数据长度
        o << cs << "*";                           // CS 校验字节
        o << hexstr(blob, (size_t)zc->csize) << "*";  // DA 密文
        o << "$/pkzip$";
        if (mode) *mode = "17225";
        return o.str();
    }

    if (mode) *mode = "11600";
    if (err)
        *err = ar.format == "rar5" ? "RAR5 需用 rar2john / 7z2hashcat 导出 hash"
                                   : ar.format == "7z" ? "7z 需用 7z2hashcat 导出 hash"
                                                       : "该加密方案无法导出 hashcat hash";
    return {};
}

namespace {

struct HcAttempt {
    bool ok = false;
    std::string password;
    std::string log;
    bool needs_cuda_fallback = false;
};

// 跑一次 hashcat，返回 potfile 里解出的口令
HcAttempt run_once(const std::string& exe, const std::string& mode,
                   const std::vector<std::string>& wordlists,
                   const std::string& hashfile, const std::string& potfile,
                   bool ignore_cuda, const ProgressCb& cb, std::atomic<bool>& cancel) {
    HcAttempt a;
    const std::string hdir = std::filesystem::path(exe).parent_path().string();
    std::ostringstream cmd;
    cmd << "cd /d " << quote(hdir) << " && " << quote(exe)
        << " -m " << mode << " -a 0 " << quote(hashfile) << " ";
    for (const auto& w : wordlists)
        cmd << quote(std::filesystem::absolute(w).string()) << " ";
    cmd << " --potfile-path " << quote(potfile)
        << " --status --status-timer 1 ";
    if (ignore_cuda) cmd << "--backend-ignore-cuda ";
    cmd << "2>&1";

    if (FILE* f = _popen(cmd.str().c_str(), "r")) {
        char line[2048];
        while (std::fgets(line, sizeof line, f)) {
            if (cancel.load()) break;
            std::string s(line);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
            if (s.empty()) continue;
            a.log += s + "\n";
            if (s.find("ptxas") != std::string::npos ||
                s.find("build failed") != std::string::npos ||
                s.find("CL_OUT_OF_HOST_MEMORY") != std::string::npos)
                a.needs_cuda_fallback = true;

            const size_t sp = s.find("Speed.#");
            if (sp != std::string::npos && cb) {
                const size_t colon = s.find(':', sp);
                if (colon != std::string::npos) {
                    double val = 0;
                    char unit[16] = {0};
                    if (std::sscanf(s.c_str() + colon + 1, "%lf %15s", &val, unit) == 2) {
                        const std::string u(unit);
                        double mul = 1;
                        if (u.rfind("kH", 0) == 0) mul = 1e3;
                        else if (u.rfind("MH", 0) == 0) mul = 1e6;
                        else if (u.rfind("GH", 0) == 0) mul = 1e9;
                        else if (u.rfind("TH", 0) == 0) mul = 1e12;
                        Progress p;
                        p.speed = val * mul;
                        cb(p);
                    }
                }
            }
        }
        _pclose(f);
    }

    if (std::ifstream pf(potfile); pf) {
        std::string line;
        while (std::getline(pf, line)) {
            const size_t c = line.find_last_of(':');
            if (c != std::string::npos && c + 1 < line.size()) {
                std::string pw = line.substr(c + 1);
                if (pw.size() >= 5 && pw.rfind("$HEX[", 0) == 0 && pw.back() == ']') {
                    // $HEX[...] 形式：还原成原始字节
                    std::string out;
                    for (size_t i = 5; i + 1 < pw.size() - 1; i += 2) {
                        auto hexv = [](char ch) -> int {
                            if (ch >= '0' && ch <= '9') return ch - '0';
                            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
                            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
                            return 0;
                        };
                        out.push_back((char)((hexv(pw[i]) << 4) | hexv(pw[i + 1])));
                    }
                    pw = out;
                }
                a.password = pw;
                a.ok = true;
                break;
            }
        }
    }
    return a;
}

}  // namespace

GpuRun run_hashcat(const Archive& ar, AttackSpec& spec, const std::string& exe,
                   const ProgressCb& cb, std::atomic<bool>& cancel) {
    GpuRun r;
    std::string mode, err;
    const std::string hash = export_hash(ar, &mode, &err);
    if (hash.empty()) {
        r.log = err.empty() ? "无法导出 hash" : err;
        return r;
    }
    r.mode = mode;
    if (spec.wordlists.empty()) { r.log = "GPU 字典攻击需要字典文件"; return r; }

    const std::string hdir = std::filesystem::path(exe).parent_path().string();
    const std::string hashfile = std::filesystem::absolute("zippwn_gpu.hash").string();
    const std::string potfile = std::filesystem::absolute("zippwn_gpu.pot").string();
    {
        std::ofstream f(hashfile, std::ios::binary);
        if (!f) { r.log = "无法写入临时 hash 文件"; return r; }
        f << hash << "\n";
    }
    std::error_code ec;
    std::filesystem::remove(potfile, ec);

    if (cb) { Progress p; cb(p); }

    // 先按默认后端跑；若 PTX 工具链不匹配或显存异常，再回退到纯 OpenCL
    HcAttempt a = run_once(exe, mode, spec.wordlists, hashfile, potfile, false, cb, cancel);
    if (!a.ok && a.needs_cuda_fallback && !cancel.load()) {
        a.log += "\n[ZipPwn] 检测到 CUDA/PTX 后端不可用，回退 --backend-ignore-cuda 重试\n";
        std::filesystem::remove(potfile, ec);
        HcAttempt b = run_once(exe, mode, spec.wordlists, hashfile, potfile, true, cb, cancel);
        b.log = a.log + b.log;
        a = b;
    }

    r.log = a.log;
    r.password = a.password;
    r.found = a.ok;
    std::filesystem::remove(hashfile, ec);
    (void)hdir;
    return r;
}

}  // namespace zpwn
