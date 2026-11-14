# ZipPwn —— 压缩包口令恢复 / 取证工作台

[![CI](https://github.com/fenzirong/zippwn/actions/workflows/ci.yml/badge.svg)](https://github.com/fenzirong/zippwn/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey)

C++20 内核 + PySide6 界面的 ZIP 口令恢复工具。原生 CPU 多线程引擎处理 ZipCrypto / WinZip AES，
GPU 后端经 hashcat 处理全部格式。所有算法都带官方向量自测，能力矩阵里的每一项都是**实测跑通**的。

> ⚠️ **免责声明**
> ZipPwn 是**安全研究与数字取证工具**，仅可用于**已获得合法授权**的场景：恢复自有或客户所属
> 压缩包的口令、评估口令强度、验证备份加密方案、安全教学与 CTF。
> **禁止**用于未授权访问他人数据、规避技术保护措施或任何违法用途。
> 使用者对所进行的一切操作及其后果承担全部责任；本软件按 MIT 许可"按原样"提供，不附带任何担保。
> 完整条款见 [DISCLAIMER.md](DISCLAIMER.md)。

---

## 能力矩阵（实测）

| 容器 / 加密 | 原生 CPU 引擎 | GPU (hashcat) | 实测状态 |
|---|---|---|---|
| ZIP + ZipCrypto (stored) | ✅ 表驱动 8 状态机 | ✅ `-m 17225` / `-m 17210` | 命中 `Tr0ub4dor&3` |
| ZIP + ZipCrypto (deflate) | ✅ 含 inflate + CRC 复核 | ✅ `-m 17225` | 命中 `sunshine2024` |
| ZIP + WinZip AES-128/192/256 | ✅ PBKDF2-SHA1 1000 + HMAC 复核 | ✅ `-m 13600` | 命中 `Passw0rd!` |
| RAR4 / RAR5 / 7z | 仅识别与路由 | ✅ `-m 12500/13000/11600` | 需 `rar2john` / `7z2hashcat` 导出 hash |

CPU 实测吞吐（ZipCrypto，单条目，32 逻辑核）：

| 线程 | 1 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|
| 候选/秒 | 4.70 M | 17.8 M | 36.6 M | 65.5 M | 68.2 M |

---

## 架构

```
┌────────────────────────────┐  ctypes   ┌──────────────────────────────┐
│ PySide6 GUI  zippwn/gui/   │ ────────► │ zippwn.dll   C++20           │
│  · 参数收集 / 进度渲染      │ ◄──────── │  crypto.cpp   CRC32/SHA1/AES  │
│  · 已知明文表格            │ progress  │  zipfmt.cpp   ZIP/Zip64 解析   │
└────────────────────────────┘ callback  │  engine.cpp   校验器+候选+调度 │
                                          │  attack.cpp   攻击面/明文对    │
┌────────────────────────────┐            │  backend.cpp  hashcat 桥接    │
│ zippwn.exe   命令行         │ ─────────► │  capi.cpp     C ABI 导出      │
└────────────────────────────┘            └──────────────────────────────┘
```

- **零第三方依赖**：CRC32 / SHA-1 / HMAC / PBKDF2 / AES / DEFLATE 全部自研，只依赖 Windows SDK。
- **GUI 与内核解耦**：GUI 崩了不影响内核，内核可用 `zippwn.exe` 独立跑。

---

## 构建

前置：Visual Studio 2022 Build Tools（C++ 工作负载）。已验证 MSVC 14.44。

```powershell
pwsh -File tools\build.ps1 -SelfTest
```

产物：`build\zippwn.exe`（命令行）、`build\zippwn.dll`（C ABI）。

> 构建必须带 `/utf-8`。源码含中文注释，MSVC 默认按 GBK 解析会把 UTF-8 尾字节吃成反斜杠，
> 报出一堆莫名其妙的语法错误。

GPU 后端：把 hashcat 解压到任意目录，然后

```powershell
$env:ZIPPWN_HASHCAT = "C:\path\to\hashcat.exe"
```

---

## 打包为 exe

```powershell
pwsh -File tools\build_exe.ps1            # 单文件（默认）
pwsh -File tools\build_exe.ps1 -Onedir    # 目录版（启动更快）
```

| 产物 | 体积 | 说明 |
|---|---|---|
| `dist\ZipPwn.exe` | 36.4 MB | 单文件，双击即用；启动时解包到 `%TEMP%\_MEIxxxx` |
| `dist\ZipPwn\ZipPwn.exe` | 1.7 MB（目录 93.9 MB） | onedir，不解包、启动快，适合压缩分发 |
| `dist\ZipPwn-0.4.0-win64.zip` | 37.5 MB | 上面 onedir 的现成压缩包 |
| `build\zippwn.exe` | 234 KB | 纯 C++ 命令行版，**零依赖**，可单独拷走 |

关键点：

- C++ 内核用 **`/MT` 静态 CRT** 编译，`zippwn.dll` / `zippwn.exe` 不依赖 `vcruntime140.dll`，
  目标机不用装 VC 运行库。
- `zippwn.dll` 与 `theme.qss` 通过 `--add-binary` / `--add-data` 打进包内；
  GUI 用 `sys._MEIPASS`（onefile）与 exe 同目录（onedir）双路径查找，源码运行也兼容。
- 已排掉 `tkinter / unittest / pydoc / numpy / PIL`，体积从 ~110 MB 压到 36 MB。
- exe 带版本信息资源（0.4.0.0，中文描述），资源管理器里属性正常。
- **hashcat 不打进包**（200 MB+ 且需匹配本机驱动）。需要 GPU 时另装并设置
  `ZIPPWN_HASHCAT`，包内 GUI 的「GPU 加速」页会自动探测。

> 环境提示：某些受限账户/沙箱环境下 `%TEMP%` 对子进程不可写，onefile 会报
> `Could not create temporary directory!`。此时改用 onedir 版，或把 `TMP`/`TEMP`
> 指向可写目录再启动。onedir 版不依赖临时目录。

---

## 用法

### 图形界面

```powershell
.\run_gui.bat        # 或  python -m zippwn.gui.app
```

页面：字典攻击 / 掩码攻击 / 混合攻击 / GPU 加速 / 漏洞攻击。

### 命令行

```powershell
build\zippwn.exe selftest                              # 密码学官方向量自测
build\zippwn.exe info    target.zip                    # 容器与加密方案
build\zippwn.exe report  target.zip                    # 攻击面评估 + 已知明文素材
build\zippwn.exe hash    target.zip                    # 导出 hashcat hash

build\zippwn.exe crack target.zip --mode dict --dict rockyou.txt --rules best64lite --threads 16
build\zippwn.exe crack target.zip --mode mask --mask "?u?l?l?l?l?d?d"
build\zippwn.exe crack target.zip --mode hybrid --dict wl.txt --hybrid "?d?d"

build\zippwn.exe gpuinfo                               # 探测 hashcat 与设备
build\zippwn.exe gpucrack target.zip --dict rockyou.txt
```

退出码：`0` 命中 / `3` 未命中 / `2` 参数或格式错误 / `130` 中断。

---

## 算法与「漏洞攻击」的真实边界

这一节是刻意写清楚的，避免夸大。

### 1. ZipCrypto 的三级漏斗

传统 PKZIP 加密是流密码，密钥状态 `(key0,key1,key2)` 由口令初始化，逐个字节推进：

```
key0 = crc32_table[(key0 ^ c) & 0xFF] ^ (key0 >> 8)
key1 = (key1 + (key0 & 0xFF)) * 134775813 + 1
key2 = crc32_table[(key2 ^ (key1 >> 24)) & 0xFF] ^ (key2 >> 8)
密钥流 = ((key2|2) & 0xFFFF) * (((key2|2) & 0xFFFF) ^ 1) >> 8
```

**结构性弱点**：那 12 字节加密头里只有**第 12 字节**有效（`crc>>24`，或 flag bit3 置位时用
`dostime>>8`），单条目误报率 1/256。所以本引擎的验证做成三级漏斗：

1. **快筛**（`test`）：只解 12 字节，不碰正文、不解压。多条目串联后误报 1/256^n。
2. **复核**（`confirm`）：命中后全量解密 → inflate → CRC32 比对，误报归零。
3. **交叉**：同一压缩包最多取 3 个加密条目做串行漏斗。

关键实现细节：**12 字节加密头本身也推进密钥状态**，解密正文前必须先把这 12 字节"过一遍"
（解出的明文头丢弃），否则密钥状态错位、后面全是垃圾。这个坑踩过。

### 2. WinZip AES

`PBKDF2-HMAC-SHA1(password, salt, 1000, 2*keylen+2)` 拆成 `encKey | authKey | pv(2)`，
CTR 模式计数器是小端 128 位、从 1 开始。同样两级：`pv` 2 字节快筛（1/65536），
命中后 HMAC-SHA1 全量复核（1/2^80）。

### 3. 已知明文（KPA）攻击

`K = P XOR C` 对 ZipCrypto 是**密钥恢复**的入口：明文对足够长时，Biham-Kocher 攻击把
密钥空间从 2^96 压到 2^38，直接还原密钥、**绕过口令**。

本工具负责其中最难的工程部分——**自动采集明文对**：

1. 未加密的同名孪生条目（明文 100% 已知，最强）
2. stored 条目的扩展名魔数（PNG/JPEG/PDF/SQLite/ZIP…）
3. 内置 OOXML / PDF 结构模板

拿到明文对后调用 [bkcrack](https://github.com/kimci86/bkcrack) 完成密钥恢复：

```powershell
build\zippwn.exe report target.zip          # 产出素材与现成命令
bkcrack -C target.zip -c "public/notice.txt" -p plain.bin -o 0
bkcrack -C target.zip -k keys -U out.zip recovered
```

**Biham-Kocher 本身没有在本项目里重写**——它是 500+ 行强耦合的密码分析代码，
重写一遍的正确性风险远大于收益。这里的选择是"参考开源项目"而不是"抄错一遍"。

### 4. 没有结构弱点的部分（不假装能绕过）

- **7z**：AES-256-CBC + SHA-256 KDF 2^19 轮，无校验位可利用
- **RAR5**：AES-256 + PBKDF2-SHA256 2^15 轮
- **WinZip AES 本体**：除 2 字节 pv 外无弱点

这三个只能靠 KDF 成本 + GPU 硬算。`zippwn report` 会如实标注"必须 GPU"。

---

## 实测踩过的坑（都已在代码里处理）

| 坑 | 现象 | 处理 |
|---|---|---|
| MSVC 默认 GBK | 中文注释导致"神秘语法错误" | 构建加 `/utf-8` |
| ZipCrypto 密钥流连续 | 正文解密全错 | 先解 12 字节头再解正文 |
| 单条目 1 字节校验 | 掩码模式报假命中 | 加 inflate + CRC 全量复核 |
| Windows 压缩 API | `COMPRESS_ALGORITHM_DEFLATE` 不存在（只有 MSZIP） | 自研 DEFLATE 解码器 |
| `$zip2$` 字段 | DF 必须是**完整密文**，结尾 `$/zip2$` 不能省 | 按 zip2john.c 注释实现 |
| hashcat CWD | 找不到 `./OpenCL/` 内核 | 以 hashcat 目录为工作目录 |
| hashcat PTX 9.1 vs 驱动 8.7 | `ptxas: Unsupported .version` | 自动回退 `--backend-ignore-cuda` |
| 字典源指针 | 读完一个词不换行 | 分离 `advance_word` / `read_line` |

---

## 参考的开源项目与规范

- [hashcat](https://hashcat.net/) —— GPU 内核后端（MIT），`OpenCL/m13600-pure.cl` 是 `$zip2$` 结构的权威依据
- [John the Ripper](https://github.com/openwall/john) —— `src/zip2john.c` 注释是 `$zip2$` / `$pkzip$` 字段的权威定义
- [bkcrack](https://github.com/kimci86/bkcrack) —— Biham-Kocher 已知明文密钥恢复
- PKWARE APPNOTE 6.3.x —— ZIP 容器与 ZipCrypto
- WinZip AES 规范（AE-1/AE-2/AE-3）—— PBKDF2 / CTR / HMAC 参数
- Biham & Kocher, *A Known Plaintext Attack on the PKZIP Stream Cipher* (1994)

---

## 目录

```
zippwn/
├── core/include/zpwn.hpp     公共接口
├── core/src/crypto.cpp       CRC32/SHA1/HMAC/PBKDF2/AES（含官方向量自测）
├── core/src/zipfmt.cpp       ZIP/Zip64 解析、加密参数、已知明文采集
├── core/src/engine.cpp       校验器、候选生成、线程池调度、DEFLATE
├── core/src/attack.cpp       密钥流提取、攻击面评估
├── core/src/backend.cpp      hashcat 桥接（hash 导出 + 自动后端回退）
├── core/src/capi.cpp         C ABI
├── cli/main.cpp              命令行
├── zippwn/gui/app.py         PySide6 界面
├── zippwn/gui/theme.qss      深色主题
├── tools/build.ps1           构建
├── tools/make_fixtures.py    生成已知口令的测试样本
└── tests/fixtures/           测试样本
```

## 已知限制

- 原生 CPU 引擎只覆盖 ZIP（ZipCrypto / WinZip AES）。RAR / 7z 走 GPU 后端。
- ZipCrypto `confirm` 对超过 128 MB 的条目跳过全量复核，退化为多条目交叉校验。
- `zipcrypto_decrypt_body` 未处理 WinZip 的强加密（type 99 以外的 PKWARE 强加密）。
- GUI 的「漏洞攻击」页只做素材采集与命令生成，密钥恢复需本地有 `bkcrack`。
