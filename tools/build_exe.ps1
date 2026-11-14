# ============================================================================
#  ZipPwn 单文件 exe 打包脚本
#
#  用法:
#    pwsh -File tools\build_exe.ps1              # onefile（推荐分发）
#    pwsh -File tools\build_exe.ps1 -Onedir      # onedir（启动更快，目录分发）
#
#  产物:
#    dist\ZipPwn.exe          单文件 GUI（内含 zippwn.dll + Qt 运行时）
#    dist\ZipPwn\ZipPwn.exe   onedir 版
#
#  说明:
#    * C++ 内核用 /MT 静态 CRT 编译（见 build.ps1），因此 exe 不依赖 VC 运行库
#    * zippwn.dll 与 theme.qss 通过 --add-binary / --add-data 打进包内
#    * hashcat 不打进包（200MB+），需要 GPU 时用 ZIPPWN_HASHCAT 指向外部安装
# ============================================================================

param(
    [switch]$Onedir,
    [switch]$SkipCore,
    # hashcat 解压目录（含 hashcat.exe）。指定后会把精简运行集复制进
    # dist\ZipPwn\hashcat\，实现"开箱即用 GPU"。仅 onedir 支持。
    [string]$BundleHashcat = ''
)

$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
$dist  = Join-Path $root 'dist'
$work  = Join-Path $build 'pyi'

$dll = Join-Path $build 'zippwn.dll'
$qss = Join-Path $root 'zippwn\gui\theme.qss'
$entry = Join-Path $root 'zippwn\gui\app.py'

# ---- 1. 确保 C++ 内核存在 ----
if (-not $SkipCore -and -not (Test-Path $dll)) {
    Write-Host '==> 未找到 zippwn.dll，先构建 C++ 内核' -ForegroundColor Cyan
    pwsh -NoProfile -File (Join-Path $PSScriptRoot 'build.ps1')
    if (-not (Test-Path $dll)) { throw 'C++ 内核构建失败' }
}
if (-not (Test-Path $dll)) { throw "缺少 $dll" }
if (-not (Test-Path $qss)) { throw "缺少 $qss" }

Write-Host ("==> 内核: {0:N0} bytes" -f (Get-Item $dll).Length) -ForegroundColor Gray

# ---- 2. PyInstaller ----
try { python -m PyInstaller --version | Out-Null }
catch { throw 'PyInstaller 未安装：python -m pip install pyinstaller' }

# ---- 3. 版本信息资源（让 exe 在资源管理器里有正经的版本信息）----
$verFile = Join-Path $build 'version_info.txt'
@'
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(0, 4, 0, 0),
    prodvers=(0, 4, 0, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([StringTable('080404B0', [
      StringStruct('CompanyName', 'ZipPwn'),
      StringStruct('FileDescription', 'ZipPwn - 压缩包口令恢复 / 取证工作台'),
      StringStruct('FileVersion', '0.4.0.0'),
      StringStruct('InternalName', 'ZipPwn'),
      StringStruct('OriginalFilename', 'ZipPwn.exe'),
      StringStruct('ProductName', 'ZipPwn'),
      StringStruct('ProductVersion', '0.4.0.0'),
      StringStruct('LegalCopyright', 'C++ core ZipPwn. GUI runtime PySide6 (LGPL).')
    ])]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
'@ | Set-Content -Path $verFile -Encoding UTF8

# ---- 4. 组装参数 ----
$mode = if ($Onedir) { '--onedir' } else { '--onefile' }
$args = @(
    '--noconfirm', '--clean', $mode, '--windowed',
    '--name', 'ZipPwn',
    '--distpath', $dist,
    '--workpath', $work,
    '--specpath', $work,
    '--add-binary', "$dll;.",
    '--add-data', "$qss;.",
    '--version-file', $verFile,
    '--noupx',
    '--exclude-module', 'tkinter',
    '--exclude-module', 'unittest',
    '--exclude-module', 'pydoc',
    '--exclude-module', 'numpy',
    '--exclude-module', 'PIL',
    $entry
)

Write-Host "==> PyInstaller ($mode)" -ForegroundColor Cyan
& python -m PyInstaller @args
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 失败 (exit $LASTEXITCODE)" }

# ---- 5. 可选：把 hashcat 精简运行集打进 onedir 包 ----
if ($BundleHashcat) {
    if (-not $Onedir) {
        Write-Host '==> 跳过 hashcat 打包：onefile 模式不支持（会让单文件膨胀到 200MB+ 且每次启动解包）' -ForegroundColor Yellow
    } else {
        $src = $BundleHashcat
        if (-not (Test-Path (Join-Path $src 'hashcat.exe'))) {
            throw "BundleHashcat 目录里没有 hashcat.exe: $src"
        }
        $dst = Join-Path $dist 'ZipPwn\hashcat'
        Write-Host "==> 打包 hashcat: $src -> $dst" -ForegroundColor Cyan
        # 必须先建目录：否则 Copy-Item 会把第一个文件当成目标文件名
        New-Item -ItemType Directory -Force -Path $dst | Out-Null

        # 运行必需项。刻意排除：
        #   modules\*.so  —— Linux 模块（Windows 用 .dll，582 个 .so 白占 166MB）
        #   docs 其余     —— 只留 license/credits 满足 MIT 署名
        #   bridges/Rust/Python/tools/extra/example* —— 开发用，运行不需要
        $items = @('hashcat.exe', 'hashcat.hcstat2', 'hashcat.dictstat2',
                   'OpenCL', 'kernels', 'tunings', 'charsets', 'masks',
                   'layouts', 'rules')
        foreach ($i in $items) {
            $p = Join-Path $src $i
            if (Test-Path $p) { Copy-Item $p -Destination $dst -Recurse -Force }
        }
        New-Item -ItemType Directory -Force -Path (Join-Path $dst 'modules') | Out-Null
        Copy-Item (Join-Path $src 'modules\*.dll') -Destination (Join-Path $dst 'modules') -Force
        New-Item -ItemType Directory -Force -Path (Join-Path $dst 'docs') | Out-Null
        foreach ($d in 'license.txt', 'credits.txt') {
            $p = Join-Path $src "docs\$d"
            if (Test-Path $p) { Copy-Item $p -Destination (Join-Path $dst 'docs') -Force }
        }

        # MIT 许可要求保留版权与许可声明
        @'
This directory contains hashcat, bundled for convenience.

  hashcat — advanced password recovery
  https://hashcat.net/  ·  https://github.com/hashcat/hashcat
  License: MIT (see docs/license.txt)
  Credits: see docs/credits.txt

Bundled files are a trimmed runtime set (Windows only):
  hashcat.exe, hashcat.hcstat2, hashcat.dictstat2,
  OpenCL/, kernels/, tunings/, charsets/, masks/, layouts/, rules/,
  modules/*.dll, docs/license.txt, docs/credits.txt

Excluded (not needed at runtime): modules/*.so (Linux), bridges/,
Rust/, Python/, tools/, extra/, example*.

ZipPwn does not modify hashcat. All hashcat code remains under its own
MIT license; see docs/license.txt for the full text.
'@ | Set-Content -Path (Join-Path $dst 'BUNDLED.txt') -Encoding UTF8

        $hcSize = (Get-ChildItem $dst -Recurse -File | Measure-Object Length -Sum).Sum
        Write-Host ("    hashcat: {0:N1} MB / {1} files" -f ($hcSize / 1MB),
                    (Get-ChildItem $dst -Recurse -File).Count) -ForegroundColor Gray
    }
}

# ---- 6. 结果 ----
$exe = if ($Onedir) { Join-Path $dist 'ZipPwn\ZipPwn.exe' } else { Join-Path $dist 'ZipPwn.exe' }
if (-not (Test-Path $exe)) { throw "未生成 $exe" }

Write-Host ''
Write-Host '==> 打包完成' -ForegroundColor Green
$size = (Get-Item $exe).Length
Write-Host ("    {0}" -f $exe)
Write-Host ("    {0:N1} MB" -f ($size / 1MB))
if ($Onedir) {
    $total = (Get-ChildItem (Join-Path $dist 'ZipPwn') -Recurse -File |
              Measure-Object -Property Length -Sum).Sum
    Write-Host ("    目录总计 {0:N1} MB" -f ($total / 1MB))
}
Write-Host ''
if ($BundleHashcat -and $Onedir) {
    Write-Host 'GPU 开箱即用：hashcat 已随包附带，启动时自动探测。' -ForegroundColor Gray
} else {
    Write-Host 'GPU 加速需另装 hashcat 并设置：' -ForegroundColor Gray
    Write-Host '    setx ZIPPWN_HASHCAT "C:\path\to\hashcat.exe"' -ForegroundColor Gray
}
