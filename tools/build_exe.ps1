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
    [switch]$SkipCore
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

# ---- 5. 结果 ----
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
Write-Host '可直接双击运行。GPU 加速需另装 hashcat 并设置：' -ForegroundColor Gray
Write-Host '    setx ZIPPWN_HASHCAT "C:\path\to\hashcat.exe"' -ForegroundColor Gray
