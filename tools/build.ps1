# ZipPwn 构建脚本（MSVC / C++20）
#
# 用法:
#   pwsh -File tools\build.ps1              # Release 构建
#   pwsh -File tools\build.ps1 -SelfTest    # 构建后跑密码学自测
#
# 产物:
#   build\zippwn.exe     命令行
#   build\zippwn.dll     C ABI，供 GUI / 其它语言通过 ctypes 调用
#
# 注意: 必须带 /utf-8 —— 源码里有中文注释，MSVC 默认按本地代码页(GBK)解析，
#       会把 UTF-8 的尾字节误认成反斜杠，导致"神秘的语法错误"。

param(
    [switch]$SelfTest,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
$obj = Join-Path $build 'obj'

$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) { $vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat' }
    }
}
# 兜底：GitHub Actions 的 windows-latest 把 VS 装在 Enterprise/Professional 目录，
# 且 vswhere 偶尔因组件 ID 差异匹配不到，这里直接按通配再找一遍
if (-not (Test-Path $vcvars)) {
    $glob = @(
        'C:\Program Files\Microsoft Visual Studio\2022\*\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\*\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2019\*\VC\Auxiliary\Build\vcvars64.bat'
    )
    foreach ($g in $glob) {
        $hit = Get-ChildItem $g -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $vcvars = $hit.FullName; break }
    }
}
if (-not (Test-Path $vcvars)) {
    throw "找不到 vcvars64.bat，请先安装 Visual Studio Build Tools（C++ 工作负载）"
}
Write-Host "==> 工具链: $vcvars" -ForegroundColor Gray

if ($Clean -and (Test-Path $build)) { Remove-Item -Recurse -Force $build }
New-Item -ItemType Directory -Force -Path $obj | Out-Null

$core = @(
    'crypto.cpp',
    'zipfmt.cpp',
    'engine.cpp',
    'attack.cpp',
    'backend.cpp'
)
$srcDir = Join-Path $root 'core\src'
$inc = Join-Path $root 'core\include'

# /MT = 静态链接 CRT：产物不依赖 vcruntime140.dll / msvcp140.dll，
# 可以直接拷到没有装 VC 运行库的机器上跑（这是打包 exe 的前提）
$flags = '/nologo /utf-8 /std:c++20 /O2 /Oi /EHsc /MT /W3 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS'

Write-Host "==> 编译核心 ($($core.Count) 个翻译单元)" -ForegroundColor Cyan
$objs = @()
foreach ($f in $core) {
    $src = Join-Path $srcDir $f
    $o = Join-Path $obj ($f -replace '\.cpp$', '.obj')
    $cmd = "`"$vcvars`" >nul 2>&1 && cl $flags /I `"$inc`" /c `"$src`" /Fo:`"$o`""
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "编译失败: $f" }
    $objs += $o
}

Write-Host "==> 编译 capi / cli" -ForegroundColor Cyan
foreach ($pair in @(@('capi.cpp', 'capi.obj'), @('..\cli\main.cpp', 'main.obj'))) {
    $src = if ($pair[0].StartsWith('..')) {
        Join-Path $root ('cli\' + (Split-Path -Leaf $pair[0]))
    } else {
        Join-Path $srcDir $pair[0]
    }
    $o = Join-Path $obj $pair[1]
    $cmd = "`"$vcvars`" >nul 2>&1 && cl $flags /I `"$inc`" /c `"$src`" /Fo:`"$o`""
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "编译失败: $src" }
    $objs += $o
}

$objsExceptMain = $objs | Where-Object { $_ -notlike '*main.obj' }

Write-Host "==> 链接 zippwn.dll" -ForegroundColor Cyan
$dll = Join-Path $build 'zippwn.dll'
$cmd = "`"$vcvars`" >nul 2>&1 && link /nologo /DLL /OUT:`"$dll`" $($objsExceptMain -join ' ')"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "链接 DLL 失败" }

Write-Host "==> 链接 zippwn.exe" -ForegroundColor Cyan
$exe = Join-Path $build 'zippwn.exe'
$cmd = "`"$vcvars`" >nul 2>&1 && link /nologo /OUT:`"$exe`" $($objs -join ' ')"
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "链接 EXE 失败" }

Write-Host "==> 完成" -ForegroundColor Green
Get-ChildItem $build -Filter 'zippwn.*' | Format-Table Name, Length -AutoSize

if ($SelfTest) {
    Write-Host "==> 密码学自测" -ForegroundColor Cyan
    & $exe selftest
    if ($LASTEXITCODE -ne 0) { throw "自测未通过" }
}
