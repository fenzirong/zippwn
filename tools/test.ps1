# ============================================================================
#  ZipPwn 回归测试
#
#  用法:
#    pwsh -File tools\test.ps1              # 全量
#    pwsh -File tools\test.ps1 -SkipGen     # 跳过 fixture 生成器测试
#
#  设计要点:
#    * 断言只依赖 **退出码** 和 **ASCII 子串**（口令本身），不匹配中文输出，
#      避免 CI 控制台编码差异导致假失败
#    * 掩码用例专门验证「1 字节校验必须被 inflate+CRC 复核挡住」——
#      这是最容易回归的一个点（早期版本会报假命中）
#    * 退出码: 0 全通过 / 1 有失败
# ============================================================================

param(
    [switch]$SkipGen
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $root 'build\zippwn.exe'
$fx   = Join-Path $root 'tests\fixtures'

if (-not (Test-Path $exe)) { throw "缺少 $exe，请先运行 tools\build.ps1" }

$script:pass = 0
$script:fail = 0
$script:lines = @()

function Invoke-Zpwn {
    param([string[]]$Argv)
    $out = & $exe @Argv 2>&1 | Out-String
    return [pscustomobject]@{ Out = $out; Code = $LASTEXITCODE }
}

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        $ok = & $Body
        if ($ok) {
            $script:pass++
            $script:lines += "  [PASS] $Name"
        } else {
            $script:fail++
            $script:lines += "  [FAIL] $Name"
        }
    } catch {
        $script:fail++
        $script:lines += "  [FAIL] $Name  ($($_.Exception.Message))"
    }
}

Write-Host '=== ZipPwn 回归测试 ===' -ForegroundColor Cyan

# ---- 1. 密码学官方向量 ----
Test-Case '密码学官方向量自测 (CRC32/SHA1/PBKDF2/AES)' {
    $r = Invoke-Zpwn @('selftest')
    $r.Code -eq 0 -and $r.Out -match 'PASS'
}

# ---- 2. ZipCrypto + stored ----
Test-Case 'ZipCrypto stored 字典+规则' {
    $r = Invoke-Zpwn @('crack', "$fx\zc_stored.zip", '--mode', 'dict',
                       '--dict', "$fx\wordlist.txt", '--rules', 'best64lite',
                       '--threads', '4')
    $r.Code -eq 0 -and $r.Out -match [regex]::Escape('Tr0ub4dor&3')
}

# ---- 3. ZipCrypto + deflate（走自研 inflate + CRC 复核）----
Test-Case 'ZipCrypto deflate 字典 (inflate+CRC 复核)' {
    $r = Invoke-Zpwn @('crack', "$fx\zc_deflate.zip", '--mode', 'dict',
                       '--dict', "$fx\wordlist.txt", '--threads', '4')
    $r.Code -eq 0 -and $r.Out -match 'sunshine2024'
}

# ---- 4. WinZip AES-256（走 HMAC-SHA1 复核）----
Test-Case 'WinZip AES-256 字典 (HMAC 复核)' {
    $r = Invoke-Zpwn @('crack', "$fx\aes256.zip", '--mode', 'dict',
                       '--dict', "$fx\wordlist.txt", '--threads', '4')
    $r.Code -eq 0 -and $r.Out -match [regex]::Escape('Passw0rd!')
}

# ---- 5. 假阳性回归：单条目 1 字节校验必须被挡住 ----
Test-Case '掩码模式无假阳性 (1 字节校验被 CRC 复核挡住)' {
    $r = Invoke-Zpwn @('crack', "$fx\zc_stored.zip", '--mode', 'mask',
                       '--mask', '?l?l?l?l', '--threads', '4')
    $r.Code -eq 3          # 3 = 未命中
}

# ---- 6. 容器解析 ----
Test-Case '容器解析识别 WinZip AES-256' {
    $r = Invoke-Zpwn @('info', "$fx\aes256.zip")
    $r.Out -match 'WinZip AES-256'
}

# ---- 7. 已知明文素材采集 ----
Test-Case '已知明文素材采集 + bkcrack 命令生成' {
    $r = Invoke-Zpwn @('report', "$fx\kpa_twin.zip")
    $r.Code -eq 0 -and $r.Out -match 'bkcrack'
}

# ---- 8. fixture 生成器可复现 ----
if (-not $SkipGen) {
    Test-Case 'fixture 生成器可复现 (生成后能被自身破解)' {
        $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
        $tmp = Join-Path $base 'zpwn_fixtures'
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        & python (Join-Path $root 'tools\make_fixtures.py') $tmp | Out-Null
        if ($LASTEXITCODE -ne 0) { return $false }
        $r = Invoke-Zpwn @('crack', "$tmp\zc_stored.zip", '--mode', 'dict',
                           '--dict', "$tmp\wordlist.txt", '--threads', '4')
        $r.Code -eq 0 -and $r.Out -match [regex]::Escape('Tr0ub4dor&3')
    }
}

# ---- 汇总 ----
$script:lines | ForEach-Object { Write-Host $_ }
Write-Host ''
if ($script:fail -eq 0) {
    Write-Host "结果: 全部通过 ($($script:pass) 项)" -ForegroundColor Green
    exit 0
} else {
    Write-Host "结果: $($script:fail) 项失败 / $($script:pass) 项通过" -ForegroundColor Red
    exit 1
}
