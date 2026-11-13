@echo off
setlocal
cd /d "%~dp0"
if not exist "build\zippwn.dll" (
    echo [*] 未找到 build\zippwn.dll，正在构建 C++ 内核...
    pwsh -NoProfile -File "tools\build.ps1"
    if errorlevel 1 (
        echo [!] 构建失败
        pause
        exit /b 1
    )
)
python -m zippwn.gui.app
if errorlevel 1 pause
endlocal
