@echo off
setlocal enabledelayedexpansion

echo ========================================================================
echo       XIII 0S1nt - Automated Windows C++20 Build Subsystem
echo               Developed by Findhost $ Travma
echo ========================================================================

set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%VS_PATH%" (
    echo [-] Error: Visual Studio 2022 build environment not found at:
    echo     %VS_PATH%
    exit /b 1
)

echo [*] Initializing Visual Studio x64 build environment...
call "%VS_PATH%" x64 >nul 2>&1
if errorlevel 1 (
    echo [-] Failed to initialize Visual Studio build environment.
    exit /b 1
)

echo [+] Build environment initialized.
echo [*] Compiling XIII 0S1nt standalone executable with MSVC C++20...

cl.exe /nologo /std:c++20 /EHsc /utf-8 /O2 /Oi /Gy /MD /I include ^
    src\main.cpp ^
    src\application.cpp ^
    src\console.cpp ^
    src\utils.cpp ^
    src\http_client.cpp ^
    src\config_manager.cpp ^
    src\license.cpp ^
    src\report_generator.cpp ^
    src\api_registry.cpp ^
    src\menu.cpp ^
    src\modules\username.cpp ^
    src\modules\email.cpp ^
    src\modules\phone.cpp ^
    src\modules\ip.cpp ^
    src\modules\domain.cpp ^
    src\modules\website.cpp ^
    src\modules\discord.cpp ^
    src\modules\github.cpp ^
    src\modules\social.cpp ^
    src\modules\breach.cpp ^
    src\modules\dns.cpp ^
    src\modules\whois.cpp ^
    src\modules\network.cpp ^
    src\modules\url_rep.cpp ^
    src\modules\hash.cpp ^
    src\modules\threat.cpp ^
    src\modules\profile.cpp ^
    src\modules\searchengine.cpp ^
    src\modules\comprehensive.cpp ^
    src\modules\report_manager.cpp ^
    src\modules\api_status.cpp ^
    src\modules\settings.cpp ^
    /link /OUT:XIII_0S1nt.exe ^
    winhttp.lib crypt32.lib bcrypt.lib advapi32.lib shell32.lib user32.lib ole32.lib

if errorlevel 1 (
    echo.
    echo [-] Build FAILED. Check compiler errors above.
    exit /b 1
)

echo.
echo ========================================================================
echo [+] BUILD SUCCESSFUL: XIII_0S1nt.exe generated!
echo ========================================================================

rem Clean up intermediate obj files
del /q *.obj >nul 2>&1

exit /b 0
