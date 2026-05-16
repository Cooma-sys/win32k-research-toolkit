@echo off
setlocal

:: Detect VS generator
cmake --help 2>&1 | findstr /i "2026" >nul && set GENERATOR=Visual Studio 18 2026
cmake --help 2>&1 | findstr /i "2025" >nul && if not defined GENERATOR set GENERATOR=Visual Studio 17 2022
if not defined GENERATOR set GENERATOR=Visual Studio 17 2022

echo [*] Using generator: %GENERATOR%

:: Setup VS environment
for %%v in (18, 17) do (
    if exist "C:\Program Files\Microsoft Visual Studio\%%v\Community\Common7\Tools\VsDevCmd.bat" (
        call "C:\Program Files\Microsoft Visual Studio\%%v\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -no_logo
        goto :build
    )
)
echo [!] Visual Studio not found. Install VS 2022 or newer.
pause & exit /b 1

:build
echo.
echo [*] Building W32KSpy...
cmake -B W32KSpy\build -S W32KSpy -G "%GENERATOR%" -A x64
cmake --build W32KSpy\build --config Release
if exist W32KSpy\build\Release\W32KSpy.exe (
    echo [OK] W32KSpy.exe built successfully
) else (
    echo [FAIL] W32KSpy.exe build failed
)

echo.
echo [*] Building W32KFuzz...
cmake -B W32KFuzz\build -S W32KFuzz -G "%GENERATOR%" -A x64
cmake --build W32KFuzz\build --config Release
if exist W32KFuzz\build\Release\W32KFuzz.exe (
    echo [OK] W32KFuzz.exe built successfully
) else (
    echo [FAIL] W32KFuzz.exe build failed
)

echo.
echo === BINARIES ===
if exist W32KSpy\build\Release\W32KSpy.exe    echo   W32KSpy\build\Release\W32KSpy.exe
if exist W32KFuzz\build\Release\W32KFuzz.exe  echo   W32KFuzz\build\Release\W32KFuzz.exe
echo.
echo Run as SYSTEM: psexec -s -i W32KSpy.exe
pause
