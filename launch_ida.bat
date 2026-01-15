@echo off
echo ========================================
echo Launching IDA Pro with Sample Backdoor
echo ========================================
echo.

REM Check if IDA Pro exists
if exist "D:\Forensics\ida.exe" (
    echo [+] Found IDA Pro at D:\Forensics\ida.exe
) else if exist "D:\Forensics\ida64.exe" (
    echo [+] Found IDA Pro 64-bit at D:\Forensics\ida64.exe
) else (
    echo [-] ERROR: IDA Pro not found at D:\Forensics\
    echo Please check the path and try again.
    pause
    exit
)

REM Check if backdoor exists
if exist "simple_backdoor_debug.exe" (
    echo [+] Found simple_backdoor_debug.exe
) else (
    echo [-] ERROR: simple_backdoor_debug.exe not found
    echo Please compile first using compile.bat
    pause
    exit
)

echo.
echo ========================================
echo Instructions:
echo ========================================
echo.
echo After IDA Pro opens:
echo.
echo 1. Wait for auto-analysis to complete
echo.
echo 2. Take screenshots using: Windows Key + Shift + S
echo.
echo 3. Follow SCREENSHOT_GUIDE.md for what to capture
echo.
echo Key shortcuts:
echo   Ctrl+I       = Imports window
echo   Shift+F12    = Strings window
echo   Shift+F3     = Functions window
echo   Spacebar     = Toggle graph view
echo.
echo ========================================
echo Launching IDA Pro now...
echo ========================================
echo.

REM Try to launch IDA Pro with the backdoor file
if exist "D:\Forensics\ida64.exe" (
    start "" "D:\Forensics\ida64.exe" "%~dp0simple_backdoor_debug.exe"
) else (
    start "" "D:\Forensics\ida.exe" "%~dp0simple_backdoor_debug.exe"
)

echo.
echo [+] IDA Pro should be launching...
echo.
echo Next steps:
echo 1. IDA Pro will open
echo 2. Click OK to analyze the file
echo 3. Wait for analysis to complete
echo 4. Follow SCREENSHOT_GUIDE.md to capture images
echo.
echo TIP: Use Windows Key + Shift + S to take screenshots
echo.
pause
