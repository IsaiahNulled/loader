@echo off
REM ============================================================
REM  deploy_secure.bat — Encrypt builds + deploy to repo
REM
REM  1. Runs encrypt_build.py to AES-256-GCM encrypt all binaries
REM  2. Copies .enc files to the GitHub repo folder
REM  3. Also copies unencrypted Loader.exe (FrontLoader downloads it directly)
REM  4. Push via GitHub Desktop when ready
REM
REM  Requires: pip install cryptography
REM ============================================================

set SRC=C:\Users\Isaiah\Desktop\external
set REPO=C:\Users\Isaiah\Documents\repo\loader
set AUTH=C:\Users\Isaiah\Desktop\external\auth-server

echo.
echo  ==========================================
echo   Encrypting + Deploying Builds
echo  ==========================================
echo.

REM -- Run encryption script --
echo  [1/3] Encrypting all builds with AES-256-GCM...
python "%AUTH%\encrypt_build.py" --all
if errorlevel 1 (
    echo  [!] Encryption failed!
    pause
    exit /b 1
)

echo.
echo  [2/3] Copying unencrypted Loader.exe (for FrontLoader)...
if not exist "%REPO%\full" mkdir "%REPO%\full"
if not exist "%REPO%\safe" mkdir "%REPO%\safe"
copy /Y "%SRC%\full\Loader\x64\Release\Loader.exe" "%REPO%\full\Loader.exe"
copy /Y "%SRC%\safe\Loader\x64\Release\Loader.exe" "%REPO%\safe\Loader.exe"

echo.
echo  [3/3] Verifying repo contents...
echo.
echo  --- full/ ---
dir /B "%REPO%\full\"
echo.
echo  --- safe/ ---
dir /B "%REPO%\safe\"
echo.

echo  ==========================================
echo   Done! Encrypted files are in the repo.
echo   build_keys.json is in auth-server/ (server only).
echo   Push via GitHub Desktop when ready.
echo  ==========================================
echo.
pause
