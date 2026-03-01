@echo off
echo Building SAFE (Read-Only) Solution...
echo.

echo Building User.exe...
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" "User\User.sln" /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
if %ERRORLEVEL% NEQ 0 (
    echo User build failed!
    pause
    exit /b 1
)

echo.
echo Building driver.sys...
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" "driver\driver.sln" /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
if %ERRORLEVEL% NEQ 0 (
    echo Driver build failed!
    pause
    exit /b 1
)

echo.
echo Building Loader.exe...
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" "Loader\Loader.sln" /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
if %ERRORLEVEL% NEQ 0 (
    echo Loader build failed!
    pause
    exit /b 1
)

echo.
echo SAFE build complete!
echo.
echo Outputs:
echo   User\x64\Release\User.exe
echo   driver\x64\Release\driver.sys  
echo   Loader\x64\Release\Loader.exe
pause
