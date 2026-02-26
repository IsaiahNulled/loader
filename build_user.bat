@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
cd /d "c:\Users\Isaiah\Desktop\external\User"
msbuild User.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /v:minimal
echo Build done.
pause
