@echo off
taskkill /F /IM FrontLoader.exe 2>nul
taskkill /F /IM FrontLoader2.exe 2>nul
del /F FrontLoader.exe FrontLoader2.exe FrontLoader.obj 2>nul
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
cl /EHsc /Fe:FrontLoader.exe FrontLoader.cpp
echo Build complete!
