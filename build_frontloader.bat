@echo off
echo Building Front Loader...
cl /EHsc /Fe:FrontLoader.exe FrontLoader.cpp urlmon.lib
echo Front Loader built successfully!
pause
