@echo off
title Jew Ware Auth Server
echo ==========================================
echo   Jew Ware Auth Server - Starting...
echo ==========================================
echo.

:: Set the admin password (special chars safe in quotes)
set "WEB_ADMIN_PASSWORD=Brenn@2003??"

:: Optional: Set a persistent Flask secret key so sessions survive restarts
set "FLASK_SECRET_KEY=JewWare_Secret_K3y_2024_xR9mP2vL8n"

echo [*] Setting admin password to: %WEB_ADMIN_PASSWORD%
echo [*] Environment variable set
echo [*] Login at http://YOUR_IP:7777/admin
echo.

:: Start the server with debug output
python server.py

pause
