@echo off
title Hash Auditor Launcher
color 0A

echo ========================================
echo   GPU Hash Auditor Initialization
echo ========================================
echo.

echo [1] Spinning up Python Orchestrator on Port 5000...
:: Opens Python in a minimized window with a specific title so we can safely close it later
start "PythonOrchestrator" /MIN python server.py

:: Give the server 2 seconds to bind to the network port
timeout /t 2 /nobreak > nul

echo [2] Launching Java Control Panel...
:: This pauses the script until you close the Java window
java Dashboard

echo.
echo [3] Shutting down Python Orchestrator...
:: Safely kills only the specific Python window we opened
taskkill /FI "WINDOWTITLE eq PythonOrchestrator*" /T /F > nul

echo.
echo Shutdown complete.