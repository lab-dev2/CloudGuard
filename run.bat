@echo off
echo ======================================================================
echo   CloudGuard: Capital One Cloud Breach Analysis and Prevention
echo ======================================================================
echo.
echo Starting local CloudGuard server on http://localhost:5000 ...
echo Everything runs locally on your laptop without AWS fees or setup!
echo.

start "" "http://localhost:5000"
python server.py
pause
