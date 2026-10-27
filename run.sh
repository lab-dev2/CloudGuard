#!/usr/bin/env bash
echo "======================================================================"
echo "  CloudGuard: Capital One Cloud Breach Analysis and Prevention"
echo "======================================================================"
echo ""
echo "Starting local CloudGuard server on http://localhost:5000 ..."
echo "Everything runs locally on your laptop without AWS fees or setup!"
echo ""

# Attempt to open browser on macOS or Linux
if which xdg-open > /dev/null; then
  xdg-open "http://localhost:5000" &
elif which open > /dev/null; then
  open "http://localhost:5000" &
fi

python3 server.py
