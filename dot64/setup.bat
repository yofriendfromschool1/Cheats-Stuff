@echo off
title Dot 64 Setup
color 1
echo Welcome to Dot 64 Setup preparing

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Installing Python...
    powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe -OutFile python_installer.exe"
    start /wait python_installer.exe /quiet InstallAllUsers=1 PrependPath=1
    del python_installer.exe
)

python -m pip install --upgrade pip
python -m pip install capstone pefile PyQt5 qdarkstyle

echo Setup successfully!

color
start run.bat
pause
