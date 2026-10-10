@echo off
chcp 65001 >nul
title 小神代理
where python >nul 2>nul
if errorlevel 1 (
  echo 未检测到 Python: https://www.python.org/downloads/
  pause
  exit /b
)
python "%~dp0proxy.py"
pause
