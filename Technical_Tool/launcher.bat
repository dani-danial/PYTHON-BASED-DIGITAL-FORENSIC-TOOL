@echo off
:: Set the window title
title NetTrace Forensic Tool - Launcher

:: Set color to Green on Black (Classic Hacker Look)
color 0A

:: Clear screen
cls

:: Change directory to the folder where this file is located
cd /d "%~dp0"

:: Run the Python tool
python forensic_tool.py

:: Keep the window open if the program crashes or finishes
pause