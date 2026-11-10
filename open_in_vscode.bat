@echo off
title Open ScamShield AI in VS Code
cd /d "%~dp0"
echo Opening ScamShield AI folder in Visual Studio Code...
code .
if %ERRORLEVEL% NEQ 0 (
    echo Trying user-installed VS Code path...
    "%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe" "%~dp0"
)
