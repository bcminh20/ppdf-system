@echo off
REM PPDF Hybrid System Launcher (Windows CMD)
REM Usage:
REM   run.bat test
REM   run.bat keygen
REM   run.bat stage2 --evidence-dir "..\KetQua"
REM   run.bat stage3 --evidence-dir "..\KetQua"
REM   run.bat full --evidence-dir "..\KetQua"

set PYTHONPATH=%~dp0;%PYTHONPATH%
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0ppdf_main.py" %*
) else (
    python "%~dp0ppdf_main.py" %*
)
