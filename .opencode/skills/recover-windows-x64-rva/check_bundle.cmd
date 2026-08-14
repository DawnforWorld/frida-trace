@echo off
setlocal
set "BUNDLE_ROOT=%~dp0"
"%BUNDLE_ROOT%\.runtime\triton-py314\Scripts\python.exe" "%BUNDLE_ROOT%\scripts\check_offline_bundle.py" %*
