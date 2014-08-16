
PowerShell -Command "Set-ExecutionPolicy Unrestricted" >> "%TEMP%\StartupLog.txt" 2>&1
PowerShell .\bootstrap\bootstrap_windows.ps1 >> "%TEMP%\StartupLog.txt" 2>&1
EXIT /B 0
