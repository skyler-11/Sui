@echo off
echo Stopping Manning Simulator on Port 4444...

FOR /F "tokens=5" %%a IN ('netstat -aon ^| find ":4444" ^| find "LISTENING"') DO (
    taskkill /F /PID %%a
)

echo App stopped successfully.
pause