@echo off
del "%WINDIR%\system32\drivers\snake.sys"
copy "%~dp0\asmmap64.sys" "%WINDIR%\system32\drivers\snake.sys"
"driver loader" snake system32\drivers\snake.sys -install_load
echo If you see any access denied, close this and relaunch the bat as Administrator.