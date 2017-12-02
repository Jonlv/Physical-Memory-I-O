"driver loader" snake system32\drivers\snake.sys -unload_uninstall
timeout 1
del "%WINDIR%\system32\drivers\snake.sys"
copy "%WINDIR%\system32\drivers\3ware.sys" "%WINDIR%\system32\drivers\snake.sys"