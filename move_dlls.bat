rem First, compile the 32 and 64 bit version of TenetTracer (in a Release mode). Then, you can use this script to copy them into the directory with the run_me.bat (default: install32_64).
set INSTALL_DIR=install32_64
move Release\TenetTracer.dll %INSTALL_DIR%\TenetTracer32.dll
move x64\Release\TenetTracer.dll %INSTALL_DIR%\TenetTracer64.dll
pause