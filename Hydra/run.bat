@echo off
rem This script was created by Nuitka to execute 'Hydra.exe' with Python DLL being found.
set PYTHON_DIR=%USERPROFILE%\AppData\Local\Programs\Python\Python312
set PATH=%PYTHON_DIR%;%PATH%
set PYTHONHOME=%PYTHON_DIR%
set NUITKA_PYTHONPATH=%USERPROFILE%\Desktop\dot64;%PYTHON_DIR%\DLLs;%PYTHON_DIR%\Lib;%PYTHON_DIR%;%PYTHON_DIR%\Lib\site-packages;%PYTHON_DIR%\Lib\site-packages\win32;%PYTHON_DIR%\Lib\site-packages\win32\lib;%PYTHON_DIR%\Lib\site-packages\Pythonwin
start "" "%~dp0Hydra.exe" %*
exit