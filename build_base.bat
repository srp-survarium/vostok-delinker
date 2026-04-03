if not defined ROOT_DIR       set "ROOT_DIR=%~dp0\.."
for %%I in ("%ROOT_DIR%")  do set "ROOT_DIR=%%~fI"

if not defined VOSTOK_DIR     set    "VOSTOK_DIR=%ROOT_DIR%\vostok"

set  "ENGINE_DIR=%VOSTOK_DIR%\sources"
set   "BUILD_DIR=%VOSTOK_DIR%\binaries\Win32"
set "OBJDIFF_DIR=%VOSTOK_DIR%\binaries\objdiff"

if exist "%OBJDIFF_DIR%\base" rmdir /s /q "%OBJDIFF_DIR%\base"

cargo run --release -- ^
  --pdb-path    "%BUILD_DIR%\survarium-dx11-win32-gold.pdb" ^
  --exe-path    "%BUILD_DIR%\survarium-dx11-win32-gold.exe" ^
  --output-path "%OBJDIFF_DIR%\base" ^
  --engine-path "%ENGINE_DIR%"

py "%VOSTOK_DIR%\scripts\generate_objdiff_config.py"
