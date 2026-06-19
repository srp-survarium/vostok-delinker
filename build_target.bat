@echo off

pushd "%~dp0"

if not defined ROOT_DIR       set "ROOT_DIR=%~dp0\.."
for %%I in ("%ROOT_DIR%")  do set "ROOT_DIR=%%~fI"

if not defined VOSTOK_DIR     set    "VOSTOK_DIR=%ROOT_DIR%\vostok"
if not defined SURVARIUM_BIN  set "SURVARIUM_BIN=D:\Projects\Survarium\binaries\win32"

set "OBJDIFF_DIR=%VOSTOK_DIR%\binaries\objdiff"

if exist "%OBJDIFF_DIR%\target" rmdir /s /q "%OBJDIFF_DIR%\target"

cargo run --release -- ^
  --pdb-path         "%SURVARIUM_BIN%\survarium.pdb" ^
  --exe-path         "%SURVARIUM_BIN%\survarium.exe" ^
  --output-path      "%OBJDIFF_DIR%\target" ^
  --engine-path      "c:\survarium\sources" ^
  --pad-empty-rdata ^
  --write-symbol-map "%OBJDIFF_DIR%\target-symbol-map.tsv"

py "%VOSTOK_DIR%\scripts\generate_objdiff_config.py"

popd
