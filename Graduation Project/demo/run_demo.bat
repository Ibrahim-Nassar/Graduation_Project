@echo off
setlocal

set "ROOT_DIR=%~dp0.."
set "SCENARIOS_DIR=%~dp0scenarios"
set "OUTPUT_DIR=%~dp0outputs"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [INFO] Running source CLI demo scenarios...

set /p LOG1=<"%SCENARIOS_DIR%\01_powershell_encoded.log"
python -m src.cli "%LOG1%" > "%OUTPUT_DIR%\01_powershell_encoded.json"
if errorlevel 1 exit /b 1

python -m src.cli --enrich-iocs "%LOG1%" > "%OUTPUT_DIR%\01_powershell_encoded_enrich.json"
if errorlevel 1 exit /b 1

set /p LOG2=<"%SCENARIOS_DIR%\02_failed_logins_bruteforce.log"
python -m src.cli "%LOG2%" > "%OUTPUT_DIR%\02_failed_logins_bruteforce.json"
if errorlevel 1 exit /b 1

set /p LOG3=<"%SCENARIOS_DIR%\03_dns_tunnel_like.log"
python -m src.cli "%LOG3%" > "%OUTPUT_DIR%\03_dns_tunnel_like.json"
if errorlevel 1 exit /b 1

echo [PASS] Demo outputs generated in "%OUTPUT_DIR%"
exit /b 0

