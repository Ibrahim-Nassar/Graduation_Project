@echo off
setlocal

set "ROOT_DIR=%~dp0.."
set "EXE_PATH=%ROOT_DIR%\dist\soc_copilot_cli\soc_copilot_cli.exe"
set "SAMPLE_LOG_FILE=%~dp0sample_inference_log.txt"
set "OUT_BASE=%~dp0smoke_output_basic.json"
set "OUT_ENRICH=%~dp0smoke_output_enrich.json"
set "JSON_VALIDATOR=%TEMP%\soc_smoke_json_validate_%RANDOM%_%RANDOM%.py"

if not exist "%EXE_PATH%" (
  echo [FAIL] Built executable not found: "%EXE_PATH%"
  echo Build first: pyinstaller --clean --noconfirm "soc_copilot_cli.spec"
  exit /b 1
)

if not exist "%SAMPLE_LOG_FILE%" (
  echo [FAIL] Sample log file not found: "%SAMPLE_LOG_FILE%"
  exit /b 1
)

set /p RAW_LOG=<"%SAMPLE_LOG_FILE%"
> "%JSON_VALIDATOR%" echo import json
>> "%JSON_VALIDATOR%" echo import sys
>> "%JSON_VALIDATOR%" echo.
>> "%JSON_VALIDATOR%" echo path = sys.argv[1]
>> "%JSON_VALIDATOR%" echo required = sys.argv[2:]
>> "%JSON_VALIDATOR%" echo.
>> "%JSON_VALIDATOR%" echo try:
>> "%JSON_VALIDATOR%" echo     with open(path, "r", encoding="utf-8") as handle:
>> "%JSON_VALIDATOR%" echo         payload = json.load(handle)
>> "%JSON_VALIDATOR%" echo except Exception as exc:
>> "%JSON_VALIDATOR%" echo     print(f"[FAIL] Invalid JSON in {path}: {exc}", file=sys.stderr)
>> "%JSON_VALIDATOR%" echo     raise SystemExit(2)
>> "%JSON_VALIDATOR%" echo.
>> "%JSON_VALIDATOR%" echo result = payload.get("result") if isinstance(payload, dict) else None
>> "%JSON_VALIDATOR%" echo if not isinstance(result, dict):
>> "%JSON_VALIDATOR%" echo     print(f"[FAIL] JSON missing object key 'result' in {path}", file=sys.stderr)
>> "%JSON_VALIDATOR%" echo     raise SystemExit(3)
>> "%JSON_VALIDATOR%" echo.
>> "%JSON_VALIDATOR%" echo missing = [key for key in required if key not in result]
>> "%JSON_VALIDATOR%" echo if missing:
>> "%JSON_VALIDATOR%" echo     print(f"[FAIL] JSON result missing keys {missing} in {path}", file=sys.stderr)
>> "%JSON_VALIDATOR%" echo     raise SystemExit(4)

echo [INFO] Running basic inference smoke test...
"%EXE_PATH%" "%RAW_LOG%" > "%OUT_BASE%"
if errorlevel 1 (
  del "%JSON_VALIDATOR%" >nul 2>&1
  echo [FAIL] Basic inference command failed.
  exit /b 1
)
python "%JSON_VALIDATOR%" "%OUT_BASE%" technique_id mapping_source
if errorlevel 1 (
  del "%JSON_VALIDATOR%" >nul 2>&1
  echo [FAIL] Basic output JSON validation failed.
  exit /b 1
)

echo [INFO] Running enrichment-enabled smoke test...
"%EXE_PATH%" --enrich-iocs "%RAW_LOG%" > "%OUT_ENRICH%"
if errorlevel 1 (
  del "%JSON_VALIDATOR%" >nul 2>&1
  echo [FAIL] Enrichment command failed.
  exit /b 1
)
python "%JSON_VALIDATOR%" "%OUT_ENRICH%" technique_id mapping_source ioc_enrichment
if errorlevel 1 (
  del "%JSON_VALIDATOR%" >nul 2>&1
  echo [FAIL] Enrichment output JSON validation failed.
  exit /b 1
)

del "%JSON_VALIDATOR%" >nul 2>&1

echo [PASS] Smoke tests passed.
echo [INFO] Outputs:
echo   "%OUT_BASE%"
echo   "%OUT_ENRICH%"
exit /b 0

