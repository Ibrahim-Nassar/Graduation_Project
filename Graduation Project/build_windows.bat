@echo off
setlocal

REM Build SOC desktop workstation executable via PyInstaller spec.
if exist ".venv\Scripts\pyinstaller.exe" (
    ".venv\Scripts\pyinstaller.exe" --clean --noconfirm "soc_copilot_cli.spec"
) else (
    pyinstaller --clean --noconfirm "soc_copilot_cli.spec"
)

endlocal

