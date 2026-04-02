# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_root = Path.cwd().resolve()
ioc_src = (project_root.parent / "AIO_security_App_New" / "src").resolve()

block_cipher = None


a = Analysis(
    [str(project_root / "desktop_app.py")],
    pathex=[str(project_root), str(ioc_src)],
    binaries=[],
    datas=[
        (str(ioc_src / "ioc_enrichment.py"), "AIO_security_App_New/src"),
    ],
    hiddenimports=["ioc_enrichment", "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="soc_workstation",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="soc_workstation",
)

