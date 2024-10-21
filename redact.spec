# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

a = Analysis(['core.py'],
             pathex=['.'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             cipher=None,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data, cipher=None)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='Redact',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False,
          icon='ICON.ico',
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None)
