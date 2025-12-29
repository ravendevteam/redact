@echo off
set FileVersion=1.0.0.3
set ProductVersion=2.0.0.0

python -m nuitka --standalone --enable-plugins=pyqt5 --include-qt-plugins=qml --remove-output --windows-disable-console --output-dir=dist --output-filename=Redact.exe --windows-icon-from-ico=ICON.ico --include-data-dir=ui=ui --follow-imports --product-name="Redact" --company-name="Raven Development Team" --file-description="Raven Redact" --file-version=%FileVersion% --product-version=%ProductVersion% --copyright="Copyright (c) 2025 Raven Development Team" app.py
pause