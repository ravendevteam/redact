@echo off
nuitka --onefile --standalone --enable-plugin=pyqt5 --remove-output --windows-icon-from-ico=ICON.ico --include-data-files=ICON.ico=ICON.ico --include-data-files=style.css=style.css --windows-console-mode=disable --output-dir=dist redact.py
pause