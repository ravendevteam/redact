@echo off
nuitka --onefile --standalone --enable-plugin=pyqt5 --remove-output --windows-icon-from-ico=ICON.ico --windows-console-mode=disable --output-dir=dist redact.py
pause