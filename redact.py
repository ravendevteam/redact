import sys
import os
import random
import string
import hashlib
import logging
import base64
import time
import math
import platform
import ctypes
from ctypes import wintypes
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget, QMessageBox, QProgressBar, QFileDialog, QDialog, QLabel, QComboBox, QHBoxLayout, QToolTip, QAction, QMenuBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon
import importlib.util

logging.basicConfig(
    filename="redact.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)



def load_plugins(app_context):
    user_home = os.path.expanduser("~")
    plugins_dir = os.path.join(user_home, "rdplugins")
    os.makedirs(plugins_dir, exist_ok=True)
    loaded_plugins = []
    for filename in os.listdir(plugins_dir):
        if filename.endswith(".py") and not filename.startswith("_"):
            plugin_path = os.path.join(plugins_dir, filename)
            mod_name = os.path.splitext(filename)[0]
            spec = importlib.util.spec_from_file_location(mod_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, "register_plugin"):
                    module.register_plugin(app_context)
                    loaded_plugins.append(mod_name)
                    print(f"Plugin '{mod_name}' loaded successfully from {plugins_dir}")
            except Exception as e:
                print(f"Failed to load plugin '{filename}' from {plugins_dir}: {e}")
    return loaded_plugins



def loadStyle():
    user_css_path = os.path.join(os.path.expanduser("~"), "rdstyle.css")
    stylesheet = None
    if os.path.exists(user_css_path):
        try:
            with open(user_css_path, 'r') as css_file:
                stylesheet = css_file.read()
            print(f"Loaded user CSS style from: {user_css_path}")
        except Exception as e:
            print(f"Error loading user CSS: {e}")
    else:
        css_file_path = os.path.join(os.path.dirname(__file__), 'style.css')
        if getattr(sys, 'frozen', False):
            css_file_path = os.path.join(sys._MEIPASS, 'style.css')
        try:
            with open(css_file_path, 'r') as css_file:
                stylesheet = css_file.read()
        except FileNotFoundError:
            print(f"Default CSS file not found: {css_file_path}")
    if stylesheet:
        app = QApplication.instance()
        if app:
            app.setStyleSheet(stylesheet)
        else:
            print("No QApplication instance found. Stylesheet not applied.")



kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
CreateFileW.restype = wintypes.HANDLE
WriteFile = kernel32.WriteFile
WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                      ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
WriteFile.restype = wintypes.BOOL
FlushFileBuffers = kernel32.FlushFileBuffers
FlushFileBuffers.argtypes = [wintypes.HANDLE]
FlushFileBuffers.restype = wintypes.BOOL
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL
bcrypt = ctypes.WinDLL('bcrypt', use_last_error=True)
BCryptGenRandom = bcrypt.BCryptGenRandom
BCryptGenRandom.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                            wintypes.ULONG, wintypes.ULONG]
BCryptGenRandom.restype = wintypes.ULONG
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
GENERIC_WRITE = 0x40000000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_WRITE_THROUGH = 0x80000000
BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002



def get_random_bytes(n):
    buf = ctypes.create_string_buffer(n)
    status = BCryptGenRandom(None, buf, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    if status != 0:
        raise OSError(status, "BCryptGenRandom failed")
    return buf.raw



def delete_vss_snapshots(drive_letter):
    try:
        is_admin = wintypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    if not is_admin:
        logging.info("Skipping VSS snapshot deletion: insufficient privileges.")
        return
    subprocess.run(
        ['vssadmin', 'delete', 'shadows', f'/for={drive_letter}:', '/all', '/quiet'],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )



def overwrite_file(path, passes, chunk_size, progress_cb):
    size = os.path.getsize(path)
    total_ops = passes * ((size + chunk_size - 1) // chunk_size)
    done = 0
    handle = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_FLAG_WRITE_THROUGH,
        None
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError("Failed to open file for overwrite")
    for pass_num in range(passes):
        offset = 0
        while offset < size:
            block = min(chunk_size, size - offset)
            if pass_num == 0:
                data = b'\xFF' * block
            elif pass_num == 1:
                data = b'\x00' * block
            elif pass_num == passes - 1:
                data = get_random_bytes(block)
            elif pass_num % 2 == 0:
                data = get_random_bytes(block)
            else:
                rnd = get_random_bytes(block)
                data = bytes((~b) & 0xFF for b in rnd)
            buf = ctypes.create_string_buffer(data)
            written = wintypes.DWORD()
            if not WriteFile(handle, buf, block, ctypes.byref(written), None) or written.value != block:
                CloseHandle(handle)
                raise OSError("Error writing to file during overwrite")
            FlushFileBuffers(handle)
            offset += block
            done += 1
            if progress_cb:
                progress_cb(int(done / total_ops * 100))
    CloseHandle(handle)



def rename_and_delete(path):
    d, name = os.path.split(path)
    ext = os.path.splitext(name)[1]
    rnd_name = base64.urlsafe_b64encode(get_random_bytes(16)).decode().rstrip('=') + ext
    new_path = os.path.join(d, rnd_name)
    os.rename(path, new_path)
    os.remove(new_path)



def secure_shred_file(file_path, passes=7, progress_callback=None):
    if not os.path.isfile(file_path) or not os.access(file_path, os.W_OK):
        return False, "File missing or unwritable"
    drive = os.path.splitdrive(file_path)[0].rstrip(':\\')
    try:
        delete_vss_snapshots(drive)
        overwrite_file(file_path, passes, 1024*1024, progress_callback)
        rename_and_delete(file_path)
        if progress_callback:
            progress_callback(100)
        return True, file_path
    except Exception as e:
        logging.exception(f"Error shredding file {file_path}: {e}")
        return False, str(e)



class DirectoryScanner(QThread):
    update_progress = pyqtSignal(int)
    file_found = pyqtSignal(str)
    scan_complete = pyqtSignal()

    def __init__(self, directories, parent=None):
        super().__init__(parent)
        self.directories = directories
        self.files = []

    def run(self):
        total_directories = len(self.directories)
        for index, directory in enumerate(self.directories):
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.files.append(file_path)
                    self.file_found.emit(file_path)
            progress = int((index + 1) / total_directories * 100)
            self.update_progress.emit(progress)
        self.scan_complete.emit()



class ShredderThread(QThread):
	update_progress = pyqtSignal(int)
	update_message = pyqtSignal(str)
	update_file_progress = pyqtSignal(int)
	shred_complete = pyqtSignal()
	shred_stopped = pyqtSignal()

	def __init__(self, files, passes, parent=None):
		super().__init__(parent)
		self.files_to_shred = files
		self.passes = passes
		self._stop_flag = False

	def stop(self):
		self._stop_flag = True

	def run(self):
		total_files = len(self.files_to_shred)
		if total_files == 0:
			logging.error("No files to redact.")
			self.shred_complete.emit()
			return
		success_count = 0
		failure_count = 0
		for index, file_path in enumerate(self.files_to_shred):
			if self._stop_flag:
				self.shred_stopped.emit()
				logging.info("Redaction process stopped by user.")
				return
			self.update_file_progress.emit(0)
			success, result = secure_shred_file(
				file_path, self.passes,
				progress_callback=lambda p: self.update_file_progress.emit(p)
			)
			if success:
				success_count += 1
				self.update_message.emit(f"Redacted: {file_path}")
			else:
				failure_count += 1
				self.update_message.emit(f"Failed: {result}")
			self.update_progress.emit(int((index + 1) / total_files * 100))
		dirs = sorted(
			{os.path.dirname(fp) for fp in self.files_to_shred},
			key=lambda d: -d.count(os.sep)
		)
		for d in dirs:
			try:
				os.rmdir(d)
				logging.info(f"Removed empty directory: {d}")
			except OSError:
				pass
		logging.info(f"Redaction Summary: Successful: {success_count}, Failed: {failure_count}")
		self.shred_complete.emit()



class Redact(QWidget):
    def __init__(self):
        super().__init__()
        app_icon = QIcon('ICON.ico')
        self.setWindowIcon(app_icon)
        self.files_to_shred = []
        self.files_to_shred_norm = set()
        self.shredder_thread = None
        self.initUI()
        app_context = {"main_window": self}
        self.plugins = load_plugins(app_context)

    def initUI(self):
        self.setWindowTitle("Raven Redact")
        self.setGeometry(300, 300, 500, 400)
        self.setAcceptDrops(True)
        self.actions = {}
        self.layout = QVBoxLayout()
        self.layout = QVBoxLayout()
        self.menu_bar = QMenuBar(self)
        self.layout.setMenuBar(self.menu_bar)
        self.createMenu()
        self.file_list = QListWidget(self)
        self.layout.addWidget(self.file_list)
        self.file_progress_bar = QProgressBar(self)
        self.file_progress_bar.setValue(0)
        self.layout.addWidget(self.file_progress_bar)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        self.layout.addWidget(self.progress_bar)
        self.shred_button = QPushButton('Shred Files', self)
        self.shred_button.clicked.connect(self.show_pass_dialog)
        self.layout.addWidget(self.shred_button)
        self.stop_button = QPushButton('Stop Shredding', self)
        self.stop_button.clicked.connect(self.stop_shredding)
        self.stop_button.setEnabled(False)
        self.layout.addWidget(self.stop_button)
        self.setLayout(self.layout)
        self.file_list.keyPressEvent = self.list_key_press_event

    def createMenu(self):
        fileMenu = self.menu_bar.addMenu('&File')
        self.createFileActions(fileMenu)
        viewMenu = self.menu_bar.addMenu('&View')
        self.createViewActions(viewMenu)

    def createFileActions(self, menu):
        openFileAction = QAction('Open File...', self)
        openFileAction.setShortcut('Ctrl+O')
        openFileAction.triggered.connect(self.openFile)
        menu.addAction(openFileAction)
        self.actions['open_file'] = openFileAction
        openFolderAction = QAction('Open Folder...', self)
        openFolderAction.setShortcut('Ctrl+Shift+O')
        openFolderAction.triggered.connect(self.openFolder)
        menu.addAction(openFolderAction)
        self.actions['open_folder'] = openFolderAction
        exitAction = QAction('Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.triggered.connect(self.close)
        menu.addAction(exitAction)
        self.actions['exit'] = exitAction

    def createViewActions(self, menu):
        clearSelAction = QAction('Clear Selection', self)
        clearSelAction.setShortcut('Ctrl+L')
        clearSelAction.triggered.connect(self.clearSelection)
        menu.addAction(clearSelAction)
        self.actions['clear_selection'] = clearSelAction

    def openFile(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Open File...", "", "All Files (*)")
        for path in files:
            self.add_file_to_list(path)

    def openFolder(self):
        directory = QFileDialog.getExistingDirectory(self, "Open Folder...")
        if directory:
            self.scan_directory(directory)

    def clearSelection(self):
        self.file_list.clear()
        self.files_to_shred.clear()
        self.files_to_shred_norm.clear()
        self.progress_bar.setValue(0)
        self.file_progress_bar.setValue(0)

    def list_key_press_event(self, event):
        if event.key() == Qt.Key_Delete:
            current_item = self.file_list.currentItem()
            if current_item:
                file_path = current_item.text()
                row = self.file_list.row(current_item)
                self.file_list.takeItem(row)
                normalized_path = os.path.normcase(os.path.abspath(file_path))
                if file_path in self.files_to_shred:
                    self.files_to_shred.remove(file_path)
                if normalized_path in self.files_to_shred_norm:
                    self.files_to_shred_norm.remove(normalized_path)
        else:
            QListWidget.keyPressEvent(self.file_list, event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isfile(file_path):
                normalized_path = os.path.normcase(os.path.abspath(file_path))
                if normalized_path not in self.files_to_shred_norm:
                    self.files_to_shred.append(file_path)
                    self.files_to_shred_norm.add(normalized_path)
                    self.file_list.addItem(file_path)
                else:
                    logging.info(f"File already in list, skipping: {file_path}")
            elif os.path.isdir(file_path):
                self.scan_directory(file_path)
            else:
                logging.warning(f"Invalid file or directory dropped: {file_path}")

    def scan_directory(self, directory):
        dialog = QDialog(self)
        dialog.setWindowTitle("Scanning Directory")
        dialog.setGeometry(400, 400, 300, 100)
        layout = QVBoxLayout(dialog)
        label = QLabel("Scanning files, please wait...", dialog)
        progress_bar = QProgressBar(dialog)
        layout.addWidget(label)
        layout.addWidget(progress_bar)
        scanner_thread = DirectoryScanner([directory])
        scanner_thread.update_progress.connect(progress_bar.setValue)
        scanner_thread.file_found.connect(self.add_file_to_list)
        scanner_thread.scan_complete.connect(dialog.accept)
        scanner_thread.start()
        dialog.exec()

    def add_file_to_list(self, file_path):
        normalized_path = os.path.normcase(os.path.abspath(file_path))
        if normalized_path not in self.files_to_shred_norm:
            self.files_to_shred.append(file_path)
            self.files_to_shred_norm.add(normalized_path)
            self.file_list.addItem(file_path)
        else:
            logging.info(f"File already in list, skipping: {file_path}")

    def show_pass_dialog(self):
        dialog = QDialog(self)
        app_icon = QIcon('ICON.ico')
        dialog.setWindowIcon(app_icon)
        dialog.setWindowTitle("Number of Passes")
        dialog.setGeometry(400, 400, 350, 150)
        dialog.setWindowFlags(dialog.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        layout = QVBoxLayout(dialog)
        label = QLabel("Choose the number of passes:")
        layout.addWidget(label)
        combo = QComboBox()
        combo.addItem("3 Passes (Least Secure)")
        combo.addItem("7 Passes (Standard)")
        combo.addItem("15 Passes (Most Secure)")
        combo.setCurrentIndex(1)
        layout.addWidget(combo)
        tooltip_label = QLabel("<u>What are passes and why are they important?</u>")
        tooltip_label.setToolTip("Passes mean how many times the data is overwritten. More passes make it harder to recover the data.")
        layout.addWidget(tooltip_label)
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(lambda: self.confirm_shredding(combo.currentIndex() + 3, dialog))
        layout.addWidget(ok_button)
        dialog.exec()

    def confirm_shredding(self, passes, parent_dialog):
        total_files = len(self.files_to_shred)
        reply = QMessageBox.question(
            self,
            "Confirmation",
            f"Are you sure you want to proceed with shredding {total_files} file{'s' if total_files != 1 else ''}? {'It' if total_files != 1 else 'They'} cannot be recovered afterwards!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.start_shredding_with_passes(passes)
            parent_dialog.accept()

    def start_shredding_with_passes(self, passes):
        if not self.files_to_shred:
            QMessageBox.warning(self, "No Files", "No files to redact.")
            return
        self.setAcceptDrops(False)
        self.shred_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.shredder_thread = ShredderThread(self.files_to_shred, passes)
        self.shredder_thread.update_message.connect(self.update_message)
        self.shredder_thread.update_progress.connect(self.update_progress)
        self.shredder_thread.update_file_progress.connect(self.update_file_progress)
        self.shredder_thread.shred_complete.connect(self.shred_complete)
        self.shredder_thread.shred_stopped.connect(self.shred_stopped)
        self.shredder_thread.start()

    def stop_shredding(self):
        if self.shredder_thread and self.shredder_thread.isRunning():
            self.shredder_thread.stop()

    def reset_ui(self):
        self.file_list.clear()
        self.files_to_shred = []
        self.files_to_shred_norm.clear()
        self.progress_bar.setValue(0)
        self.file_progress_bar.setValue(0)
        self.setAcceptDrops(True)
        self.shred_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.shredder_thread = None

    @pyqtSlot(str)
    def update_message(self, message):
        items = self.file_list.findItems(message.split(": ")[-1], Qt.MatchExactly)
        if items:
            items[0].setText(message)

    @pyqtSlot(int)
    def update_progress(self, value):
        self.progress_bar.setValue(value)

    @pyqtSlot(int)
    def update_file_progress(self, value):
        self.file_progress_bar.setValue(value)

    @pyqtSlot()
    def shred_complete(self):
        QMessageBox.information(self, "Success", "Redaction process completed.")
        self.reset_ui()

    @pyqtSlot()
    def shred_stopped(self):
        QMessageBox.warning(self, "Stopped", "Redaction process was stopped.")
        self.reset_ui()



if __name__ == '__main__':
    app = QApplication(sys.argv)
    loadStyle()
    ex = Redact()
    ex.show()
    sys.exit(app.exec_())