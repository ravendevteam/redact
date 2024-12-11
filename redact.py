import sys
import os
import random
import string
import hashlib
import logging
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget, QMessageBox, QProgressBar, QFileDialog, QDialog, QLabel, QComboBox, QHBoxLayout, QToolTip
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot

logging.basicConfig(
    filename="redact.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def secure_shred_file(file_path, passes=7):
    try:
        if not os.path.exists(file_path) or not os.access(file_path, os.W_OK):
            logging.error(f"File not accessible: {file_path}")
            return False

        file_size = os.path.getsize(file_path)
        chunk_size = 64 * 1024

        with open(file_path, 'r+b') as file:
            for i in range(passes):
                file.seek(0)
                for _ in range(0, file_size, chunk_size):
                    data = os.urandom(chunk_size) if i % 2 == 0 else b'\xFF' * chunk_size
                    file.write(data)
                    file.flush()
                    os.fsync(file.fileno())

            file.seek(0)
            for _ in range(0, file_size, chunk_size):
                file.write(b'\x00' * chunk_size)
                file.flush()
                os.fsync(file.fileno())

        with open(file_path, 'w') as file:
            file.truncate(0)
            file.flush()
            os.fsync(file.fileno())

        new_name = ''.join(random.choices(string.ascii_letters + string.digits, k=hashlib.sha256(file_path.encode()).digest_size))
        new_path = os.path.join(os.path.dirname(file_path), new_name)
        os.rename(file_path, new_path)

        logging.info(f"Redacted: {file_path} -> Renamed to: {new_path}")
        return new_path

    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return None

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

            shredded_path = secure_shred_file(file_path, self.passes)
            if shredded_path:
                success_count += 1
                self.update_message.emit(f"Redacted: {file_path}")
            else:
                failure_count += 1
                self.update_message.emit(f"Failed to redact: {file_path}")

            self.update_progress.emit(int((index + 1) / total_files * 100))

        logging.info(f"Redaction Summary: Successful: {success_count}, Failed: {failure_count}")
        self.shred_complete.emit()

class FileShredderApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Raven Redact")
        self.setGeometry(300, 300, 500, 400)
        self.setAcceptDrops(True)

        self.layout = QVBoxLayout()

        self.file_list = QListWidget(self)
        self.layout.addWidget(self.file_list)

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

        self.files_to_shred = []
        self.shredder_thread = None

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isfile(file_path):
                self.files_to_shred.append(file_path)
                self.file_list.addItem(file_path)
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
        self.files_to_shred.append(file_path)
        self.file_list.addItem(file_path)

    def show_pass_dialog(self):
        dialog = QDialog(self)
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
        ok_button.clicked.connect(lambda: self.start_shredding_with_passes(combo.currentIndex() + 3) or dialog.accept())
        layout.addWidget(ok_button)

        dialog.exec()

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
        self.shredder_thread.shred_complete.connect(self.shred_complete)
        self.shredder_thread.shred_stopped.connect(self.shred_stopped)
        self.shredder_thread.start()

    def stop_shredding(self):
        if self.shredder_thread and self.shredder_thread.isRunning():
            self.shredder_thread.stop()

    def reset_ui(self):
        self.file_list.clear()
        self.files_to_shred = []
        self.progress_bar.setValue(0)
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
    ex = FileShredderApp()
    ex.show()
    sys.exit(app.exec_())
