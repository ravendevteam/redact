import os
import threading
from datetime import datetime, UTC

from PyQt5.QtCore import QObject, QThread, pyqtSignal, pyqtSlot, pyqtProperty
from PyQt5.QtWidgets import QFileDialog

from utils.redact_utils import secure_shred_file
from utils.fs_utils import remove_empty_dirs


def _timestamp() -> str:
	return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


class DirectoryScanner(QThread):
	file_found = pyqtSignal(str)
	scan_complete = pyqtSignal()
	scan_error = pyqtSignal(str)

	def __init__(self, directory: str):
		super().__init__()
		self.directory = directory
		self._stop_flag = threading.Event()

	def stop(self) -> None:
		self._stop_flag.set()

	def run(self) -> None:
		try:
			for root, _, files in os.walk(self.directory):
				if self._stop_flag.is_set():
					break
				for name in files:
					if self._stop_flag.is_set():
						break
					self.file_found.emit(os.path.join(root, name))
		except Exception as exc:
			self.scan_error.emit(str(exc))
		self.scan_complete.emit()


class ShredderThread(QThread):
	file_progress = pyqtSignal(int)
	overall_progress = pyqtSignal(int)
	log_message = pyqtSignal(str)
	completed = pyqtSignal(int, int, bool)

	def __init__(self, files: list[str], allow_partial_ads: bool, verify: bool):
		super().__init__()
		self._files = list(files)
		self._stop_flag = threading.Event()
		self.allow_partial_ads = allow_partial_ads
		self.verify = verify

	def stop(self) -> None:
		self._stop_flag.set()

	def run(self) -> None:
		total = len(self._files)
		if total == 0:
			self.completed.emit(0, 0, False)
			return
		failures = 0
		for index, path in enumerate(self._files):
			if self._stop_flag.is_set():
				self.completed.emit(failures, total, True)
				return
			self.file_progress.emit(0)
			success, status, _meta = secure_shred_file(
				path,
				self._stop_flag,
				self.allow_partial_ads,
				progress_callback=lambda p: self.file_progress.emit(p),
				verify=self.verify
			)
			if self._stop_flag.is_set():
				self.completed.emit(failures, total, True)
				return
			display_name = os.path.basename(path) or path
			if success:
				self.log_message.emit(f"[REDACTED] {display_name} {status}")
			else:
				failures += 1
				self.log_message.emit(f"[FAILURE] {display_name} {status}")
			self.overall_progress.emit(int((index + 1) / total * 100))
		self.completed.emit(failures, total, False)


class RedactController(QObject):
	fileAdded = pyqtSignal(str)
	filesCleared = pyqtSignal()
	logAdded = pyqtSignal(str)
	isShreddingChanged = pyqtSignal(bool)
	fileCountChanged = pyqtSignal(int)
	currentFileProgressChanged = pyqtSignal(int)
	overallProgressChanged = pyqtSignal(int)
	redactionCompleted = pyqtSignal(int, int, bool)

	def __init__(self, log_file_path: str | None = None):
		super().__init__()
		self._files: list[str] = []
		self._files_norm: set[str] = set()
		self._scanners: set[DirectoryScanner] = set()
		self._shredder: ShredderThread | None = None
		self._is_shredding = False
		self._current_file_progress = 0
		self._overall_progress = 0
		self._allow_partial_ads = False
		self._verify = True
		self._folder_roots: set[str] = set()
		self._stop_requested = False
		self._log_file_path = self._normalize_log_path(log_file_path)
		self._log_file_failed = False

	@pyqtProperty(bool, notify=isShreddingChanged)
	def isShredding(self) -> bool:
		return self._is_shredding

	@pyqtProperty(int, notify=fileCountChanged)
	def fileCount(self) -> int:
		return len(self._files)

	@pyqtProperty(int, notify=currentFileProgressChanged)
	def currentFileProgress(self) -> int:
		return self._current_file_progress

	@pyqtProperty(int, notify=overallProgressChanged)
	def overallProgress(self) -> int:
		return self._overall_progress

	def _emit_log(self, message: str) -> None:
		entry = f"{_timestamp()} {message}"
		self.logAdded.emit(entry)
		self._append_log_file(entry)

	def _normalize_log_path(self, path: str | None) -> str:
		if not path:
			return ""
		cleaned = path.strip()
		if not cleaned:
			return ""
		expanded = os.path.expandvars(os.path.expanduser(cleaned))
		return os.path.abspath(expanded)

	def _append_log_file(self, entry: str) -> None:
		if not self._log_file_path or self._log_file_failed:
			return
		try:
			log_dir = os.path.dirname(self._log_file_path)
			if log_dir:
				os.makedirs(log_dir, exist_ok=True)
			with open(self._log_file_path, "a", encoding="utf-8") as handle:
				handle.write(entry.rstrip("\n") + "\n")
		except Exception:
			self._log_file_failed = True

	def _set_is_shredding(self, value: bool) -> None:
		if self._is_shredding == value:
			return
		self._is_shredding = value
		self.isShreddingChanged.emit(value)

	def _set_current_file_progress(self, value: int) -> None:
		value = max(0, min(100, int(value)))
		if self._current_file_progress == value:
			return
		self._current_file_progress = value
		self.currentFileProgressChanged.emit(value)

	def _set_overall_progress(self, value: int) -> None:
		value = max(0, min(100, int(value)))
		if self._overall_progress == value:
			return
		self._overall_progress = value
		self.overallProgressChanged.emit(value)


	def _add_file(self, path: str) -> None:
		if not path:
			return
		abs_path = os.path.abspath(path)
		norm = os.path.normcase(abs_path)
		if norm in self._files_norm:
			return
		self._files.append(abs_path)
		self._files_norm.add(norm)
		self.fileAdded.emit(abs_path)
		self.fileCountChanged.emit(len(self._files))

	def _clear_files(self) -> None:
		self._files.clear()
		self._files_norm.clear()
		self._folder_roots.clear()
		self.filesCleared.emit()
		self.fileCountChanged.emit(0)

	def _scan_folder(self, directory: str) -> None:
		if not directory or not os.path.isdir(directory):
			return
		self._folder_roots.add(os.path.abspath(directory))
		scanner = DirectoryScanner(directory)
		self._scanners.add(scanner)
		scanner.file_found.connect(self._add_file)
		scanner.scan_complete.connect(lambda: self._on_scan_complete(scanner))
		scanner.scan_error.connect(lambda msg: self._emit_log(f"[FAILURE] Scan error {msg}"))
		scanner.start()

	def _on_scan_complete(self, scanner: DirectoryScanner) -> None:
		if scanner in self._scanners:
			self._scanners.remove(scanner)
		self._emit_log(f"[INFO] Scan complete ({self.fileCount} files queued)")

	@pyqtSlot()
	def openFile(self) -> None:
		if self._is_shredding:
			return
		paths, _ = QFileDialog.getOpenFileNames(None, "Open File...", "", "All Files (*)")
		for path in paths:
			if os.path.isfile(path):
				self._add_file(path)

	@pyqtSlot()
	def openFolder(self) -> None:
		if self._is_shredding:
			return
		directory = QFileDialog.getExistingDirectory(None, "Open Folder...")
		if directory:
			self._scan_folder(directory)

	@pyqtSlot(str)
	def addPath(self, path: str) -> None:
		if self._is_shredding:
			return
		if not path:
			return
		if os.path.isdir(path):
			self._scan_folder(path)
		elif os.path.isfile(path):
			self._add_file(path)

	@pyqtSlot()
	def clearSelection(self) -> None:
		if self._is_shredding:
			return
		for scanner in list(self._scanners):
			scanner.stop()
			scanner.wait(250)
		self._scanners.clear()
		if not self._files:
			return
		self._clear_files()
		self._set_current_file_progress(0)
		self._set_overall_progress(0)

	@pyqtSlot()
	def requestShredding(self) -> None:
		if self._is_shredding:
			return
		if not self._files:
			self._emit_log("[FAILURE] No files queued")
			return
		self.startShredding()

	@pyqtSlot()
	def startShredding(self) -> None:
		if self._is_shredding:
			return
		if not self._files:
			self._emit_log("[FAILURE] No files queued")
			return
		self._stop_requested = False
		for scanner in list(self._scanners):
			scanner.stop()
			scanner.wait(250)
		self._scanners.clear()
		self._set_is_shredding(True)
		self._set_current_file_progress(0)
		self._set_overall_progress(0)
		self._emit_log(f"[INFO] Starting redaction for {len(self._files)} files")
		self._shredder = ShredderThread(self._files, self._allow_partial_ads, self._verify)
		self._shredder.file_progress.connect(self._set_current_file_progress)
		self._shredder.overall_progress.connect(self._set_overall_progress)
		self._shredder.log_message.connect(self._emit_log)
		self._shredder.completed.connect(self._on_shred_complete)
		self._shredder.start()

	@pyqtSlot()
	def stopShredding(self) -> None:
		if not self._shredder or not self._shredder.isRunning():
			return
		self._stop_requested = True
		self._emit_log("[INFO] Stop requested")
		self._shredder.stop()

	def _on_shred_complete(self, failures: int, total: int, stopped: bool) -> None:
		if self._shredder:
			self._shredder.quit()
			self._shredder.wait(250)
		self._shredder = None
		self._set_is_shredding(False)
		stop_flag = stopped or self._stop_requested
		if not self._stop_requested and self._folder_roots:
			try:
				removed = remove_empty_dirs(sorted(self._folder_roots))
				if removed:
					self._emit_log(f"[INFO] Removed {removed} empty folder(s)")
			except Exception as exc:
				self._emit_log(f"[FAILURE] Folder cleanup error {exc}")
		if stop_flag:
			self._emit_log("[INFO] Redaction stopped")
		elif failures == 0:
			self._emit_log("[INFO] Redaction complete")
		else:
			self._emit_log(f"[FAILURE] {failures} of {total} file(s) failed")
		self.redactionCompleted.emit(failures, total, stop_flag)
		self._clear_files()
		self._set_current_file_progress(0)
		self._set_overall_progress(0)
