import os
import sys
import threading
from datetime import datetime, UTC
from PyQt5.QtCore import QUrl, Qt, qInstallMessageHandler, QCoreApplication
from PyQt5.QtQml import QQmlApplicationEngine
from PyQt5.QtWidgets import QApplication

from utils.fs_utils import remove_empty_dirs
from utils.redact_controller import RedactController

EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_USAGE = 2
EXIT_FATAL = 3
EXIT_INTERRUPTED = 130

CLI_ALLOWED_KEYS = {
	"file",
	"files",
	"folder",
	"folders",
	"log",
	"silent",
	"verify",
	"help"
}

def _strip_wrapping_quotes(value: str) -> str:
	if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
		return value[1:-1]
	return value

def _parse_bool(value: str) -> bool:
	return value.strip().lower() in ("1", "true", "yes", "on")

def _parse_kv_args(argv: list[str]) -> tuple[dict[str, list[str]], list[str]]:
	kv: dict[str, list[str]] = {}
	cleaned = []
	for arg in argv:
		if "=" not in arg:
			cleaned.append(arg)
			continue
		key, raw_value = arg.split("=", 1)
		key = key.strip().lower()
		value = _strip_wrapping_quotes(raw_value.strip())
		kv.setdefault(key, []).append(value)
	return kv, cleaned

def _timestamp() -> str:
	return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"

def _normalize_log_path(path: str) -> str:
	if not path:
		return ""
	cleaned = path.strip()
	if not cleaned:
		return ""
	expanded = os.path.expandvars(os.path.expanduser(cleaned))
	return os.path.abspath(expanded)

def _make_cli_logger(log_file_path: str, silent: bool):
	log_path = _normalize_log_path(log_file_path)
	log_failed = False

	def _append_to_file(entry: str) -> None:
		nonlocal log_failed
		if not log_path or log_failed:
			return
		try:
			log_dir = os.path.dirname(log_path)
			if log_dir:
				os.makedirs(log_dir, exist_ok=True)
			with open(log_path, "a", encoding="utf-8") as handle:
				handle.write(entry.rstrip("\n") + "\n")
		except Exception:
			log_failed = True

	def _log_line(message: str, *, print_message: bool = True) -> None:
		if log_path and not log_failed:
			_append_to_file(f"{_timestamp()} {message}")
		if print_message and not silent:
			print(message)

	return _log_line

def _install_qt_message_handler() -> None:
	def _handler(mode, context, message):
		print(f"[Qt] {message}")
	qInstallMessageHandler(_handler)

def _app_base_dir() -> str:
	base = getattr(sys, "_MEIPASS", None)
	if base and os.path.isdir(base):
		return base
	if getattr(sys, "frozen", False):
		return os.path.dirname(sys.executable)
	return os.path.dirname(os.path.abspath(__file__))

def resource_path(*parts: str) -> str:
	return os.path.join(_app_base_dir(), *parts)

def _load_qml(engine: QQmlApplicationEngine):
	qml_file = resource_path("ui", "Main.qml")
	if not os.path.isfile(qml_file):
		raise FileNotFoundError(qml_file)
	engine.load(QUrl.fromLocalFile(qml_file))
	if not engine.rootObjects():
		raise RuntimeError("QML failed to load")
	return engine.rootObjects()[0]

def _apply_window_flags(win) -> None:
	win.setFlags(Qt.Window | Qt.FramelessWindowHint)

def _cli_help_text() -> str:
	return "\n".join([
		"Redact",
		"(c) Raven Development Team. Licensed under BSD-3-Clause.",
		"",
		"Usage:",
		"    app.py file=\"C:\\\\folder1\\\\folder2\\\\file_to_redact.txt\"",
		"    app.py folder=\"C:\\\\folder1\\\\folder2\\\\folder_to_redact\"",
		"",
		"Arguments:",
		"    file=PATH       File to redact. Repeat for multiple files.",
		"    files=PATH      Alias for file.",
		"    folder=PATH     Add a folder (recursive). Repeat for multiple folders.",
		"    folders=PATH    Alias for folder.",
		"    log=PATH        Append log entries to file.",
		"    verify=BOOL     Verify last overwrite pass (default: true).",
		"    silent=BOOL     Suppress output/progress bars (default: false).",
		"    help=BOOL       Show this help.",
		"",
		"Notes:",
		"    * Values can be quoted to include spaces.",
		"    * Use repeated arguments for multiple files/folders.",
		"    * Run help=true with no other arguments to show this help.",
		"",
		"Exit codes:",
		f"    {EXIT_SUCCESS}      Success (all files redacted).",
		f"    {EXIT_PARTIAL}      Partial success (one or more failures).",
		f"    {EXIT_USAGE}      Invalid usage / no files queued.",
		f"    {EXIT_FATAL}      Fatal error.",
		f"    {EXIT_INTERRUPTED}    Interrupted (Ctrl+C).",
	])

def _render_bar(value: int, width: int = 24) -> str:
	value = max(0, min(100, int(value)))
	filled = int(width * value / 100)
	return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

class _TerminalProgress:
	def __init__(self, enabled: bool):
		self.enabled = enabled and sys.stdout.isatty()
		self.current = 0
		self.overall = 0
		self._initialized = False
		if self.enabled:
			self._write_lines()

	def update(self, current: int | None = None, overall: int | None = None) -> None:
		if not self.enabled:
			return
		if current is not None:
			self.current = current
		if overall is not None:
			self.overall = overall
		self._write_lines()

	def _write_lines(self) -> None:
		try:
			line1 = f"Current file { _render_bar(self.current) } {self.current:3d}%"
			line2 = f"Overall      { _render_bar(self.overall) } {self.overall:3d}%"
			if self._initialized:
				sys.stdout.write("\x1b[2A\r\x1b[2K" + line1 + "\n")
				sys.stdout.write("\r\x1b[2K" + line2 + "\n")
			else:
				sys.stdout.write(line1 + "\n" + line2 + "\n")
				self._initialized = True
			sys.stdout.flush()
		except Exception:
			self.enabled = False

def _collect_paths(kv: dict[str, list[str]], keys: list[str]) -> list[str]:
	paths: list[str] = []
	for key in keys:
		values = kv.get(key, [])
		paths.extend([v for v in values if v])
	return paths

def _build_file_list(files: list[str], folders: list[str], log_line) -> list[str]:
	seen = set()
	collected: list[str] = []
	def _on_walk_error(err):
		log_line(f"[WARN] Folder scan error: {err}")
	for path in files:
		if not os.path.isfile(path):
			log_line(f"[WARN] File not found: {path}")
			continue
		norm = os.path.normcase(os.path.abspath(path))
		if norm in seen:
			continue
		seen.add(norm)
		collected.append(os.path.abspath(path))
	for folder in folders:
		if not os.path.isdir(folder):
			log_line(f"[WARN] Folder not found: {folder}")
			continue
		try:
			for root, _, file_names in os.walk(folder, onerror=_on_walk_error):
				for name in file_names:
					path = os.path.join(root, name)
					norm = os.path.normcase(os.path.abspath(path))
					if norm in seen:
						continue
					seen.add(norm)
					collected.append(os.path.abspath(path))
		except Exception as exc:
			log_line(f"[WARN] Failed to scan folder {folder}: {exc}")
	return collected

def _run_cli(files: list[str], folders: list[str], silent: bool, verify: bool, log_line) -> int:
	from utils.redact_utils import secure_shred_file

	try:
		file_list = _build_file_list(files, folders, log_line)
		if not file_list:
			log_line("[FAILURE] No files queued")
			return EXIT_USAGE
		log_line(f"[INFO] Starting redaction for {len(file_list)} files", print_message=False)
		stop_flag = threading.Event()
		progress = _TerminalProgress(enabled=not silent)
		fail_messages: list[str] = []
		failures = 0
		total = len(file_list)
		for index, path in enumerate(file_list):
			def _progress_cb(value: int, idx=index, total_files=total):
				overall = int(((idx + (value / 100)) / total_files) * 100)
				progress.update(current=value, overall=overall)
			progress.update(current=0, overall=int((index / total) * 100))
			try:
				success, status, _meta = secure_shred_file(
					path,
					stop_flag,
					allow_partial_ads=False,
					progress_callback=_progress_cb,
					verify=verify
				)
			except Exception as exc:
				success = False
				status = f"Exception {exc.__class__.__name__}"
			display_name = os.path.basename(path) or path
			if success:
				log_line(f"[REDACTED] {display_name} {status}", print_message=False)
			else:
				failures += 1
				message = f"[FAILURE] {display_name} {status}"
				log_line(message, print_message=False)
				if progress.enabled:
					fail_messages.append(message)
				elif not silent:
					print(message)
		progress.update(current=100, overall=100)
		if fail_messages:
			print("\n".join(fail_messages))
		if folders:
			try:
				removed = remove_empty_dirs(sorted(set(folders)))
				if removed:
					log_line(f"[INFO] Removed {removed} empty folder(s)", print_message=False)
			except Exception as exc:
				log_line(f"[WARN] Folder cleanup failed: {exc}")
		if failures == 0:
			log_line("[OK] Redaction complete")
			return EXIT_SUCCESS
		log_line(f"[FAILURE] {failures} file(s) failed")
		return EXIT_PARTIAL
	except KeyboardInterrupt:
		log_line("[INFO] Interrupted")
		return EXIT_INTERRUPTED
	except Exception as exc:
		log_line(f"[FAILURE] Fatal error: {exc}")
		return EXIT_FATAL

def main() -> int:
	argv = sys.argv[1:]
	kv, argv = _parse_kv_args(argv)
	help_requested = False
	if "help" in kv:
		help_requested = any(_parse_bool(value) for value in kv.get("help", []))
	if help_requested:
		has_other_keys = any(key != "help" for key in kv.keys())
		has_other_args = bool(argv)
		if has_other_keys or has_other_args:
			print("[FAILURE] help=true must be used alone.")
			return EXIT_USAGE
		print(_cli_help_text())
		return EXIT_SUCCESS
	silent = _parse_bool(kv.get("silent", ["0"])[-1]) if kv.get("silent") else False
	verify = _parse_bool(kv.get("verify", ["1"])[-1]) if kv.get("verify") else True
	log_file_path = kv.get("log", [""])[-1] if kv.get("log") else ""
	files = _collect_paths(kv, ["file", "files"])
	folders = _collect_paths(kv, ["folder", "folders"])
	use_cli = bool(files or folders)
	log_line = _make_cli_logger(log_file_path, silent)
	if use_cli and kv:
		unknown = sorted(set(kv.keys()) - CLI_ALLOWED_KEYS)
		if unknown:
			log_line(f"[WARN] Unknown CLI keys ignored: {', '.join(unknown)}")
	if use_cli:
		return _run_cli(files, folders, silent, verify, log_line)
	_install_qt_message_handler()
	QCoreApplication.setOrganizationName("Raven Development Team")
	QCoreApplication.setOrganizationDomain("ravendev.example")
	QCoreApplication.setApplicationName("RAVEN Vault")
	qt_argv = [sys.argv[0]] + argv
	app = QApplication(qt_argv)
	engine = QQmlApplicationEngine()
	redact_controller = RedactController(log_file_path=log_file_path)
	engine.rootContext().setContextProperty("redactController", redact_controller)
	window = _load_qml(engine)
	_apply_window_flags(window)
	return app.exec_()

if __name__ == "__main__":
	raise SystemExit(main())
