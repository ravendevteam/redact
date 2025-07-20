import base64
import ctypes
import hashlib
import importlib.util
import logging
import os
import random
import sys
from ctypes import wintypes
from datetime import datetime, timezone
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
	QAction, QApplication, QFileDialog, QLabel, QMenuBar,
	QMessageBox, QProgressBar, QPushButton, QVBoxLayout, QWidget,
	QListWidget, QDialog
)



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
		except Exception:
			pass
	else:
		css_file_path = os.path.join(os.path.dirname(__file__), 'style.css')
		if getattr(sys, 'frozen', False):
			css_file_path = os.path.join(sys._MEIPASS, 'style.css')
		try:
			with open(css_file_path, 'r') as css_file:
				stylesheet = css_file.read()
		except Exception:
			pass
	if stylesheet:
		app = QApplication.instance()
		if app:
			app.setStyleSheet(stylesheet)



def log_info(msg):
	logging.info(msg)



def log_error(msg):
	logging.error(msg)



def log_exception(msg):
	logging.exception(msg)



_drive_ssd_cache = {}
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
	wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
	wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]
CreateFileW.restype = wintypes.HANDLE
WriteFile = kernel32.WriteFile
WriteFile.argtypes = [
	wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
	ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
WriteFile.restype = wintypes.BOOL
FlushFileBuffers = kernel32.FlushFileBuffers
FlushFileBuffers.argtypes = [wintypes.HANDLE]
FlushFileBuffers.restype = wintypes.BOOL
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL
GetFileSizeEx = kernel32.GetFileSizeEx
GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
GetFileSizeEx.restype = wintypes.BOOL
FindFirstStreamW = kernel32.FindFirstStreamW
FindFirstStreamW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
FindFirstStreamW.restype = wintypes.HANDLE
FindNextStreamW = kernel32.FindNextStreamW
FindNextStreamW.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
FindNextStreamW.restype = wintypes.BOOL
FindClose = kernel32.FindClose
FindClose.argtypes = [wintypes.HANDLE]
FindClose.restype = wintypes.BOOL
DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = [
	wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
	wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
DeviceIoControl.restype = wintypes.BOOL
SetFilePointerEx = kernel32.SetFilePointerEx
SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
SetFilePointerEx.restype = wintypes.BOOL
SetEndOfFile = kernel32.SetEndOfFile
SetEndOfFile.argtypes = [wintypes.HANDLE]
SetEndOfFile.restype = wintypes.BOOL
SetFileTime = kernel32.SetFileTime
SetFileTime.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
SetFileTime.restype = wintypes.BOOL
GetDiskFreeSpaceW = kernel32.GetDiskFreeSpaceW
GetDiskFreeSpaceW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
GetDiskFreeSpaceW.restype = wintypes.BOOL
GetFileAttributesW = kernel32.GetFileAttributesW
GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
GetFileAttributesW.restype = wintypes.DWORD
SetFileAttributesW = kernel32.SetFileAttributesW
SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
SetFileAttributesW.restype = wintypes.BOOL
BCryptGenRandom = bcrypt.BCryptGenRandom
BCryptGenRandom.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.ULONG, wintypes.ULONG]
BCryptGenRandom.restype = wintypes.ULONG
FormatMessageW = kernel32.FormatMessageW
FormatMessageW.argtypes = [wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID]
FormatMessageW.restype = wintypes.DWORD
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_FLAG_WRITE_THROUGH = 0x80000000
MAX_RENAMES_MIN = 3
MAX_RENAMES_MAX = 6
IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
StorageDeviceSeekPenaltyProperty = 7
StorageDeviceTrimProperty = 8
StorageDeviceProperty = 0



class STORAGE_PROPERTY_QUERY(ctypes.Structure):
	_fields_ = [
		("PropertyId", ctypes.c_int),
		("QueryType", ctypes.c_int),
		("AdditionalParameters", ctypes.c_byte * 1)
	]



class STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
	_fields_ = [
		("Version", wintypes.DWORD),
		("Size", wintypes.DWORD),
		("DeviceType", ctypes.c_byte),
		("DeviceTypeModifier", ctypes.c_byte),
		("RemovableMedia", ctypes.c_ubyte),
		("CommandQueueing", ctypes.c_ubyte),
		("VendorIdOffset", wintypes.DWORD),
		("ProductIdOffset", wintypes.DWORD),
		("ProductRevisionOffset", wintypes.DWORD),
		("SerialNumberOffset", wintypes.DWORD),
		("BusType", ctypes.c_byte),
		("RawPropertiesLength", wintypes.DWORD)
	]



class DEVICE_SEEK_PENALTY_DESCRIPTOR(ctypes.Structure):
	_fields_ = [
		("Version", wintypes.DWORD),
		("Size", wintypes.DWORD),
		("IncursSeekPenalty", wintypes.BOOL)
	]



class DEVICE_TRIM_DESCRIPTOR(ctypes.Structure):
	_fields_ = [
		("Version", wintypes.DWORD),
		("Size", wintypes.DWORD),
		("TrimEnabled", wintypes.BOOL)
	]



class WIN32_FIND_STREAM_DATA(ctypes.Structure):
	_fields_ = [
		("StreamSize", ctypes.c_longlong),
		("cStreamName", ctypes.c_wchar * 296)
	]



NEUTRAL_FILETIME = wintypes.FILETIME()
_epoch_ft = int((datetime(2000,1,1,tzinfo=timezone.utc) - datetime(1601,1,1,tzinfo=timezone.utc)).total_seconds()*10**7)
NEUTRAL_FILETIME.dwLowDateTime = _epoch_ft & 0xffffffff
NEUTRAL_FILETIME.dwHighDateTime = (_epoch_ft >> 32) & 0xffffffff



def _query_storage_property(root_drive, property_id, out_size):
	path = f"\\\\.\\{root_drive.rstrip(':')}:"
	h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
	if h == INVALID_HANDLE_VALUE:
		return None
	try:
		query = STORAGE_PROPERTY_QUERY()
		query.PropertyId = property_id
		query.QueryType = 0
		outbuf = ctypes.create_string_buffer(out_size)
		return_len = wintypes.DWORD()
		ok = DeviceIoControl(
			h, IOCTL_STORAGE_QUERY_PROPERTY,
			ctypes.byref(query), ctypes.sizeof(query),
			outbuf, ctypes.sizeof(outbuf),
			ctypes.byref(return_len), None
		)
		if not ok:
			return None
		return outbuf
	finally:
		CloseHandle(h)



def get_last_error_message():
	err = ctypes.get_last_error()
	if not err:
		return ""
	buf = ctypes.create_unicode_buffer(1024)
	flags = 0x00001000
	if FormatMessageW(flags, None, err, 0, buf, len(buf), None):
		return f"{err}: {buf.value.strip()}"
	return f"{err}"



def hash_filename(path):
	return hashlib.sha256(path.encode('utf-8', 'ignore')).hexdigest()



def is_probable_ssd(file_path):
	try:
		root = os.path.splitdrive(os.path.abspath(file_path))[0] or "C:"
		if root in _drive_ssd_cache:
			return _drive_ssd_cache[root]
		result = False
		raw = _query_storage_property(root, StorageDeviceProperty, 1024)
		bus_type = None
		if raw:
			try:
				desc = STORAGE_DEVICE_DESCRIPTOR.from_buffer_copy(raw)
				bus_type = desc.BusType
				if bus_type == 11:
					result = True
			except Exception:
				pass
		if not result:
			sp_raw = _query_storage_property(root, StorageDeviceSeekPenaltyProperty, ctypes.sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR))
			if sp_raw:
				try:
					seek_desc = DEVICE_SEEK_PENALTY_DESCRIPTOR.from_buffer_copy(sp_raw)
					if seek_desc.Version != 0 and seek_desc.IncursSeekPenalty == 0:
						result = True
				except Exception:
					pass
		if not result:
			trim_raw = _query_storage_property(root, StorageDeviceTrimProperty, ctypes.sizeof(DEVICE_TRIM_DESCRIPTOR))
			if trim_raw:
				try:
					trim_desc = DEVICE_TRIM_DESCRIPTOR.from_buffer_copy(trim_raw)
					if trim_desc.Version != 0 and trim_desc.TrimEnabled and (bus_type in (7, 9, 0, None)):
						result = True
				except Exception:
					pass
		if not result and raw:
			try:
				desc = STORAGE_DEVICE_DESCRIPTOR.from_buffer_copy(raw)
				if desc.CommandQueueing and desc.RemovableMedia == 0 and desc.BusType in (7, 9, 11):
					result = True
			except Exception:
				pass
		_drive_ssd_cache[root] = result
		return result
	except Exception:
		return False



def list_alternate_streams(path):
	res = []
	data = WIN32_FIND_STREAM_DATA()
	handle = FindFirstStreamW(path, 1, ctypes.byref(data), 0)
	if handle == INVALID_HANDLE_VALUE:
		return res
	try:
		while True:
			name = data.cStreamName
			if name and name.startswith(":") and name.endswith(":$DATA") and name != "::$DATA":
				base = name.split(":",2)
				if len(base) >= 2 and base[1]:
					res.append(base[1])
			if not FindNextStreamW(handle, ctypes.byref(data)):
				break
	finally:
		FindClose(handle)
	return res



_random_buffer = ctypes.create_string_buffer(1024 * 1024)

def refill_random_buf(size):
	if size > len(_random_buffer):
		raise ValueError("size exceeds buffer")
	status = BCryptGenRandom(None, _random_buffer, size, 0x00000002)
	if status != 0:
		raise OSError(status, "BCryptGenRandom failed")
	return _random_buffer

FILE_ATTRIBUTE_COMPRESSED = 0x00000800
FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200

def clear_attributes(path):
	attr = GetFileAttributesW(path)
	if attr == 0xffffffff:
		return
	normal = 0x00000080
	SetFileAttributesW(path, normal)

def _clear_advanced_attributes(path):
	attr = GetFileAttributesW(path)
	if attr == 0xffffffff:
		return
	normal = 0x00000080
	if attr & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE):
		SetFileAttributesW(path, normal)
	else:
		clear_attributes(path)

def _fsctl_zero_range(handle, start, length):
	FSCTL_SET_ZERO_DATA = 0x000980c8
	class FILE_ZERO_DATA_INFORMATION(ctypes.Structure):
		_fields_=[('FileOffset', ctypes.c_longlong), ('BeyondFinalZero', ctypes.c_longlong)]
	info = FILE_ZERO_DATA_INFORMATION()
	info.FileOffset = start
	info.BeyondFinalZero = start + length
	return_len = wintypes.DWORD()
	DeviceIoControl(handle, FSCTL_SET_ZERO_DATA,
	                ctypes.byref(info), ctypes.sizeof(info),
	                None, 0, ctypes.byref(return_len), None)

def overwrite_stream(handle, size, progress_cb=None, progress_base=0, progress_span=100,
                     pass_mode="random", chacha=None):
	if size <= 0:
		return
	chunk = len(_random_buffer)
	total_chunks = (size + chunk - 1) // chunk
	for idx in range(total_chunks):
		to_write = chunk if (idx < total_chunks - 1) else (size - (chunk * (total_chunks - 1)))
		if pass_mode == "zero":
			ctypes.memset(_random_buffer, 0, to_write)
		elif pass_mode == "ones":
			ctypes.memset(_random_buffer, 0xFF, to_write)
		else:
			refill_random_buf(to_write)
		written = wintypes.DWORD()
		if not WriteFile(handle, _random_buffer, to_write, ctypes.byref(written), None) or written.value != to_write:
			raise OSError(f"Write failed {get_last_error_message()}")
		if progress_cb:
			p = progress_base + int((idx + 1) / total_chunks * progress_span)
			progress_cb(p if p <= 100 else 100)
	if not FlushFileBuffers(handle):
		raise OSError(f"Flush failed {get_last_error_message()}")

def get_cluster_size(path):
	drive = os.path.splitdrive(os.path.abspath(path))[0] or "C:"
	sectors = wintypes.DWORD()
	bytes_per_sector = wintypes.DWORD()
	free_clusters = wintypes.DWORD()
	total_clusters = wintypes.DWORD()
	if not GetDiskFreeSpaceW(f"{drive}\\", ctypes.byref(sectors), ctypes.byref(bytes_per_sector), ctypes.byref(free_clusters), ctypes.byref(total_clusters)):
		return 0
	return sectors.value * bytes_per_sector.value

def pad_cluster_slack(handle, original_size, path, is_ssd):
	if original_size <= 0:
		return
	cluster = get_cluster_size(path)
	if cluster <= 0:
		return
	aligned = ((original_size + cluster - 1) // cluster) * cluster
	if aligned == original_size:
		return
	if SetFilePointerEx(handle, original_size, None, 0) == 0:
		return
	extra = aligned - original_size
	while extra > 0:
		w = min(extra, len(_random_buffer))
		refill_random_buf(w)
		written = wintypes.DWORD()
		if not WriteFile(handle, _random_buffer, w, ctypes.byref(written), None) or written.value != w:
			break
		extra -= w
	FlushFileBuffers(handle)
	if SetFilePointerEx(handle, original_size, None, 0) != 0:
		SetEndOfFile(handle)
	FlushFileBuffers(handle)

def _verify_random_samples(path, original_size, is_ssd):
	if is_ssd or original_size <= 0:
		return True
	try:
		with open(path, "rb", buffering=0) as fd:
			if original_size <= 8192:
				data = fd.read()
				if not data:
					return True
				return len(set(data)) != 1
			sample_size = 32768
			samples = min(10, max(4, original_size // (1024 * 1024)))
			step = max(sample_size, original_size // (samples + 1))
			uniform_value = None
			observed_any = False
			for i in range(samples):
				offset = (i + 1) * step
				if offset >= original_size:
					break
				fd.seek(offset)
				block = fd.read(min(sample_size, original_size - offset))
				if not block:
					continue
				observed_any = True
				bs = set(block)
				if len(bs) > 1:
					return True
				b = next(iter(bs))
				if uniform_value is None:
					uniform_value = b
				elif b != uniform_value:
					return True
			if not observed_any:
				return True
			return False
	except Exception:
		return True

def multi_variance_renames(path, is_ssd):
	base_count = random.randint(MAX_RENAMES_MIN, MAX_RENAMES_MAX)
	if not is_ssd:
		base_count += 2
	chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	dirname, name = os.path.split(path)
	ext = os.path.splitext(name)[1]
	current = path
	for _ in range(base_count):
		new_len = random.randint(12, 24)
		rnd = ''.join(random.choices(chars, k=new_len))
		new_path = os.path.join(dirname, rnd + ext)
		try:
			os.rename(current, new_path)
			current = new_path
		except OSError:
			break
	return current

def set_neutral_timestamps(handle):
	SetFileTime(handle, ctypes.byref(NEUTRAL_FILETIME), ctypes.byref(NEUTRAL_FILETIME), ctypes.byref(NEUTRAL_FILETIME))

def shred_single_path(path, progress_cb, result_recorder, multi_rename=True):
	_clear_advanced_attributes(path)
	is_ssd = is_probable_ssd(path)
	handle = CreateFileW(
		path,
		GENERIC_WRITE | GENERIC_READ,
		0,
		None,
		OPEN_EXISTING,
		FILE_FLAG_WRITE_THROUGH,
		None
	)
	if handle == INVALID_HANDLE_VALUE:
		raise OSError(f"Open failed {get_last_error_message()}")
	size_ll = ctypes.c_longlong(0)
	if not GetFileSizeEx(handle, ctypes.byref(size_ll)):
		CloseHandle(handle)
		raise OSError(f"GetFileSizeEx failed {get_last_error_message()}")
	size = size_ll.value
	try:
		set_neutral_timestamps(handle)
		pad_cluster_slack(handle, size, path, is_ssd)
		if size > 0:
			if is_ssd:
				overwrite_stream(handle, size, progress_cb, 0, 90, pass_mode="random")
			else:
				overwrite_stream(handle, size, progress_cb, 0, 30, pass_mode="zero")
				overwrite_stream(handle, size, progress_cb, 30, 30, pass_mode="ones")
				overwrite_stream(handle, size, progress_cb, 60, 30, pass_mode="random")
	finally:
		CloseHandle(handle)
	streams = list_alternate_streams(path)
	for s in streams:
		stream_path = f"{path}:{s}"
		try:
			_clear_advanced_attributes(stream_path)
			h2 = CreateFileW(
				stream_path,
				GENERIC_WRITE | GENERIC_READ,
				0,
				None,
				OPEN_EXISTING,
				FILE_FLAG_WRITE_THROUGH,
				None
			)
			if h2 != INVALID_HANDLE_VALUE:
				try:
					size_ll = ctypes.c_longlong(0)
					if GetFileSizeEx(h2, ctypes.byref(size_ll)):
						sz = size_ll.value
						if sz > 0:
							if is_ssd:
								overwrite_stream(h2, sz, None, 0, 100, pass_mode="random")
							else:
								overwrite_stream(h2, sz, None, 0, 33, pass_mode="zero")
								overwrite_stream(h2, sz, None, 33, 34, pass_mode="ones")
								overwrite_stream(h2, sz, None, 67, 33, pass_mode="random")
					set_neutral_timestamps(h2)
				finally:
					CloseHandle(h2)
			try:
				os.remove(stream_path)
			except OSError:
				pass
		except Exception:
			pass
	if progress_cb:
		progress_cb(92)
	if not is_ssd and not _verify_random_samples(path, size, is_ssd):
		log_error("Post-write verification failed")
	final_path = path
	if multi_rename:
		final_path = multi_variance_renames(path, is_ssd)
	if progress_cb:
		progress_cb(96)
	if is_ssd and size > 0:
		h = CreateFileW(
			final_path,
			GENERIC_WRITE | GENERIC_READ,
			0,
			None,
			OPEN_EXISTING,
			FILE_FLAG_WRITE_THROUGH,
			None
		)
		if h != INVALID_HANDLE_VALUE:
			try:
				_fsctl_zero_range(h, 0, size)
			finally:
				CloseHandle(h)
	try:
		os.remove(final_path)
	except OSError as e:
		raise OSError(f"Delete failed {e}")
	if progress_cb:
		progress_cb(100)
	result_recorder['ssd'] = is_ssd
	result_recorder['streams'] = len(streams)
	result_recorder['size'] = size

def secure_shred_file(file_path, progress_callback=None):
	rec = {}
	if not os.path.isfile(file_path) or not os.access(file_path, os.W_OK):
		return False, "File missing or unwritable", rec
	try:
		shred_single_path(file_path, progress_callback, rec)
		if progress_callback:
			progress_callback(100)
		return True, file_path, rec
	except Exception as e:
		log_exception(f"Error shredding file {file_path}: {e}")
		return False, str(e), rec



def get_base_dir():
	if getattr(sys, 'frozen', False):
		return os.path.dirname(sys.executable)
	return os.path.dirname(os.path.abspath(__file__))



def first_run_marker_path():
	return os.path.join(get_base_dir(), ".redact_first_run_ssd_notice")



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

	def __init__(self, files, parent=None):
		super().__init__(parent)
		self.files_to_shred = files
		self._stop_flag = False

	def stop(self):
		self._stop_flag = True

	def run(self):
		total_files = len(self.files_to_shred)
		if total_files == 0:
			self.shred_complete.emit()
			return
		for index, file_path in enumerate(self.files_to_shred):
			if self._stop_flag:
				self.shred_stopped.emit()
				return
			self.update_file_progress.emit(0)
			success, result, meta = secure_shred_file(
				file_path,
				progress_callback=lambda p: self.update_file_progress.emit(p)
			)
			display_name = hash_filename(file_path)
			if success:
				prefix = "[REDACTED]"
				self.update_message.emit(f"{prefix} {display_name}")
				log_info(f"REDACTED file_hash={display_name} size={meta.get('size')} streams={meta.get('streams')} ssd={meta.get('ssd')}")
			else:
				prefix = "[FAILURE]"
				self.update_message.emit(f"{prefix} {display_name} {result}")
				log_error(f"FAILURE file_hash={display_name} error={result}")
			self.update_progress.emit(int((index + 1) / total_files * 100))
		self.shred_complete.emit()



class Redact(QWidget):
	def __init__(self):
		super().__init__()
		app_icon = QIcon(os.path.join(get_base_dir(), 'ICON.ico'))
		self.setWindowIcon(app_icon)
		self.files_to_shred = []
		self.files_to_shred_norm = set()
		self.shredder_thread = None
		self.init_ui()
		app_context = {"main_window": self}
		self.plugins = load_plugins(app_context)
		self.warned_ssd_session = False

	def init_ui(self):
		self.setWindowTitle("Raven Redact")
		self.setGeometry(300, 300, 600, 440)
		self.setAcceptDrops(True)
		self.actions = {}
		self.layout = QVBoxLayout()
		self.menu_bar = QMenuBar(self)
		self.layout.setMenuBar(self.menu_bar)
		self.create_menu()
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

	def create_menu(self):
		fileMenu = self.menu_bar.addMenu('&File')
		self.createFileActions(fileMenu)
		viewMenu = self.menu_bar.addMenu('&View')
		self.createViewActions(viewMenu)

	def createFileActions(self, menu):
		open_fileAction = QAction('Open File...', self)
		open_fileAction.setShortcut('Ctrl+O')
		open_fileAction.triggered.connect(self.open_file)
		menu.addAction(open_fileAction)
		self.actions['open_file'] = open_fileAction
		open_folderAction = QAction('Open Folder...', self)
		open_folderAction.setShortcut('Ctrl+Shift+O')
		open_folderAction.triggered.connect(self.open_folder)
		menu.addAction(open_folderAction)
		self.actions['open_folder'] = open_folderAction
		exitAction = QAction('Exit', self)
		exitAction.setShortcut('Ctrl+Q')
		exitAction.triggered.connect(self.close)
		menu.addAction(exitAction)
		self.actions['exit'] = exitAction

	def createViewActions(self, menu):
		clearSelAction = QAction('Clear Selection', self)
		clearSelAction.setShortcut('Ctrl+L')
		clearSelAction.triggered.connect(self.clear_selection)
		menu.addAction(clearSelAction)
		self.actions['clear_selection'] = clearSelAction

	def open_file(self):
		files, _ = QFileDialog.getOpenFileNames(self, "Open File...", "", "All Files (*)")
		for path in files:
			self.add_file_to_list(path)

	def open_folder(self):
		directory = QFileDialog.getExistingDirectory(self, "Open Folder...")
		if directory:
			self.scan_directory(directory)

	def clear_selection(self):
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
				norm = os.path.normcase(os.path.abspath(file_path))
				if file_path in self.files_to_shred:
					self.files_to_shred.remove(file_path)
				if norm in self.files_to_shred_norm:
					self.files_to_shred_norm.remove(norm)
		else:
			QListWidget.keyPressEvent(self.file_list, event)

	def dragEnterEvent(self, event):
		if event.mimeData().hasUrls():
			event.acceptProposedAction()

	def dropEvent(self, event):
		for url in event.mimeData().urls():
			file_path = url.toLocalFile()
			if os.path.isfile(file_path):
				norm = os.path.normcase(os.path.abspath(file_path))
				if norm not in self.files_to_shred_norm:
					self.files_to_shred.append(file_path)
					self.files_to_shred_norm.add(norm)
					self.file_list.addItem(file_path)
			elif os.path.isdir(file_path):
				self.scan_directory(file_path)

	def scan_directory(self, directory):
		dialog = QDialog(self)
		dialog.setWindowTitle("Scanning Directory")
		dialog.setGeometry(400, 400, 300, 100)
		layout = QVBoxLayout(dialog)
		label = QLabel("Scanning files, please wait...", dialog)
		progress_bar = QProgressBar(dialog)
		layout.addWidget(label)
		layout.addWidget(progress_bar)
		self.scanner_thread = DirectoryScanner([directory])
		self.scanner_thread.update_progress.connect(progress_bar.setValue)
		self.scanner_thread.file_found.connect(self.add_file_to_list)
		self.scanner_thread.scan_complete.connect(dialog.accept)
		self.scanner_thread.start()
		dialog.exec()

	def add_file_to_list(self, file_path):
		norm = os.path.normcase(os.path.abspath(file_path))
		if norm not in self.files_to_shred_norm:
			self.files_to_shred.append(file_path)
			self.files_to_shred_norm.add(norm)
			self.file_list.addItem(file_path)

	def show_pass_dialog(self):
		self.confirm_shredding()

	def confirm_shredding(self):
		total_files = len(self.files_to_shred)
		if total_files == 0:
			QMessageBox.warning(self, "No Files", "No files to redact.")
			return
		reply = QMessageBox.question(
			self,
			"Confirmation",
			f"Proceed shredding {total_files} file{'s' if total_files != 1 else ''}? This cannot be reversed.",
			QMessageBox.Yes | QMessageBox.No,
			QMessageBox.No
		)
		if reply == QMessageBox.Yes:
			if self.should_show_ssd_notice():
				self.show_ssd_notice()
			self.start_shredding()

	def should_show_ssd_notice(self):
		if os.path.exists(first_run_marker_path()):
			return False
		return any(is_probable_ssd(p) for p in self.files_to_shred)

	def show_ssd_notice(self):
		msg = (
			"You are deleting files on a solid‑state drive (SSD / NVMe).\n\n"
			"Redact overwrites the live file data and its named streams, "
			"but SSDs silently move and remap physical cells for wear‑leveling. "
			"That means tiny remnants of old data blocks outside the current allocation "
			"could still exist until the drive reuses those cells.\n\n"
			"For everyday secure deletion, Redact's overwrite is strong. "
			"For total assurance (e.g. highly sensitive or regulated data) use full‑disk encryption from day one, "
			"then later remove the encryption key (crypto erase) or run the drive's built‑in Secure Erase/Sanitize. "
			"Physical destruction is the final step for decommissioned media.\n\n"
			"Redact handled your selected files thoroughly; this is an informational notice shown only once."
		)
		QMessageBox.information(self, "SSD Advisory", msg)
		try:
			with open(first_run_marker_path(), "w", encoding="utf-8") as f:
				f.write("shown")
		except Exception:
			pass

	def start_shredding(self):
		if not self.files_to_shred:
			QMessageBox.warning(self, "No Files", "No files to redact.")
			return
		self.setAcceptDrops(False)
		self.shred_button.setEnabled(False)
		self.stop_button.setEnabled(True)
		self.shredder_thread = ShredderThread(self.files_to_shred)
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
		items = self.file_list.findItems(message.split()[-1], Qt.MatchContains)

	@pyqtSlot(int)
	def update_progress(self, value):
		self.progress_bar.setValue(value)
	@pyqtSlot(int)
	def update_file_progress(self, value):
		self.file_progress_bar.setValue(value)

	@pyqtSlot()
	def shred_complete(self):
		QMessageBox.information(self, "Complete", "Redaction process completed.")
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