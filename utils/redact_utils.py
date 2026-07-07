import ctypes
import hashlib
import logging
import os
import secrets
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

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
ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
	wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
	ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
ReadFile.restype = wintypes.BOOL
FlushFileBuffers = kernel32.FlushFileBuffers
FlushFileBuffers.argtypes = [wintypes.HANDLE]
FlushFileBuffers.restype = wintypes.BOOL
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL
DeleteFileW = kernel32.DeleteFileW
DeleteFileW.argtypes = [wintypes.LPCWSTR]
DeleteFileW.restype = wintypes.BOOL
MoveFileExW = kernel32.MoveFileExW
MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
MoveFileExW.restype = wintypes.BOOL
GetFileInformationByHandle = kernel32.GetFileInformationByHandle
GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
GetFileInformationByHandle.restype = wintypes.BOOL
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
GetDiskFreeSpaceW.argtypes = [
	wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
	ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)
]
GetDiskFreeSpaceW.restype = wintypes.BOOL
GetVolumePathNameW = kernel32.GetVolumePathNameW
GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
GetVolumePathNameW.restype = wintypes.BOOL
GetVolumeInformationW = kernel32.GetVolumeInformationW
GetVolumeInformationW.argtypes = [
	wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
	ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
	wintypes.LPWSTR, wintypes.DWORD
]
GetVolumeInformationW.restype = wintypes.BOOL
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
FormatMessageW.argtypes = [
	wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
	wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID
]
FormatMessageW.restype = wintypes.DWORD

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
FindStreamInfoStandard = 0
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
MOVEFILE_REPLACE_EXISTING = 0x00000001
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_COMPRESSED = 0x00000800
FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
MAX_RENAMES_MIN = 3
MAX_RENAMES_MAX = 6
OVERWRITE_PASSES = 2


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
	_fields_ = [
		("StreamSize", ctypes.c_longlong),
		("cStreamName", ctypes.c_wchar * 296)
	]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
	_fields_ = [
		("dwFileAttributes", wintypes.DWORD),
		("ftCreationTime", wintypes.FILETIME),
		("ftLastAccessTime", wintypes.FILETIME),
		("ftLastWriteTime", wintypes.FILETIME),
		("dwVolumeSerialNumber", wintypes.DWORD),
		("nFileSizeHigh", wintypes.DWORD),
		("nFileSizeLow", wintypes.DWORD),
		("nNumberOfLinks", wintypes.DWORD),
		("nFileIndexHigh", wintypes.DWORD),
		("nFileIndexLow", wintypes.DWORD)
	]


NEUTRAL_FILETIME = wintypes.FILETIME()
_epoch_ft = int((datetime(2000, 1, 1, tzinfo=UTC) - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 10**7)
NEUTRAL_FILETIME.dwLowDateTime = _epoch_ft & 0xffffffff
NEUTRAL_FILETIME.dwHighDateTime = (_epoch_ft >> 32) & 0xffffffff

_random_buffer = bytearray(1024 * 1024)


@dataclass(frozen=True)
class FilesystemPolicy:
	name: str
	supported: bool
	full_redact: bool
	support_ads: bool
	support_hard_links: bool
	support_resident_files: bool
	support_sparse: bool
	support_compression: bool


@dataclass(frozen=True)
class UnsupportedFilesystem:
	path: str
	volume_root: str
	filesystem_name: str
	reason: str


FILESYSTEM_POLICIES = {
	"NTFS": FilesystemPolicy("NTFS", True, True, True, True, True, True, True),
	"EXFAT": FilesystemPolicy("exFAT", True, False, False, False, False, False, False),
	"FAT32": FilesystemPolicy("FAT32", True, False, False, False, False, False, False),
}
SUPPORTED_FILESYSTEM_NAMES = "NTFS, exFAT, and FAT32"


def get_last_error_message():
	err = ctypes.get_last_error()
	if not err:
		return ""
	buf = ctypes.create_unicode_buffer(1024)
	flags = 0x00001000
	if FormatMessageW(flags, None, err, 0, buf, len(buf), None):
		return f"{err}: {buf.value.strip()}"
	return f"{err}"


def get_volume_root(path):
	abs_path = os.path.abspath(path)
	buf = ctypes.create_unicode_buffer(32768)
	if not GetVolumePathNameW(abs_path, buf, len(buf)):
		raise OSError(f"GetVolumePathNameW failed {get_last_error_message()}")
	return buf.value


def get_volume_filesystem_name(volume_root):
	volume_name = ctypes.create_unicode_buffer(261)
	filesystem_name = ctypes.create_unicode_buffer(261)
	serial = wintypes.DWORD()
	max_component_len = wintypes.DWORD()
	flags = wintypes.DWORD()
	if not GetVolumeInformationW(
		volume_root,
		volume_name,
		len(volume_name),
		ctypes.byref(serial),
		ctypes.byref(max_component_len),
		ctypes.byref(flags),
		filesystem_name,
		len(filesystem_name)
	):
		raise OSError(f"GetVolumeInformationW failed for {volume_root} {get_last_error_message()}")
	return filesystem_name.value


def policy_for_filesystem(filesystem_name):
	return FILESYSTEM_POLICIES.get(filesystem_name.upper())


def is_reparse_point(path):
	attr = GetFileAttributesW(path)
	if attr == 0xffffffff:
		return False
	return bool(attr & FILE_ATTRIBUTE_REPARSE_POINT)


def collect_filesystem_policies(paths):
	volume_cache = {}
	path_policies = {}
	unsupported = []
	for path in paths:
		abs_path = os.path.abspath(path)
		norm = os.path.normcase(abs_path)
		try:
			volume_root = get_volume_root(abs_path)
			volume_key = os.path.normcase(volume_root)
			if volume_key not in volume_cache:
				fs_name = get_volume_filesystem_name(volume_root)
				volume_cache[volume_key] = (volume_root, fs_name, policy_for_filesystem(fs_name))
			cached_root, fs_name, policy = volume_cache[volume_key]
			if not policy or not policy.supported:
				unsupported.append(UnsupportedFilesystem(
					path=abs_path,
					volume_root=cached_root,
					filesystem_name=fs_name or "unknown",
					reason=f"Unsupported filesystem {fs_name or 'unknown'}"
				))
				continue
			path_policies[norm] = policy
		except Exception as exc:
			unsupported.append(UnsupportedFilesystem(
				path=abs_path,
				volume_root="",
				filesystem_name="unknown",
				reason=str(exc)
			))
	return path_policies, unsupported


def _delete_file_win32(path):
	if not DeleteFileW(path):
		raise OSError(f"Delete failed {get_last_error_message()}")


def _move_file_win32(source, target):
	if not MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING):
		raise OSError(f"Rename failed {get_last_error_message()}")


def _get_hard_link_count(handle):
	info = BY_HANDLE_FILE_INFORMATION()
	if not GetFileInformationByHandle(handle, ctypes.byref(info)):
		return None
	return int(info.nNumberOfLinks)


def _add_warning(result_recorder, message):
	result_recorder.setdefault("warnings", []).append(message)


def _random_int(min_value, max_value):
	return min_value + secrets.randbelow(max_value - min_value + 1)


def _random_token(length):
	value = ""
	while len(value) < length:
		value += secrets.token_urlsafe(length)
	return value[:length]


def _split_spans(total, count):
	base = total // count
	remainder = total % count
	return [base + (1 if i < remainder else 0) for i in range(count)]


def list_alternate_streams(path):
	res = []
	data = WIN32_FIND_STREAM_DATA()
	handle = FindFirstStreamW(path, FindStreamInfoStandard, ctypes.byref(data), 0)
	if handle == INVALID_HANDLE_VALUE:
		return res
	try:
		while True:
			name = data.cStreamName
			if name and name.startswith(":") and name.endswith(":$DATA") and name != "::$DATA":
				base = name.split(":", 2)
				if len(base) >= 2 and base[1]:
					res.append(base[1])
			if not FindNextStreamW(handle, ctypes.byref(data)):
				break
	finally:
		FindClose(handle)
	return res


def refill_random_buf(size):
	if size > len(_random_buffer):
		raise ValueError("size exceeds buffer")
	tmp_type = ctypes.c_ubyte * size
	tmp = tmp_type()
	status = BCryptGenRandom(None, tmp, size, 0x00000002)
	if status != 0:
		raise OSError(status, "BCryptGenRandom failed")
	_random_buffer[:size] = bytes(tmp)
	return _random_buffer


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
	if attr & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE):
		normal = 0x00000080
		SetFileAttributesW(path, normal)
	else:
		clear_attributes(path)


def set_neutral_timestamps(handle):
	SetFileTime(handle, ctypes.byref(NEUTRAL_FILETIME), ctypes.byref(NEUTRAL_FILETIME), ctypes.byref(NEUTRAL_FILETIME))


def get_cluster_size(path):
	drive = os.path.splitdrive(os.path.abspath(path))[0] or "C:"
	sectors = wintypes.DWORD()
	bytes_per_sector = wintypes.DWORD()
	free_clusters = wintypes.DWORD()
	total_clusters = wintypes.DWORD()
	if not GetDiskFreeSpaceW(f"{drive}\\", ctypes.byref(sectors), ctypes.byref(bytes_per_sector), ctypes.byref(free_clusters), ctypes.byref(total_clusters)):
		return 0
	return sectors.value * bytes_per_sector.value


def pad_cluster_slack(handle, original_size, path, stop_flag):
	if stop_flag.is_set():
		return
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
		if stop_flag.is_set():
			break
		w = min(extra, len(_random_buffer))
		refill_random_buf(w)
		written = wintypes.DWORD()
		if not WriteFile(handle, (ctypes.c_char * w).from_buffer_copy(_random_buffer[:w]), w, ctypes.byref(written), None) or written.value != w:
			break
		extra -= w
	FlushFileBuffers(handle)
	if SetFilePointerEx(handle, original_size, None, 0) != 0:
		SetEndOfFile(handle)
	FlushFileBuffers(handle)


def multi_variance_renames(path, stop_flag):
	if stop_flag.is_set():
		return path
	count = _random_int(MAX_RENAMES_MIN, MAX_RENAMES_MAX)
	dirname, name = os.path.split(path)
	ext = os.path.splitext(name)[1]
	current = path
	for _ in range(count):
		if stop_flag.is_set():
			break
		new_len = _random_int(12, 28)
		rnd = _random_token(new_len)
		new_ext_mode = _random_int(0, 9)
		if new_ext_mode == 0:
			new_path = os.path.join(dirname, rnd)
		elif new_ext_mode == 1:
			new_path = os.path.join(dirname, rnd + "." + _random_token(_random_int(2, 4)).lower())
		else:
			new_path = os.path.join(dirname, rnd + ext)
		try:
			_move_file_win32(current, new_path)
			current = new_path
		except OSError:
			break
	return current


def destroy_filename_variants(path, stop_flag):
	if stop_flag.is_set():
		return path
	dirname, name = os.path.split(path)
	ext = os.path.splitext(name)[1]
	current = path
	for new_path in (
		os.path.join(dirname, _random_token(96) + ext),
		os.path.join(dirname, _random_token(8) + "." + _random_token(3).lower())
	):
		if stop_flag.is_set():
			return current
		try:
			_move_file_win32(current, new_path)
			current = new_path
		except OSError:
			return current
	return multi_variance_renames(current, stop_flag)


def _inflate_small_resident(handle, size, path, stop_flag):
	if stop_flag.is_set():
		return size
	if size <= 0:
		return size
	cluster = get_cluster_size(path)
	target = cluster if cluster > 0 else 2048
	if size >= target:
		return size
	if SetFilePointerEx(handle, size, None, 0) == 0:
		return size
	to_add = target - size
	while to_add > 0:
		if stop_flag.is_set():
			break
		w = min(to_add, len(_random_buffer))
		refill_random_buf(w)
		written = wintypes.DWORD()
		if not WriteFile(handle, (ctypes.c_char * w).from_buffer_copy(_random_buffer[:w]), w, ctypes.byref(written), None) or written.value != w:
			break
		to_add -= w
	FlushFileBuffers(handle)
	if SetFilePointerEx(handle, size, None, 0) != 0:
		SetEndOfFile(handle)
	FlushFileBuffers(handle)
	return size


def overwrite_file_random(handle, size, stop_flag, progress_cb=None, base=0, span=90):
	if size <= 0:
		return hashlib.sha256(b"").digest()
	if SetFilePointerEx(handle, 0, None, 0) == 0:
		raise OSError(f"Seek (rewind) failed {get_last_error_message()}")
	hash_ctx = hashlib.sha256()
	remaining = size
	buf_len = len(_random_buffer)
	while remaining > 0:
		if stop_flag.is_set():
			raise RuntimeError("cancelled")
		fill = min(buf_len, remaining)
		refill_random_buf(fill)
		written = wintypes.DWORD()
		if not WriteFile(handle, (ctypes.c_char * fill).from_buffer_copy(_random_buffer[:fill]), fill, ctypes.byref(written), None) or written.value != fill:
			raise OSError(f"Write failed {get_last_error_message()}")
		hash_ctx.update(_random_buffer[:fill])
		remaining -= fill
		if progress_cb:
			done = size - remaining
			p = base + int(done / size * span)
			if p > 100:
				p = 100
			progress_cb(p)
	if not FlushFileBuffers(handle):
		raise OSError(f"Flush failed {get_last_error_message()}")
	return hash_ctx.digest()


def verify_file(handle, size, expected_digest, stop_flag, progress_cb=None, base=90, span=8):
	if size <= 0:
		return True
	if SetFilePointerEx(handle, 0, None, 0) == 0:
		return False
	hash_ctx = hashlib.sha256()
	remaining = size
	buf = (ctypes.c_ubyte * len(_random_buffer))()
	while remaining > 0:
		if stop_flag.is_set():
			raise RuntimeError("cancelled")
		to_read = min(len(_random_buffer), remaining)
		read_bytes = wintypes.DWORD()
		ok = ReadFile(handle, ctypes.byref(buf), to_read, ctypes.byref(read_bytes), None)
		if not ok or read_bytes.value != to_read:
			return False
		chunk = bytes(buf[:to_read])
		hash_ctx.update(chunk)
		remaining -= to_read
		if progress_cb:
			done = size - remaining
			p = base + int(done / size * span)
			if p > 100:
				p = 100
			progress_cb(p)
	return hash_ctx.digest() == expected_digest


def shred_single_path(path, progress_cb, result_recorder, stop_flag, allow_partial_ads, multi_rename=True, verify=True, filesystem_policy=None):
	result_recorder["status"] = "unknown"
	result_recorder.setdefault("warnings", [])
	if is_reparse_point(path):
		result_recorder["status"] = "reparse_point_refused"
		raise OSError("Refusing to redact reparse point")
	policy = filesystem_policy or FILESYSTEM_POLICIES["NTFS"]
	result_recorder["filesystem"] = policy.name
	if not policy.full_redact:
		_add_warning(result_recorder, f"Filesystem {policy.name} is supported, but NTFS-only protections are not available.")
	if policy.support_sparse or policy.support_compression:
		_clear_advanced_attributes(path)
	else:
		clear_attributes(path)
	handle = CreateFileW(
		path,
		GENERIC_WRITE | GENERIC_READ,
		0,
		None,
		OPEN_EXISTING,
		FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN,
		None
	)
	if handle == INVALID_HANDLE_VALUE:
		result_recorder["status"] = "open_failed"
		raise OSError(f"Open failed {get_last_error_message()}")
	if policy.support_hard_links:
		link_count = _get_hard_link_count(handle)
		if link_count is not None:
			result_recorder["hard_links"] = link_count
			if link_count > 1:
				_add_warning(result_recorder, f"File has {link_count} hard links; data may remain accessible until every link is removed.")
	size_ll = ctypes.c_longlong(0)
	if not GetFileSizeEx(handle, ctypes.byref(size_ll)):
		CloseHandle(handle)
		result_recorder["status"] = "size_failed"
		raise OSError(f"GetFileSizeEx failed {get_last_error_message()}")
	orig_size = size_ll.value
	try:
		set_neutral_timestamps(handle)
		pad_cluster_slack(handle, orig_size, path, stop_flag)
		if policy.support_resident_files:
			_inflate_small_resident(handle, orig_size, path, stop_flag)
		if orig_size > 0:
			overwrite_span = 86 if verify else 96
			base = 0
			if verify:
				spans = _split_spans(overwrite_span, OVERWRITE_PASSES * 2)
				for pass_index in range(OVERWRITE_PASSES):
					write_span = spans[pass_index * 2]
					verify_span = spans[(pass_index * 2) + 1]
					digest_written = overwrite_file_random(handle, orig_size, stop_flag, progress_cb, base, write_span)
					base += write_span
					ok = verify_file(handle, orig_size, digest_written, stop_flag, progress_cb, base, verify_span)
					base += verify_span
					if not ok:
						result_recorder["status"] = "verify_failed"
						raise OSError("Verification failed")
			else:
				spans = _split_spans(overwrite_span, OVERWRITE_PASSES)
				for span in spans:
					overwrite_file_random(handle, orig_size, stop_flag, progress_cb, base, span)
					base += span
		if progress_cb:
			progress_cb(96 if verify else 98)
	finally:
		CloseHandle(handle)
	if stop_flag.is_set():
		result_recorder["status"] = "cancelled"
		raise RuntimeError("cancelled")
	streams = list_alternate_streams(path) if policy.support_ads else []
	for s in streams:
		if stop_flag.is_set():
			result_recorder["status"] = "cancelled"
			raise RuntimeError("cancelled")
		stream_path = f"{path}:{s}"
		if policy.support_sparse or policy.support_compression:
			_clear_advanced_attributes(stream_path)
		else:
			clear_attributes(stream_path)
		h2 = CreateFileW(
			stream_path,
			GENERIC_WRITE | GENERIC_READ,
			0,
			None,
			OPEN_EXISTING,
			FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN,
			None
		)
		if h2 == INVALID_HANDLE_VALUE:
			if not allow_partial_ads:
				result_recorder["status"] = "ads_open_failed"
				raise OSError(f"ADS open failed {s}")
			continue
		try:
			size_ll2 = ctypes.c_longlong(0)
			if GetFileSizeEx(h2, ctypes.byref(size_ll2)):
				sz = size_ll2.value
				if sz > 0:
					if verify:
						ads_verify_failed = False
						for _ in range(OVERWRITE_PASSES):
							dw = overwrite_file_random(h2, sz, stop_flag)
							if not verify_file(h2, sz, dw, stop_flag):
								if not allow_partial_ads:
									result_recorder["status"] = "ads_verify_failed"
									raise OSError(f"ADS verify failed {s}")
								ads_verify_failed = True
								break
						if ads_verify_failed:
							continue
					else:
						for _ in range(OVERWRITE_PASSES):
							overwrite_file_random(h2, sz, stop_flag)
			set_neutral_timestamps(h2)
		finally:
			CloseHandle(h2)
		try:
			_delete_file_win32(stream_path)
		except OSError:
			if not allow_partial_ads:
				result_recorder["status"] = "ads_remove_failed"
				raise
	if policy.support_ads:
		remaining_streams = list_alternate_streams(path)
		if remaining_streams:
			result_recorder["ads_remaining"] = len(remaining_streams)
			if not allow_partial_ads:
				result_recorder["status"] = "ads_delete_verify_failed"
				raise OSError(f"ADS delete verification failed; {len(remaining_streams)} stream(s) remain")
	if progress_cb:
		progress_cb(98)
	final_path = path
	if multi_rename and not stop_flag.is_set():
		final_path = destroy_filename_variants(path, stop_flag)
	if stop_flag.is_set():
		result_recorder["status"] = "cancelled"
		raise RuntimeError("cancelled")
	try:
		_delete_file_win32(final_path)
	except OSError as e:
		result_recorder["status"] = "delete_failed"
		raise OSError(str(e))
	result_recorder["streams"] = len(streams)
	result_recorder["size"] = orig_size
	if result_recorder.get("status") not in (
		"verify_failed",
		"delete_failed",
		"ads_open_failed",
		"ads_verify_failed",
		"ads_remove_failed",
		"ads_delete_verify_failed",
		"cancelled"
	):
		result_recorder["status"] = "ok"
	if progress_cb:
		progress_cb(100)


def secure_shred_file(file_path, stop_flag, allow_partial_ads, progress_callback=None, verify=True, filesystem_policy=None):
	rec = {"warnings": []}
	if not os.path.isfile(file_path):
		rec["status"] = "missing"
		return False, "File missing", rec
	if is_reparse_point(file_path):
		rec["status"] = "reparse_point_refused"
		return False, "Refusing to redact reparse point", rec
	policy = filesystem_policy
	if policy is None:
		path_policies, unsupported = collect_filesystem_policies([file_path])
		if unsupported:
			item = unsupported[0]
			rec["status"] = "unsupported_filesystem"
			rec["filesystem"] = item.filesystem_name
			return False, f"Unsupported filesystem {item.filesystem_name}", rec
		policy = path_policies.get(os.path.normcase(os.path.abspath(file_path)), FILESYSTEM_POLICIES["NTFS"])
	try:
		shred_single_path(file_path, progress_callback, rec, stop_flag, allow_partial_ads, verify=verify, filesystem_policy=policy)
		if progress_callback:
			progress_callback(100)
		success = rec.get("status") == "ok"
		return success, rec.get("status"), rec
	except RuntimeError as e:
		return False, str(e), rec
	except Exception as e:
		if "status" not in rec:
			rec["status"] = "exception"
		logger.exception("Error redacting file %s: %s", file_path, e)
		return False, str(e), rec
