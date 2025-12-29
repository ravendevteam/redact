import os


def remove_empty_dirs(roots: list[str]) -> int:
	removed = 0
	for root in roots:
		if not root or not os.path.isdir(root):
			continue
		for current, _dirs, _files in os.walk(root, topdown=False):
			try:
				if not os.listdir(current):
					os.rmdir(current)
					removed += 1
			except OSError:
				continue
	return removed
