pragma Singleton
import QtQuick 2.15

QtObject {
	property var window: null

	function setWindow(win) {
		window = win
	}

	function resize(width, height) {
		if (!window)
			return
		window.width = width
		window.height = height
	}
}
