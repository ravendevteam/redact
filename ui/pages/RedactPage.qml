import QtQuick 2.15
import QtQuick.Layouts 1.15
import Qt.labs.settings 1.1
import "../components"

Item {
	id: root
	anchors.fill: parent

	property var controller: (typeof redactController === "undefined") ? null : redactController
	property bool controllerReady: controller !== null
	property bool shreddingActive: controllerReady ? controller.isShredding : false
	property int currentProgress: controllerReady ? controller.currentFileProgress : 0
	property int overallProgressValue: controllerReady ? controller.overallProgress : 0
	property int pagePadding: 14
	property color panelBorder: "#2A2A2A"
	property color panelBg: "#050505"
	property color panelBgSoft: "#0A0A0A"
	property color textPrimary: "#FFFFFF"
	property color textMuted: "#7A7A7A"

	FontLoader {
		id: interFont
		source: "../fonts/inter.ttf"
	}

	FontLoader {
		id: logFont
		source: "../fonts/cascadia_mono.ttf"
	}

	Settings {
		id: appSettings
		property bool suppressSsdWarning: false
	}

	ListModel { id: fileModel }
	ListModel { id: logModel }

	function normalizeDropPath(value) {
		var raw = ""
		if (value === null || value === undefined)
			return raw
		if (value.toString)
			raw = value.toString()
		else
			raw = String(value)
		if (raw.indexOf("file:///") === 0)
			raw = raw.slice(8)
		else if (raw.indexOf("file://") === 0)
			raw = raw.slice(7)
		raw = decodeURIComponent(raw)
		if (raw.length > 2 && raw[0] === "/" && raw[2] === ":")
			raw = raw.slice(1)
		return raw
	}

	function openConfirmDialog() {
		confirmDialog.title = "Confirm Redaction"
		confirmDialog.message = "Proceed shredding " + fileModel.count + " file" + (fileModel.count !== 1 ? "s" : "") + "? This cannot be reversed."
		confirmDialog.showDialog()
	}

	function handleConfirmAccepted() {
		confirmDialog.hideDialog()
		if (!controllerReady)
			return
		if (!appSettings.suppressSsdWarning) {
			ssdDialog.checkboxChecked = false
			ssdDialog.showDialog()
			return
		}
		controller.startShredding()
	}

	function parseLogMessage(raw) {
		var text = raw === undefined || raw === null ? "" : String(raw)
		var timestampMatch = text.match(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}Z?/)
		var timestamp = timestampMatch ? timestampMatch[0] : ""
		var remainder = timestamp ? text.slice(timestamp.length) : text
		remainder = remainder.replace(/^\s+/, "")
		var tag = ""
		if (remainder.length > 0 && remainder[0] === "[") {
			var idx = remainder.indexOf("]")
			if (idx > 0)
				tag = remainder.slice(0, idx + 1)
		}
		var body = tag.length ? remainder.slice(tag.length).trim() : remainder
		return { timestamp: timestamp, tag: tag, body: body, message: text }
	}

	Connections {
		target: controller

		function onFileAdded(path) {
			fileModel.append({ "path": path })
		}

		function onFilesCleared() {
			fileModel.clear()
		}

		function onLogAdded(message) {
			logModel.append(parseLogMessage(message))
		}

		function onRedactionCompleted(failures, total, stopped) {
			if (stopped || failures === 0 || total === 0)
				return
			failureDialog.title = "Redaction Completed With Errors"
			failureDialog.message = failures + " of " + total + " file(s) failed to redact.\n\nSee the Log for details on each failure."
			failureDialog.showDialog()
		}
	}

	ColumnLayout {
		anchors.fill: parent
		anchors.margins: root.pagePadding
		spacing: 12


		RowLayout {
			Layout.fillWidth: true
			Layout.preferredHeight: 34
			spacing: 10

			PrimaryButton {
				text: "Open File"
				Layout.preferredWidth: 92
				enabled: root.controllerReady && !root.shreddingActive
				fontFamily: interFont.name
				onClicked: {
					if (root.controllerReady)
						root.controller.openFile()
				}
			}

			PrimaryButton {
				text: "Open Folder"
				Layout.preferredWidth: 104
				enabled: root.controllerReady && !root.shreddingActive
				fontFamily: interFont.name
				onClicked: {
					if (root.controllerReady)
						root.controller.openFolder()
				}
			}

			PrimaryButton {
				text: "Clear Selection"
				Layout.preferredWidth: 122
				enabled: root.controllerReady && !root.shreddingActive && fileModel.count > 0
				fontFamily: interFont.name
				onClicked: {
					if (root.controllerReady)
						root.controller.clearSelection()
				}
			}

			Item { Layout.fillWidth: true }

		}

		ColumnLayout {
			Layout.fillWidth: true
			Layout.fillHeight: true
			spacing: 6

			ListPanel {
				id: queuePanel
				Layout.fillWidth: true
				Layout.fillHeight: true
				title: "Queue"
				detailText: fileModel.count + " files"
				emptyText: "Drop files here or use Open File / Open Folder."
				model: fileModel
				textRole: "path"
				fontFamily: interFont.name
				titleColor: root.textPrimary
				detailColor: root.textMuted
				bodyColor: root.textPrimary
				emptyColor: root.textMuted
				borderColor: root.panelBorder
				backgroundColor: root.panelBg
				dropEnabled: true
				dropHighlightColor: "#3A3A3A"

				onDroppedUrls: {
					if (!root.controllerReady)
						return
					for (var i = 0; i < urls.length; i++) {
						var path = root.normalizeDropPath(urls[i])
						if (path && path.length)
							root.controller.addPath(path)
					}
				}
			}

			ListPanel {
				Layout.fillWidth: true
				Layout.fillHeight: true
				title: "Log"
				detailText: logModel.count + " entries"
				emptyText: "No redaction activity yet."
				model: logModel
				textRole: "message"
				fontFamily: interFont.name
				titleColor: root.textPrimary
				detailColor: root.textMuted
				bodyColor: root.textPrimary
				emptyColor: root.textMuted
				borderColor: root.panelBorder
				backgroundColor: root.panelBg
				autoScrollToEnd: true
				delegateComponent: logDelegate
			}
		}

		ColumnLayout {
			Layout.fillWidth: true
			Layout.preferredHeight: 86
			spacing: 10

			ProgressMeter {
				label: "Current file"
				value: root.currentProgress
				fontFamily: interFont.name
				textColor: root.textMuted
				trackColor: root.panelBgSoft
				borderColor: root.panelBorder
			}

			ProgressMeter {
				label: "Overall progress"
				value: root.overallProgressValue
				fontFamily: interFont.name
				textColor: root.textMuted
				trackColor: root.panelBgSoft
				borderColor: root.panelBorder
			}
		}

		RowLayout {
			Layout.fillWidth: true
			Layout.preferredHeight: 36
			spacing: 10

			Item { Layout.fillWidth: true }

			PrimaryButton {
				text: "Shred Files"
				Layout.preferredWidth: 112
				enabled: root.controllerReady && !root.shreddingActive && fileModel.count > 0
				fontFamily: interFont.name
				onClicked: openConfirmDialog()
			}

			PrimaryButton {
				text: "Stop Shredding"
				Layout.preferredWidth: 138
				enabled: root.controllerReady && root.shreddingActive
				fontFamily: interFont.name
				onClicked: {
					if (root.controllerReady)
						root.controller.stopShredding()
				}
			}
		}
	}

	DialogWindow {
		id: confirmDialog
		fontFamily: interFont.name
		primaryText: "Yes"
		secondaryText: "No"
		onAccepted: handleConfirmAccepted()
		onRejected: hideDialog()
	}

	DialogWindow {
		id: ssdDialog
		fontFamily: interFont.name
		title: "SSD Notice"
		message: "Solid-state drives move data around for performance and wear leveling. That means overwriting a file does not always erase every copy of the data. This is fundamentally how SSDs work. Redact is strong against data recovery, but total erasure on SSDs cannot be guaranteed. For highly sensitive data, use full-disk encryption and securely erase the keys."
		primaryText: "Continue"
		secondaryText: "Cancel"
		showCheckbox: true
		checkboxText: "Don't show again"
		onAccepted: {
			hideDialog()
			if (checkboxChecked)
				appSettings.suppressSsdWarning = true
			if (root.controllerReady)
				root.controller.startShredding()
		}
		onRejected: hideDialog()
	}

	DialogWindow {
		id: failureDialog
		fontFamily: interFont.name
		primaryText: "OK"
		onAccepted: hideDialog()
		onRejected: hideDialog()
	}

	Component {
		id: logDelegate

		Item {
			width: ListView.view ? ListView.view.width : 0
			height: Math.max(timestampText.implicitHeight, typeText.implicitHeight, messageText.implicitHeight)

			property string logMessage: (typeof message === "undefined") ? "" : String(message)
			property string logTimestamp: (typeof timestamp === "undefined") ? "" : String(timestamp)
			property string logTag: (typeof tag === "undefined") ? "" : String(tag)
			property string logBody: (typeof body === "undefined") ? logMessage : String(body)

			function typeColor(tag) {
				if (tag === "[INFO]")
					return "#3A8FD8"
				if (tag === "[REDACTED]")
					return "#3FBF6A"
				if (tag === "[FAILURE]" || tag === "[ERROR]")
					return "#D65A5A"
					return root.textPrimary
			}

			RowLayout {
				anchors.fill: parent
				spacing: 6

				Text {
					id: timestampText
					text: logTimestamp
					Layout.preferredWidth: implicitWidth
					Layout.alignment: Qt.AlignVCenter
					color: "#5A5A5A"
					font.family: logFont.name
					font.pixelSize: 12
					elide: Text.ElideRight
				}

				Text {
					id: typeText
					text: logTag
					Layout.preferredWidth: implicitWidth
					Layout.alignment: Qt.AlignVCenter
					color: typeColor(logTag)
					font.family: logFont.name
					font.pixelSize: 12
					elide: Text.ElideRight
					visible: logTag.length > 0
				}

				Text {
					id: messageText
					text: logBody
					Layout.fillWidth: true
					Layout.alignment: Qt.AlignVCenter
					color: root.textPrimary
					font.family: logFont.name
					font.pixelSize: 12
					elide: Text.ElideRight
				}
			}
		}
	}
}
