import QtQuick 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../components"

Window {
	id: root
	width: dialogFrame.implicitWidth
	height: dialogFrame.implicitHeight
	visible: false
	modality: Qt.ApplicationModal
	flags: Qt.Window | Qt.FramelessWindowHint
	color: "transparent"

	property string title: ""
	property string message: ""
	property string primaryText: "OK"
	property string secondaryText: ""
	property string fontFamily: ""
	property color borderColor: "#2A2A2A"
	property color backgroundColor: "#000000"
	property color titleBarColor: "#000000"
	property color textColor: "#FFFFFF"
	property color mutedColor: "#7A7A7A"
	property bool closable: true
	property bool showCheckbox: false
	property string checkboxText: ""
	property bool checkboxChecked: false

	signal accepted()
	signal rejected()

	function centerOnMain() {
		if (!WindowManager.window)
			return
		x = Math.round(WindowManager.window.x + (WindowManager.window.width - width) / 2)
		y = Math.round(WindowManager.window.y + (WindowManager.window.height - height) / 2)
	}

	function showDialog() {
		centerOnMain()
		visible = true
		raise()
		requestActivate()
	}

	function hideDialog() {
		visible = false
	}

	Rectangle {
		anchors.fill: parent
		color: root.backgroundColor
		border.color: root.borderColor
		border.width: 1
		implicitWidth: 440
		implicitHeight: contentLayout.implicitHeight + 2
		id: dialogFrame

		ColumnLayout {
			id: contentLayout
			anchors.fill: parent
			anchors.margins: 1
			spacing: 12

			Rectangle {
				Layout.fillWidth: true
				Layout.preferredHeight: 30
				color: root.titleBarColor

				MouseArea {
					anchors.fill: parent
					acceptedButtons: Qt.LeftButton
					onPressed: root.startSystemMove()
				}

				Text {
					anchors.left: parent.left
					anchors.leftMargin: 10
					anchors.verticalCenter: parent.verticalCenter
					text: root.title
					color: root.textColor
					font.family: root.fontFamily
					font.pixelSize: 12
				}

				Rectangle {
					anchors.right: parent.right
					anchors.rightMargin: 0
					anchors.top: parent.top
					anchors.bottom: parent.bottom
					width: 28
					color: mouse.containsMouse ? "#B00020" : "transparent"
					visible: root.closable

					Canvas {
						anchors.centerIn: parent
						width: 12
						height: 12
						renderTarget: Canvas.Image

						onPaint: {
							var ctx = getContext("2d")
							ctx.setTransform(1, 0, 0, 1, 0, 0)
							ctx.clearRect(0, 0, width, height)
							ctx.strokeStyle = root.textColor
							ctx.lineWidth = 1
							ctx.lineCap = "square"
							ctx.lineJoin = "miter"

							var offset = 0.5
							ctx.beginPath()
							ctx.moveTo(offset, offset)
							ctx.lineTo(width - offset, height - offset)
							ctx.moveTo(width - offset, offset)
							ctx.lineTo(offset, height - offset)
							ctx.stroke()
						}
					}

					MouseArea {
						id: mouse
						anchors.fill: parent
						hoverEnabled: true
						onClicked: root.rejected()
					}
				}
			}

			ColumnLayout {
				Layout.fillWidth: true
				Layout.margins: 16
				spacing: 12

				Text {
					Layout.fillWidth: true
					text: root.message
					color: root.textColor
					font.family: root.fontFamily
					font.pixelSize: 12
					wrapMode: Text.WordWrap
					horizontalAlignment: Text.AlignLeft
					verticalAlignment: Text.AlignTop
					Layout.alignment: Qt.AlignLeft | Qt.AlignTop
				}

				Item {
					id: checkboxRow
					Layout.fillWidth: true
					Layout.preferredHeight: checkboxContent.implicitHeight
					visible: root.showCheckbox

					Row {
						id: checkboxContent
						anchors.left: parent.left
						anchors.right: parent.right
						anchors.verticalCenter: parent.verticalCenter
						spacing: 8

						Rectangle {
							width: 14
							height: 14
							border.color: root.borderColor
							border.width: 1
							color: "transparent"

							Rectangle {
								anchors.fill: parent
								anchors.margins: 3
								visible: root.checkboxChecked
								color: root.textColor
							}
						}

						Text {
							width: Math.max(0, checkboxRow.width - 22)
							text: root.checkboxText
							color: root.mutedColor
							font.family: root.fontFamily
							font.pixelSize: 12
							wrapMode: Text.WordWrap
						}
					}

					MouseArea {
						anchors.fill: parent
						onClicked: root.checkboxChecked = !root.checkboxChecked
					}
				}

				RowLayout {
					Layout.fillWidth: true
					spacing: 8

					Item { Layout.fillWidth: true }

					PrimaryButton {
						text: root.secondaryText
						fontFamily: root.fontFamily
						visible: root.secondaryText.length > 0
						enabled: root.secondaryText.length > 0
						Layout.preferredWidth: 80
						onClicked: root.rejected()
					}

					PrimaryButton {
						text: root.primaryText
						fontFamily: root.fontFamily
						Layout.preferredWidth: 80
						onClicked: root.accepted()
					}
				}
			}
		}
	}
}
