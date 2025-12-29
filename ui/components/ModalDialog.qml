import QtQuick 2.15
import QtQuick.Layouts 1.15
import "../components"

Item {
	id: root
	anchors.fill: parent
	visible: false
	z: 999

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

	signal accepted()
	signal rejected()

	Rectangle {
		anchors.fill: parent
		color: "#000000"
		opacity: 0.65

		MouseArea {
			anchors.fill: parent
		}
	}

	Rectangle {
		id: dialogFrame
		width: 420
		color: root.backgroundColor
		border.color: root.borderColor
		border.width: 1
		anchors.centerIn: parent

		ColumnLayout {
			anchors.fill: parent
			spacing: 12

			Rectangle {
				Layout.fillWidth: true
				Layout.preferredHeight: 30
				color: root.titleBarColor

				Text {
					anchors.left: parent.left
					anchors.leftMargin: 10
					anchors.verticalCenter: parent.verticalCenter
					text: root.title
					color: root.textColor
					font.family: root.fontFamily
					font.pixelSize: 12
				}

					PrimaryButton {
						anchors.right: parent.right
						anchors.rightMargin: 4
						anchors.verticalCenter: parent.verticalCenter
						width: 28
						height: 20
						text: "X"
						fontFamily: root.fontFamily
						visible: root.closable
						onClicked: root.rejected()
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
