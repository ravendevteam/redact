import QtQuick 2.15
import QtQuick.Layouts 1.15

Item {
	id: root

	property string label: ""
	property int value: 0
	property string fontFamily: ""
	property color textColor: "#7A7A7A"
	property color trackColor: "#0A0A0A"
	property color borderColor: "#2A2A2A"
	property color fillColor: "#141414"
	property int textSize: 11
	property int barHeight: 10
	property int spacing: 6

	implicitHeight: textSize + spacing + barHeight

	Layout.fillWidth: true
	Layout.preferredHeight: implicitHeight

	Column {
		anchors.fill: parent
		spacing: root.spacing

		RowLayout {
			width: parent.width
			height: root.textSize + 3

			Text {
				text: root.label
				color: root.textColor
				font.family: root.fontFamily
				font.pixelSize: root.textSize
			}

			Item { Layout.fillWidth: true }

			Text {
				text: Math.max(0, Math.min(100, root.value)) + "%"
				color: root.textColor
				font.family: root.fontFamily
				font.pixelSize: root.textSize
			}
		}

		Rectangle {
			width: parent.width
			height: root.barHeight
			radius: 0
			color: root.trackColor
			border.color: root.borderColor
			border.width: 1

			Rectangle {
				height: parent.height
				width: parent.width * Math.max(0, Math.min(1, root.value / 100))
				radius: 0
				color: root.fillColor
			}
		}
	}
}
