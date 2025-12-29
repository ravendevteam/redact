import QtQuick 2.15

Rectangle {
	id: root

	property string text: ""
	property string fontFamily: ""
	property bool enabled: true
	signal clicked()

	width: 84
	height: 32
	color: !enabled ? "#000000" : (mouse.containsMouse ? "#111111" : "#000000")
	border.color: "#2A2A2A"
	border.width: 1

	Text {
		anchors.centerIn: parent
		text: root.text
		color: root.enabled ? "#FFFFFF" : "#7A7A7A"
		font.pixelSize: 13
		font.family: root.fontFamily
	}

	MouseArea {
		id: mouse
		anchors.fill: parent
		hoverEnabled: true
		enabled: root.enabled
		onClicked: root.clicked()
	}
}
