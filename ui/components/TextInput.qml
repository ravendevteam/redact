import QtQuick 2.15

Item {
	id: root

	property alias text: input.text
	property alias validator: input.validator
	property alias maximumLength: input.maximumLength
	property alias acceptableInput: input.acceptableInput
	property string placeholderText: ""
	property bool enabled: true

	width: 320
	height: 36

	Rectangle {
		anchors.fill: parent
		color: "#000000"
		border.color: "#2A2A2A"
		border.width: 1
	}

	TextInput {
		id: input
		anchors.fill: parent
		anchors.margins: 10
		color: "#FFFFFF"
		font.pixelSize: 13
		enabled: root.enabled
		clip: true
	}

	Text {
		anchors.left: parent.left
		anchors.leftMargin: 10
		anchors.verticalCenter: parent.verticalCenter
		text: root.placeholderText
		color: "#7A7A7A"
		font.pixelSize: 13
		visible: input.text.length === 0
	}
}
