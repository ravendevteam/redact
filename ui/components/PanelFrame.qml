import QtQuick 2.15

Rectangle {
	id: root

	property int padding: 10
	property color borderColor: "#2A2A2A"
	property color backgroundColor: "#050505"
	property int borderWidth: 1
	property alias contentItem: contentItem
	default property alias content: contentItem.data

	color: root.backgroundColor
	border.color: root.borderColor
	border.width: root.borderWidth
	radius: 0

	Item {
		id: contentItem
		anchors.fill: parent
		anchors.margins: root.padding
	}
}
