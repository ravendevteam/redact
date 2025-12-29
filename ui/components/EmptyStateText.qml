import QtQuick 2.15

Text {
	id: root

	property int maxWidthOffset: 40

	horizontalAlignment: Text.AlignHCenter
	wrapMode: Text.WordWrap
	width: Math.max(0, parent ? parent.width - root.maxWidthOffset : 0)
}
