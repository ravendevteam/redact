import QtQuick 2.15
import QtQuick.Layouts 1.15

RowLayout {
	id: root

	property string title: ""
	property string detail: ""
	property string fontFamily: ""
	property string detailFontFamily: ""
	property color titleColor: "#FFFFFF"
	property color detailColor: "#7A7A7A"
	property int titleSize: 13
	property int detailSize: 12

	Text {
		text: root.title
		color: root.titleColor
		font.family: root.fontFamily
		font.pixelSize: root.titleSize
	}

	Item { Layout.fillWidth: true }

	Text {
		visible: root.detail.length > 0
		text: root.detail
		color: root.detailColor
		font.family: root.detailFontFamily.length ? root.detailFontFamily : root.fontFamily
		font.pixelSize: root.detailSize
	}
}
