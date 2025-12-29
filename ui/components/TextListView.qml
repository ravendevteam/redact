import QtQuick 2.15

ListView {
	id: list

	property string textRole: ""
	property color textColor: "#FFFFFF"
	property string fontFamily: ""
	property int fontSize: 12
	property int itemSpacing: 6
	property Component delegateComponent: null

	clip: true
	spacing: list.itemSpacing

	function resolveText(row, modelDataValue) {
		if (list.textRole && list.model && list.model.get) {
			var item = list.model.get(row)
			if (item && item[list.textRole] !== undefined)
				return item[list.textRole]
		}
		if (modelDataValue !== undefined) {
			if (list.textRole && modelDataValue[list.textRole] !== undefined)
				return modelDataValue[list.textRole]
			return modelDataValue
		}
		return ""
	}

	Component {
		id: defaultDelegate

		Text {
			text: list.resolveText(index, typeof modelData === "undefined" ? undefined : modelData)
			color: list.textColor
			font.family: list.fontFamily
			font.pixelSize: list.fontSize
			width: list.width
			elide: Text.ElideRight
		}
	}

	delegate: list.delegateComponent ? list.delegateComponent : defaultDelegate
}
