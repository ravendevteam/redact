import QtQuick 2.15
import QtQuick.Layouts 1.15

Item {
	id: root

	property string title: ""
	property string detailText: ""
	property string emptyText: ""
	property var model: null
	property string textRole: ""
	property string fontFamily: ""
	property string detailFontFamily: ""
	property color titleColor: "#FFFFFF"
	property color detailColor: "#7A7A7A"
	property color bodyColor: "#FFFFFF"
	property color emptyColor: "#7A7A7A"
	property color borderColor: "#2A2A2A"
	property color backgroundColor: "#050505"
	property int titleSize: 13
	property int detailSize: 12
	property int bodySize: 12
	property int padding: 10
	property int itemSpacing: 6
	property bool autoScrollToEnd: false
	property bool pendingAutoScroll: false
	property bool dropEnabled: false
	property Component delegateComponent: null
	signal droppedUrls(var urls)
	property color dropHighlightColor: "#2A2A2A"

	function isEmptyModel() {
		if (!root.model)
			return true
		if (root.model.count !== undefined)
			return root.model.count === 0
		if (root.model.length !== undefined)
			return root.model.length === 0
		return false
	}

	ColumnLayout {
		anchors.fill: parent
		spacing: 6

		SectionHeader {
			Layout.fillWidth: true
			title: root.title
			detail: root.detailText
			fontFamily: root.fontFamily
			detailFontFamily: root.detailFontFamily
			titleColor: root.titleColor
			detailColor: root.detailColor
			titleSize: root.titleSize
			detailSize: root.detailSize
		}

		PanelFrame {
			Layout.fillWidth: true
			Layout.fillHeight: true
			padding: root.padding
			borderColor: root.borderColor
			backgroundColor: root.backgroundColor

			TextListView {
				id: listView
				anchors.fill: parent
				model: root.model
				textRole: root.textRole
				textColor: root.bodyColor
				fontFamily: root.fontFamily
				fontSize: root.bodySize
				itemSpacing: root.itemSpacing
				delegateComponent: root.delegateComponent

				onCountChanged: {
					if (!root.autoScrollToEnd)
						return
					if (count > 0)
						root.pendingAutoScroll = true
				}

				onContentHeightChanged: {
					if (!root.autoScrollToEnd || !root.pendingAutoScroll)
						return
					if (count > 0)
						positionViewAtIndex(count - 1, ListView.End)
					root.pendingAutoScroll = false
				}
			}

			EmptyStateText {
				anchors.centerIn: parent
				text: root.emptyText
				color: root.emptyColor
				font.family: root.fontFamily
				font.pixelSize: root.bodySize
				visible: root.emptyText.length > 0 && root.isEmptyModel()
			}

			DropArea {
				anchors.fill: parent
				enabled: root.dropEnabled
				visible: root.dropEnabled
				onEntered: {
					drag.acceptProposedAction()
					dropOverlay.visible = true
				}

				onExited: dropOverlay.visible = false
				onDropped: {
					drop.acceptProposedAction()
					dropOverlay.visible = false
					root.droppedUrls(drop.urls)
				}
			}

			Rectangle {
				id: dropOverlay
				anchors.fill: parent
				color: "transparent"
				border.color: root.dropHighlightColor
				border.width: 1
				visible: false
			}
		}
	}
}
