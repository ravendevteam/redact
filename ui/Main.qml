import QtQuick 2.15
import QtQuick.Window 2.15
import "components" as Components
import "pages"

Window {
	id: window
	visible: true
	width: 550
	height: 640
	color: "transparent"
	title: "Raven Redact"
	flags: Qt.Window | Qt.FramelessWindowHint

	property int titleBarHeight: 38
	property int titleFontSize: 14
	property int titleVaultOffsetY: -1
	property color borderColor: "#2A2A2A"
	property bool isMaximized: (visibility === Window.Maximized)
	property int resizeMargin: 6

	Component.onCompleted: {
		Components.WindowManager.setWindow(window)
		Qt.callLater(function() {
			window.x = Math.round((Screen.width - window.width) / 2)
			window.y = Math.round((Screen.height - window.height) / 2)
		})
	}



	FontLoader {
		id: chakraPetchFont
		source: "fonts/chakra_petch.ttf"
	}

	FontLoader {
		id: interFont
		source: "fonts/inter.ttf"
	}

	Rectangle {
		id: rootFrame
		anchors.fill: parent
		color: "transparent"
		border.color: window.borderColor
		border.width: 1

		Rectangle {
			id: titleBar
			x: 0
			y: 0
			width: parent.width
			height: window.titleBarHeight
			color: "#000000"

			MouseArea {
				anchors.fill: parent
				acceptedButtons: Qt.LeftButton

				onPressed: window.startSystemMove()

				onDoubleClicked: {
					if (window.visibility === Window.Maximized)
						window.visibility = Window.Windowed
					else
						window.visibility = Window.Maximized
				}
			}

			Row {
				anchors.left: parent.left
				anchors.leftMargin: 12
				anchors.verticalCenter: parent.verticalCenter
				height: parent.height
				width: parent.width - buttonsRow.width - 24
				spacing: 4
				clip: true

				Text {
					text: "RAVEN"
					color: "#FFFFFF"
					font.family: chakraPetchFont.name
					font.pixelSize: window.titleFontSize
					font.bold: true
					y: 1
					height: parent.height
					verticalAlignment: Text.AlignVCenter
				}

				Text {
					text: "Redact"
					color: "#FFFFFF"
						font.pixelSize: window.titleFontSize
					y: window.titleVaultOffsetY + 1
					height: parent.height
					verticalAlignment: Text.AlignVCenter
					elide: Text.ElideRight
				}

				Item {
					width: 12
					height: 1
				}

				Text {
					text: " "
					color: "#FFFFFF"
						font.pixelSize: window.titleFontSize
					height: parent.height
					verticalAlignment: Text.AlignVCenter
				}
			}

			Row {
				id: buttonsRow
				spacing: 0
				anchors.right: parent.right
				anchors.top: parent.top
				anchors.bottom: parent.bottom

				VectorTitleButton {
					iconType: "minimize"
					onClicked: window.showMinimized()
				}

				VectorMaximizeButton {
					onClicked: {
						if (window.visibility === Window.Maximized)
							window.visibility = Window.Windowed
						else
							window.visibility = Window.Maximized
					}
				}

				VectorTitleButton {
					iconType: "close"
					iconSize: 12
					hoverColor: "#B00020"
					onClicked: Qt.quit()
				}
			}
		}

		Rectangle {
			x: 0
			y: window.titleBarHeight
			width: parent.width
			height: 1
			color: window.borderColor
		}

		Rectangle {
			id: contentBackground
			x: 0
			y: window.titleBarHeight + 1
			width: parent.width
			height: parent.height - window.titleBarHeight - 1
			color: "#000000"
			opacity: 0.9

			Loader {
				id: pageLoader
				anchors.fill: parent
				sourceComponent: redactPageComponent
			}
		}
	}


	Component {
		id: redactPageComponent

		RedactPage { }
	}

	Rectangle {
		anchors.fill: parent
		color: "transparent"
		border.color: window.borderColor
		border.width: 1
	}

	MouseArea {
		anchors.left: parent.left
		anchors.top: parent.top
		anchors.bottom: parent.bottom
		width: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeHorCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.LeftEdge)
	}

	MouseArea {
		anchors.right: parent.right
		anchors.top: parent.top
		anchors.bottom: parent.bottom
		width: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeHorCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.RightEdge)
	}

	MouseArea {
		anchors.left: parent.left
		anchors.right: parent.right
		anchors.top: parent.top
		height: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeVerCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.TopEdge)
	}

	MouseArea {
		anchors.left: parent.left
		anchors.right: parent.right
		anchors.bottom: parent.bottom
		height: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeVerCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.BottomEdge)
	}

	MouseArea {
		anchors.left: parent.left
		anchors.top: parent.top
		width: window.resizeMargin
		height: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeFDiagCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.TopEdge | Qt.LeftEdge)
	}

	MouseArea {
		anchors.right: parent.right
		anchors.top: parent.top
		width: window.resizeMargin
		height: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeBDiagCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.TopEdge | Qt.RightEdge)
	}

	MouseArea {
		anchors.left: parent.left
		anchors.bottom: parent.bottom
		width: window.resizeMargin
		height: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeBDiagCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.BottomEdge | Qt.LeftEdge)
	}

	MouseArea {
		anchors.right: parent.right
		anchors.bottom: parent.bottom
		width: window.resizeMargin
		height: window.resizeMargin
		acceptedButtons: Qt.LeftButton
		cursorShape: Qt.SizeFDiagCursor
		enabled: !window.isMaximized
		onPressed: window.startSystemResize(Qt.BottomEdge | Qt.RightEdge)
	}

	component TitleButton: Rectangle {
		width: 46
		height: parent.height
		color: "transparent"

		property string text: ""
		property string iconSource: ""
		property int iconSize: 12
		property bool smoothIcon: false
		property color hoverColor: "#1A1A1A"
		signal clicked()

		Rectangle {
			anchors.fill: parent
			color: mouse.containsMouse ? hoverColor : "transparent"
		}

		Image {
			anchors.centerIn: parent
			width: parent.iconSize
			height: parent.iconSize
			sourceSize.width: parent.iconSize
			sourceSize.height: parent.iconSize
			source: parent.iconSource
			visible: parent.iconSource.length > 0
			fillMode: Image.PreserveAspectFit
			smooth: parent.smoothIcon
			antialiasing: parent.smoothIcon
			mipmap: parent.smoothIcon
		}

		MouseArea {
			id: mouse
			anchors.fill: parent
			hoverEnabled: true
			onClicked: parent.clicked()
		}
	}

	component MaximizeButton: Rectangle {
		width: 46
		height: parent.height
		color: "transparent"
		signal clicked()

		property bool isMaximized: window.visibility === Window.Maximized
		property color hoverColor: "#1A1A1A"
		property int iconSize: 12
		property bool smoothIcon: false

		Rectangle {
			anchors.fill: parent
			color: mouse.containsMouse ? hoverColor : "transparent"
		}

		Image {
			anchors.centerIn: parent
			width: parent.iconSize
			height: parent.iconSize
			sourceSize.width: parent.iconSize
			sourceSize.height: parent.iconSize
			source: isMaximized ? "images/restore.png" : "images/maximize.png"
			fillMode: Image.PreserveAspectFit
			smooth: parent.smoothIcon
			antialiasing: parent.smoothIcon
			mipmap: parent.smoothIcon
		}

		MouseArea {
			id: mouse
			anchors.fill: parent
			hoverEnabled: true
			onClicked: parent.clicked()
		}
	}

	component VectorTitleButton: Rectangle {
		width: 46
		height: parent.height
		color: "transparent"

		property string iconType: "minimize"
		property int iconSize: 12
		property real lineWidth: 1
		property color strokeColor: "#FFFFFF"
		property color hoverColor: "#1A1A1A"
		signal clicked()

		Rectangle {
			anchors.fill: parent
			color: mouse.containsMouse ? hoverColor : "transparent"
		}

		Canvas {
			id: iconCanvas
			anchors.centerIn: parent
			width: parent.iconSize
			height: parent.iconSize
			renderTarget: Canvas.Image

			onPaint: {
				var ctx = getContext("2d")
				ctx.setTransform(1, 0, 0, 1, 0, 0)
				ctx.clearRect(0, 0, width, height)
				ctx.strokeStyle = parent.strokeColor
				ctx.lineWidth = parent.lineWidth
				ctx.lineCap = "square"
				ctx.lineJoin = "miter"

				var offset = 0.5
				if (parent.iconType === "minimize") {
					var y = Math.round(height / 2) + 0.5
					ctx.beginPath()
					ctx.moveTo(offset, y)
					ctx.lineTo(width - offset, y)
					ctx.stroke()
				} else if (parent.iconType === "maximize") {
					ctx.strokeRect(offset, offset, width - 2 * offset, height - 2 * offset)
				} else if (parent.iconType === "restore") {
					var shift = 2
					ctx.fillStyle = "#000000"
					ctx.strokeRect(offset + shift, offset, width - 2 * offset - shift, height - 2 * offset - shift)
					ctx.fillRect(offset, offset + shift, width - 2 * offset - shift, height - 2 * offset - shift)
					ctx.strokeRect(offset, offset + shift, width - 2 * offset - shift, height - 2 * offset - shift)
				} else if (parent.iconType === "close") {
					ctx.beginPath()
					ctx.moveTo(offset, offset)
					ctx.lineTo(width - offset, height - offset)
					ctx.moveTo(width - offset, offset)
					ctx.lineTo(offset, height - offset)
					ctx.stroke()
				}
			}
		}

		MouseArea {
			id: mouse
			anchors.fill: parent
			hoverEnabled: true
			onClicked: parent.clicked()
		}

		onIconTypeChanged: iconCanvas.requestPaint()
		onIconSizeChanged: iconCanvas.requestPaint()
		onStrokeColorChanged: iconCanvas.requestPaint()
	}

	component VectorMaximizeButton: VectorTitleButton {
		property bool isMaximized: window.visibility === Window.Maximized
		iconType: isMaximized ? "restore" : "maximize"
	}
}
