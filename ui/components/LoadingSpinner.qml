import QtQuick 2.15

Item {
	id: root
	property int size: 24
	property int lineWidth: 3
	property color color: "#FFFFFF"
	property bool running: true
	property int segments: 32

	width: size
	height: size

	Canvas {
		id: canvas
		anchors.fill: parent
		antialiasing: true

		onPaint: {
			var ctx = getContext("2d")
			var radius = Math.max(0, Math.min(width, height) / 2 - root.lineWidth)
			var cx = width / 2
			var cy = height / 2
			var startAngle = 0
			var endAngle = Math.PI * 1.5
			var span = endAngle - startAngle
			var steps = Math.max(2, root.segments)
			var c = root.color

			ctx.clearRect(0, 0, width, height)
			ctx.lineWidth = root.lineWidth
			ctx.lineCap = "round"

			for (var i = 0; i < steps; i++) {
				var t = i / (steps - 1)
				var a0 = startAngle + t * span
				var a1 = startAngle + Math.min(1, (i + 1) / (steps - 1)) * span
				ctx.strokeStyle = Qt.rgba(c.r, c.g, c.b, t)
				ctx.beginPath()
				ctx.arc(cx, cy, radius, a0, a1, false)
				ctx.stroke()
			}
		}
	}

	RotationAnimator on rotation {
		from: 0
		to: 360
		duration: 900
		loops: Animation.Infinite
		running: root.running
	}
}
