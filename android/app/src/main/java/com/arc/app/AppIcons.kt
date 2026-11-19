package com.arc.app

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.util.lerp

internal fun DrawScope.poly(color: Color, stroke: Float, vararg pts: Float) {
    val p = Path().apply {
        moveTo(pts[0] * size.width, pts[1] * size.height)
        for (i in 2 until pts.size step 2) lineTo(pts[i] * size.width, pts[i + 1] * size.height)
        if (stroke <= 0f) close()
    }
    drawPath(p, color, style = if (stroke > 0f) Stroke(stroke, cap = StrokeCap.Round, join = StrokeJoin.Round) else Fill)
}

@Composable
internal fun StatusCircleIcon(isRunning: Boolean) {
    val t by animateFloatAsState(
        targetValue = if (isRunning) 1f else 0f,
        animationSpec = spring(dampingRatio = 0.9f, stiffness = 520f),
        label = "statusMark",
    )
    Canvas(modifier = Modifier.size(34.dp)) {
        val s = 2.8.dp.toPx()
        val squash = 1f - 0.07f * (4f * t * (1f - t))
        scale(squash, squash) {
            drawCircle(color = Color.White, style = Stroke(width = s))
            val w = size.width
            val h = size.height
            val a1 = Offset(lerp(0.22f, 0.28f, t) * w, lerp(0.22f, 0.52f, t) * h)
            val a2 = Offset(lerp(0.78f, 0.45f, t) * w, lerp(0.78f, 0.68f, t) * h)
            val b1 = Offset(lerp(0.78f, 0.45f, t) * w, lerp(0.22f, 0.68f, t) * h)
            val b2 = Offset(lerp(0.22f, 0.74f, t) * w, lerp(0.78f, 0.35f, t) * h)
            drawLine(Color.White, a1, a2, strokeWidth = s, cap = StrokeCap.Round)
            drawLine(Color.White, b1, b2, strokeWidth = s, cap = StrokeCap.Round)
        }
    }
}

@Composable
internal fun GlobeIcon(color: Color = Color(0xFF1C1E21)) {
    Canvas(modifier = Modifier.size(34.dp)) {
        val s = 2.8.dp.toPx()
        val r = size.minDimension / 2f - s
        val c = Offset(size.width / 2f, size.height / 2f)
        drawCircle(color = color, radius = r, center = c, style = Stroke(width = s))

        drawOval(
            color = color,
            topLeft = Offset(c.x - r * 0.42f, c.y - r),
            size = Size(r * 0.84f, r * 2f),
            style = Stroke(width = s)
        )

        drawLine(color, Offset(c.x - r, c.y), Offset(c.x + r, c.y), strokeWidth = s, cap = StrokeCap.Round)
        val dy = r * 0.48f
        drawLine(color, Offset(c.x - r * 0.86f, c.y - dy), Offset(c.x + r * 0.86f, c.y - dy), strokeWidth = s, cap = StrokeCap.Round)
        drawLine(color, Offset(c.x - r * 0.86f, c.y + dy), Offset(c.x + r * 0.86f, c.y + dy), strokeWidth = s, cap = StrokeCap.Round)
    }
}

@Composable
internal fun LightningBoltIcon(color: Color = Color(0xFF1C1E21)) {
    Canvas(modifier = Modifier.size(24.dp)) {
        poly(color, 0f, 0.35f, 0.08f, 0.72f, 0.08f, 0.52f, 0.44f, 0.74f, 0.44f, 0.36f, 0.94f, 0.44f, 0.54f, 0.28f, 0.54f)
    }
}
