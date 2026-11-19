package com.arc.app

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.dropShadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.layout
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.util.lerp
import kotlin.math.hypot
import kotlin.math.max

private val ArcEase = CubicBezierEasing(0.22f, 1f, 0.36f, 1f)

@Composable
internal fun AppBackground(modifier: Modifier = Modifier) {
    val palette = LocalAppPalette.current
    Box(modifier = modifier.fillMaxSize().background(palette.bg))
}

@Composable
internal fun RaisedCard(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    shape: Shape,
    tint: Color,
    enabled: Boolean = true,
    shadowRadius: Dp = 18.dp,
    interactionSource: MutableInteractionSource? = null,
    showRipple: Boolean = true,
    rippleRadius: Dp = Dp.Unspecified,
    revealFromPress: Boolean = false,
    morphShadow: Boolean = false,
    underlay: (@Composable BoxScope.() -> Unit)? = null,
    content: @Composable BoxScope.() -> Unit,
) {
    val dark = LocalAppPalette.current.isDark
    val density = LocalDensity.current
    val interaction = interactionSource ?: remember { MutableInteractionSource() }
    val rippleColor = if (dark) Color.White.copy(alpha = 0.28f) else Color.Black.copy(alpha = 0.20f)
    val resolvedIndication = if (showRipple) {
        ripple(bounded = true, radius = rippleRadius, color = rippleColor)
    } else {
        null
    }

    var heightPx by remember { mutableFloatStateOf(0f) }
    val tallPx = LocalWindowInfo.current.containerSize.height.toFloat()
    val morphGrowAmount = morphGrow(heightPx, density, tallPx)
    val drawnShadow = if (morphShadow) {
        shadowRadius * (1f - morphGrowAmount)
    } else {
        shadowDrawn(shadowRadius, heightPx, density)
    }
    val morphPad = if (morphShadow) MaxShadowReserve * (1f - morphGrowAmount) else 0.dp

    var lastPress by remember { mutableStateOf(Offset.Unspecified) }
    var settledColor by remember { mutableStateOf(tint) }
    var incomingColor by remember { mutableStateOf(tint) }
    var revealOrigin by remember { mutableStateOf(Offset.Unspecified) }
    val reveal = remember { Animatable(1f) }

    LaunchedEffect(interaction) {
        interaction.interactions.collect { ev ->
            if (ev is PressInteraction.Press) lastPress = ev.pressPosition
        }
    }
    if (revealFromPress) {
        LaunchedEffect(tint) {
            if (tint == settledColor && reveal.value >= 1f) return@LaunchedEffect
            incomingColor = tint
            revealOrigin = lastPress
            lastPress = Offset.Unspecified
            reveal.snapTo(0f)
            reveal.animateTo(1f, tween(420, easing = ArcEase))
            settledColor = incomingColor
        }
    }

    Box(
        modifier = modifier.onSizeChanged { heightPx = it.height.toFloat() },
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .then(if (morphShadow) Modifier.padding(morphPad) else Modifier)
                .arcDropShadow(shape, drawnShadow, dark)
                .clip(shape)
                .clickable(
                    enabled = enabled,
                    interactionSource = interaction,
                    indication = resolvedIndication,
                    onClick = onClick,
                ),
        ) {
        when {
            revealFromPress -> {
                val p = reveal.value
                Canvas(modifier = Modifier.fillMaxSize()) {
                    drawRect(settledColor)
                    if (p > 0f && (p < 1f || incomingColor != settledColor)) {
                        val o = if (revealOrigin != Offset.Unspecified) {
                            revealOrigin
                        } else {
                            Offset(size.width / 2f, size.height / 2f)
                        }
                        val maxR = hypot(
                            max(o.x, size.width - o.x),
                            max(o.y, size.height - o.y),
                        )
                        val r = maxR * p
                        drawCircle(incomingColor, radius = r, center = o)
                        val edge = (1f - p).coerceAtLeast(0f)
                        if (edge > 0.02f && r > 2f) {
                            drawCircle(
                                color = Color.White.copy(alpha = 0.55f * edge),
                                radius = r,
                                center = o,
                                style = Stroke(width = 12.dp.toPx(), cap = StrokeCap.Round),
                            )
                        }
                    }
                }
            }
            underlay != null -> underlay()
            else -> Box(modifier = Modifier.fillMaxSize().background(tint))
        }
        content()
        }
    }
}

internal val MaxShadowReserve = 32.dp
internal val ChipShadowReserve = 14.dp

internal fun Modifier.reserveShadow(vertical: Dp): Modifier = this.layout { measurable, constraints ->
    val v = vertical.roundToPx()
    val placeable = measurable.measure(constraints)
    val h = (placeable.height - 2 * v).coerceAtLeast(0)
    layout(placeable.width, h) {
        placeable.place(0, -v)
    }
}

internal fun morphGrow(heightPx: Float, density: Density, tallPx: Float): Float {
    val restOuterPx = with(density) { (RegionCardHeight + MaxShadowReserve * 2).toPx() }
    val span = (tallPx - restOuterPx).coerceAtLeast(1f)
    return if (heightPx <= 0f) 0f else ((heightPx - restOuterPx) / span).coerceIn(0f, 1f)
}

internal fun shadowDrawn(shadowRadius: Dp, heightPx: Float, density: Density): Dp {
    if (heightPx <= 0f) return shadowRadius
    val short = with(density) { RegionCardHeight.toPx() }
    val tall = with(density) { 820.dp.toPx() }
    val grow = ((heightPx - short) / (tall - short)).coerceIn(0f, 1f)
    return shadowRadius * (1f - grow)
}

internal fun Modifier.arcDropShadow(shape: Shape, drawnShadow: Dp, dark: Boolean): Modifier =
    if (drawnShadow > 0.5.dp) {
        dropShadow(shape) {
            radius = drawnShadow.toPx()
            color = if (dark) Color.Black.copy(alpha = 0.55f) else Color(0xFF1A2330).copy(alpha = 0.16f)
            offset = Offset(0f, (drawnShadow * 0.38f).toPx())
        }
    } else {
        this
    }

@Composable
internal fun MorphPage(
    modifier: Modifier = Modifier,
    shape: Shape,
    tint: Color,
    shadowRadius: Dp = 22.dp,
    content: @Composable BoxScope.() -> Unit,
) {
    val dark = LocalAppPalette.current.isDark
    val density = LocalDensity.current
    val tallPx = LocalWindowInfo.current.containerSize.height.toFloat()
    var heightPx by remember { mutableFloatStateOf(0f) }
    val grow = morphGrow(heightPx, density, tallPx)
    val drawnShadow = shadowRadius * (1f - grow)
    val pad = MaxShadowReserve * (1f - grow)
    // Shadow and fill live inside the morphing bounds so the shared-element
    // overlay layer cannot clip them away during the transition.
    Box(modifier = modifier.onSizeChanged { heightPx = it.height.toFloat() }) {
        Box(
            Modifier
                .fillMaxSize()
                .padding(pad)
                .arcDropShadow(shape, drawnShadow, dark)
                .clip(shape)
                .background(tint)
        )
        Box(Modifier.fillMaxSize().padding(pad), content = content)
    }
}

internal val RegionCardHeight = 122.dp

internal object MorphPageShape : Shape {
    override fun createOutline(
        size: Size,
        layoutDirection: LayoutDirection,
        density: Density,
    ): Outline {
        val short = with(density) { RegionCardHeight.toPx() }
        val tall = with(density) { 820.dp.toPx() }
        val t = ((size.height - short) / (tall - short)).coerceIn(0f, 1f)
        val radius = with(density) { lerp(24.dp.toPx(), 0.dp.toPx(), t) }
        return Outline.Rounded(
            RoundRect(
                rect = Rect(0f, 0f, size.width, size.height),
                topLeft = CornerRadius(radius),
                topRight = CornerRadius(radius),
                bottomRight = CornerRadius(radius),
                bottomLeft = CornerRadius(radius),
            )
        )
    }
}
