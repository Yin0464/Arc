package com.arc.app

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibilityScope
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

private val PageContentPad = 20.dp
private val PageTopPad = 12.dp
private val TestButtonSize = 44.dp
private val TestIconSize = 24.dp
private val NodeCardHeight = 88.dp
private val NodeGridGap = 12.dp
private val NodeGridPadV = 4.dp

@Composable
internal fun NodePage(
    regionIdx: Int,
    regions: List<Region>,
    selectedNodeIdx: Int,
    onSelectNode: (Int) -> Unit,
    onSelectRegion: (Int) -> Unit,
    animatedVisibilityScope: AnimatedVisibilityScope,
) {
    val palette = LocalAppPalette.current
    val isTesting by AppState.isTestingLatency.collectAsStateWithLifecycle()

    val consumePageNested = remember {
        object : NestedScrollConnection {
            override fun onPostScroll(
                consumed: Offset,
                available: Offset,
                source: NestedScrollSource
            ): Offset = Offset(0f, available.y)

            override suspend fun onPostFling(consumed: Velocity, available: Velocity): Velocity =
                Velocity(0f, available.y)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        awaitPointerEvent()
                    }
                }
            }
            .statusBarsPadding()
            .padding(top = PageTopPad)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    start = PageContentPad,
                    end = PageContentPad - (TestButtonSize - TestIconSize) / 2,
                    bottom = 4.dp,
                )
                .then(
                    with(animatedVisibilityScope) {
                        Modifier.animateEnterExit(
                            enter = fadeIn(tween(380, delayMillis = 70, easing = FastOutSlowInEasing)) +
                                slideInVertically(tween(420, delayMillis = 70, easing = FastOutSlowInEasing)) { it / 6 },
                            exit = fadeOut(tween(300, delayMillis = 90, easing = FastOutSlowInEasing)) +
                                scaleOut(targetScale = 0.97f, animationSpec = tween(320, delayMillis = 90, easing = FastOutSlowInEasing)) +
                                slideOutVertically(tween(320, delayMillis = 90, easing = FastOutSlowInEasing)) { it / 10 },
                        )
                    }
                ),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "选择节点",
                fontSize = 20.sp,
                fontWeight = FontWeight.SemiBold,
                color = palette.textPrimary
            )
            Box(
                modifier = Modifier
                    .size(TestButtonSize)
                    .clickable(
                        enabled = !isTesting,
                        indication = null,
                        interactionSource = null,
                    ) {
                        AppState.triggerBatchLatencyTest()
                    },
                contentAlignment = Alignment.Center
            ) {
                if (isTesting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(TestIconSize),
                        color = palette.brand,
                        strokeWidth = 2.6.dp,
                        strokeCap = StrokeCap.Round
                    )
                } else {
                    LightningBoltIcon(palette.textPrimary)
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                // Keep drop shadows inside the enter/exit layer so the shared-element
                // overlay cannot clip them; reported height stays 32.dp + 10.dp.
                .reserveShadow(ChipShadowReserve)
                .then(
                    with(animatedVisibilityScope) {
                        Modifier.animateEnterExit(
                            enter = fadeIn(tween(400, delayMillis = 120, easing = FastOutSlowInEasing)) +
                                slideInVertically(tween(440, delayMillis = 120, easing = FastOutSlowInEasing)) { it / 5 },
                            exit = fadeOut(tween(280, delayMillis = 40, easing = FastOutSlowInEasing)) +
                                scaleOut(targetScale = 0.96f, animationSpec = tween(300, delayMillis = 40, easing = FastOutSlowInEasing)) +
                                slideOutVertically(tween(300, delayMillis = 40, easing = FastOutSlowInEasing)) { it / 8 },
                        )
                    }
                )
                .padding(
                    start = PageContentPad,
                    end = PageContentPad,
                    top = ChipShadowReserve,
                    bottom = 10.dp + ChipShadowReserve,
                ),
            horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally)
        ) {
            regions.forEachIndexed { idx, region ->
                val name = region.name
                val selected = idx == regionIdx
                val chipTint = if (selected) palette.chipSelected else palette.card
                val chipText by animateColorAsState(
                    if (selected) palette.chipSelectedContent else palette.textPrimary,
                    tween(280, easing = FastOutSlowInEasing),
                    label = "chipText",
                )
                RaisedCard(
                    onClick = { onSelectRegion(idx) },
                    shape = ChipCorner,
                    tint = chipTint,
                    shadowRadius = 10.dp,
                    revealFromPress = true,
                    showRipple = false,
                    modifier = Modifier.weight(1f).height(32.dp),
                ) {
                    BoxWithConstraints(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize().padding(horizontal = 2.dp)) {

                        val density = LocalDensity.current
                        val glyphs = name.length.coerceAtLeast(1) + 0.3f
                        val fitPx = with(density) { maxWidth.toPx() } / glyphs
                        val wantPx = with(density) { 14.sp.toPx() }
                        val sizeSp = with(density) { minOf(wantPx, fitPx).toSp() }
                        Text(
                            text = name,
                            fontSize = sizeSp,
                            maxLines = 1,
                            softWrap = false,
                            color = chipText,
                        )
                    }
                }
            }
        }

        AnimatedContent(
            targetState = regionIdx,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .then(
                    with(animatedVisibilityScope) {
                        Modifier.animateEnterExit(
                            enter = fadeIn(tween(440, delayMillis = 170, easing = FastOutSlowInEasing)) +
                                slideInVertically(tween(480, delayMillis = 170, easing = FastOutSlowInEasing)) { it / 8 },
                            exit = fadeOut(tween(260, easing = FastOutSlowInEasing)) +
                                scaleOut(targetScale = 0.96f, animationSpec = tween(280, easing = FastOutSlowInEasing)) +
                                slideOutVertically(tween(280, easing = FastOutSlowInEasing)) { it / 8 },
                        )
                    }
                ),
            transitionSpec = {
                val dir = if (targetState >= initialState) 1 else -1
                (fadeIn(tween(280, easing = FastOutSlowInEasing)) +
                    slideInHorizontally(tween(340, easing = FastOutSlowInEasing)) { dir * it / 6 }) togetherWith
                    (fadeOut(tween(200, easing = FastOutSlowInEasing)) +
                        slideOutHorizontally(tween(240, easing = FastOutSlowInEasing)) { -dir * it / 6 })
            },
            label = "regionNodes",
        ) { shownIdx ->
            val shownNodes = regions.getOrNull(shownIdx)?.nodes.orEmpty()
            LazyVerticalGrid(
                columns = GridCells.Fixed(2),
                modifier = Modifier
                    .fillMaxSize()
                    .nestedScroll(consumePageNested),
                contentPadding = PaddingValues(horizontal = PageContentPad, vertical = NodeGridPadV),
                horizontalArrangement = Arrangement.spacedBy(NodeGridGap),
                verticalArrangement = Arrangement.spacedBy(NodeGridGap)
            ) {
                itemsIndexed(shownNodes) { idx, node ->
                    NodeCard(
                        name = node.name,
                        proto = node.proto,
                        selected = shownIdx == regionIdx && idx == selectedNodeIdx,
                        latency = AppState.nodeLatencies["${shownIdx}_${idx}"],
                        onClick = { onSelectNode(idx) }
                    )
                }
            }
        }
    }
}

@Composable
private fun NodeCard(
    name: String,
    proto: String,
    selected: Boolean,
    latency: Int?,
    onClick: () -> Unit
) {
    val palette = LocalAppPalette.current
    val bg = if (selected) palette.cardSelected else palette.card
    val titleColor by animateColorAsState(
        if (selected) palette.onBrand else palette.textPrimary,
        tween(280, easing = FastOutSlowInEasing),
        label = "nodeTitle",
    )
    val protoColor by animateColorAsState(
        if (selected) palette.onBrand.copy(alpha = 0.78f) else palette.textSecondary,
        tween(280, easing = FastOutSlowInEasing),
        label = "nodeProto",
    )
    val latColor = latencyTint(latency, selected)

    RaisedCard(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(NodeCardHeight),
        shape = NodeCorner,
        tint = bg,
        shadowRadius = if (selected) 16.dp else 12.dp,
        revealFromPress = true,
        showRipple = false,
    ) {
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = name,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    color = titleColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = proto,
                    fontSize = 13.sp,
                    color = protoColor,
                    maxLines = 1
                )
            }

            if (latency != null) {
                Text(
                    text = if (latency > 0) latency.toString() else "—",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = latColor,
                    modifier = Modifier.padding(start = 6.dp)
                )
            }
        }
    }
}

private fun latencyTint(latency: Int?, selected: Boolean): Color {
    if (latency == null) return Color.Transparent
    val base = when {
        latency < 0 -> LatencyRed
        latency < 150 -> LatencyGreen
        latency < 300 -> LatencyYellow
        else -> LatencyRed
    }
    return if (selected) {
        when {
            latency < 0 -> Color(0xFFFFABAB)
            latency < 150 -> Color(0xFFB9F6CA)
            latency < 300 -> Color(0xFFFFE082)
            else -> Color(0xFFFFABAB)
        }
    } else base
}
