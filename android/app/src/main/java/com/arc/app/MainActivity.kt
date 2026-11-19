package com.arc.app

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.BoundsTransform
import androidx.compose.animation.ExperimentalSharedTransitionApi
import androidx.compose.animation.SharedTransitionLayout
import androidx.compose.animation.SharedTransitionScope
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.addOutline
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.util.lerp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.hypot
import kotlin.math.max

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.auto(
                android.graphics.Color.TRANSPARENT,
                android.graphics.Color.TRANSPARENT
            ),
            navigationBarStyle = SystemBarStyle.auto(
                android.graphics.Color.TRANSPARENT,
                android.graphics.Color.TRANSPARENT
            )
        )

        applyAnimationFrameRate()
        setContent {
            val view = LocalView.current
            SideEffect { view.setRequestedFrameRate(120f) }
            val dark = isSystemInDarkTheme()
            val palette = if (dark) DarkPalette else LightPalette
            val scheme = if (dark) {
                darkColorScheme(
                    background = palette.bg,
                    surface = palette.card,
                    surfaceContainerLow = palette.sheet,
                    primary = palette.brand,
                    onPrimary = palette.onBrand,
                    onBackground = palette.textPrimary,
                    onSurface = palette.textPrimary,
                )
            } else {
                lightColorScheme(
                    background = palette.bg,
                    surface = palette.card,
                    surfaceContainerLow = palette.sheet,
                    primary = palette.brand,
                    onPrimary = palette.onBrand,
                    onBackground = palette.textPrimary,
                    onSurface = palette.textPrimary,
                )
            }
            val activity = this
            MaterialTheme(colorScheme = scheme) {
                CompositionLocalProvider(LocalAppPalette provides palette) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        AppBackground()
                        AppRoot(onToggleVpn = { AppState.setVpn(activity, it) })
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        applyAnimationFrameRate()
        if (Native.isLoaded()) {
            // Only clear UI when core is down. Do not set true from isCoreRunning()
            // here: during async stopVpn the TUN may still be open briefly while
            // AppState already says stopped — resurrecting "运行中" would fight stop.
            if (!Native.isCoreRunning()) {
                AppState.isVpnRunning.value = false
            }
            AppState.refreshTile(this)
        }
    }

    private fun applyAnimationFrameRate() {
        val display = display ?: return
        val current = display.mode
        val same = display.supportedModes.filter {
            it.physicalWidth == current.physicalWidth && it.physicalHeight == current.physicalHeight
        }
        val pool = same.ifEmpty { display.supportedModes.toList() }
        val mode = pool.filter { it.refreshRate >= 119.5f }.minByOrNull { it.refreshRate }
            ?: pool.maxByOrNull { it.refreshRate }
            ?: return
        val lp = window.attributes
        lp.preferredDisplayModeId = mode.modeId
        lp.preferredRefreshRate = 120f
        window.attributes = lp
        window.decorView.setRequestedFrameRate(120f)
    }
}

private val ArcEase = CubicBezierEasing(0.22f, 1f, 0.36f, 1f)

private val RegionMorph = BoundsTransform { initial, target ->
    val collapsing = target.height < initial.height
    spring(
        dampingRatio = if (collapsing) 0.90f else 0.92f,
        stiffness = if (collapsing) 360f else 480f,
        visibilityThreshold = Rect.VisibilityThreshold,
    )
}

// Expand: region-card content leaves quickly; sheet content eases in (kept from 13.3).
private val RegionContentEnter =
    fadeIn(tween(380, delayMillis = 140, easing = ArcEase)) +
        scaleIn(initialScale = 0.94f, animationSpec = tween(420, delayMillis = 140, easing = ArcEase))

private val RegionContentExit =
    fadeOut(tween(160, easing = FastOutSlowInEasing)) +
        scaleOut(targetScale = 1.02f, animationSpec = tween(180, easing = FastOutSlowInEasing))

private val PageContentEnter =
    fadeIn(tween(340, delayMillis = 70, easing = ArcEase)) +
        scaleIn(initialScale = 0.97f, animationSpec = tween(380, delayMillis = 70, easing = ArcEase))

private val PageContentExit =
    fadeOut(tween(300, easing = FastOutSlowInEasing)) +
        scaleOut(targetScale = 0.96f, animationSpec = tween(320, easing = FastOutSlowInEasing))

@OptIn(ExperimentalSharedTransitionApi::class)
@Composable
fun AppRoot(onToggleVpn: (Boolean) -> Unit) {
    val ctx = LocalContext.current
    val palette = LocalAppPalette.current
    val isRunning by AppState.isVpnRunning.collectAsStateWithLifecycle()
    val regionIdx by AppState.currentRegionIdx.collectAsStateWithLifecycle()
    val nodeIdx by AppState.currentNodeIdx.collectAsStateWithLifecycle()
    val nativeReady by AppState.nativeReady.collectAsStateWithLifecycle()
    val nativeError by AppState.nativeError.collectAsStateWithLifecycle()
    val lastVpnError by AppState.lastVpnError.collectAsStateWithLifecycle()
    val coreRecovering by AppState.coreRecovering.collectAsStateWithLifecycle()
    val uiMessage by AppState.uiMessage.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(uiMessage) {
        val msg = uiMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg)
        AppState.consumeUiMessage()
    }

    var showNodePage by remember { mutableStateOf(false) }
    BackHandler(enabled = showNodePage) { showNodePage = false }

    val vpnAuthLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) onToggleVpn(true)
    }

    val regions by AppState.regions.collectAsStateWithLifecycle()
    val nodes = regions.getOrNull(regionIdx)?.nodes.orEmpty()
    val currentNodeName = nodes.getOrNull(nodeIdx)?.name.orEmpty()
    val proxySubtitle = when {
        !nativeReady && nativeError != null -> "核心加载失败"
        !nativeReady -> "加载中…"
        currentNodeName.isEmpty() -> regions.getOrNull(regionIdx)?.name.orEmpty()
        else -> currentNodeName
    }

    SharedTransitionLayout(modifier = Modifier.fillMaxSize()) {
        val sharedRegion = rememberSharedContentState(key = "region-page")
        val morphClip = remember {
            object : SharedTransitionScope.OverlayClip {
                private val path = Path()
                override fun getClipPath(
                    sharedContentState: SharedTransitionScope.SharedContentState,
                    bounds: Rect,
                    layoutDirection: LayoutDirection,
                    density: Density,
                ): Path {
                    // Clip tight to the morphing bounds. Shadows are reserved
                    // inside those bounds, so an outset clip is no longer needed.
                    val restOuter = with(density) { (RegionCardHeight + MaxShadowReserve * 2).toPx() }
                    val tall = with(density) { 820.dp.toPx() }
                    val grow = ((bounds.height - restOuter) / (tall - restOuter).coerceAtLeast(1f))
                        .coerceIn(0f, 1f)
                    val radius = with(density) { lerp(24.dp.toPx(), 0.dp.toPx(), grow) }
                    path.reset()
                    path.addRoundRect(
                        RoundRect(
                            left = bounds.left,
                            top = bounds.top,
                            right = bounds.right,
                            bottom = bounds.bottom,
                            cornerRadius = CornerRadius(radius),
                        )
                    )
                    return path
                }
            }
        }

        Box(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing)
        ) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                val vpnActive = isRunning || coreRecovering
                HomeCardButton(
                    modifier = Modifier.padding(horizontal = 32.dp),
                    title = when {
                        !nativeReady && nativeError != null -> "核心错误"
                        !nativeReady -> "加载中"
                        coreRecovering -> "重连中"
                        isRunning -> "运行中"
                        else -> "已停止"
                    },
                    subtitle = nativeError ?: lastVpnError,
                    backgroundColor = if (vpnActive) palette.brand else palette.stopped,
                    contentColor = palette.onBrand,
                    subtitleColor = palette.onBrand,
                    icon = { StatusCircleIcon(isRunning = vpnActive) },
                    revealFromPress = true,
                    onClick = {
                        if (!nativeReady) return@HomeCardButton
                        if (vpnActive) {
                            onToggleVpn(false)
                        } else {
                            val prep = VpnService.prepare(ctx)
                            if (prep != null) vpnAuthLauncher.launch(prep) else onToggleVpn(true)
                        }
                    }
                )

                Spacer(modifier = Modifier.height(72.dp - MaxShadowReserve))

                Box(
                    modifier = Modifier
                        .padding(horizontal = (32.dp - MaxShadowReserve).coerceAtLeast(0.dp))
                        .fillMaxWidth()
                        .height(RegionCardHeight + MaxShadowReserve * 2)
                ) {
                    androidx.compose.animation.AnimatedVisibility(
                        visible = !showNodePage,
                        enter = fadeIn(tween(400, easing = ArcEase)),
                        exit = fadeOut(tween(420, easing = FastOutSlowInEasing)),
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        HomeCardButton(
                            title = "地区",
                            subtitle = proxySubtitle,
                            backgroundColor = palette.card,
                            contentColor = palette.textPrimary,
                            subtitleColor = palette.textSecondary,
                            icon = { GlobeIcon(palette.textPrimary) },
                            shape = MorphPageShape,
                            morphShadow = true,
                            modifier = Modifier
                                .sharedBounds(
                                    sharedContentState = sharedRegion,
                                    animatedVisibilityScope = this,
                                    enter = RegionContentEnter,
                                    exit = RegionContentExit,
                                    boundsTransform = RegionMorph,
                                    resizeMode = SharedTransitionScope.ResizeMode.RemeasureToBounds,
                                    clipInOverlayDuringTransition = morphClip,
                                    zIndexInOverlay = 1f,
                                )
                                .fillMaxSize(),
                            onClick = { if (nativeReady) showNodePage = true },
                        )
                    }
                }
            }

            SnackbarHost(
                hostState = snackbarHostState,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .navigationBarsPadding()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            )
        }

        AnimatedVisibility(
            visible = showNodePage,
            enter = fadeIn(tween(400, easing = ArcEase)),
            exit = fadeOut(tween(420, easing = FastOutSlowInEasing)),
            modifier = Modifier.fillMaxSize(),
        ) {
            MorphPage(
                modifier = Modifier
                    .sharedBounds(
                        sharedContentState = sharedRegion,
                        animatedVisibilityScope = this@AnimatedVisibility,
                        enter = PageContentEnter,
                        exit = PageContentExit,
                        boundsTransform = RegionMorph,
                        resizeMode = SharedTransitionScope.ResizeMode.RemeasureToBounds,
                        clipInOverlayDuringTransition = morphClip,
                        zIndexInOverlay = 1f,
                    )
                    .fillMaxSize(),
                shape = MorphPageShape,
                tint = palette.sheet,
            ) {
                NodePage(
                    regionIdx = regionIdx,
                    regions = regions,
                    selectedNodeIdx = nodeIdx,
                    onSelectNode = { newNIdx ->
                        AppState.selectNodeInCurrentRegion(newNIdx)
                    },
                    onSelectRegion = { newAIdx -> AppState.selectRegion(newAIdx) },
                    animatedVisibilityScope = this@AnimatedVisibility,
                )
            }
        }
    }
}

@Composable
private fun HomeCardButton(
    title: String,
    subtitle: String?,
    backgroundColor: Color,
    contentColor: Color,
    subtitleColor: Color,
    icon: @Composable () -> Unit,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    shape: Shape = CardCorner,
    revealFromPress: Boolean = false,
    morphShadow: Boolean = false,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(
        if (pressed) 0.975f else 1f,
        spring(dampingRatio = 0.9f, stiffness = 600f),
        label = "cardScale",
    )

    RaisedCard(
        onClick = onClick,
        modifier = (if (morphShadow) {
            modifier.fillMaxSize()
        } else {
            modifier
                .fillMaxWidth()
                .height(RegionCardHeight)
        }).graphicsLayer {
            scaleX = scale
            scaleY = scale
        },
        shape = shape,
        tint = backgroundColor,
        shadowRadius = 22.dp,
        interactionSource = interaction,
        revealFromPress = revealFromPress,
        showRipple = !revealFromPress,
        morphShadow = morphShadow,
    ) {
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 34.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(modifier = Modifier.size(38.dp), contentAlignment = Alignment.Center) {
                icon()
            }
            Spacer(modifier = Modifier.width(28.dp))
            Column(
                modifier = Modifier.animateContentSize(tween(320, easing = FastOutSlowInEasing)),
                verticalArrangement = Arrangement.Center,
            ) {
                AnimatedContent(
                    targetState = title,
                    transitionSpec = {
                        (fadeIn(tween(320, delayMillis = 40, easing = ArcEase)) +
                            scaleIn(initialScale = 0.96f, animationSpec = tween(340, delayMillis = 40, easing = ArcEase)) +
                            slideInVertically(tween(340, delayMillis = 40, easing = ArcEase)) { it / 4 }) togetherWith
                            (fadeOut(tween(240, easing = FastOutSlowInEasing)) +
                                scaleOut(targetScale = 1.02f, animationSpec = tween(260, easing = FastOutSlowInEasing)) +
                                slideOutVertically(tween(260, easing = FastOutSlowInEasing)) { -it / 5 }) using
                            SizeTransform(clip = false)
                    },
                    label = "cardTitle",
                ) { t ->
                    Text(
                        text = t,
                        fontSize = 21.sp,
                        fontWeight = FontWeight.Medium,
                        color = contentColor,
                    )
                }
                AnimatedContent(
                    targetState = subtitle.orEmpty(),
                    transitionSpec = {
                        (fadeIn(tween(340, delayMillis = 70, easing = ArcEase)) +
                            scaleIn(initialScale = 0.96f, animationSpec = tween(360, delayMillis = 70, easing = ArcEase)) +
                            slideInVertically(tween(360, delayMillis = 70, easing = ArcEase)) { it / 4 }) togetherWith
                            (fadeOut(tween(240, easing = FastOutSlowInEasing)) +
                                scaleOut(targetScale = 1.02f, animationSpec = tween(260, easing = FastOutSlowInEasing)) +
                                slideOutVertically(tween(260, easing = FastOutSlowInEasing)) { -it / 5 }) using
                            SizeTransform(clip = false)
                    },
                    label = "cardSub",
                ) { s ->
                    if (s.isNotEmpty()) {
                        Column {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = s,
                                fontSize = 16.sp,
                                color = subtitleColor,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }
    }
}
