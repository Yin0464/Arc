package com.arc.app

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

internal val BrandBlue = Color(0xFF0A2C4E)
internal val BrandBlueLit = Color(0xFF163E66)
internal val StoppedGray = Color(0xFF797A7C)
internal val StoppedGrayDark = Color(0xFF5A5C60)
internal val LatencyGreen = Color(0xFF2E7D32)
internal val LatencyYellow = Color(0xFFF9A825)
internal val LatencyRed = Color(0xFFC62828)

internal data class AppPalette(
    val bg: Color,
    val card: Color,
    val cardSelected: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val brand: Color,
    val stopped: Color,
    val onBrand: Color,
    val chipSelected: Color,
    val chipSelectedContent: Color,
    val sheet: Color,
    val isDark: Boolean,
)

internal val LightPalette = AppPalette(
    bg = Color.White,
    card = Color.White,
    cardSelected = BrandBlue,
    textPrimary = Color(0xFF1C1E21),
    textSecondary = Color(0xFF5E636B),
    brand = BrandBlue,
    stopped = StoppedGray,
    onBrand = Color.White,
    chipSelected = BrandBlue,
    chipSelectedContent = Color.White,
    sheet = Color.White,
    isDark = false,
)

internal val DarkPalette = AppPalette(
    bg = Color(0xFF0B0F16),
    card = Color(0xFF1C222C),
    cardSelected = BrandBlueLit,
    textPrimary = Color(0xFFF2F4F7),
    textSecondary = Color(0xFFB0B4BB),
    brand = BrandBlueLit,
    stopped = StoppedGrayDark,
    onBrand = Color.White,
    chipSelected = BrandBlueLit,
    chipSelectedContent = Color.White,
    sheet = Color(0xFF121820),
    isDark = true,
)

internal val CardCorner = RoundedCornerShape(24.dp)
internal val NodeCorner = RoundedCornerShape(18.dp)
internal val ChipCorner = RoundedCornerShape(14.dp)

internal val LocalAppPalette = staticCompositionLocalOf { LightPalette }
