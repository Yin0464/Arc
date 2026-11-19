package com.arc.app

/** Pure notification title/text for the VPN foreground service. */
object VpnNotification {
    fun title(recovering: Boolean): String =
        if (recovering) "VPN恢复中" else "VPN运行中"

    fun text(
        node: String?,
        latencyMs: Int?,
        recovering: Boolean,
    ): String {
        val base = node?.trim().orEmpty()
        if (recovering) {
            return if (base.isEmpty()) "正在重连核心" else "正在重连 · $base"
        }
        if (base.isEmpty()) return "VPN运行中"
        val lat = latencyMs
        return if (lat != null && lat > 0) "$base · ${lat}ms" else base
    }
}
