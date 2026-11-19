package com.arc.app

import android.content.Context

/** Loads the plaintext node table bundled as APK asset `nodes.json` into the core. */
object NodeStore {
    fun load(ctx: Context): String? = runCatching {
        val bytes = checked(ctx.assets.open("nodes.json").use { it.readBytes() })
        Native.loadNodes(bytes).ifEmpty { null }
    }.getOrElse { "节点表加载失败：${it.message ?: it.javaClass.simpleName}" }

    internal fun checked(json: ByteArray): ByteArray {
        require(json.isNotEmpty()) { "empty node table" }
        return json
    }
}
