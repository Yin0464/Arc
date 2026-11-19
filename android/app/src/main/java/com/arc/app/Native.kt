package com.arc.app

import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

object Native {
    @Volatile private var loaded = false

    @Synchronized
    fun ensureLoaded() {
        if (loaded) return
        System.loadLibrary("arc")
        loaded = true
    }

    fun isLoaded(): Boolean = loaded

    interface LatencyListener {
        fun onStateChanged(testing: Boolean)
        fun onNodeResult(nodeIdx: Int, latencyMs: Int)
    }

    @Volatile var vpnService: VpnService? = null
    @Volatile var latencyListener: LatencyListener? = null

    @Volatile var underlyingNetwork: Network? = null

    private val mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    @JvmStatic external fun startCore(tunFd: Int, regionIdx: Int, nodeIdx: Int): String
    @JvmStatic external fun stopCore()
    @JvmStatic external fun isCoreRunning(): Boolean
    @JvmStatic external fun switchNode(regionIdx: Int, nodeIdx: Int)

    /** JSON `[{name, nodes: [{name, proto}]}]`; see [parseCatalog]. */
    @JvmStatic external fun getCatalog(): String

    /** Installs a plaintext node table while the core is stopped; returns an error or "". */
    @JvmStatic external fun loadNodes(table: ByteArray): String
    @JvmStatic external fun testRegionLatencies(regionIdx: Int)

    @JvmStatic external fun cancelBatchLatencyTest()
    @JvmStatic external fun notifyNetworkChanged(kind: Int)
    @JvmStatic external fun setProtector(enabled: Boolean)
    @JvmStatic external fun setDataDir(dir: String)

    @JvmStatic external fun setUnderlying(dnsServers: String, v6: Int)

    @JvmStatic fun protect(fd: Int): Boolean {
        val vpn = vpnService ?: return false
        if (!vpn.protect(fd)) return false
        val net = underlyingNetwork ?: return true

        fun bindOnce(): Boolean = runCatching {
            val pfd = ParcelFileDescriptor.adoptFd(fd)
            try {
                net.bindSocket(pfd.fileDescriptor)
            } finally {
                pfd.detachFd()
            }
            true
        }.getOrElse { false }

        if (!bindOnce()) bindOnce()
        return true
    }
    @JvmStatic fun onLatencyState(testing: Boolean) { latencyListener?.onStateChanged(testing) }
    @JvmStatic fun onLatencyResult(nodeIdx: Int, latencyMs: Int) { latencyListener?.onNodeResult(nodeIdx, latencyMs) }

    @JvmStatic fun onCoreDied() {
        mainScope.launch {
            (vpnService as? ArcVpnService)?.reestablishAfterCoreDeath()
        }
    }
}
