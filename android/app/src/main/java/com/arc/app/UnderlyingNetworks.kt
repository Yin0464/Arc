package com.arc.app

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.SystemClock
import java.net.Inet6Address
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks candidate underlying networks, ranks them, and registers the
 * ConnectivityManager callback. The owning [VpnService] keeps Handler affinity,
 * executors, Toast, and TUN lifecycle; this helper owns networkInfos / pick / adopt.
 */
internal class UnderlyingNetworks(
    private val service: VpnService,
    private val handler: Handler,
    private val onNetworkChanged: (kind: NetChangeKind) -> Unit,
) {
    private data class NetInfo(
        @Volatile var losingUntil: Long = 0L,
        @Volatile var blocked: Boolean = false,
    )

    private val networkInfos = ConcurrentHashMap<Network, NetInfo>()

    @Volatile var netCallback: ConnectivityManager.NetworkCallback? = null
        private set
    @Volatile var underlying: Network? = null
    @Volatile var underlyingAddrs: String? = null
    @Volatile var underlyingValidated = false
    @Volatile var awaitingRegain = false
    @Volatile var sawUnvalidated = false

    fun isBlocked(network: Network): Boolean = networkInfos[network]?.blocked == true

    fun clear() {
        networkInfos.clear()
        underlying = null
        underlyingAddrs = null
        underlyingValidated = false
        awaitingRegain = false
        sawUnvalidated = false
    }

    fun detachCallback(cm: ConnectivityManager?) {
        runCatching {
            netCallback?.let { cb -> cm?.unregisterNetworkCallback(cb) }
        }
        netCallback = null
    }

    /** Unregister callback and drop tracked state (stopVpn). */
    fun unregister(cm: ConnectivityManager?) {
        detachCallback(cm)
        clear()
    }

    /** Unregister callback and reset selected underlying; keep networkInfos (reestablish). */
    fun resetUnderlyingKeepTracked() {
        underlying = null
        underlyingAddrs = null
        underlyingValidated = false
        awaitingRegain = false
        sawUnvalidated = false
    }

    private fun cm(): ConnectivityManager? =
        service.getSystemService(ConnectivityManager::class.java)

    private fun candidateNetworks(cm: ConnectivityManager): List<Network> {
        val tracked = networkInfos.keys.toList()
        if (tracked.isNotEmpty()) return tracked
        return listOfNotNull(cm.activeNetwork)
    }

    fun pickUnderlyingNetwork(): Network? {
        val cm = cm() ?: return null
        val best = selectBestNetwork(cm)
        val active = cm.activeNetwork
        if (active != null && cm.getNetworkCapabilities(active)?.isUnderlyingUsable() == true) {
            if (best == null || priorityOf(cm, active) <= priorityOf(cm, best)) return active
        }
        return best
    }

    private fun priorityOf(cm: ConnectivityManager, network: Network): Int {
        val info = networkInfos[network]
        return networkPriority(
            caps = cm.getNetworkCapabilities(network),
            losing = info != null && info.losingUntil > SystemClock.elapsedRealtime(),
            blocked = info?.blocked == true,
        )
    }

    /**
     * Cold start / reestablish gate: wait briefly for validated+unblocked
     * underlying (coalesce with awaitingRegain). [cancelled] preserves netEpoch cancellation.
     */
    fun awaitReadyUnderlying(cancelled: () -> Boolean): Network? {
        val cm = cm() ?: return null
        val gate = awaitingRegain
        val deadline = SystemClock.elapsedRealtime() + NetChangePolicy.awaitReadyWaitMs(gate)
        while (true) {
            if (cancelled()) return null
            val best = pickUnderlyingNetwork()
            if (best != null) {
                val blocked = isBlocked(best)
                val caps = cm.getNetworkCapabilities(best)
                if (!blocked && caps?.isUnderlyingValidated() == true) return best
                if (!gate && !blocked && caps?.isUnderlyingUsable() == true) {
                    if (SystemClock.elapsedRealtime() + 400L >= deadline) return best
                }
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                val best = pickUnderlyingNetwork() ?: return null
                if (isBlocked(best)) return null
                val caps = cm.getNetworkCapabilities(best)
                return if (caps?.isUnderlyingUsable() == true) best else null
            }
            try {
                Thread.sleep(150L)
            } catch (_: InterruptedException) {
                return null
            }
        }
    }

    fun pushUnderlying(lp: LinkProperties) {
        runCatching {
            val dns = lp.dnsServers.mapNotNull { it.hostAddress }.joinToString(",")
            val v6Addr = lp.linkAddresses.any {
                val a = it.address
                a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress &&
                    (a.address[0].toInt() and 0xfe) != 0xfc
            }
            val v6Route = lp.routes.any { it.isDefaultRoute && it.destination.address is Inet6Address }
            Native.setUnderlying(dns, if (v6Addr && v6Route) 1 else 0)
        }
    }

    fun selectBestNetwork(cm: ConnectivityManager): Network? {
        return candidateNetworks(cm)
            .filter { n ->
                val caps = cm.getNetworkCapabilities(n) ?: return@filter false
                caps.isUnderlyingUsable()
            }
            .minByOrNull { priorityOf(cm, it) }
    }

    /**
     * Picks best underlying and notifies Go.
     * [reasonFull] true only for lost-underlying / offline-regain ([NetChangePolicy.isHard]).
     * Multi-net switch without loss, or a different link-address signature, is soft-path.
     * That address change does not downgrade [reasonFull] (see [NetChangePolicy.networkChangeFull]).
     * Losing all candidates clears the bound network and notifies hard.
     */
    fun adoptBestNetwork(cm: ConnectivityManager, reasonFull: Boolean) {
        val best = selectBestNetwork(cm)
        if (best == null) {
            if (underlying != null) {
                runCatching { Native.setUnderlying("", -1) }
                underlying = null
                underlyingAddrs = null
                underlyingValidated = false
                awaitingRegain = true
                sawUnvalidated = false
                Native.underlyingNetwork = null
                onNetworkChanged(NetChangeKind.Hard)
            }
            return
        }
        val prev = underlying
        val switched = prev != best
        underlying = best
        Native.underlyingNetwork = best
        cm.getLinkProperties(best)?.let { lp ->
            pushUnderlying(lp)
            val sig = linkAddrSig(lp)
            val addrChanged = underlyingAddrs != null && underlyingAddrs != sig
            NetChangePolicy.networkChangeFull(reasonFull, switched, addrChanged)?.let(onNetworkChanged)
            underlyingAddrs = sig
        } ?: run {
            NetChangePolicy.networkChangeFull(reasonFull, switched, addrChanged = false)?.let(onNetworkChanged)
        }
        if (switched) {
            underlyingValidated = false
            sawUnvalidated = false
            awaitingRegain = false
        }
    }

    fun registerNetworkCallback() {
        if (netCallback != null) return
        runCatching {
            val cm = cm() ?: return

            val cb = object : ConnectivityManager.NetworkCallback() {
                private fun isUnderlying(network: Network): Boolean {
                    val caps = cm.getNetworkCapabilities(network) ?: return false
                    return caps.isUnderlyingUsable()
                }

                override fun onAvailable(network: Network) {
                    if (netCallback !== this || !isUnderlying(network)) return
                    networkInfos.putIfAbsent(network, NetInfo())
                    adoptBestNetwork(cm, reasonFull = NetChangePolicy.isHard(lostOrNullUnderlying = false, offlineRegain = awaitingRegain))
                }

                override fun onLosing(network: Network, maxMsToLive: Int) {
                    if (netCallback !== this) return
                    val info = networkInfos.getOrPut(network) { NetInfo() }
                    info.losingUntil = SystemClock.elapsedRealtime() + maxMsToLive.toLong().coerceAtLeast(0L)
                    adoptBestNetwork(cm, reasonFull = false)
                }

                override fun onLost(network: Network) {
                    if (netCallback !== this) return
                    networkInfos.remove(network)
                    if (underlying == network) {
                        adoptBestNetwork(cm, reasonFull = NetChangePolicy.isHard(lostOrNullUnderlying = true, offlineRegain = false))
                    } else {
                        selectBestNetwork(cm)?.let { best ->
                            cm.getLinkProperties(best)?.let { pushUnderlying(it) }
                        }
                    }
                }

                override fun onBlockedStatusChanged(network: Network, blocked: Boolean) {
                    if (netCallback !== this) return
                    networkInfos.getOrPut(network) { NetInfo() }.blocked = blocked
                    if (network != underlying) {
                        if (!blocked) adoptBestNetwork(cm, reasonFull = false)
                        return
                    }
                    if (blocked) {
                        val prev = underlying
                        adoptBestNetwork(cm, reasonFull = false)
                        if (underlying == prev || underlying == null ||
                            networkInfos[underlying]?.blocked == true
                        ) {
                            awaitingRegain = true
                        }
                    } else {
                        if (awaitingRegain) awaitingRegain = false
                        onNetworkChanged(NetChangeKind.SoftLite)
                    }
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (netCallback !== this) return
                    if (!caps.isUnderlyingUsable()) {
                        if (networkInfos.remove(network) != null && network == underlying) {
                            adoptBestNetwork(cm, reasonFull = NetChangePolicy.isHard(lostOrNullUnderlying = true, offlineRegain = false))
                        }
                        return
                    }
                    networkInfos.getOrPut(network) { NetInfo() }
                    if (network != underlying) {
                        adoptBestNetwork(cm, reasonFull = NetChangePolicy.isHard(lostOrNullUnderlying = false, offlineRegain = awaitingRegain))
                    }
                    if (network != underlying) return
                    val ok = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    if (!ok) {
                        if (underlyingValidated) sawUnvalidated = true
                        underlyingValidated = false
                        return
                    }
                    if (sawUnvalidated) {
                        sawUnvalidated = false
                        onNetworkChanged(NetChangeKind.SoftLite)
                    }
                    underlyingValidated = true
                    if (awaitingRegain && networkInfos[network]?.blocked != true) {
                        awaitingRegain = false
                    }
                }

                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                    if (netCallback !== this) return
                    if (underlying == null || network != underlying) {
                        val best = selectBestNetwork(cm)
                        if (best == network) pushUnderlying(lp)
                        return
                    }
                    pushUnderlying(lp)
                    val sig = linkAddrSig(lp)
                    val prev = underlyingAddrs
                    if (prev != null && prev != sig) onNetworkChanged(NetChangeKind.SoftPath)
                    underlyingAddrs = sig
                }
            }
            netCallback = cb
            cm.registerBestMatchingNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                cb,
                handler,
            )
        }.onFailure {
            netCallback = null
        }
    }

    companion object {
        fun linkAddrSig(lp: LinkProperties): String =
            lp.linkAddresses.map { it.address.hostAddress ?: "" }.sorted().joinToString(",")
    }
}

/** Internet + non-VPN — the underlying candidate filter used by the VPN service. */
fun NetworkCapabilities.isUnderlyingUsable(): Boolean =
    hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
        hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)

fun NetworkCapabilities.isUnderlyingValidated(): Boolean =
    isUnderlyingUsable() && hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)

/** Lower is better: Wi-Fi / Ethernet 0, cellular 4, anything else 10; losing +10, blocked +40. */
fun networkPriority(caps: NetworkCapabilities?, losing: Boolean, blocked: Boolean): Int {
    var score = when {
        caps == null -> 100
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 0
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 4
        else -> 10
    }
    if (losing) score += 10
    if (blocked) score += 40
    return score
}
