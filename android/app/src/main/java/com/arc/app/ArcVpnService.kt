package com.arc.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.widget.Toast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

class ArcVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.arc.app.START"
        const val ACTION_STOP = "com.arc.app.STOP"
        private const val CHANNEL_ID = "arc_vpn"
        private const val NOTIF_ID = 1

        /** Session epoch: bumps on start/stop/reestablish teardown; stale net work is dropped. */
        private val netMu = Any()
        private var netEpoch = 0

        private val coreLifeExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "arc-core-life").apply { isDaemon = true }
        }

        private val netChangeExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "arc-net").apply { isDaemon = true }
        }
    }

    private val serviceJob = SupervisorJob()
    private val mainScope = CoroutineScope(serviceJob + Dispatchers.Main.immediate)
    // ConnectivityManager.registerBestMatchingNetworkCallback requires a Handler (thread affinity).
    private val netCallbackHandler = Handler(Looper.getMainLooper())

    private var coreDeathAttempts = 0
    private var reestablishJob: Job? = null
    private var tunPfd: ParcelFileDescriptor? = null
    private var wakeRegistered = false
    private var startId = 0
    private var lastWakeElapsed = 0L

    private val netChangeMu = Any()
    private var pendingNetChange: NetChangeKind? = null
    private var pendingNetEpoch = 0
    private val flushNetworkChanged = Runnable { flushPendingNetworkChanged() }

    private val nets = UnderlyingNetworks(
        service = this,
        handler = netCallbackHandler,
        onNetworkChanged = { kind -> postNetworkChanged(kind) },
    )

    /** Screen-on / user-present → always soft network reset (never hard by itself). */
    private val wakeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_ON, Intent.ACTION_USER_PRESENT -> {
                    if (!Native.isLoaded() || !Native.isCoreRunning()) return
                    val now = SystemClock.elapsedRealtime()
                    if (now - lastWakeElapsed < 1_500L) return
                    lastWakeElapsed = now
                    postNetworkChanged(NetChangeKind.SoftLite)
                }
            }
        }
    }

    /**
     * Coalesce network-change notifies for 250ms. A later event in the window
     * upgrades the pending kind (hard > soft-path > soft-lite). Hard flushes
     * immediately and cancels a waiting soft notify.
     */
    private fun postNetworkChanged(kind: NetChangeKind) {
        val epoch = synchronized(netMu) { netEpoch }
        var flushNow = false
        synchronized(netChangeMu) {
            val cur = pendingNetChange
            if (cur == null) {
                pendingNetChange = kind
                pendingNetEpoch = epoch
                if (kind == NetChangeKind.Hard) {
                    flushNow = true
                } else {
                    netCallbackHandler.postDelayed(flushNetworkChanged, 250L)
                }
            } else {
                pendingNetChange = cur.stronger(kind)
                pendingNetEpoch = epoch
                if (pendingNetChange == NetChangeKind.Hard && cur != NetChangeKind.Hard) {
                    netCallbackHandler.removeCallbacks(flushNetworkChanged)
                    flushNow = true
                }
            }
        }
        if (flushNow) flushPendingNetworkChanged()
    }

    private fun flushPendingNetworkChanged() {
        val (kind, epoch) = synchronized(netChangeMu) {
            val k = pendingNetChange ?: return
            pendingNetChange = null
            netCallbackHandler.removeCallbacks(flushNetworkChanged)
            k to pendingNetEpoch
        }
        netChangeExecutor.execute {
            val alive = synchronized(netMu) { epoch == netEpoch && Native.isCoreRunning() }
            if (!alive) return@execute
            Native.notifyNetworkChanged(kind.code)
        }
    }

    private fun cancelPendingNetworkChanged() {
        synchronized(netChangeMu) {
            pendingNetChange = null
            netCallbackHandler.removeCallbacks(flushNetworkChanged)
        }
    }

    fun refreshNotification() {
        mainScope.launch { postForegroundNotification() }
    }

    fun reestablishAfterCoreDeath() {
        if (Native.isCoreRunning()) return
        AppState.coreRecovering.value = true
        AppState.refreshTile(this)
        refreshNotification()
        val probeEarly = nets.pickUnderlyingNetwork()
        if (probeEarly == null || nets.isBlocked(probeEarly)) {
            nets.awaitingRegain = true
            val defer = 2_000L
            AppState.lastVpnError.value = "等待底层网络后重连"
            reestablishJob?.cancel()
            val epoch = synchronized(netMu) { netEpoch }
            reestablishJob = mainScope.launch {
                delay(defer)
                if (synchronized(netMu) { epoch != netEpoch }) return@launch
                reestablishAfterCoreDeath()
            }
            return
        }
        coreDeathAttempts++
        if (coreDeathAttempts > 3) {
            val msg = "核心反复退出，已停止"
            AppState.lastVpnError.value = msg
            AppState.coreRecovering.value = false
            reestablishJob?.cancel()
            reestablishJob = null
            stopVpn()
            serviceToast(msg)
            return
        }
        val backoff = minOf(8_000L, 1_000L shl (coreDeathAttempts - 1).coerceAtMost(3))
        AppState.lastVpnError.value = "核心退出，${backoff}ms 后重连"
        refreshNotification()
        reestablishJob?.cancel()
        val epochAtDelay = synchronized(netMu) { netEpoch }
        reestablishJob = mainScope.launch {
            delay(backoff)
            if (synchronized(netMu) { epochAtDelay != netEpoch }) return@launch
            if (Native.isCoreRunning()) return@launch
            val probe = nets.pickUnderlyingNetwork()
            if (probe == null || nets.isBlocked(probe)) {
                nets.awaitingRegain = true
                if (coreDeathAttempts > 0) coreDeathAttempts--
                val defer = 2_000L
                AppState.lastVpnError.value = "等待底层网络后重连"
                val e2 = synchronized(netMu) { netEpoch }
                reestablishJob = mainScope.launch {
                    delay(defer)
                    if (synchronized(netMu) { e2 != netEpoch }) return@launch
                    reestablishAfterCoreDeath()
                }
                return@launch
            }
            synchronized(netMu) {
                if (Native.isCoreRunning()) return@launch
                netEpoch++
                runCatching {
                    nets.detachCallback(getSystemService(ConnectivityManager::class.java))
                    nets.resetUnderlyingKeepTracked()
                    Native.underlyingNetwork = null
                }
                runCatching { Native.setUnderlying("", -1) }
                runCatching { Native.setProtector(false) }
                Native.vpnService = null
                val oldPfd = tunPfd
                tunPfd = null
                runCatching { oldPfd?.close() }
            }
            AppState.isVpnRunning.value = false
            AppState.refreshTile(this@ArcVpnService)
            startVpn()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        this.startId = startId
        if (intent?.action == ACTION_STOP) {
            stopSession()
            stopSelf(startId)
            return START_NOT_STICKY
        }

        startVpn()
        return START_STICKY
    }

    override fun onRevoke() {
        stopSession()
        stopSelf(startId)
        super.onRevoke()
    }

    private fun registerWakeReceiver() {
        if (wakeRegistered) return
        runCatching {
            registerReceiver(
                wakeReceiver,
                IntentFilter().apply {
                    addAction(Intent.ACTION_SCREEN_ON)
                    addAction(Intent.ACTION_USER_PRESENT)
                },
                Context.RECEIVER_NOT_EXPORTED,
            )
            wakeRegistered = true
        }
    }

    private fun unregisterWakeReceiver() {
        if (!wakeRegistered) return
        runCatching { unregisterReceiver(wakeReceiver) }
        wakeRegistered = false
    }

    private fun startVpn() {
        postForegroundNotification()
        registerWakeReceiver()
        val epoch = synchronized(netMu) {
            netEpoch++
            netEpoch
        }
        mainScope.launch {
            AppState.awaitInit()
            coreLifeExecutor.execute { startOnWorker(epoch) }
        }
    }

    private fun startOnWorker(epoch: Int) {
        fun cancelled() = synchronized(netMu) { epoch != netEpoch }
        fun fail(msg: String) {
            val shown = VpnErrors.friendly(msg)
            mainScope.launch {
                if (cancelled()) return@launch
                AppState.lastVpnError.value = shown
                stopVpn()
                serviceToast(shown)
            }
        }
        try {
            if (!Native.isLoaded() || !AppState.nativeReady.value) {
                fail(AppState.nativeError.value ?: "核心未就绪")
                return
            }
            if (cancelled()) return
            nets.registerNetworkCallback()
            if (Native.isCoreRunning()) {
                mainScope.launch {
                    if (cancelled()) return@launch
                    AppState.isVpnRunning.value = true
                    AppState.coreRecovering.value = false
                    nets.registerNetworkCallback()
                    postForegroundNotification()
                    AppState.refreshTile(this@ArcVpnService)
                }
                return
            }

            // Always-on / upgrade / cold-start gate: prefer validated+unblocked underlying.
            val under = nets.awaitReadyUnderlying(::cancelled)
            if (cancelled()) return
            if (under == null) {
                // Coalesce with awaitingRegain; defer instead of establish+startCore storm.
                mainScope.launch {
                    if (cancelled()) return@launch
                    nets.awaitingRegain = true
                    AppState.lastVpnError.value = "等待可用网络"
                    if (!Native.isCoreRunning()) {
                        val defer = 1_500L
                        reestablishJob?.cancel()
                        reestablishJob = mainScope.launch {
                            delay(defer)
                            if (cancelled()) return@launch
                            if (!Native.isCoreRunning()) startVpn()
                        }
                    }
                }
                return
            }

            val builder = Builder()
                .setSession(getString(R.string.app_name))
                // Paired with ustack usDefaultMSS=1380 (MTU-40 IPv4); IPv6 would be MTU-60.
                .setMtu(1420)
                .addAddress("172.19.0.1", 30)
                .addAddress("fdfe:dcba:9876::1", 126)
                .addDnsServer("172.19.0.2")
                .addDnsServer("fdfe:dcba:9876::2")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setMetered(false)
                .setBlocking(true)

            // Underlying networks stay undeclared (system default): a pinned network that
            // is lost before the update lands makes apps' getActiveNetworkInfo() null.
            nets.underlying = under
            Native.underlyingNetwork = under
            getSystemService(ConnectivityManager::class.java)?.getLinkProperties(under)?.let { lp ->
                nets.pushUnderlying(lp)
                nets.underlyingAddrs = UnderlyingNetworks.linkAddrSig(lp)
            }

            val pfd = builder.establish() ?: run {
                fail("VPN 建立失败（系统拒绝）")
                return
            }
            if (cancelled()) {
                runCatching { pfd.close() }
                return
            }
            val goPfd = runCatching { ParcelFileDescriptor.dup(pfd.fileDescriptor) }.getOrElse {
                runCatching { pfd.close() }
                fail(it.message?.takeIf { m -> m.isNotBlank() } ?: "VPN fd dup 失败")
                return
            }
            synchronized(netMu) {
                if (cancelled()) {
                    runCatching { goPfd.close() }
                    runCatching { pfd.close() }
                    return
                }
                val oldPfd = tunPfd
                if (oldPfd != null && oldPfd !== pfd) {
                    runCatching { oldPfd.close() }
                }
                tunPfd = pfd
            }
            Native.vpnService = this
            Native.setProtector(true)
            val rawFd = goPfd.detachFd()
            val aIdx = AppState.currentRegionIdx.value
            val nIdx = AppState.currentNodeIdx.value
            val err = runCatching {
                Native.startCore(rawFd, aIdx, nIdx)
            }.fold(
                onSuccess = { it },
                onFailure = { t -> t.message?.takeIf { it.isNotBlank() } ?: "VPN 启动失败" }
            )
            mainScope.launch {
                if (cancelled()) {
                    // Only a stop clears tunPfd; a newer start owns this core.
                    if (synchronized(netMu) { tunPfd == null }) stopVpn()
                    return@launch
                }
                if (err.isNotEmpty()) {
                    val shown = VpnErrors.friendly(err)
                    AppState.lastVpnError.value = shown
                    stopVpn()
                    serviceToast(shown)
                    return@launch
                }
                if (!Native.isCoreRunning()) return@launch
                coreDeathAttempts = 0
                AppState.coreRecovering.value = false
                AppState.lastVpnError.value = null
                AppState.isVpnRunning.value = true
                nets.registerNetworkCallback()
                postForegroundNotification()
                AppState.refreshTile(this@ArcVpnService)
            }
        } catch (t: Throwable) {
            fail(t.message?.takeIf { it.isNotBlank() } ?: "VPN 启动失败")
        }
    }

    private fun serviceToast(msg: String) {
        mainScope.launch {
            Toast.makeText(applicationContext, msg, Toast.LENGTH_LONG).show()
        }
    }

    private fun stopVpn() {
        stopSession()
        stopSelf(startId)
    }

    private fun stopSession() {
        reestablishJob?.cancel()
        reestablishJob = null
        cancelPendingNetworkChanged()
        unregisterWakeReceiver()
        AppState.coreRecovering.value = false
        val pfdToClose: ParcelFileDescriptor?
        synchronized(netMu) {
            netEpoch++
            runCatching {
                nets.unregister(getSystemService(ConnectivityManager::class.java))
                Native.underlyingNetwork = null
            }
            pfdToClose = tunPfd
            tunPfd = null
        }
        AppState.isVpnRunning.value = false
        AppState.refreshTile(this)
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        if (Native.isLoaded()) {
            runCatching { Native.stopCore() }
            runCatching { Native.setUnderlying("", -1) }
            runCatching { Native.setProtector(false) }
        }
        runCatching { pfdToClose?.close() }
        Native.vpnService = null
    }

    override fun onDestroy() {
        stopSession()
        serviceJob.cancel()
        super.onDestroy()
    }

    private fun currentNotifParts(): Pair<String, String> {
        val recovering = AppState.coreRecovering.value
        val regions = AppState.regions.value
        val aIdx = AppState.currentRegionIdx.value
        val nIdx = AppState.currentNodeIdx.value
        val node = regions.getOrNull(aIdx)?.nodes?.getOrNull(nIdx)?.name
        val lat = AppState.nodeLatencies["${aIdx}_$nIdx"]
        return VpnNotification.title(recovering) to VpnNotification.text(node, lat, recovering)
    }

    private fun postForegroundNotification() {
        runCatching {
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val (title, text) = currentNotifParts()
        val notif = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(Icon.createWithResource(this, R.drawable.ic_tile_logo))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
        runCatching { startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) }
        runCatching {
            getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, notif)
        }
    }
}
