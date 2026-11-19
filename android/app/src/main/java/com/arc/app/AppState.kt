package com.arc.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.service.quicksettings.TileService
import androidx.compose.runtime.mutableStateMapOf
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

private val Context.arcDataStore: DataStore<Preferences> by preferencesDataStore(name = "arc_prefs")

object AppState {
    private val KEY_REGION = intPreferencesKey("region_idx")
    private val KEY_CATALOG_FP = stringPreferencesKey("catalog_fp")
    private fun keyForNode(regionIdx: Int) = intPreferencesKey("node_idx_slot_$regionIdx")

    private val appJob = SupervisorJob()
    private val mainScope = CoroutineScope(appJob + Dispatchers.Main.immediate)
    private val switchDispatcher = Executors.newSingleThreadExecutor { r ->
        Thread(r, "arc-switch").apply { isDaemon = true }
    }.asCoroutineDispatcher()
    private val initDispatcher = Executors.newSingleThreadExecutor { r ->
        Thread(r, "arc-init").apply { isDaemon = true }
    }.asCoroutineDispatcher()
    private val switchScope = CoroutineScope(appJob + switchDispatcher)
    private val initScope = CoroutineScope(appJob + initDispatcher)

    private lateinit var app: Context
    private val initDone = CompletableDeferred<Unit>()

    val isVpnRunning = MutableStateFlow(false)
    val isTestingLatency = MutableStateFlow(false)
    val currentRegionIdx = MutableStateFlow(0)
    val currentNodeIdx = MutableStateFlow(0)

    val nativeReady = MutableStateFlow(false)
    val nativeError = MutableStateFlow<String?>(null)
    val lastVpnError = MutableStateFlow<String?>(null)
    val coreRecovering = MutableStateFlow(false)
    val uiMessage = MutableStateFlow<String?>(null)

    private var nodeMemorySlots: IntArray = IntArray(0)
    val nodeLatencies = mutableStateMapOf<String, Int>()

    /** Regions in core order; replaced wholesale when a node table loads. */
    val regions = MutableStateFlow<List<Region>>(emptyList())

    private fun store() = app.arcDataStore

    /** Called once from [ArcApp.onCreate]; loads the core and catalog off the main thread. */
    fun start(context: Context) {
        app = context.applicationContext
        initScope.launch {
            runCatching {
                Native.ensureLoaded()
                Native.setDataDir(app.filesDir.absolutePath)
                loadCatalog(NodeStore.load(app))
            }.onFailure { fail(it) }
            initDone.complete(Unit)
            withContext(Dispatchers.Main.immediate) { refreshTile(app) }
        }
    }

    /** Suspends until [start] finished, successfully or not. */
    suspend fun awaitInit() = initDone.await()

    private fun fail(t: Throwable) {
        nativeReady.value = false
        nativeError.value = t.message?.takeIf { it.isNotBlank() } ?: t.javaClass.simpleName
    }

    private suspend fun loadCatalog(loadErr: String?) {
        val list = parseCatalog(Native.getCatalog())
        if (list.isEmpty()) error(loadErr ?: "empty proxy catalog")
        loadErr?.let { postUiMessage(it) }

        val prefs = store().data.first()
        val fp = catalogFingerprint(list)
        val prevFp = prefs[KEY_CATALOG_FP]
        val (slots, reset) = restoreSlots(list, prevFp) { prefs[keyForNode(it)] }
        if (prevFp != fp) {
            store().edit { ed ->
                ed[KEY_CATALOG_FP] = fp
                reset.forEachIndexed { i, r -> if (r) ed[keyForNode(i)] = 0 }
            }
        }
        val savedRegion = (prefs[KEY_REGION] ?: 0).coerceIn(0, list.size - 1)
        withContext(Dispatchers.Main.immediate) {
            nodeMemorySlots = slots
            regions.value = list
            nodeLatencies.clear()
            currentRegionIdx.value = savedRegion
            currentNodeIdx.value = slots[savedRegion]
        }
        Native.switchNode(savedRegion, slots[savedRegion])
        isVpnRunning.value = Native.isCoreRunning()
        nativeError.value = null
        nativeReady.value = true
    }

    private fun saveInt(key: Preferences.Key<Int>, v: Int) {
        switchScope.launch { store().edit { it[key] = v } }
    }

    fun consumeUiMessage() {
        uiMessage.value = null
    }

    private fun postUiMessage(msg: String) {
        mainScope.launch { uiMessage.value = msg }
    }

    fun setVpn(ctx: Context, on: Boolean) {
        if (!nativeReady.value) return
        val i = Intent(ctx, ArcVpnService::class.java)
            .setAction(if (on) ArcVpnService.ACTION_START else ArcVpnService.ACTION_STOP)
        if (on) ctx.startForegroundService(i) else ctx.startService(i)
    }

    fun selectNodeInCurrentRegion(newNodeIdx: Int) {
        if (!nativeReady.value) return
        val aIdx = currentRegionIdx.value
        val prevNode = nodeMemorySlots[aIdx]
        if (prevNode == newNodeIdx) return

        nodeMemorySlots[aIdx] = newNodeIdx
        currentNodeIdx.value = newNodeIdx
        saveInt(keyForNode(aIdx), newNodeIdx)

        switchScope.launch {
            val ok = runCatching { Native.switchNode(aIdx, newNodeIdx) }.isSuccess
            if (ok) {
                withContext(Dispatchers.Main.immediate) { refreshVpnNotification() }
                return@launch
            }
            withContext(Dispatchers.Main.immediate) {
                if (currentRegionIdx.value == aIdx && currentNodeIdx.value == newNodeIdx) {
                    nodeMemorySlots[aIdx] = prevNode
                    currentNodeIdx.value = prevNode
                    saveInt(keyForNode(aIdx), prevNode)
                    switchScope.launch { runCatching { Native.switchNode(aIdx, prevNode) } }
                }
                postUiMessage("切换节点失败，已恢复上次选择")
            }
        }
    }

    fun selectRegion(newRegionIdx: Int) {
        if (!nativeReady.value) return
        val prevRegion = currentRegionIdx.value
        if (prevRegion == newRegionIdx) return

        invalidateInFlightLatency()
        val prevNode = currentNodeIdx.value
        val rememberedNode = nodeMemorySlots[newRegionIdx]
        currentRegionIdx.value = newRegionIdx
        currentNodeIdx.value = rememberedNode
        saveInt(KEY_REGION, newRegionIdx)

        switchScope.launch {
            val ok = runCatching { Native.switchNode(newRegionIdx, rememberedNode) }.isSuccess
            if (ok) {
                withContext(Dispatchers.Main.immediate) { refreshVpnNotification() }
                return@launch
            }
            withContext(Dispatchers.Main.immediate) {
                if (currentRegionIdx.value == newRegionIdx && currentNodeIdx.value == rememberedNode) {
                    currentRegionIdx.value = prevRegion
                    currentNodeIdx.value = prevNode
                    saveInt(KEY_REGION, prevRegion)
                    switchScope.launch { runCatching { Native.switchNode(prevRegion, prevNode) } }
                }
                postUiMessage("切换地区失败，已恢复上次选择")
            }
        }
    }

    private var latencyTestGen = 0

    private const val LATENCY_STALE_MS = 60_000L
    private var clearLatenciesJob: Job? = null

    private fun cancelLatencyAutoClear() {
        clearLatenciesJob?.cancel()
        clearLatenciesJob = null
    }

    private fun scheduleLatencyAutoClear() {
        clearLatenciesJob?.cancel()
        clearLatenciesJob = mainScope.launch {
            delay(LATENCY_STALE_MS)
            nodeLatencies.clear()
            refreshVpnNotification()
        }
    }

    fun triggerBatchLatencyTest() {
        if (!nativeReady.value || isTestingLatency.value) return
        val aIdx = currentRegionIdx.value
        val gen = ++latencyTestGen
        cancelLatencyAutoClear()
        Native.latencyListener = object : Native.LatencyListener {
            override fun onStateChanged(testing: Boolean) {
                mainScope.launch {
                    if (gen != latencyTestGen) return@launch
                    isTestingLatency.value = testing
                    if (!testing) scheduleLatencyAutoClear()
                }
            }

            override fun onNodeResult(nodeIdx: Int, latencyMs: Int) {
                mainScope.launch {
                    if (gen != latencyTestGen) return@launch
                    nodeLatencies["${aIdx}_$nodeIdx"] = latencyMs
                    if (aIdx == currentRegionIdx.value && nodeIdx == currentNodeIdx.value) {
                        refreshVpnNotification()
                    }
                }
            }
        }
        Native.testRegionLatencies(aIdx)
    }

    private fun invalidateInFlightLatency() {
        if (!isTestingLatency.value) return
        latencyTestGen++
        isTestingLatency.value = false

        Native.latencyListener = null
        if (Native.isLoaded()) {
            runCatching { Native.cancelBatchLatencyTest() }
        }

        scheduleLatencyAutoClear()
    }

    private fun refreshVpnNotification() {
        (Native.vpnService as? ArcVpnService)?.refreshNotification()
    }

    fun refreshTile(ctx: Context) {
        mainScope.launch { ArcTileService.listening?.sync() }
        runCatching {
            TileService.requestListeningState(
                ctx.applicationContext,
                ComponentName(ctx.applicationContext, ArcTileService::class.java),
            )
        }
    }
}
