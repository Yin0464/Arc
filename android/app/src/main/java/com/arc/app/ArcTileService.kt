package com.arc.app

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class ArcTileService : TileService() {
    companion object {
        var listening: ArcTileService? = null
    }

    override fun onStartListening() {
        super.onStartListening()
        listening = this
        sync()
    }

    override fun onStopListening() {
        if (listening === this) listening = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (!AppState.nativeReady.value) {
            val actIntent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, actIntent, PendingIntent.FLAG_IMMUTABLE))
            return
        }
        val on = !AppState.isVpnRunning.value && !AppState.coreRecovering.value && !Native.isCoreRunning()
        if (on && VpnService.prepare(this) != null) {
            val actIntent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, actIntent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            if (!on) {
                AppState.isVpnRunning.value = false
                AppState.coreRecovering.value = false
                sync()
            }
            AppState.setVpn(this, on)
        }
    }

    fun sync() {
        val tile = qsTile ?: return
        tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_logo)
        tile.label = getString(R.string.app_name)
        tile.subtitle = null
        tile.state = if (AppState.isVpnRunning.value || AppState.coreRecovering.value) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }
}
