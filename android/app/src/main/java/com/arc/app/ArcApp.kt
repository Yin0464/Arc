package com.arc.app

import android.app.Application

/** Starts core and catalog init once per process, before any activity, service or tile. */
class ArcApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AppState.start(this)
    }
}
