package com.agepony.app

import android.app.Application
import com.agepony.app.security.AutoLock
import com.agepony.app.security.TempFiles

/**
 * Process-level setup. Owns what must outlive any single activity: the auto-lock timer and
 * screen-off lock (audit H-3), and the sweep of plaintext staging files a previous process
 * may have left in the cache (audits L-19, M-8).
 */
class AgePonyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        TempFiles.sweep(this)
        AutoLock.install(this)
    }
}
