package com.agepony.app.vault

import android.content.Context
import android.content.pm.PackageManager
import java.net.InetSocketAddress
import java.net.Proxy

//
// 4.2.0 proxy support for the one network public-key lookup: RecipientImport's
// GitHub .keys fetch. Kept as a pure, side-effect-free helper so the logic is
// unit-testable without a live network.
//

/** Which kind of proxy the GitHub key fetch should use. */
enum class ProxyType(val key: String) {
    NONE("none"),
    HTTP("http"),
    SOCKS("socks");

    companion object {
        fun fromKey(k: String?): ProxyType = entries.firstOrNull { it.key == k } ?: NONE
    }
}

/**
 * The user's proxy settings, resolved into a [java.net.Proxy] for the key fetch.
 */
data class ProxyConfig(
    val type: ProxyType,
    val host: String,
    val port: Int,
    val username: String = "",
    val password: String = "",
) {
    /** True when a proxy is selected (anything but NONE). */
    val enabled: Boolean get() = type != ProxyType.NONE

    /** Optional SOCKS5 / proxy credentials are present. */
    val hasCredentials: Boolean get() = username.isNotEmpty() || password.isNotEmpty()

    /**
     * A stable signature so the shared client is rebuilt only when the proxy
     * config actually changes. Credentials are part of it: a new username or
     * password is a different Tor circuit (stream isolation), so the client
     * has to be rebuilt to pick it up.
     */
    val signature: String get() = "${type.key}|${host.trim()}|$port|$username|$password"
    /**
     * Returns null for a direct connection (proxy disabled). Throws
     * [IllegalArgumentException] when the proxy is enabled but host/port are
     * incomplete, so a half-filled setting can never silently fall back to a
     * de-anonymising direct connection.
     */
    fun toJavaProxy(): Proxy? {
        if (type == ProxyType.NONE) return null
        val h = host.trim()
        require(h.isNotEmpty() && port in 1..65535) { "Incomplete proxy settings." }
        val javaType = when (type) {
            ProxyType.HTTP -> Proxy.Type.HTTP
            ProxyType.SOCKS -> Proxy.Type.SOCKS
            ProxyType.NONE -> return null
        }
        // createUnresolved hands the hostname to the proxy rather than resolving
        // it locally -- this is what prevents a DNS leak when routing over Tor.
        return Proxy(javaType, InetSocketAddress.createUnresolved(h, port))
    }

    companion object {
        /** Orbot's default local SOCKS5 listener. */
        const val ORBOT_HOST = "127.0.0.1"
        const val ORBOT_PORT = 9050
        const val ORBOT_PACKAGE = "org.torproject.android"

        /** A direct (no-proxy) config. */
        val DIRECT = ProxyConfig(ProxyType.NONE, "", 0)

        /** Whether Orbot is installed, to drive the settings hint. */
        fun isOrbotInstalled(context: Context): Boolean = try {
            context.packageManager.getPackageInfo(ORBOT_PACKAGE, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
}
