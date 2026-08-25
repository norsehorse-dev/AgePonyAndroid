package com.agepony.app.network

import com.agepony.app.vault.ProxyConfig
import com.agepony.app.vault.ProxyType
import okhttp3.Credentials
import okhttp3.OkHttpClient
import java.net.Authenticator
import java.net.PasswordAuthentication
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

//
// The single OkHttp client for AgePony's one and only network path: the GitHub
// .keys fetch in RecipientImport. Building it here (not per call) means the
// proxy setting is applied in exactly one place, and a dead proxy makes the
// fetch FAIL -- there is no direct fallback anywhere.
//
// Why OkHttp rather than the plain HttpURLConnection this replaced: for a SOCKS
// proxy OkHttp hands the socket an *unresolved* target address, so the proxy
// (Tor) resolves the hostname. HttpURLConnection tends to resolve on-device
// first, which leaks the DNS lookup outside Tor. Avoiding that leak is the whole
// point of the feature, so it has to hold.
//
object HttpClientFactory {

    private const val CONNECT_MS = 15_000L
    private const val READ_MS = 15_000L

    // Tor adds latency; give proxied requests more headroom.
    private const val TOR_CONNECT_MS = 30_000L
    private const val TOR_READ_MS = 30_000L

    @Volatile private var cached: OkHttpClient? = null
    @Volatile private var cachedSignature: String? = null

    // SOCKS5 username/password reach the JVM socket layer only through the
    // process-wide default Authenticator. It is installed once; the holder
    // below is swapped per config so a credential change takes effect without
    // touching setDefault again. It answers only for the active proxy host and
    // port on a PROXY request, and returns null otherwise, so it never supplies
    // credentials to anything else in the process.
    @Volatile private var socksCredentials: PasswordAuthentication? = null
    @Volatile private var socksHost: String? = null
    @Volatile private var socksPort: Int = -1
    private val authenticatorInstalled = AtomicBoolean(false)

    /** The shared client for [config], rebuilt only when the config changes. */
    @Synchronized
    fun client(config: ProxyConfig): OkHttpClient {
        val signature = config.signature
        val existing = cached
        if (existing != null && cachedSignature == signature) return existing
        val built = build(config)
        cached = built
        cachedSignature = signature
        return built
    }

    private fun build(config: ProxyConfig): OkHttpClient {
        val proxied = config.enabled
        // Throws on incomplete proxy settings, which surfaces as a failed fetch
        // rather than a silent direct connection (fail-closed).
        val proxy = config.toJavaProxy()

        if (proxied && config.type == ProxyType.SOCKS && config.hasCredentials) {
            socksCredentials =
                PasswordAuthentication(config.username, config.password.toCharArray())
            socksHost = config.host.trim()
            socksPort = config.port
            ensureAuthenticatorInstalled()
        } else {
            socksCredentials = null
            socksHost = null
            socksPort = -1
        }

        val builder = OkHttpClient.Builder()
            .connectTimeout(if (proxied) TOR_CONNECT_MS else CONNECT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(if (proxied) TOR_READ_MS else READ_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(if (proxied) TOR_READ_MS else READ_MS, TimeUnit.MILLISECONDS)
            // No automatic retry onto another route: there is no non-proxy route
            // to fall back to, and we never want one.
            .retryOnConnectionFailure(false)

        if (proxy != null) {
            builder.proxy(proxy)
            // HTTP proxy Basic auth. (SOCKS auth is handled by the JVM
            // Authenticator above; OkHttp's proxyAuthenticator is HTTP-only.)
            if (config.type == ProxyType.HTTP && config.hasCredentials) {
                val credential = Credentials.basic(config.username, config.password)
                builder.proxyAuthenticator(object : okhttp3.Authenticator {
                    override fun authenticate(
                        route: okhttp3.Route?,
                        response: okhttp3.Response,
                    ): okhttp3.Request? {
                        // Already tried once (header present): give up rather than loop.
                        if (response.request.header("Proxy-Authorization") != null) return null
                        return response.request.newBuilder()
                            .header("Proxy-Authorization", credential)
                            .build()
                    }
                })
            }
        }
        return builder.build()
    }

    private fun ensureAuthenticatorInstalled() {
        if (authenticatorInstalled.compareAndSet(false, true)) {
            Authenticator.setDefault(object : Authenticator() {
                override fun getPasswordAuthentication(): PasswordAuthentication? {
                    val cred = socksCredentials ?: return null
                    if (requestorType != Authenticator.RequestorType.PROXY) return null
                    val host = socksHost ?: return null
                    val reqHost = requestingHost ?: return null
                    if (!reqHost.equals(host, ignoreCase = true)) return null
                    if (requestingPort != socksPort) return null
                    return cred
                }
            })
        }
    }
}
