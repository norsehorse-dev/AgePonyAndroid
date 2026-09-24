package com.agepony.app.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy

/**
 * ProxyConfig.toJavaProxy resolves the user's proxy settings for the GitHub key
 * fetch. Pure java.net logic, so it runs as a host unit test with no network.
 */
class ProxyConfigTest {

    @Test
    fun none_isDirectConnection() {
        assertNull(ProxyConfig(ProxyType.NONE, "127.0.0.1", 9050).toJavaProxy())
    }

    @Test
    fun socks_buildsUnresolvedSocksProxy() {
        val p = ProxyConfig(ProxyType.SOCKS, "127.0.0.1", 9050).toJavaProxy()!!
        assertEquals(Proxy.Type.SOCKS, p.type())
        val a = p.address() as InetSocketAddress
        assertTrue("hostname must stay unresolved so DNS goes via the proxy", a.isUnresolved)
        assertEquals("127.0.0.1", a.hostString)
        assertEquals(9050, a.port)
    }

    @Test
    fun http_buildsHttpProxy() {
        val p = ProxyConfig(ProxyType.HTTP, "proxy.example", 8080).toJavaProxy()!!
        assertEquals(Proxy.Type.HTTP, p.type())
        assertEquals(8080, (p.address() as InetSocketAddress).port)
    }

    @Test
    fun trimsHost() {
        val p = ProxyConfig(ProxyType.SOCKS, "  127.0.0.1  ", 9050).toJavaProxy()!!
        assertEquals("127.0.0.1", (p.address() as InetSocketAddress).hostString)
    }

    @Test(expected = IllegalArgumentException::class)
    fun enabledWithBlankHost_throws() {
        ProxyConfig(ProxyType.SOCKS, "   ", 9050).toJavaProxy()
    }

    @Test(expected = IllegalArgumentException::class)
    fun enabledWithZeroPort_throws() {
        ProxyConfig(ProxyType.HTTP, "127.0.0.1", 0).toJavaProxy()
    }

    @Test(expected = IllegalArgumentException::class)
    fun enabledWithPortTooHigh_throws() {
        ProxyConfig(ProxyType.HTTP, "127.0.0.1", 70000).toJavaProxy()
    }

    @Test
    fun fromKey_roundTripsAndDefaults() {
        assertEquals(ProxyType.SOCKS, ProxyType.fromKey("socks"))
        assertEquals(ProxyType.HTTP, ProxyType.fromKey("http"))
        assertEquals(ProxyType.NONE, ProxyType.fromKey("none"))
        assertEquals(ProxyType.NONE, ProxyType.fromKey(null))
        assertEquals(ProxyType.NONE, ProxyType.fromKey("garbage"))
    }
}
