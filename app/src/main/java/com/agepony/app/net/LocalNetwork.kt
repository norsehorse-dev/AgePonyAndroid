package com.agepony.app.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

/**
 * The two bits of local-network plumbing the phone-to-phone key transfer needs. Nothing here
 * reaches the internet: addresses are this phone's own, and the only connection made is to the
 * other phone on the same Wi-Fi.
 */
object LocalNetwork {
    /** This phone's private IPv4 addresses (Wi-Fi, or its own hotspot), for the receive QR code. */
    fun localAddresses(): List<String> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && !it.isVirtual }
            .flatMap { it.inetAddresses.toList() }
            .filterIsInstance<Inet4Address>()
            .filter { it.isSiteLocalAddress }
            .mapNotNull { it.hostAddress }
            .distinct()
    }.getOrDefault(emptyList())

    /**
     * Open a socket to the other phone over Wi-Fi. With mobile data on, Android can route even a
     * local address over cellular, which never reaches the other phone, so the socket is bound
     * to the Wi-Fi network when there is one.
     */
    fun connectOverWifi(context: Context, host: String, port: Int, timeoutMs: Int = 5_000): Socket {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        @Suppress("DEPRECATION")
        val wifi = cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
        val socket = wifi?.socketFactory?.createSocket() ?: Socket()
        socket.connect(InetSocketAddress(host, port), timeoutMs)
        return socket
    }
}
