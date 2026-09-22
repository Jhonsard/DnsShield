package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.vpn.packet.DnsPacket
import com.example.vpn.packet.DnsPacketParser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer

/**
 * Core VpnService implementing the on-device DNS interception architecture.
 *
 * It establishes a TUN virtual interface configured to route exclusively DNS traffic (port 53)
 * towards a virtual gateway/DNS address, thereby avoiding full-traffic packet inspection overhead.
 */
class LocalDnsVpnService : VpnService() {

    sealed class VpnStatus {
        data object Idle : VpnStatus()
        data object Starting : VpnStatus()
        data class Running(val virtualIp: String, val gatewayIp: String) : VpnStatus()
        data object Stopping : VpnStatus()
        data class Error(val message: String) : VpnStatus()
    }

    data class InterceptedQuery(
        val timestamp: Long = System.currentTimeMillis(),
        val domain: String,
        val queryType: String,
        val sourceIp: String,
        val isBlocked: Boolean = false
    )

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var packetLoopJob: Job? = null

    private var tunInterface: ParcelFileDescriptor? = null
    private var isRunning: Boolean = false

    companion object {
        const val TAG = "LocalDnsVpnService"

        // Actions
        const val ACTION_START = "com.example.vpn.ACTION_START"
        const val ACTION_STOP = "com.example.vpn.ACTION_STOP"

        // Network parameters
        const val VPN_MTU = 1500
        const val VIRTUAL_IP_V4 = "10.10.10.1"
        const val VIRTUAL_GATEWAY_V4 = "10.10.10.2"
        const val VIRTUAL_IP_V6 = "fd00::1"
        const val VIRTUAL_GATEWAY_V6 = "fd00::2"

        // Notification channel
        private const val NOTIFICATION_CHANNEL_ID = "shield_vpn_channel"
        private const val NOTIFICATION_ID = 1001

        private val _vpnStatus = MutableStateFlow<VpnStatus>(VpnStatus.Idle)
        val vpnStatus: StateFlow<VpnStatus> = _vpnStatus.asStateFlow()

        private val _capturedQueries = MutableStateFlow<List<InterceptedQuery>>(emptyList())
        val capturedQueries: StateFlow<List<InterceptedQuery>> = _capturedQueries.asStateFlow()

        /**
         * Helper method to request starting the VPN service.
         */
        fun start(context: Context) {
            val intent = Intent(context, LocalDnsVpnService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Helper method to request stopping the VPN service.
         */
        fun stop(context: Context) {
            val intent = Intent(context, LocalDnsVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    // =========================================================================
    // Lifecycle: onCreate
    // =========================================================================
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VpnService onCreate: Initializing service and notification channels")
        createNotificationChannel()
    }

    // =========================================================================
    // Lifecycle: onStartCommand
    // =========================================================================
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        Log.i(TAG, "VpnService onStartCommand with action: $action")

        when (action) {
            ACTION_START -> {
                if (!isRunning) {
                    _vpnStatus.value = VpnStatus.Starting
                    // 1. Mandatory foreground notification immediately to satisfy ANR/FGS requirements
                    startForeground(NOTIFICATION_ID, buildForegroundNotification("Initialisation de la protection..."))

                    // 2. Establish TUN interface and launch worker loop
                    val success = establishTunAndStart()
                    if (!success) {
                        Log.e(TAG, "Échec de l'établissement du tunnel VPN")
                        stopSelf()
                        return START_NOT_STICKY
                    }
                }
            }
            ACTION_STOP -> {
                Log.i(TAG, "Arrêt demandé via ACTION_STOP")
                teardownVpn()
                stopSelf()
                return START_NOT_STICKY
            }
        }

        return START_STICKY
    }

    // =========================================================================
    // Builder Pattern: Establishing TUN Interface
    // =========================================================================
    /**
     * Constructs and establishes the TUN virtual network interface using VpnService.Builder.
     * Configures targeted routing so only DNS packets (IPv4/IPv6) enter the tunnel.
     */
    private fun establishTunAndStart(): Boolean {
        try {
            val configureIntent = PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val builder = Builder().apply {
                setSession("ShieldDNS-Core")
                setMtu(VPN_MTU)
                setConfigureIntent(configureIntent)
                setBlocking(true)

                // 1. Assign Virtual IP to local tun0 interface
                addAddress(VIRTUAL_IP_V4, 32)
                addAddress(VIRTUAL_IP_V6, 128)

                // 2. Designate Virtual DNS Gateway
                addDnsServer(VIRTUAL_GATEWAY_V4)
                addDnsServer(VIRTUAL_GATEWAY_V6)

                // 3. Selective routing: ONLY forward packets targeting our virtual DNS resolver
                // Regular application data (TCP 80/443, etc.) bypasses the TUN interface entirely.
                addRoute(VIRTUAL_GATEWAY_V4, 32)
                addRoute(VIRTUAL_GATEWAY_V6, 128)

                // 4. Whitelist self application to prevent socket recursion
                try {
                    addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    Log.w(TAG, "Impossible d'exclure le package $packageName", e)
                }
            }

            // Establish file descriptor
            tunInterface = builder.establish()
            if (tunInterface == null) {
                _vpnStatus.value = VpnStatus.Error("Permission VPN révoquée ou échec establish()")
                return false
            }

            isRunning = true
            _vpnStatus.value = VpnStatus.Running(VIRTUAL_IP_V4, VIRTUAL_GATEWAY_V4)

            // Update persistent notification with active state
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.notify(
                NOTIFICATION_ID,
                buildForegroundNotification("Protection active — Filtrage local DNS")
            )

            // Launch reading loop on background IO thread
            val fd = tunInterface!!.fileDescriptor
            packetLoopJob = serviceScope.launch {
                runTunReadLoop(fd)
            }

            Log.i(TAG, "Interface TUN établie avec succès (Virtual IP: $VIRTUAL_IP_V4, Gateway: $VIRTUAL_GATEWAY_V4)")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Exception lors de l'établissement du tunnel", e)
            _vpnStatus.value = VpnStatus.Error(e.message ?: "Erreur inconnue")
            return false
        }
    }

    /**
     * IO worker loop processing incoming IP datagrams from the TUN interface.
     */
    private fun runTunReadLoop(fd: java.io.FileDescriptor) {
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)

        // Pre-allocate direct byte buffers to eliminate JVM GC churn in the hot path
        val packetBuffer = ByteBuffer.allocateDirect(VPN_MTU)
        val rawBuffer = ByteArray(VPN_MTU)

        Log.i(TAG, "Boucle de lecture TUN démarrée")

        while (serviceScope.isActive && isRunning) {
            try {
                packetBuffer.clear()
                val readBytes = inputStream.read(rawBuffer)
                if (readBytes <= 0) continue

                packetBuffer.put(rawBuffer, 0, readBytes)
                packetBuffer.flip()

                // Route datagram to DNS inspection engine
                handlePacket(packetBuffer, readBytes, outputStream)

            } catch (e: IOException) {
                if (isRunning) {
                    Log.e(TAG, "Erreur IO dans la boucle TUN", e)
                }
                break
            }
        }

        Log.i(TAG, "Boucle de lecture TUN terminée")
    }

    /**
     * Parses the packet header to extract DNS datagrams and responds locally or forwards upstream.
     */
    private fun handlePacket(buffer: ByteBuffer, length: Int, outStream: FileOutputStream) {
        val dnsPacket = DnsPacketParser.parse(buffer, length) ?: return
        if (dnsPacket.isQuery) {
            onDnsQueryIntercepted(dnsPacket, buffer, outStream)
        }
    }

    /**
     * Skeleton hook for DNS question inspection and future filtering logic.
     * Extracts QNAME (domain), QTYPE (A, AAAA, etc.), and sets up the interception point.
     */
    private fun onDnsQueryIntercepted(
        dnsPacket: DnsPacket,
        rawIpBuffer: ByteBuffer,
        outStream: FileOutputStream
    ) {
        val domain = dnsPacket.primaryDomain ?: return
        val queryType = dnsPacket.primaryQueryType.name
        val srcIp = dnsPacket.ipHeader.sourceIp.hostAddress ?: "unknown"

        Log.d(
            TAG,
            "DNS Query interceptée: domain=$domain, type=$queryType, id=0x${dnsPacket.dnsHeader.id.toString(16)}, src=$srcIp"
        )

        // Store query in live ring buffer for UI diagnostics and verification
        val intercepted = InterceptedQuery(
            domain = domain,
            queryType = queryType,
            sourceIp = srcIp,
            isBlocked = false // Squelette de filtrage : sera évalué par le moteur de règles (Trie / hosts)
        )

        val currentList = _capturedQueries.value.toMutableList()
        if (currentList.size >= 50) {
            currentList.removeAt(currentList.size - 1)
        }
        currentList.add(0, intercepted)
        _capturedQueries.value = currentList

        // Future filtering logic hook:
        // val shouldBlock = FilterEngine.matches(domain)
        // if (shouldBlock) {
        //     val blockedReply = DnsResponseForge.forgeBlocked(dnsPacket)
        //     outStream.write(blockedReply)
        // } else {
        //     forwardUpstream(dnsPacket, outStream)
        // }
    }

    // =========================================================================
    // Lifecycle: onRevoke
    // =========================================================================
    override fun onRevoke() {
        Log.w(TAG, "VpnService onRevoke: Le système ou l'utilisateur a révoqué l'accès VPN")
        teardownVpn()
        super.onRevoke()
    }

    // =========================================================================
    // Lifecycle: onDestroy
    // =========================================================================
    override fun onDestroy() {
        Log.i(TAG, "VpnService onDestroy: Libération des ressources et fermeture du tunnel")
        teardownVpn()
        serviceScope.cancel()
        super.onDestroy()
    }

    /**
     * Gracefully stops the worker loop and closes the TUN descriptor.
     */
    private fun teardownVpn() {
        if (!isRunning && tunInterface == null) return

        _vpnStatus.value = VpnStatus.Stopping
        isRunning = false

        packetLoopJob?.cancel()
        packetLoopJob = null

        try {
            tunInterface?.close()
            tunInterface = null
        } catch (e: IOException) {
            Log.e(TAG, "Erreur lors de la fermeture de ParcelFileDescriptor", e)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        _vpnStatus.value = VpnStatus.Idle
        Log.i(TAG, "Teardown VPN terminé")
    }

    // =========================================================================
    // Notification Management
    // =========================================================================
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Filtrage DNS ShieldDNS",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Notification persistante pour le maintien du VPN local"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(contentText: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("ShieldDNS")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
