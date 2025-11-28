package io.grapevine.network

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import nl.tudelft.ipv8.IPv8
import nl.tudelft.ipv8.IPv8Configuration
import nl.tudelft.ipv8.OverlayConfiguration
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.attestation.trustchain.TrustChainCommunity
import nl.tudelft.ipv8.attestation.trustchain.TrustChainSettings
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainSQLiteStore
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.keyvault.JavaCryptoProvider
import nl.tudelft.ipv8.messaging.EndpointAggregator
import nl.tudelft.ipv8.messaging.udp.UdpEndpoint
import nl.tudelft.ipv8.peerdiscovery.DiscoveryCommunity
import nl.tudelft.ipv8.peerdiscovery.strategy.PeriodicSimilarity
import nl.tudelft.ipv8.peerdiscovery.strategy.RandomChurn
import nl.tudelft.ipv8.peerdiscovery.strategy.RandomWalk
import nl.tudelft.ipv8.sqldelight.Database
import org.slf4j.LoggerFactory
import java.io.File
import java.net.InetAddress

/**
 * Manages the IPv8 network stack for Grapevine.
 */
class NetworkManager(
    private val port: Int = 8090,
    private val databasePath: String = getDefaultDatabasePath()
) {
    private val logger = LoggerFactory.getLogger(NetworkManager::class.java)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var ipv8: IPv8? = null
    private var privateKey: PrivateKey? = null
    private var trustChainManager: TrustChainManager? = null
    private val peerListeners = mutableListOf<PeerListener>()

    /**
     * Initializes the IPv8 stack with the given private key.
     *
     * @param privateKeyBytes The raw private key bytes, or null to generate a new key
     * @return The public key bytes for the initialized identity
     */
    fun initialize(privateKeyBytes: ByteArray? = null): ByteArray {
        logger.info("Initializing IPv8 network stack on port $port")

        // Generate or restore private key
        privateKey = if (privateKeyBytes != null) {
            JavaCryptoProvider.keyFromPrivateBin(privateKeyBytes)
        } else {
            JavaCryptoProvider.generateKey()
        }

        // Create peer identity
        val myPeer = Peer(privateKey!!)

        // Create UDP endpoint
        val udpEndpoint = UdpEndpoint(port, InetAddress.getByName("0.0.0.0"))
        val endpoint = EndpointAggregator(udpEndpoint, null)

        // Configure overlays
        val discoveryOverlay = createDiscoveryCommunity()
        val trustChainOverlay = createTrustChainCommunity()
        val grapevineOverlay = OverlayConfiguration(
            GrapevineOverlay.Factory(),
            listOf(RandomWalk.Factory())
        )

        val config = IPv8Configuration(
            overlays = listOf(discoveryOverlay, trustChainOverlay, grapevineOverlay),
            walkerInterval = 1.0
        )

        // Initialize IPv8
        ipv8 = IPv8(endpoint, config, myPeer)
        ipv8!!.start()

        logger.info("IPv8 started with peer ID: ${myPeer.mid}")

        // Initialize TrustChain manager
        trustChainManager = TrustChainManager(ipv8!!)

        // Start peer monitoring
        startPeerMonitoring()

        return privateKey!!.pub().keyToBin()
    }

    private fun createDiscoveryCommunity(): OverlayConfiguration<DiscoveryCommunity> {
        return OverlayConfiguration(
            DiscoveryCommunity.Factory(),
            listOf(
                RandomWalk.Factory(timeout = 3.0, peers = 20),
                RandomChurn.Factory(),
                PeriodicSimilarity.Factory()
            )
        )
    }

    private fun createTrustChainCommunity(): OverlayConfiguration<TrustChainCommunity> {
        val settings = TrustChainSettings()

        // Ensure database directory exists
        File(databasePath).parentFile?.mkdirs()

        val driver = app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver("jdbc:sqlite:$databasePath")
        Database.Schema.create(driver)
        val database = Database(driver)
        val store = TrustChainSQLiteStore(database)

        return OverlayConfiguration(
            TrustChainCommunity.Factory(settings, store),
            listOf(RandomWalk.Factory())
        )
    }

    /**
     * Gets the current private key bytes for persistence.
     */
    fun getPrivateKeyBytes(): ByteArray? {
        return privateKey?.keyToBin()
    }

    /**
     * Gets the public key bytes.
     */
    fun getPublicKeyBytes(): ByteArray? {
        return privateKey?.pub()?.keyToBin()
    }

    /**
     * Gets the peer ID (member ID) of the local peer.
     */
    fun getPeerId(): String? {
        return ipv8?.myPeer?.mid
    }

    /**
     * Gets the Grapevine overlay instance.
     */
    fun getOverlay(): GrapevineOverlay? {
        return ipv8?.getOverlay()
    }

    /**
     * Gets the TrustChain manager for block operations.
     */
    fun getTrustChainManager(): TrustChainManager? {
        return trustChainManager
    }

    /**
     * Gets the TrustChain community directly.
     */
    fun getTrustChainCommunity(): TrustChainCommunity? {
        return ipv8?.getOverlay()
    }

    /**
     * Gets all connected peers.
     */
    fun getConnectedPeers(): List<Peer> {
        return getOverlay()?.getConnectedPeers() ?: emptyList()
    }

    /**
     * Adds a listener for peer events.
     */
    fun addPeerListener(listener: PeerListener) {
        peerListeners.add(listener)
    }

    /**
     * Removes a peer listener.
     */
    fun removePeerListener(listener: PeerListener) {
        peerListeners.remove(listener)
    }

    /**
     * Sends a ping to all connected peers.
     */
    fun broadcastPing() {
        getOverlay()?.broadcastPing()
    }

    /**
     * Stops the IPv8 network stack.
     */
    fun stop() {
        logger.info("Stopping IPv8 network stack")
        scope.cancel()
        ipv8?.stop()
        ipv8 = null
    }

    /**
     * Returns whether the network is currently running.
     */
    fun isRunning(): Boolean {
        return ipv8?.isStarted() == true
    }

    private fun startPeerMonitoring() {
        scope.launch {
            var previousPeers = emptySet<String>()

            while (isActive) {
                val currentPeers = getConnectedPeers().map { it.mid }.toSet()

                // Detect new peers
                val newPeers = currentPeers - previousPeers
                for (peerId in newPeers) {
                    val peer = getConnectedPeers().find { it.mid == peerId }
                    if (peer != null) {
                        logger.info("New peer connected: $peerId")
                        peerListeners.forEach { it.onPeerConnected(peer) }
                    }
                }

                // Detect disconnected peers
                val disconnectedPeers = previousPeers - currentPeers
                for (peerId in disconnectedPeers) {
                    logger.info("Peer disconnected: $peerId")
                    peerListeners.forEach { it.onPeerDisconnected(peerId) }
                }

                previousPeers = currentPeers
                delay(1000)
            }
        }
    }

    /**
     * Listener interface for peer connection events.
     */
    interface PeerListener {
        fun onPeerConnected(peer: Peer) {}
        fun onPeerDisconnected(peerId: String) {}
    }

    companion object {
        private fun getDefaultDatabasePath(): String {
            val userHome = System.getProperty("user.home")
            val appDataDir = when {
                System.getProperty("os.name").lowercase().contains("win") -> {
                    System.getenv("APPDATA") ?: "$userHome/AppData/Roaming"
                }
                System.getProperty("os.name").lowercase().contains("mac") -> {
                    "$userHome/Library/Application Support"
                }
                else -> {
                    System.getenv("XDG_DATA_HOME") ?: "$userHome/.local/share"
                }
            }
            return "$appDataDir/Grapevine/trustchain.db"
        }
    }
}
