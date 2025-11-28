package io.grapevine.network

import nl.tudelft.ipv8.Community
import nl.tudelft.ipv8.Overlay
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.messaging.Packet
import org.slf4j.LoggerFactory

/**
 * The main overlay network for Grapevine.
 * Handles peer discovery and message routing for the social network.
 */
class GrapevineOverlay : Community() {
    override val serviceId = "d7e5285a1c8a8e4f7b0c9d2e3f4a5b6c7d8e9f0a"

    private val logger = LoggerFactory.getLogger(GrapevineOverlay::class.java)
    private val messageListeners = mutableListOf<MessageListener>()

    companion object {
        // Message type IDs
        const val MSG_PING = 1
        const val MSG_PONG = 2
        const val MSG_BLOCK_REQUEST = 10
        const val MSG_BLOCK_RESPONSE = 11
        const val MSG_CONTENT_REQUEST = 20
        const val MSG_CONTENT_RESPONSE = 21
    }

    init {
        messageHandlers[MSG_PING] = ::onPing
        messageHandlers[MSG_PONG] = ::onPong
    }

    /**
     * Adds a listener for incoming messages.
     */
    fun addMessageListener(listener: MessageListener) {
        messageListeners.add(listener)
    }

    /**
     * Removes a message listener.
     */
    fun removeMessageListener(listener: MessageListener) {
        messageListeners.remove(listener)
    }

    /**
     * Returns all currently connected peers.
     */
    fun getConnectedPeers(): List<Peer> {
        return getPeers()
    }

    /**
     * Sends a ping to a specific peer.
     */
    fun sendPing(peer: Peer) {
        logger.debug("Sending ping to ${peer.mid}")
        val packet = serializePacket(MSG_PING, PingPayload(System.currentTimeMillis()))
        send(peer, packet)
    }

    /**
     * Broadcasts a ping to all connected peers.
     */
    fun broadcastPing() {
        val peers = getPeers()
        logger.debug("Broadcasting ping to ${peers.size} peers")
        val payload = PingPayload(System.currentTimeMillis())
        for (peer in peers) {
            val packet = serializePacket(MSG_PING, payload)
            send(peer, packet)
        }
    }

    private fun onPing(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(PingPayload.Deserializer)
        logger.debug("Received ping from ${peer.mid}, timestamp: ${payload.timestamp}")

        // Respond with pong
        val pongPacket = serializePacket(MSG_PONG, PongPayload(payload.timestamp, System.currentTimeMillis()))
        send(peer, pongPacket)

        messageListeners.forEach { it.onPingReceived(peer, payload.timestamp) }
    }

    private fun onPong(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(PongPayload.Deserializer)
        val rtt = System.currentTimeMillis() - payload.originalTimestamp
        logger.debug("Received pong from ${peer.mid}, RTT: ${rtt}ms")

        messageListeners.forEach { it.onPongReceived(peer, rtt) }
    }

    /**
     * Factory for creating GrapevineOverlay instances.
     */
    class Factory : Overlay.Factory<GrapevineOverlay>(GrapevineOverlay::class.java)

    /**
     * Listener interface for overlay messages.
     */
    interface MessageListener {
        fun onPingReceived(peer: Peer, timestamp: Long) {}
        fun onPongReceived(peer: Peer, rtt: Long) {}
    }
}
