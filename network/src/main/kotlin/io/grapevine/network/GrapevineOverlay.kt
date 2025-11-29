package io.grapevine.network

import nl.tudelft.ipv8.Community
import nl.tudelft.ipv8.Overlay
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.messaging.Packet
import org.slf4j.LoggerFactory

/**
 * The main overlay network for Grapevine.
 * Handles peer discovery and message routing for the social network.
 *
 * ## Message Signing and Verification
 * All outgoing messages are cryptographically signed using the user's Ed25519
 * private key. Incoming messages are verified against the sender's public key.
 * Messages with invalid signatures are rejected and logged.
 *
 * To enable signing, call [setMessageSigner] with a configured [MessageSigner].
 * Without a signer, messages are sent unsigned (for backward compatibility during
 * development, but not recommended for production).
 */
class GrapevineOverlay : Community() {
    override val serviceId = "d7e5285a1c8a8e4f7b0c9d2e3f4a5b6c7d8e9f0a"

    private val logger = LoggerFactory.getLogger(GrapevineOverlay::class.java)
    private val messageListeners = mutableListOf<MessageListener>()
    private var messageSigner: MessageSigner? = null

    /**
     * Whether to require signatures on incoming messages.
     * When true (default), unsigned or invalid messages are rejected.
     * Set to false only for testing or backward compatibility.
     */
    var requireSignatures: Boolean = true

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
     * Sets the message signer for signing outgoing messages and verifying incoming ones.
     *
     * @param signer The MessageSigner to use, or null to disable signing
     */
    fun setMessageSigner(signer: MessageSigner?) {
        this.messageSigner = signer
        if (signer != null) {
            logger.info("Message signing enabled")
        } else {
            logger.warn("Message signing disabled - messages will not be authenticated")
        }
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
     * Sends a signed ping to a specific peer.
     */
    fun sendPing(peer: Peer) {
        logger.debug("Sending ping to ${peer.mid}")
        val timestamp = System.currentTimeMillis()
        val payload = messageSigner?.signPing(timestamp) ?: PingPayload(timestamp)
        val packet = serializePacket(MSG_PING, payload)
        send(peer, packet)
    }

    /**
     * Broadcasts a signed ping to all connected peers.
     */
    fun broadcastPing() {
        val peers = getPeers()
        logger.debug("Broadcasting ping to ${peers.size} peers")
        val timestamp = System.currentTimeMillis()
        val payload = messageSigner?.signPing(timestamp) ?: PingPayload(timestamp)
        for (peer in peers) {
            val packet = serializePacket(MSG_PING, payload)
            send(peer, packet)
        }
    }

    private fun onPing(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(PingPayload.Deserializer)

        // Verify signature if signer is configured
        val signer = messageSigner
        if (signer != null) {
            val result = signer.verifyPing(payload)
            when (result) {
                is VerificationResult.Valid -> {
                    logger.debug("Received verified ping from ${peer.mid}, timestamp: ${payload.timestamp}")
                }
                is VerificationResult.Unsigned -> {
                    if (requireSignatures) {
                        logger.warn("REJECTED unsigned ping from ${peer.mid}")
                        messageListeners.forEach { it.onVerificationFailed(peer, "ping", "Message not signed") }
                        return
                    }
                    logger.warn("Accepting unsigned ping from ${peer.mid} (signatures not required)")
                }
                is VerificationResult.Invalid -> {
                    logger.warn("REJECTED ping with invalid signature from ${peer.mid}: ${result.reason}")
                    messageListeners.forEach { it.onVerificationFailed(peer, "ping", result.reason) }
                    return
                }
            }
        } else {
            logger.debug("Received ping from ${peer.mid}, timestamp: ${payload.timestamp} (verification disabled)")
        }

        // Respond with signed pong
        val responseTimestamp = System.currentTimeMillis()
        val pongPayload = messageSigner?.signPong(payload.timestamp, responseTimestamp)
            ?: PongPayload(payload.timestamp, responseTimestamp)
        val pongPacket = serializePacket(MSG_PONG, pongPayload)
        send(peer, pongPacket)

        messageListeners.forEach { it.onPingReceived(peer, payload.timestamp) }
    }

    private fun onPong(packet: Packet) {
        val (peer, payload) = packet.getAuthPayload(PongPayload.Deserializer)

        // Verify signature if signer is configured
        val signer = messageSigner
        if (signer != null) {
            val result = signer.verifyPong(payload)
            when (result) {
                is VerificationResult.Valid -> {
                    val rtt = System.currentTimeMillis() - payload.originalTimestamp
                    logger.debug("Received verified pong from ${peer.mid}, RTT: ${rtt}ms")
                }
                is VerificationResult.Unsigned -> {
                    if (requireSignatures) {
                        logger.warn("REJECTED unsigned pong from ${peer.mid}")
                        messageListeners.forEach { it.onVerificationFailed(peer, "pong", "Message not signed") }
                        return
                    }
                    logger.warn("Accepting unsigned pong from ${peer.mid} (signatures not required)")
                }
                is VerificationResult.Invalid -> {
                    logger.warn("REJECTED pong with invalid signature from ${peer.mid}: ${result.reason}")
                    messageListeners.forEach { it.onVerificationFailed(peer, "pong", result.reason) }
                    return
                }
            }
        } else {
            val rtt = System.currentTimeMillis() - payload.originalTimestamp
            logger.debug("Received pong from ${peer.mid}, RTT: ${rtt}ms (verification disabled)")
        }

        val rtt = System.currentTimeMillis() - payload.originalTimestamp
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

        /**
         * Called when signature verification fails for an incoming message.
         *
         * @param peer The peer that sent the message
         * @param messageType The type of message that failed verification
         * @param reason Description of why verification failed
         */
        fun onVerificationFailed(peer: Peer, messageType: String, reason: String) {}
    }
}
