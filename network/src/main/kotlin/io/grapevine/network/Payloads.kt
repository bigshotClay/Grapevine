package io.grapevine.network

import nl.tudelft.ipv8.messaging.Deserializable
import nl.tudelft.ipv8.messaging.Serializable
import java.nio.ByteBuffer

/**
 * Payload for ping messages with cryptographic signature.
 *
 * The signature covers the timestamp to prevent replay attacks.
 *
 * @property timestamp Unix timestamp in milliseconds when the ping was sent
 * @property signature Ed25519 signature (64 bytes) over the timestamp
 * @property signerPublicKey Ed25519 public key (32 bytes) of the sender
 */
class PingPayload(
    val timestamp: Long,
    val signature: ByteArray = ByteArray(0),
    val signerPublicKey: ByteArray = ByteArray(0)
) : Serializable {

    /**
     * Returns the data that should be signed (timestamp as 8 bytes).
     */
    fun getSignableData(): ByteArray {
        return ByteBuffer.allocate(8).putLong(timestamp).array()
    }

    /**
     * Checks if this payload has a signature attached.
     */
    fun isSigned(): Boolean {
        return signature.size == SIGNATURE_SIZE && signerPublicKey.size == PUBLIC_KEY_SIZE
    }

    override fun serialize(): ByteArray {
        // Format: timestamp (8) + signature (64) + public key (32) = 104 bytes
        val buffer = ByteBuffer.allocate(8 + SIGNATURE_SIZE + PUBLIC_KEY_SIZE)
        buffer.putLong(timestamp)
        buffer.put(if (signature.size == SIGNATURE_SIZE) signature else ByteArray(SIGNATURE_SIZE))
        buffer.put(if (signerPublicKey.size == PUBLIC_KEY_SIZE) signerPublicKey else ByteArray(PUBLIC_KEY_SIZE))
        return buffer.array()
    }

    companion object Deserializer : Deserializable<PingPayload> {
        const val SIGNATURE_SIZE = 64
        const val PUBLIC_KEY_SIZE = 32
        const val PAYLOAD_SIZE = 8 + SIGNATURE_SIZE + PUBLIC_KEY_SIZE

        override fun deserialize(buffer: ByteArray, offset: Int): Pair<PingPayload, Int> {
            val bb = ByteBuffer.wrap(buffer, offset, PAYLOAD_SIZE)
            val timestamp = bb.getLong()
            val signature = ByteArray(SIGNATURE_SIZE)
            bb.get(signature)
            val signerPublicKey = ByteArray(PUBLIC_KEY_SIZE)
            bb.get(signerPublicKey)
            return Pair(PingPayload(timestamp, signature, signerPublicKey), PAYLOAD_SIZE)
        }
    }
}

/**
 * Payload for pong messages (response to ping) with cryptographic signature.
 *
 * The signature covers both timestamps to bind the response to the original ping.
 *
 * @property originalTimestamp The timestamp from the ping message being responded to
 * @property responseTimestamp Unix timestamp in milliseconds when the pong was sent
 * @property signature Ed25519 signature (64 bytes) over both timestamps
 * @property signerPublicKey Ed25519 public key (32 bytes) of the sender
 */
class PongPayload(
    val originalTimestamp: Long,
    val responseTimestamp: Long,
    val signature: ByteArray = ByteArray(0),
    val signerPublicKey: ByteArray = ByteArray(0)
) : Serializable {

    /**
     * Returns the data that should be signed (both timestamps as 16 bytes).
     */
    fun getSignableData(): ByteArray {
        return ByteBuffer.allocate(16)
            .putLong(originalTimestamp)
            .putLong(responseTimestamp)
            .array()
    }

    /**
     * Checks if this payload has a signature attached.
     */
    fun isSigned(): Boolean {
        return signature.size == SIGNATURE_SIZE && signerPublicKey.size == PUBLIC_KEY_SIZE
    }

    override fun serialize(): ByteArray {
        // Format: originalTimestamp (8) + responseTimestamp (8) + signature (64) + public key (32) = 112 bytes
        val buffer = ByteBuffer.allocate(16 + SIGNATURE_SIZE + PUBLIC_KEY_SIZE)
        buffer.putLong(originalTimestamp)
        buffer.putLong(responseTimestamp)
        buffer.put(if (signature.size == SIGNATURE_SIZE) signature else ByteArray(SIGNATURE_SIZE))
        buffer.put(if (signerPublicKey.size == PUBLIC_KEY_SIZE) signerPublicKey else ByteArray(PUBLIC_KEY_SIZE))
        return buffer.array()
    }

    companion object Deserializer : Deserializable<PongPayload> {
        const val SIGNATURE_SIZE = 64
        const val PUBLIC_KEY_SIZE = 32
        const val PAYLOAD_SIZE = 16 + SIGNATURE_SIZE + PUBLIC_KEY_SIZE

        override fun deserialize(buffer: ByteArray, offset: Int): Pair<PongPayload, Int> {
            val bb = ByteBuffer.wrap(buffer, offset, PAYLOAD_SIZE)
            val originalTimestamp = bb.getLong()
            val responseTimestamp = bb.getLong()
            val signature = ByteArray(SIGNATURE_SIZE)
            bb.get(signature)
            val signerPublicKey = ByteArray(PUBLIC_KEY_SIZE)
            bb.get(signerPublicKey)
            return Pair(PongPayload(originalTimestamp, responseTimestamp, signature, signerPublicKey), PAYLOAD_SIZE)
        }
    }
}
