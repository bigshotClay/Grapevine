package io.grapevine.network

import nl.tudelft.ipv8.messaging.Deserializable
import nl.tudelft.ipv8.messaging.Serializable
import java.nio.ByteBuffer

/**
 * Payload for ping messages.
 */
class PingPayload(val timestamp: Long) : Serializable {
    override fun serialize(): ByteArray {
        return ByteBuffer.allocate(8).putLong(timestamp).array()
    }

    companion object Deserializer : Deserializable<PingPayload> {
        override fun deserialize(buffer: ByteArray, offset: Int): Pair<PingPayload, Int> {
            val timestamp = ByteBuffer.wrap(buffer, offset, 8).getLong()
            return Pair(PingPayload(timestamp), 8)
        }
    }
}

/**
 * Payload for pong messages (response to ping).
 */
class PongPayload(
    val originalTimestamp: Long,
    val responseTimestamp: Long
) : Serializable {
    override fun serialize(): ByteArray {
        return ByteBuffer.allocate(16)
            .putLong(originalTimestamp)
            .putLong(responseTimestamp)
            .array()
    }

    companion object Deserializer : Deserializable<PongPayload> {
        override fun deserialize(buffer: ByteArray, offset: Int): Pair<PongPayload, Int> {
            val bb = ByteBuffer.wrap(buffer, offset, 16)
            val originalTimestamp = bb.getLong()
            val responseTimestamp = bb.getLong()
            return Pair(PongPayload(originalTimestamp, responseTimestamp), 16)
        }
    }
}
