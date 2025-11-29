package io.grapevine.network

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadsTest {

    @Test
    fun `PingPayload serializes and deserializes correctly`() {
        val timestamp = 1234567890123L
        val signature = ByteArray(64) { it.toByte() }
        val publicKey = ByteArray(32) { (it + 100).toByte() }

        val payload = PingPayload(timestamp, signature, publicKey)
        val serialized = payload.serialize()
        val (deserialized, size) = PingPayload.deserialize(serialized, 0)

        assertEquals(PingPayload.PAYLOAD_SIZE, size)
        assertEquals(timestamp, deserialized.timestamp)
        assertArrayEquals(signature, deserialized.signature)
        assertArrayEquals(publicKey, deserialized.signerPublicKey)
    }

    @Test
    fun `PingPayload getSignableData returns timestamp bytes`() {
        val timestamp = 1234567890123L
        val payload = PingPayload(timestamp)

        val signableData = payload.getSignableData()

        assertEquals(8, signableData.size)
        // Verify it's big-endian encoding of timestamp
        val reconstructed = java.nio.ByteBuffer.wrap(signableData).getLong()
        assertEquals(timestamp, reconstructed)
    }

    @Test
    fun `PingPayload isSigned returns false for empty signature`() {
        val payload = PingPayload(System.currentTimeMillis())

        assertFalse(payload.isSigned())
    }

    @Test
    fun `PingPayload isSigned returns true for valid signature and key`() {
        val payload = PingPayload(
            System.currentTimeMillis(),
            ByteArray(64),
            ByteArray(32)
        )

        assertTrue(payload.isSigned())
    }

    @Test
    fun `PingPayload isSigned returns false for wrong signature size`() {
        val payload = PingPayload(
            System.currentTimeMillis(),
            ByteArray(32), // Wrong size
            ByteArray(32)
        )

        assertFalse(payload.isSigned())
    }

    @Test
    fun `PingPayload isSigned returns false for wrong public key size`() {
        val payload = PingPayload(
            System.currentTimeMillis(),
            ByteArray(64),
            ByteArray(16) // Wrong size
        )

        assertFalse(payload.isSigned())
    }

    @Test
    fun `PongPayload serializes and deserializes correctly`() {
        val originalTimestamp = 1234567890123L
        val responseTimestamp = 1234567890456L
        val signature = ByteArray(64) { it.toByte() }
        val publicKey = ByteArray(32) { (it + 100).toByte() }

        val payload = PongPayload(originalTimestamp, responseTimestamp, signature, publicKey)
        val serialized = payload.serialize()
        val (deserialized, size) = PongPayload.deserialize(serialized, 0)

        assertEquals(PongPayload.PAYLOAD_SIZE, size)
        assertEquals(originalTimestamp, deserialized.originalTimestamp)
        assertEquals(responseTimestamp, deserialized.responseTimestamp)
        assertArrayEquals(signature, deserialized.signature)
        assertArrayEquals(publicKey, deserialized.signerPublicKey)
    }

    @Test
    fun `PongPayload getSignableData returns both timestamps`() {
        val originalTimestamp = 1234567890123L
        val responseTimestamp = 1234567890456L
        val payload = PongPayload(originalTimestamp, responseTimestamp)

        val signableData = payload.getSignableData()

        assertEquals(16, signableData.size)
        val buffer = java.nio.ByteBuffer.wrap(signableData)
        assertEquals(originalTimestamp, buffer.getLong())
        assertEquals(responseTimestamp, buffer.getLong())
    }

    @Test
    fun `PongPayload isSigned returns false for empty signature`() {
        val payload = PongPayload(System.currentTimeMillis(), System.currentTimeMillis())

        assertFalse(payload.isSigned())
    }

    @Test
    fun `PongPayload isSigned returns true for valid signature and key`() {
        val payload = PongPayload(
            System.currentTimeMillis(),
            System.currentTimeMillis(),
            ByteArray(64),
            ByteArray(32)
        )

        assertTrue(payload.isSigned())
    }

    @Test
    fun `PingPayload serialization fills zeros for missing signature`() {
        val payload = PingPayload(12345L)
        val serialized = payload.serialize()

        assertEquals(PingPayload.PAYLOAD_SIZE, serialized.size)

        // Check that signature and public key areas are zeros
        val signatureStart = 8
        val publicKeyStart = 8 + 64
        for (i in signatureStart until signatureStart + 64) {
            assertEquals(0.toByte(), serialized[i], "Signature byte at $i should be zero")
        }
        for (i in publicKeyStart until publicKeyStart + 32) {
            assertEquals(0.toByte(), serialized[i], "Public key byte at $i should be zero")
        }
    }

    @Test
    fun `PongPayload serialization fills zeros for missing signature`() {
        val payload = PongPayload(12345L, 67890L)
        val serialized = payload.serialize()

        assertEquals(PongPayload.PAYLOAD_SIZE, serialized.size)

        // Check that signature and public key areas are zeros
        val signatureStart = 16
        val publicKeyStart = 16 + 64
        for (i in signatureStart until signatureStart + 64) {
            assertEquals(0.toByte(), serialized[i], "Signature byte at $i should be zero")
        }
        for (i in publicKeyStart until publicKeyStart + 32) {
            assertEquals(0.toByte(), serialized[i], "Public key byte at $i should be zero")
        }
    }

    @Test
    fun `PingPayload deserialization with offset works correctly`() {
        val payload = PingPayload(12345L, ByteArray(64) { 1 }, ByteArray(32) { 2 })
        val serialized = payload.serialize()

        // Add prefix bytes
        val prefixedBuffer = ByteArray(10 + serialized.size)
        System.arraycopy(serialized, 0, prefixedBuffer, 10, serialized.size)

        val (deserialized, size) = PingPayload.deserialize(prefixedBuffer, 10)

        assertEquals(PingPayload.PAYLOAD_SIZE, size)
        assertEquals(12345L, deserialized.timestamp)
    }

    @Test
    fun `PongPayload deserialization with offset works correctly`() {
        val payload = PongPayload(12345L, 67890L, ByteArray(64) { 1 }, ByteArray(32) { 2 })
        val serialized = payload.serialize()

        // Add prefix bytes
        val prefixedBuffer = ByteArray(10 + serialized.size)
        System.arraycopy(serialized, 0, prefixedBuffer, 10, serialized.size)

        val (deserialized, size) = PongPayload.deserialize(prefixedBuffer, 10)

        assertEquals(PongPayload.PAYLOAD_SIZE, size)
        assertEquals(12345L, deserialized.originalTimestamp)
        assertEquals(67890L, deserialized.responseTimestamp)
    }
}
