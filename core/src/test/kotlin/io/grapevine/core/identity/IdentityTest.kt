package io.grapevine.core.identity

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Base64

class IdentityTest {

    @Test
    fun `create identity with valid public key`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        assertEquals(32, identity.publicKey.size)
        assertNull(identity.displayName)
        assertNull(identity.avatarHash)
        assertNull(identity.bio)
        assertTrue(identity.createdAt > 0)
    }

    @Test
    fun `create identity with all fields`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(
            publicKey = publicKey,
            displayName = "Test User",
            avatarHash = "abc123",
            bio = "This is a test bio",
            createdAt = 1234567890L
        )

        assertEquals("Test User", identity.displayName)
        assertEquals("abc123", identity.avatarHash)
        assertEquals("This is a test bio", identity.bio)
        assertEquals(1234567890L, identity.createdAt)
    }

    @Test
    fun `reject invalid public key size`() {
        assertThrows<IllegalArgumentException> {
            Identity(publicKey = ByteArray(16))
        }

        assertThrows<IllegalArgumentException> {
            Identity(publicKey = ByteArray(64))
        }
    }

    @Test
    fun `reject display name exceeding max length`() {
        val publicKey = ByteArray(32)
        val longName = "a".repeat(Identity.MAX_DISPLAY_NAME_LENGTH + 1)

        assertThrows<IllegalArgumentException> {
            Identity(publicKey = publicKey, displayName = longName)
        }
    }

    @Test
    fun `accept display name at max length`() {
        val publicKey = ByteArray(32)
        val maxName = "a".repeat(Identity.MAX_DISPLAY_NAME_LENGTH)

        val identity = Identity(publicKey = publicKey, displayName = maxName)
        assertEquals(maxName, identity.displayName)
    }

    @Test
    fun `reject bio exceeding max length`() {
        val publicKey = ByteArray(32)
        val longBio = "a".repeat(Identity.MAX_BIO_LENGTH + 1)

        assertThrows<IllegalArgumentException> {
            Identity(publicKey = publicKey, bio = longBio)
        }
    }

    @Test
    fun `publicKeyBase64 returns correct encoding`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        val expectedBase64 = Base64.getEncoder().encodeToString(publicKey)
        assertEquals(expectedBase64, identity.publicKeyBase64)
    }

    @Test
    fun `shortId returns first 8 characters of base64 key`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        assertEquals(8, identity.shortId.length)
        assertEquals(identity.publicKeyBase64.take(8), identity.shortId)
    }

    @Test
    fun `fromPublicKeyBase64 creates identity correctly`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val base64 = Base64.getEncoder().encodeToString(publicKey)

        val identity = Identity.fromPublicKeyBase64(
            publicKeyBase64 = base64,
            displayName = "Test"
        )

        assertArrayEquals(publicKey, identity.publicKey)
        assertEquals("Test", identity.displayName)
    }

    @Test
    fun `equals compares all fields`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity1 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 1000L)
        val identity2 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 1000L)
        val identity3 = Identity(publicKey = publicKey, displayName = "Different", createdAt = 1000L)

        assertEquals(identity1, identity2)
        assertNotEquals(identity1, identity3)
    }

    @Test
    fun `hashCode is consistent with equals`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity1 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 1000L)
        val identity2 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 1000L)

        assertEquals(identity1.hashCode(), identity2.hashCode())
    }
}
