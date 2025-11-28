package io.grapevine.core.identity

import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Base64

class IdentityTest {

    private val validAvatarHash = "a".repeat(64) // 64 hex chars for SHA-256

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
            avatarHash = validAvatarHash,
            bio = "This is a test bio",
            createdAt = 1234567890L
        )

        assertEquals("Test User", identity.displayName)
        assertEquals(validAvatarHash, identity.avatarHash)
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
    fun `publicKeyBase64 returns URL-safe encoding without padding`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        val expectedBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)
        assertEquals(expectedBase64, identity.publicKeyBase64)
        // Verify no padding characters
        assertFalse(identity.publicKeyBase64.contains("="))
        // Verify URL-safe (no + or /)
        assertFalse(identity.publicKeyBase64.contains("+"))
        assertFalse(identity.publicKeyBase64.contains("/"))
    }

    @Test
    fun `shortId returns first 8 characters of base64 key`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        assertEquals(8, identity.shortId.length)
        assertEquals(identity.publicKeyBase64.take(8), identity.shortId)
    }

    @Test
    fun `shortId is URL-safe`() {
        // Test with various byte patterns that would produce + or / in standard Base64
        repeat(100) { seed ->
            val publicKey = ByteArray(32) { ((it + seed) % 256).toByte() }
            val identity = Identity(publicKey = publicKey)

            assertFalse(identity.shortId.contains("+"), "shortId contains + for seed $seed")
            assertFalse(identity.shortId.contains("/"), "shortId contains / for seed $seed")
            assertFalse(identity.shortId.contains("="), "shortId contains = for seed $seed")
        }
    }

    @Test
    fun `fromPublicKeyBase64 creates identity correctly with standard base64`() {
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
    fun `fromPublicKeyBase64 creates identity correctly with URL-safe base64`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val base64 = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)

        val identity = Identity.fromPublicKeyBase64(
            publicKeyBase64 = base64,
            displayName = "Test"
        )

        assertArrayEquals(publicKey, identity.publicKey)
        assertEquals("Test", identity.displayName)
    }

    // ==================== Immutability Tests ====================

    @Test
    fun `mutating original array does not affect identity`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        // Mutate the original array
        publicKey[0] = 0xFF.toByte()

        // Identity should be unchanged
        assertEquals(0.toByte(), identity.publicKey[0])
    }

    @Test
    fun `mutating returned publicKey does not affect identity`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        // Get the public key and mutate it
        val retrievedKey = identity.publicKey
        retrievedKey[0] = 0xFF.toByte()

        // Identity should be unchanged
        assertEquals(0.toByte(), identity.publicKey[0])
    }

    @Test
    fun `multiple calls to publicKey return independent copies`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        val key1 = identity.publicKey
        val key2 = identity.publicKey

        // Should be equal in content
        assertArrayEquals(key1, key2)
        // But not the same instance
        assertNotSame(key1, key2)
    }

    @Test
    fun `deepCopy creates independent instance`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey, displayName = "Alice")

        val copy = identity.deepCopy()

        // Should be equal
        assertEquals(identity, copy)
        // But independent arrays
        assertNotSame(identity.publicKey, copy.publicKey)
    }

    @Test
    fun `copy method creates independent instance`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey, displayName = "Alice")

        val copy = identity.copy(displayName = "Bob")

        assertEquals("Alice", identity.displayName)
        assertEquals("Bob", copy.displayName)
        assertArrayEquals(identity.publicKey, copy.publicKey)
    }

    // ==================== Equality Tests ====================

    @Test
    fun `equals excludes createdAt`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity1 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 1000L)
        val identity2 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 2000L)

        // Should be equal despite different createdAt
        assertEquals(identity1, identity2)
    }

    @Test
    fun `hashCode excludes createdAt`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity1 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 1000L)
        val identity2 = Identity(publicKey = publicKey, displayName = "Test", createdAt = 2000L)

        // Should have same hash despite different createdAt
        assertEquals(identity1.hashCode(), identity2.hashCode())
    }

    @Test
    fun `equals compares publicKey, displayName, avatarHash, and bio`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity1 = Identity(publicKey = publicKey, displayName = "Test")
        val identity2 = Identity(publicKey = publicKey, displayName = "Test")
        val identity3 = Identity(publicKey = publicKey, displayName = "Different")

        assertEquals(identity1, identity2)
        assertNotEquals(identity1, identity3)
    }

    @Test
    fun `equals returns false for different public keys`() {
        val publicKey1 = ByteArray(32) { it.toByte() }
        val publicKey2 = ByteArray(32) { (it + 1).toByte() }

        val identity1 = Identity(publicKey = publicKey1, displayName = "Test")
        val identity2 = Identity(publicKey = publicKey2, displayName = "Test")

        assertNotEquals(identity1, identity2)
    }

    // ==================== toString Tests ====================

    @Test
    fun `toString does not contain full public key bytes`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        val str = identity.toString()

        // Should contain shortId
        assertTrue(str.contains(identity.shortId))
        // Should not contain full base64 key (43 chars for 32 bytes)
        assertFalse(str.contains(identity.publicKeyBase64))
    }

    @Test
    fun `toString truncates long bio`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val longBio = "a".repeat(100)
        val identity = Identity(publicKey = publicKey, bio = longBio)

        val str = identity.toString()

        // Should contain truncated bio with ellipsis
        assertTrue(str.contains("..."))
        assertFalse(str.contains(longBio))
    }

    @Test
    fun `toString shows short bio fully`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val shortBio = "Hello world"
        val identity = Identity(publicKey = publicKey, bio = shortBio)

        val str = identity.toString()

        assertTrue(str.contains(shortBio))
        assertFalse(str.contains("..."))
    }

    // ==================== Validation Tests ====================

    @Test
    fun `blank display name becomes null`() {
        val publicKey = ByteArray(32)
        val identity = Identity(publicKey = publicKey, displayName = "   ")

        // Blank string is trimmed to empty, which becomes null
        assertNull(identity.displayName)
    }

    @Test
    fun `trim whitespace from display name`() {
        val publicKey = ByteArray(32)
        val identity = Identity(publicKey = publicKey, displayName = "  Alice  ")

        assertEquals("Alice", identity.displayName)
    }

    @Test
    fun `empty display name becomes null`() {
        val publicKey = ByteArray(32)
        val identity = Identity(publicKey = publicKey, displayName = "")

        assertNull(identity.displayName)
    }

    @Test
    fun `reject invalid avatar hash format`() {
        val publicKey = ByteArray(32)

        // Too short
        assertThrows<IllegalArgumentException> {
            Identity(publicKey = publicKey, avatarHash = "abc123")
        }

        // Invalid characters
        assertThrows<IllegalArgumentException> {
            Identity(publicKey = publicKey, avatarHash = "g".repeat(64))
        }

        // Too long
        assertThrows<IllegalArgumentException> {
            Identity(publicKey = publicKey, avatarHash = "a".repeat(65))
        }
    }

    @Test
    fun `accept valid avatar hash`() {
        val publicKey = ByteArray(32)
        val validHash = "abcdef0123456789".repeat(4) // 64 hex chars

        val identity = Identity(publicKey = publicKey, avatarHash = validHash)
        assertEquals(validHash, identity.avatarHash)
    }

    @Test
    fun `accept uppercase avatar hash`() {
        val publicKey = ByteArray(32)
        val validHash = "ABCDEF0123456789".repeat(4) // 64 hex chars

        val identity = Identity(publicKey = publicKey, avatarHash = validHash)
        assertEquals(validHash, identity.avatarHash)
    }

    @Test
    fun `display name validates by unicode codepoints not chars`() {
        val publicKey = ByteArray(32)
        // Emoji that takes 2 chars in UTF-16 but is 1 codepoint
        val emoji = "\uD83D\uDE00" // 😀
        val nameWithEmoji = emoji.repeat(Identity.MAX_DISPLAY_NAME_LENGTH)

        // This should work - 64 codepoints even though more chars
        val identity = Identity(publicKey = publicKey, displayName = nameWithEmoji)
        assertEquals(nameWithEmoji, identity.displayName)
    }

    @Test
    fun `trim whitespace from bio`() {
        val publicKey = ByteArray(32)
        val identity = Identity(publicKey = publicKey, bio = "  Hello world  ")

        assertEquals("Hello world", identity.bio)
    }

    @Test
    fun `empty bio becomes null`() {
        val publicKey = ByteArray(32)
        val identity = Identity(publicKey = publicKey, bio = "")

        assertNull(identity.bio)
    }

    // ==================== Serialization Tests ====================

    @Test
    fun `serialization round trip preserves all fields`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val original = Identity(
            publicKey = publicKey,
            displayName = "Alice",
            avatarHash = validAvatarHash,
            bio = "Hello world",
            createdAt = 1234567890L
        )

        val json = Json.encodeToString(Identity.serializer(), original)
        val restored = Json.decodeFromString(Identity.serializer(), json)

        assertArrayEquals(original.publicKey, restored.publicKey)
        assertEquals(original.displayName, restored.displayName)
        assertEquals(original.avatarHash, restored.avatarHash)
        assertEquals(original.bio, restored.bio)
        assertEquals(original.createdAt, restored.createdAt)
    }

    @Test
    fun `serialization uses publicKey as field name`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val identity = Identity(publicKey = publicKey)

        val json = Json.encodeToString(Identity.serializer(), identity)

        assertTrue(json.contains("\"publicKey\""))
    }
}
