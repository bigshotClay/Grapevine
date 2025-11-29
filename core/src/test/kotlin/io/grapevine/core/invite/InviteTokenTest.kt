package io.grapevine.core.invite

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom

class InviteTokenTest {
    private val random = SecureRandom()

    private fun generatePublicKey(): ByteArray {
        val key = ByteArray(32)
        random.nextBytes(key)
        return key
    }

    private fun generateSignature(): ByteArray {
        val sig = ByteArray(64)
        random.nextBytes(sig)
        return sig
    }

    private fun createToken(
        tokenCode: String = "test-token-code-12345678901234567890",
        publicKey: ByteArray = generatePublicKey(),
        signature: ByteArray = generateSignature(),
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long? = null,
        maxUses: Int? = null,
        currentUses: Int = 0,
        message: String? = null
    ): InviteToken {
        return InviteToken(
            tokenCode = tokenCode,
            inviterPublicKey = publicKey,
            signature = signature,
            createdAt = createdAt,
            expiresAt = expiresAt,
            maxUses = maxUses,
            currentUses = currentUses,
            message = message
        )
    }

    // ==================== Basic Creation Tests ====================

    @Test
    fun `token creation succeeds with valid parameters`() {
        val publicKey = generatePublicKey()
        val signature = generateSignature()

        val token = createToken(
            publicKey = publicKey,
            signature = signature
        )

        assertEquals("test-token-code-12345678901234567890", token.tokenCode)
        assertArrayEquals(publicKey, token.inviterPublicKey)
        assertArrayEquals(signature, token.signature)
        assertEquals(0, token.currentUses)
        assertNull(token.expiresAt)
        assertNull(token.maxUses)
    }

    @Test
    fun `token creation fails with blank token code`() {
        assertThrows<IllegalArgumentException> {
            createToken(tokenCode = "   ")
        }
    }

    @Test
    fun `token creation fails with invalid public key size`() {
        assertThrows<IllegalArgumentException> {
            createToken(publicKey = ByteArray(16))
        }
    }

    @Test
    fun `token creation fails with invalid signature size`() {
        assertThrows<IllegalArgumentException> {
            createToken(signature = ByteArray(32))
        }
    }

    @Test
    fun `token creation fails with negative created timestamp`() {
        assertThrows<IllegalArgumentException> {
            createToken(createdAt = -1)
        }
    }

    @Test
    fun `token creation fails with expiration before creation`() {
        val now = System.currentTimeMillis()
        assertThrows<IllegalArgumentException> {
            createToken(createdAt = now, expiresAt = now - 1000)
        }
    }

    @Test
    fun `token creation fails with zero max uses`() {
        assertThrows<IllegalArgumentException> {
            createToken(maxUses = 0)
        }
    }

    @Test
    fun `token creation fails with negative max uses`() {
        assertThrows<IllegalArgumentException> {
            createToken(maxUses = -1)
        }
    }

    @Test
    fun `token creation fails with negative current uses`() {
        assertThrows<IllegalArgumentException> {
            createToken(currentUses = -1)
        }
    }

    @Test
    fun `token creation fails with message exceeding max length`() {
        val longMessage = "a".repeat(257)
        assertThrows<IllegalArgumentException> {
            createToken(message = longMessage)
        }
    }

    @Test
    fun `token creation accepts message at max length`() {
        val message = "a".repeat(256)
        val token = createToken(message = message)
        assertEquals(message, token.message)
    }

    // ==================== Expiration Tests ====================

    @Test
    fun `isExpired returns false when no expiration set`() {
        val token = createToken(expiresAt = null)
        assertFalse(token.isExpired())
    }

    @Test
    fun `isExpired returns false before expiration time`() {
        val future = System.currentTimeMillis() + 3600_000
        val token = createToken(expiresAt = future)
        assertFalse(token.isExpired())
    }

    @Test
    fun `isExpired returns true after expiration time`() {
        val past = System.currentTimeMillis() - 1000
        val token = createToken(createdAt = past - 2000, expiresAt = past)
        assertTrue(token.isExpired())
    }

    @Test
    fun `isExpired returns true at exact expiration time`() {
        val now = System.currentTimeMillis()
        val token = createToken(createdAt = now - 1000, expiresAt = now)
        assertTrue(token.isExpired(now))
    }

    @Test
    fun `isExpired respects custom time parameter`() {
        val token = createToken(
            createdAt = 1000,
            expiresAt = 5000
        )

        assertFalse(token.isExpired(4999))
        assertTrue(token.isExpired(5000))
        assertTrue(token.isExpired(5001))
    }

    // ==================== Usage Limit Tests ====================

    @Test
    fun `isExhausted returns false when no max uses set`() {
        val token = createToken(maxUses = null, currentUses = 100)
        assertFalse(token.isExhausted())
    }

    @Test
    fun `isExhausted returns false when uses below max`() {
        val token = createToken(maxUses = 5, currentUses = 4)
        assertFalse(token.isExhausted())
    }

    @Test
    fun `isExhausted returns true when uses equals max`() {
        val token = createToken(maxUses = 5, currentUses = 5)
        assertTrue(token.isExhausted())
    }

    @Test
    fun `isExhausted returns true when uses exceeds max`() {
        val token = createToken(maxUses = 5, currentUses = 6)
        assertTrue(token.isExhausted())
    }

    @Test
    fun `remainingUses returns null when unlimited`() {
        val token = createToken(maxUses = null)
        assertNull(token.remainingUses())
    }

    @Test
    fun `remainingUses returns correct count`() {
        val token = createToken(maxUses = 10, currentUses = 3)
        assertEquals(7, token.remainingUses())
    }

    @Test
    fun `remainingUses returns zero when exhausted`() {
        val token = createToken(maxUses = 5, currentUses = 5)
        assertEquals(0, token.remainingUses())
    }

    @Test
    fun `remainingUses returns zero when over limit`() {
        val token = createToken(maxUses = 5, currentUses = 10)
        assertEquals(0, token.remainingUses())
    }

    // ==================== Validity Tests ====================

    @Test
    fun `isValid returns true for non-expired unlimited token`() {
        val token = createToken(expiresAt = null, maxUses = null)
        assertTrue(token.isValid())
    }

    @Test
    fun `isValid returns true for non-expired token with remaining uses`() {
        val future = System.currentTimeMillis() + 3600_000
        val token = createToken(expiresAt = future, maxUses = 10, currentUses = 5)
        assertTrue(token.isValid())
    }

    @Test
    fun `isValid returns false for expired token`() {
        val past = System.currentTimeMillis() - 1000
        val token = createToken(createdAt = past - 2000, expiresAt = past)
        assertFalse(token.isValid())
    }

    @Test
    fun `isValid returns false for exhausted token`() {
        val token = createToken(maxUses = 5, currentUses = 5)
        assertFalse(token.isValid())
    }

    @Test
    fun `isValid returns false for expired and exhausted token`() {
        val past = System.currentTimeMillis() - 1000
        val token = createToken(
            createdAt = past - 2000,
            expiresAt = past,
            maxUses = 5,
            currentUses = 5
        )
        assertFalse(token.isValid())
    }

    // ==================== Increment Use Count Tests ====================

    @Test
    fun `withIncrementedUseCount increments count`() {
        val token = createToken(currentUses = 3)
        val incremented = token.withIncrementedUseCount()

        assertEquals(3, token.currentUses)
        assertEquals(4, incremented.currentUses)
    }

    @Test
    fun `withIncrementedUseCount preserves other fields`() {
        val publicKey = generatePublicKey()
        val signature = generateSignature()
        val now = System.currentTimeMillis()
        val token = createToken(
            publicKey = publicKey,
            signature = signature,
            createdAt = now,
            expiresAt = now + 3600_000,
            maxUses = 5,
            currentUses = 2,
            message = "Hello"
        )

        val incremented = token.withIncrementedUseCount()

        assertEquals(token.tokenCode, incremented.tokenCode)
        assertArrayEquals(publicKey, incremented.inviterPublicKey)
        assertArrayEquals(signature, incremented.signature)
        assertEquals(token.createdAt, incremented.createdAt)
        assertEquals(token.expiresAt, incremented.expiresAt)
        assertEquals(token.maxUses, incremented.maxUses)
        assertEquals(token.message, incremented.message)
        assertEquals(3, incremented.currentUses)
    }

    // ==================== Defensive Copy Tests ====================

    @Test
    fun `inviterPublicKey returns defensive copy`() {
        val publicKey = generatePublicKey()
        val token = createToken(publicKey = publicKey)

        val retrieved1 = token.inviterPublicKey
        val retrieved2 = token.inviterPublicKey

        assertNotSame(retrieved1, retrieved2)
        assertArrayEquals(retrieved1, retrieved2)
    }

    @Test
    fun `signature returns defensive copy`() {
        val signature = generateSignature()
        val token = createToken(signature = signature)

        val retrieved1 = token.signature
        val retrieved2 = token.signature

        assertNotSame(retrieved1, retrieved2)
        assertArrayEquals(retrieved1, retrieved2)
    }

    @Test
    fun `modifying retrieved publicKey does not affect token`() {
        val publicKey = generatePublicKey()
        val token = createToken(publicKey = publicKey)

        val retrieved = token.inviterPublicKey
        retrieved.fill(0)

        assertFalse(token.inviterPublicKey.all { it == 0.toByte() })
    }

    // ==================== Equality and HashCode Tests ====================

    @Test
    fun `equals returns true for identical tokens`() {
        val publicKey = generatePublicKey()
        val signature = generateSignature()

        val token1 = InviteToken(
            tokenCode = "code",
            inviterPublicKey = publicKey,
            signature = signature,
            createdAt = 1000,
            expiresAt = 2000,
            maxUses = 5,
            currentUses = 2,
            message = "hello"
        )
        val token2 = InviteToken(
            tokenCode = "code",
            inviterPublicKey = publicKey.copyOf(),
            signature = signature.copyOf(),
            createdAt = 1000,
            expiresAt = 2000,
            maxUses = 5,
            currentUses = 2,
            message = "hello"
        )

        assertEquals(token1, token2)
        assertEquals(token1.hashCode(), token2.hashCode())
    }

    @Test
    fun `equals returns false for different tokens`() {
        val token1 = createToken(tokenCode = "code1")
        val token2 = createToken(tokenCode = "code2")

        assertNotEquals(token1, token2)
    }

    // ==================== ToString Tests ====================

    @Test
    fun `toString does not expose full public key`() {
        val token = createToken()
        val str = token.toString()

        // Should contain truncated representations
        assertTrue(str.contains("..."))
        // Should not contain the full public key hex
        val fullHex = token.inviterPublicKey.joinToString("") { "%02x".format(it) }
        assertFalse(str.contains(fullHex))
    }

    // ==================== Base64 Factory Tests ====================

    @Test
    fun `fromBase64 creates token from base64 encoded keys`() {
        val publicKey = generatePublicKey()
        val signature = generateSignature()

        val publicKeyBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)
        val signatureBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature)

        val token = InviteToken.fromBase64(
            tokenCode = "test-code",
            inviterPublicKeyBase64 = publicKeyBase64,
            signatureBase64 = signatureBase64
        )

        assertArrayEquals(publicKey, token.inviterPublicKey)
        assertArrayEquals(signature, token.signature)
    }

    @Test
    fun `inviterPublicKeyBase64 returns correct encoding`() {
        val publicKey = generatePublicKey()
        val token = createToken(publicKey = publicKey)

        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)
        assertEquals(expected, token.inviterPublicKeyBase64)
    }
}
