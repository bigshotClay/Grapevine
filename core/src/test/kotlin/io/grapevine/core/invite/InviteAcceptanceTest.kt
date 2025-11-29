package io.grapevine.core.invite

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom

class InviteAcceptanceTest {
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

    private fun createAcceptance(
        tokenCode: String = "test-token-code-12345678901234567890",
        inviterPublicKey: ByteArray = generatePublicKey(),
        inviteePublicKey: ByteArray = generatePublicKey(),
        inviterSignature: ByteArray = generateSignature(),
        inviteeSignature: ByteArray = generateSignature(),
        acceptedAt: Long = System.currentTimeMillis(),
        message: String? = null
    ): InviteAcceptance {
        return InviteAcceptance(
            tokenCode = tokenCode,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            inviterSignature = inviterSignature,
            inviteeSignature = inviteeSignature,
            acceptedAt = acceptedAt,
            message = message
        )
    }

    // ==================== Basic Creation Tests ====================

    @Test
    fun `acceptance creation succeeds with valid parameters`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val inviterSig = generateSignature()
        val inviteeSig = generateSignature()

        val acceptance = createAcceptance(
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            inviterSignature = inviterSig,
            inviteeSignature = inviteeSig
        )

        assertEquals("test-token-code-12345678901234567890", acceptance.tokenCode)
        assertArrayEquals(inviterKey, acceptance.inviterPublicKey)
        assertArrayEquals(inviteeKey, acceptance.inviteePublicKey)
        assertArrayEquals(inviterSig, acceptance.inviterSignature)
        assertArrayEquals(inviteeSig, acceptance.inviteeSignature)
    }

    @Test
    fun `acceptance creation fails with blank token code`() {
        assertThrows<IllegalArgumentException> {
            createAcceptance(tokenCode = "   ")
        }
    }

    @Test
    fun `acceptance creation fails with invalid inviter public key size`() {
        assertThrows<IllegalArgumentException> {
            createAcceptance(inviterPublicKey = ByteArray(16))
        }
    }

    @Test
    fun `acceptance creation fails with invalid invitee public key size`() {
        assertThrows<IllegalArgumentException> {
            createAcceptance(inviteePublicKey = ByteArray(16))
        }
    }

    @Test
    fun `acceptance creation fails with invalid inviter signature size`() {
        assertThrows<IllegalArgumentException> {
            createAcceptance(inviterSignature = ByteArray(32))
        }
    }

    @Test
    fun `acceptance creation fails with invalid invitee signature size`() {
        assertThrows<IllegalArgumentException> {
            createAcceptance(inviteeSignature = ByteArray(32))
        }
    }

    @Test
    fun `acceptance creation fails with negative timestamp`() {
        assertThrows<IllegalArgumentException> {
            createAcceptance(acceptedAt = -1)
        }
    }

    @Test
    fun `acceptance creation fails when inviter and invitee are same`() {
        val sameKey = generatePublicKey()
        assertThrows<IllegalArgumentException> {
            createAcceptance(
                inviterPublicKey = sameKey,
                inviteePublicKey = sameKey.copyOf()
            )
        }
    }

    // ==================== Defensive Copy Tests ====================

    @Test
    fun `inviterPublicKey returns defensive copy`() {
        val acceptance = createAcceptance()

        val retrieved1 = acceptance.inviterPublicKey
        val retrieved2 = acceptance.inviterPublicKey

        assertNotSame(retrieved1, retrieved2)
        assertArrayEquals(retrieved1, retrieved2)
    }

    @Test
    fun `inviteePublicKey returns defensive copy`() {
        val acceptance = createAcceptance()

        val retrieved1 = acceptance.inviteePublicKey
        val retrieved2 = acceptance.inviteePublicKey

        assertNotSame(retrieved1, retrieved2)
        assertArrayEquals(retrieved1, retrieved2)
    }

    @Test
    fun `inviterSignature returns defensive copy`() {
        val acceptance = createAcceptance()

        val retrieved1 = acceptance.inviterSignature
        val retrieved2 = acceptance.inviterSignature

        assertNotSame(retrieved1, retrieved2)
        assertArrayEquals(retrieved1, retrieved2)
    }

    @Test
    fun `inviteeSignature returns defensive copy`() {
        val acceptance = createAcceptance()

        val retrieved1 = acceptance.inviteeSignature
        val retrieved2 = acceptance.inviteeSignature

        assertNotSame(retrieved1, retrieved2)
        assertArrayEquals(retrieved1, retrieved2)
    }

    @Test
    fun `modifying retrieved publicKey does not affect acceptance`() {
        val inviterKey = generatePublicKey()
        val acceptance = createAcceptance(inviterPublicKey = inviterKey)

        val retrieved = acceptance.inviterPublicKey
        retrieved.fill(0)

        assertFalse(acceptance.inviterPublicKey.all { it == 0.toByte() })
    }

    // ==================== Base64 Encoding Tests ====================

    @Test
    fun `inviterPublicKeyBase64 returns correct encoding`() {
        val inviterKey = generatePublicKey()
        val acceptance = createAcceptance(inviterPublicKey = inviterKey)

        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterKey)
        assertEquals(expected, acceptance.inviterPublicKeyBase64)
    }

    @Test
    fun `inviteePublicKeyBase64 returns correct encoding`() {
        val inviteeKey = generatePublicKey()
        val acceptance = createAcceptance(inviteePublicKey = inviteeKey)

        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteeKey)
        assertEquals(expected, acceptance.inviteePublicKeyBase64)
    }

    @Test
    fun `fromBase64 creates acceptance from base64 encoded keys`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val inviterSig = generateSignature()
        val inviteeSig = generateSignature()

        val inviterKeyBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterKey)
        val inviteeKeyBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteeKey)
        val inviterSigBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterSig)
        val inviteeSigBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteeSig)

        val acceptance = InviteAcceptance.fromBase64(
            tokenCode = "test-code",
            inviterPublicKeyBase64 = inviterKeyBase64,
            inviteePublicKeyBase64 = inviteeKeyBase64,
            inviterSignatureBase64 = inviterSigBase64,
            inviteeSignatureBase64 = inviteeSigBase64
        )

        assertArrayEquals(inviterKey, acceptance.inviterPublicKey)
        assertArrayEquals(inviteeKey, acceptance.inviteePublicKey)
        assertArrayEquals(inviterSig, acceptance.inviterSignature)
        assertArrayEquals(inviteeSig, acceptance.inviteeSignature)
    }

    // ==================== Equality and HashCode Tests ====================

    @Test
    fun `equals returns true for identical acceptances`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val inviterSig = generateSignature()
        val inviteeSig = generateSignature()

        val acceptance1 = InviteAcceptance(
            tokenCode = "code",
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            inviterSignature = inviterSig,
            inviteeSignature = inviteeSig,
            acceptedAt = 1000,
            message = "hello"
        )
        val acceptance2 = InviteAcceptance(
            tokenCode = "code",
            inviterPublicKey = inviterKey.copyOf(),
            inviteePublicKey = inviteeKey.copyOf(),
            inviterSignature = inviterSig.copyOf(),
            inviteeSignature = inviteeSig.copyOf(),
            acceptedAt = 1000,
            message = "hello"
        )

        assertEquals(acceptance1, acceptance2)
        assertEquals(acceptance1.hashCode(), acceptance2.hashCode())
    }

    @Test
    fun `equals returns false for different acceptances`() {
        val acceptance1 = createAcceptance(tokenCode = "code1")
        val acceptance2 = createAcceptance(tokenCode = "code2")

        assertNotEquals(acceptance1, acceptance2)
    }

    // ==================== ToString Tests ====================

    @Test
    fun `toString does not expose sensitive data`() {
        val acceptance = createAcceptance()
        val str = acceptance.toString()

        // Should be fully redacted
        assertTrue(str.contains("<redacted>"))
        // Should not contain the full public key hex
        val fullHex = acceptance.inviterPublicKey.joinToString("") { "%02x".format(it) }
        assertFalse(str.contains(fullHex))
        // Should not contain token code
        assertFalse(str.contains(acceptance.tokenCode))
    }

    // ==================== Copy Tests ====================

    @Test
    fun `copy creates independent copy with same values`() {
        val acceptance = createAcceptance(message = "Original")
        val copied = acceptance.copy()

        assertEquals(acceptance.tokenCode, copied.tokenCode)
        assertArrayEquals(acceptance.inviterPublicKey, copied.inviterPublicKey)
        assertArrayEquals(acceptance.inviteePublicKey, copied.inviteePublicKey)
        assertEquals(acceptance.message, copied.message)
    }

    @Test
    fun `copy allows changing specific fields`() {
        val acceptance = createAcceptance(message = "Original")
        val copied = acceptance.copy(message = "Changed")

        assertEquals("Original", acceptance.message)
        assertEquals("Changed", copied.message)
    }

    // ==================== Message Tests ====================

    @Test
    fun `message is trimmed and empty becomes null`() {
        val acceptance = createAcceptance(message = "  ")
        assertNull(acceptance.message)
    }

    @Test
    fun `message is trimmed of whitespace`() {
        val acceptance = createAcceptance(message = "  Hello World  ")
        assertEquals("Hello World", acceptance.message)
    }

    // ==================== ToString Redaction Tests ====================

    @Test
    fun `toString is fully redacted`() {
        val acceptance = createAcceptance()
        val str = acceptance.toString()

        assertTrue(str.contains("<redacted>"))
        assertFalse(str.contains(acceptance.tokenCode))
    }

    @Test
    fun `toDebugString shows partial key fingerprints`() {
        val acceptance = createAcceptance()
        val debugStr = acceptance.toDebugString()

        // Should contain partial info but not full keys
        assertTrue(debugStr.contains("..."))
        assertTrue(debugStr.contains("acceptedAt"))
    }

    // ==================== Base64 Normalization Tests ====================

    @Test
    fun `fromBase64 handles URL-safe encoding without padding`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val inviterSig = generateSignature()
        val inviteeSig = generateSignature()

        // URL-safe without padding
        val inviterKeyBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterKey)
        val inviteeKeyBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteeKey)
        val inviterSigBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterSig)
        val inviteeSigBase64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteeSig)

        val acceptance = InviteAcceptance.fromBase64(
            tokenCode = "test-code",
            inviterPublicKeyBase64 = inviterKeyBase64,
            inviteePublicKeyBase64 = inviteeKeyBase64,
            inviterSignatureBase64 = inviterSigBase64,
            inviteeSignatureBase64 = inviteeSigBase64
        )

        assertArrayEquals(inviterKey, acceptance.inviterPublicKey)
    }

    @Test
    fun `fromBase64 handles standard encoding with padding`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val inviterSig = generateSignature()
        val inviteeSig = generateSignature()

        // Standard Base64 with padding
        val inviterKeyBase64 = java.util.Base64.getEncoder().encodeToString(inviterKey)
        val inviteeKeyBase64 = java.util.Base64.getEncoder().encodeToString(inviteeKey)
        val inviterSigBase64 = java.util.Base64.getEncoder().encodeToString(inviterSig)
        val inviteeSigBase64 = java.util.Base64.getEncoder().encodeToString(inviteeSig)

        val acceptance = InviteAcceptance.fromBase64(
            tokenCode = "test-code",
            inviterPublicKeyBase64 = inviterKeyBase64,
            inviteePublicKeyBase64 = inviteeKeyBase64,
            inviterSignatureBase64 = inviterSigBase64,
            inviteeSignatureBase64 = inviteeSigBase64
        )

        assertArrayEquals(inviterKey, acceptance.inviterPublicKey)
    }

    @Test
    fun `fromBase64 throws descriptive error for invalid encoding`() {
        val exception = assertThrows<IllegalArgumentException> {
            InviteAcceptance.fromBase64(
                tokenCode = "test-code",
                inviterPublicKeyBase64 = "not-valid-base64!!!",
                inviteePublicKeyBase64 = java.util.Base64.getEncoder().encodeToString(generatePublicKey()),
                inviterSignatureBase64 = java.util.Base64.getEncoder().encodeToString(generateSignature()),
                inviteeSignatureBase64 = java.util.Base64.getEncoder().encodeToString(generateSignature())
            )
        }

        assertTrue(exception.message?.contains("inviterPublicKey") == true)
    }

    // ==================== Serialization Roundtrip Tests ====================

    @Test
    fun `toMap and fromMap roundtrip preserves data`() {
        val original = createAcceptance(message = "Test message")

        val map = original.toMap()
        val restored = InviteAcceptance.fromMap(map)

        assertEquals(original.tokenCode, restored.tokenCode)
        assertArrayEquals(original.inviterPublicKey, restored.inviterPublicKey)
        assertArrayEquals(original.inviteePublicKey, restored.inviteePublicKey)
        assertArrayEquals(original.inviterSignature, restored.inviterSignature)
        assertArrayEquals(original.inviteeSignature, restored.inviteeSignature)
        assertEquals(original.acceptedAt, restored.acceptedAt)
        assertEquals(original.message, restored.message)
    }

    @Test
    fun `toMap contains all expected keys`() {
        val acceptance = createAcceptance(message = "Hello")
        val map = acceptance.toMap()

        assertTrue(map.containsKey("tokenCode"))
        assertTrue(map.containsKey("inviterPublicKey"))
        assertTrue(map.containsKey("inviteePublicKey"))
        assertTrue(map.containsKey("inviterSignature"))
        assertTrue(map.containsKey("inviteeSignature"))
        assertTrue(map.containsKey("acceptedAt"))
        assertTrue(map.containsKey("message"))
    }

    @Test
    fun `fromMap throws for missing required field`() {
        val exception = assertThrows<IllegalArgumentException> {
            InviteAcceptance.fromMap(mapOf("tokenCode" to "test"))
        }

        assertTrue(exception.message?.contains("Missing required field") == true)
    }

    // ==================== Constant Time Comparison Tests ====================

    @Test
    fun `constantTimeEquals returns true for equal arrays`() {
        val arr1 = generatePublicKey()
        val arr2 = arr1.copyOf()

        assertTrue(InviteAcceptance.constantTimeEquals(arr1, arr2))
    }

    @Test
    fun `constantTimeEquals returns false for different arrays`() {
        val arr1 = generatePublicKey()
        val arr2 = generatePublicKey()

        assertFalse(InviteAcceptance.constantTimeEquals(arr1, arr2))
    }

    @Test
    fun `constantTimeEquals returns false for different lengths`() {
        val arr1 = ByteArray(32)
        val arr2 = ByteArray(64)

        assertFalse(InviteAcceptance.constantTimeEquals(arr1, arr2))
    }

    // ==================== Signature Base64 Accessors ====================

    @Test
    fun `inviterSignatureBase64 returns correct encoding`() {
        val sig = generateSignature()
        val acceptance = createAcceptance(inviterSignature = sig)

        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
        assertEquals(expected, acceptance.inviterSignatureBase64)
    }

    @Test
    fun `inviteeSignatureBase64 returns correct encoding`() {
        val sig = generateSignature()
        val acceptance = createAcceptance(inviteeSignature = sig)

        val expected = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
        assertEquals(expected, acceptance.inviteeSignatureBase64)
    }
}
