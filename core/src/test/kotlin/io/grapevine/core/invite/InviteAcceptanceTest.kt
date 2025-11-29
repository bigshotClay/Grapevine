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
    fun `toString does not expose full public keys`() {
        val acceptance = createAcceptance()
        val str = acceptance.toString()

        // Should contain truncated representations
        assertTrue(str.contains("..."))
        // Should not contain the full public key hex
        val fullHex = acceptance.inviterPublicKey.joinToString("") { "%02x".format(it) }
        assertFalse(str.contains(fullHex))
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
}
