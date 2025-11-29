package io.grapevine.network

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class MessageSignerTest {

    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var messageSigner: MessageSigner
    private lateinit var privateKey: ByteArray
    private lateinit var publicKey: ByteArray

    @BeforeEach
    fun setUp() {
        cryptoProvider = CryptoProvider()
        val (pubKey, secKey) = cryptoProvider.generateSigningKeyPairRaw()
        privateKey = secKey
        publicKey = pubKey
        messageSigner = MessageSigner.create(privateKey, publicKey)
    }

    // ==================== Ping Signing Tests ====================

    @Test
    fun `signPing creates signed payload`() {
        val timestamp = System.currentTimeMillis()

        val signedPing = messageSigner.signPing(timestamp)

        assertEquals(timestamp, signedPing.timestamp)
        assertTrue(signedPing.isSigned())
        assertEquals(64, signedPing.signature.size)
        assertArrayEquals(publicKey, signedPing.signerPublicKey)
    }

    @Test
    fun `signPing signature is deterministic for same timestamp`() {
        val timestamp = 1234567890123L

        val signed1 = messageSigner.signPing(timestamp)
        val signed2 = messageSigner.signPing(timestamp)

        assertArrayEquals(signed1.signature, signed2.signature)
    }

    @Test
    fun `signPing signature differs for different timestamps`() {
        val signed1 = messageSigner.signPing(1234567890123L)
        val signed2 = messageSigner.signPing(1234567890124L)

        assertFalse(signed1.signature.contentEquals(signed2.signature))
    }

    // ==================== Pong Signing Tests ====================

    @Test
    fun `signPong creates signed payload`() {
        val originalTimestamp = 1234567890123L
        val responseTimestamp = 1234567890456L

        val signedPong = messageSigner.signPong(originalTimestamp, responseTimestamp)

        assertEquals(originalTimestamp, signedPong.originalTimestamp)
        assertEquals(responseTimestamp, signedPong.responseTimestamp)
        assertTrue(signedPong.isSigned())
        assertEquals(64, signedPong.signature.size)
        assertArrayEquals(publicKey, signedPong.signerPublicKey)
    }

    @Test
    fun `signPong signature differs when timestamps differ`() {
        val signed1 = messageSigner.signPong(100L, 200L)
        val signed2 = messageSigner.signPong(100L, 201L)

        assertFalse(signed1.signature.contentEquals(signed2.signature))
    }

    // ==================== Ping Verification Tests ====================

    @Test
    fun `verifyPing returns Valid for correctly signed payload`() {
        val signedPing = messageSigner.signPing(System.currentTimeMillis())

        val result = messageSigner.verifyPing(signedPing)

        assertTrue(result.isValid())
        assertEquals(VerificationResult.Valid, result)
    }

    @Test
    fun `verifyPing returns Unsigned for unsigned payload`() {
        val unsignedPing = PingPayload(System.currentTimeMillis())

        val result = messageSigner.verifyPing(unsignedPing)

        assertFalse(result.isValid())
        assertFalse(result.isSigned())
        assertEquals(VerificationResult.Unsigned, result)
    }

    @Test
    fun `verifyPing returns Invalid for tampered timestamp`() {
        val signedPing = messageSigner.signPing(1234567890123L)
        // Create payload with different timestamp but same signature
        val tamperedPing = PingPayload(
            9999999999999L, // Different timestamp
            signedPing.signature,
            signedPing.signerPublicKey
        )

        val result = messageSigner.verifyPing(tamperedPing)

        assertFalse(result.isValid())
        assertTrue(result.isSigned())
        assertTrue(result is VerificationResult.Invalid)
    }

    @Test
    fun `verifyPing returns Invalid for tampered signature`() {
        val signedPing = messageSigner.signPing(System.currentTimeMillis())
        val tamperedSignature = signedPing.signature.copyOf()
        tamperedSignature[0] = (tamperedSignature[0].toInt() xor 0xFF).toByte()

        val tamperedPing = PingPayload(
            signedPing.timestamp,
            tamperedSignature,
            signedPing.signerPublicKey
        )

        val result = messageSigner.verifyPing(tamperedPing)

        assertFalse(result.isValid())
        assertTrue(result is VerificationResult.Invalid)
    }

    @Test
    fun `verifyPing returns Invalid for wrong public key`() {
        val signedPing = messageSigner.signPing(System.currentTimeMillis())

        // Create different key pair
        val (wrongPublicKey, _) = cryptoProvider.generateSigningKeyPairRaw()

        val pingWithWrongKey = PingPayload(
            signedPing.timestamp,
            signedPing.signature,
            wrongPublicKey
        )

        val result = messageSigner.verifyPing(pingWithWrongKey)

        assertFalse(result.isValid())
        assertTrue(result is VerificationResult.Invalid)
    }

    // ==================== Pong Verification Tests ====================

    @Test
    fun `verifyPong returns Valid for correctly signed payload`() {
        val signedPong = messageSigner.signPong(100L, 200L)

        val result = messageSigner.verifyPong(signedPong)

        assertTrue(result.isValid())
        assertEquals(VerificationResult.Valid, result)
    }

    @Test
    fun `verifyPong returns Unsigned for unsigned payload`() {
        val unsignedPong = PongPayload(100L, 200L)

        val result = messageSigner.verifyPong(unsignedPong)

        assertFalse(result.isValid())
        assertEquals(VerificationResult.Unsigned, result)
    }

    @Test
    fun `verifyPong returns Invalid for tampered timestamps`() {
        val signedPong = messageSigner.signPong(100L, 200L)
        val tamperedPong = PongPayload(
            999L, // Different original timestamp
            200L,
            signedPong.signature,
            signedPong.signerPublicKey
        )

        val result = messageSigner.verifyPong(tamperedPong)

        assertFalse(result.isValid())
        assertTrue(result is VerificationResult.Invalid)
    }

    // ==================== Cross-Identity Verification Tests ====================

    @Test
    fun `signature from one identity cannot be verified by another`() {
        // Create second signer with different keys
        val (otherPublicKey, otherSecretKey) = cryptoProvider.generateSigningKeyPairRaw()
        val otherSigner = MessageSigner.create(otherSecretKey, otherPublicKey)

        // Sign with first signer
        val signedPing = messageSigner.signPing(System.currentTimeMillis())

        // Verify should work with original signer
        assertTrue(messageSigner.verifyPing(signedPing).isValid())

        // Create payload claiming to be from other signer but with original signature
        val pingWithWrongClaim = PingPayload(
            signedPing.timestamp,
            signedPing.signature,
            otherPublicKey // Wrong public key
        )

        // Verification should fail
        assertFalse(messageSigner.verifyPing(pingWithWrongClaim).isValid())
    }

    @Test
    fun `signatures are identity-bound`() {
        val (otherPublicKey, otherSecretKey) = cryptoProvider.generateSigningKeyPairRaw()
        val otherSigner = MessageSigner.create(otherSecretKey, otherPublicKey)

        val timestamp = System.currentTimeMillis()
        val signedByFirst = messageSigner.signPing(timestamp)
        val signedBySecond = otherSigner.signPing(timestamp)

        // Signatures should be different
        assertFalse(signedByFirst.signature.contentEquals(signedBySecond.signature))

        // Each verifies with the correct public key
        assertTrue(messageSigner.verifyPing(signedByFirst).isValid())
        assertTrue(otherSigner.verifyPing(signedBySecond).isValid())
    }

    // ==================== Factory Method Tests ====================

    @Test
    fun `create throws for invalid private key size`() {
        val invalidPrivateKey = ByteArray(32) // Should be 64

        assertThrows<IllegalArgumentException> {
            MessageSigner.create(invalidPrivateKey, publicKey)
        }
    }

    @Test
    fun `create throws for invalid public key size`() {
        val invalidPublicKey = ByteArray(64) // Should be 32

        assertThrows<IllegalArgumentException> {
            MessageSigner.create(privateKey, invalidPublicKey)
        }
    }

    @Test
    fun `create makes defensive copies of keys`() {
        val privateKeyCopy = privateKey.copyOf()
        val publicKeyCopy = publicKey.copyOf()

        val signer = MessageSigner.create(privateKeyCopy, publicKeyCopy)

        // Modify the original arrays
        privateKeyCopy.fill(0)
        publicKeyCopy.fill(0)

        // Signer should still work
        val signedPing = signer.signPing(System.currentTimeMillis())
        assertTrue(signedPing.isSigned())

        // And verify should work
        val result = signer.verifyPing(signedPing)
        assertTrue(result.isValid())
    }

    // ==================== VerificationResult Tests ====================

    @Test
    fun `VerificationResult isValid returns correct values`() {
        assertTrue(VerificationResult.Valid.isValid())
        assertFalse(VerificationResult.Unsigned.isValid())
        assertFalse(VerificationResult.Invalid("test").isValid())
    }

    @Test
    fun `VerificationResult isSigned returns correct values`() {
        assertTrue(VerificationResult.Valid.isSigned())
        assertFalse(VerificationResult.Unsigned.isSigned())
        assertTrue(VerificationResult.Invalid("test").isSigned())
    }

    @Test
    fun `VerificationResult Invalid contains reason`() {
        val result = VerificationResult.Invalid("Test reason")

        assertTrue(result is VerificationResult.Invalid)
        assertEquals("Test reason", (result as VerificationResult.Invalid).reason)
    }
}
