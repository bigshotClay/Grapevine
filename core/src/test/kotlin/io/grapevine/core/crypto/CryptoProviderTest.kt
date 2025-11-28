package io.grapevine.core.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CryptoProviderTest {
    private lateinit var crypto: CryptoProvider

    @BeforeEach
    fun setUp() {
        crypto = CryptoProvider()
    }

    @Test
    fun `generateSigningKeyPair creates valid key pair`() {
        val keyPair = crypto.generateSigningKeyPair()

        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.secretKey)
        assertEquals(CryptoProvider.ED25519_PUBLIC_KEY_BYTES, keyPair.publicKey.asBytes.size)
        assertEquals(CryptoProvider.ED25519_SECRET_KEY_BYTES, keyPair.secretKey.asBytes.size)
    }

    @Test
    fun `generateBoxKeyPair creates valid key pair`() {
        val keyPair = crypto.generateBoxKeyPair()

        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.secretKey)
        assertEquals(CryptoProvider.X25519_PUBLIC_KEY_BYTES, keyPair.publicKey.asBytes.size)
        assertEquals(CryptoProvider.X25519_SECRET_KEY_BYTES, keyPair.secretKey.asBytes.size)
    }

    @Test
    fun `sign and verify roundtrip succeeds`() {
        val keyPair = crypto.generateSigningKeyPair()
        val message = "Hello, Grapevine!".toByteArray()

        val signature = crypto.sign(message, keyPair.secretKey)

        assertEquals(CryptoProvider.ED25519_SIGNATURE_BYTES, signature.size)
        assertTrue(crypto.verify(message, signature, keyPair.publicKey))
    }

    @Test
    fun `verify fails with wrong public key`() {
        val keyPair1 = crypto.generateSigningKeyPair()
        val keyPair2 = crypto.generateSigningKeyPair()
        val message = "Hello, Grapevine!".toByteArray()

        val signature = crypto.sign(message, keyPair1.secretKey)

        assertFalse(crypto.verify(message, signature, keyPair2.publicKey))
    }

    @Test
    fun `verify fails with tampered message`() {
        val keyPair = crypto.generateSigningKeyPair()
        val message = "Hello, Grapevine!".toByteArray()
        val tamperedMessage = "Hello, World!".toByteArray()

        val signature = crypto.sign(message, keyPair.secretKey)

        assertFalse(crypto.verify(tamperedMessage, signature, keyPair.publicKey))
    }

    @Test
    fun `sha256 produces consistent hash`() {
        val data = "Test data for hashing".toByteArray()

        val hash1 = crypto.sha256(data)
        val hash2 = crypto.sha256(data)

        assertEquals(CryptoProvider.SHA256_BYTES, hash1.size)
        assertArrayEquals(hash1, hash2)
    }

    @Test
    fun `sha256 produces different hash for different data`() {
        val data1 = "Test data 1".toByteArray()
        val data2 = "Test data 2".toByteArray()

        val hash1 = crypto.sha256(data1)
        val hash2 = crypto.sha256(data2)

        assertFalse(hash1.contentEquals(hash2))
    }

    @Test
    fun `keyExchange produces same shared secret for both parties`() {
        val aliceKeyPair = crypto.generateBoxKeyPair()
        val bobKeyPair = crypto.generateBoxKeyPair()

        val aliceSharedSecret = crypto.keyExchange(aliceKeyPair.secretKey, bobKeyPair.publicKey)
        val bobSharedSecret = crypto.keyExchange(bobKeyPair.secretKey, aliceKeyPair.publicKey)

        assertArrayEquals(aliceSharedSecret, bobSharedSecret)
    }

    @Test
    fun `convertEd25519ToX25519 key conversion works`() {
        val ed25519KeyPair = crypto.generateSigningKeyPair()

        val x25519PublicKey = crypto.convertEd25519ToX25519PublicKey(ed25519KeyPair.publicKey)
        val x25519SecretKey = crypto.convertEd25519ToX25519SecretKey(ed25519KeyPair.secretKey)

        assertEquals(CryptoProvider.X25519_PUBLIC_KEY_BYTES, x25519PublicKey.asBytes.size)
        assertEquals(CryptoProvider.X25519_SECRET_KEY_BYTES, x25519SecretKey.asBytes.size)
    }

    @Test
    fun `randomBytes produces unique values`() {
        val bytes1 = crypto.randomBytes(32)
        val bytes2 = crypto.randomBytes(32)

        assertEquals(32, bytes1.size)
        assertEquals(32, bytes2.size)
        assertFalse(bytes1.contentEquals(bytes2))
    }
}
