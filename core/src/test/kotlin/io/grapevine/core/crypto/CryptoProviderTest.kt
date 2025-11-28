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

    @Test
    fun `getPublicKeyFromSecretKey extracts public key from 64-byte secret key`() {
        val keyPair = crypto.generateSigningKeyPair()

        val extractedPublicKey = crypto.getPublicKeyFromSecretKey(keyPair.secretKey.asBytes)

        assertArrayEquals(keyPair.publicKey.asBytes, extractedPublicKey)
    }

    @Test
    fun `getPublicKeyFromSecretKey derives public key from 32-byte seed`() {
        // Generate a keypair and extract the seed (first 32 bytes of secret key)
        val keyPair = crypto.generateSigningKeyPair()
        val seed = keyPair.secretKey.asBytes.copyOfRange(0, CryptoProvider.ED25519_SEED_BYTES)

        val derivedPublicKey = crypto.getPublicKeyFromSecretKey(seed)

        // The derived public key should match the original keypair's public key
        assertArrayEquals(keyPair.publicKey.asBytes, derivedPublicKey)
    }

    @Test
    fun `getPublicKeyFromSecretKey returns copy not reference for 64-byte key`() {
        val keyPair = crypto.generateSigningKeyPair()
        val secretKeyBytes = keyPair.secretKey.asBytes

        val extractedPublicKey = crypto.getPublicKeyFromSecretKey(secretKeyBytes)

        // Modify the extracted key and verify original is not affected
        val originalBytes = keyPair.publicKey.asBytes.copyOf()
        extractedPublicKey[0] = (extractedPublicKey[0].toInt() xor 0xFF).toByte()

        // The original public key should remain unchanged
        assertArrayEquals(originalBytes, keyPair.publicKey.asBytes)
    }

    @Test
    fun `getPublicKeyFromSecretKey throws for invalid key size`() {
        val exception16 = assertThrows(IllegalArgumentException::class.java) {
            crypto.getPublicKeyFromSecretKey(ByteArray(16)) // Too small
        }
        assertTrue(exception16.message!!.contains("16"))

        val exception0 = assertThrows(IllegalArgumentException::class.java) {
            crypto.getPublicKeyFromSecretKey(ByteArray(0)) // Empty
        }
        assertTrue(exception0.message!!.contains("0"))

        val exception128 = assertThrows(IllegalArgumentException::class.java) {
            crypto.getPublicKeyFromSecretKey(ByteArray(128)) // Too large
        }
        assertTrue(exception128.message!!.contains("128"))
    }

    @Test
    fun `getPublicKeyFromSecretKey produces consistent results for same seed`() {
        val seed = crypto.randomBytes(CryptoProvider.ED25519_SEED_BYTES)

        val publicKey1 = crypto.getPublicKeyFromSecretKey(seed)
        val publicKey2 = crypto.getPublicKeyFromSecretKey(seed)

        assertArrayEquals(publicKey1, publicKey2)
    }

    @Suppress("DEPRECATION")
    @Test
    fun `deprecated extractPublicKeyFromSecretKey delegates to new method`() {
        val keyPair = crypto.generateSigningKeyPair()

        val extractedPublicKey = crypto.extractPublicKeyFromSecretKey(keyPair.secretKey.asBytes)

        assertArrayEquals(keyPair.publicKey.asBytes, extractedPublicKey)
    }
}
