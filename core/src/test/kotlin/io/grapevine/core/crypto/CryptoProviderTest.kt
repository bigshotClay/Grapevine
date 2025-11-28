package io.grapevine.core.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

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

        assertEquals(CryptoProvider.ED25519_PUBLIC_KEY_BYTES, extractedPublicKey.size)
        assertArrayEquals(keyPair.publicKey.asBytes, extractedPublicKey)
        assertNotSame(keyPair.publicKey.asBytes, extractedPublicKey)
    }

    @Test
    fun `getPublicKeyFromSecretKey derives public key from 32-byte seed`() {
        // Generate a keypair and extract the seed (first 32 bytes of secret key)
        val keyPair = crypto.generateSigningKeyPair()
        val seed = keyPair.secretKey.asBytes.copyOfRange(0, CryptoProvider.ED25519_SEED_BYTES)

        val derivedPublicKey = crypto.getPublicKeyFromSecretKey(seed)

        // The derived public key should match the original keypair's public key
        assertEquals(CryptoProvider.ED25519_PUBLIC_KEY_BYTES, derivedPublicKey.size)
        assertArrayEquals(keyPair.publicKey.asBytes, derivedPublicKey)
    }

    @ParameterizedTest(name = "valid size {0} bytes")
    @ValueSource(ints = [32, 64])
    fun `getPublicKeyFromSecretKey accepts valid sizes`(size: Int) {
        val keyPair = crypto.generateSigningKeyPair()
        val input = when (size) {
            CryptoProvider.ED25519_SECRET_KEY_BYTES -> keyPair.secretKey.asBytes
            CryptoProvider.ED25519_SEED_BYTES -> keyPair.secretKey.asBytes.copyOfRange(0, CryptoProvider.ED25519_SEED_BYTES)
            else -> throw IllegalArgumentException("Unexpected size: $size")
        }

        val publicKey = crypto.getPublicKeyFromSecretKey(input)

        assertEquals(CryptoProvider.ED25519_PUBLIC_KEY_BYTES, publicKey.size)
        assertArrayEquals(keyPair.publicKey.asBytes, publicKey)
    }

    @Test
    fun `getPublicKeyFromSecretKey returns copy not reference for 64-byte key`() {
        val keyPair = crypto.generateSigningKeyPair()
        val secretKeyBytes = keyPair.secretKey.asBytes

        val extractedPublicKey = crypto.getPublicKeyFromSecretKey(secretKeyBytes)

        // Verify identity - must be a different array instance
        assertNotSame(keyPair.publicKey.asBytes, extractedPublicKey)

        // Modify the extracted key and verify original is not affected
        val originalBytes = keyPair.publicKey.asBytes.copyOf()
        extractedPublicKey[0] = (extractedPublicKey[0].toInt() xor 0xFF).toByte()

        // The original public key should remain unchanged
        assertArrayEquals(originalBytes, keyPair.publicKey.asBytes)
    }

    @ParameterizedTest(name = "invalid size {0} bytes")
    @ValueSource(ints = [0, 16, 31, 33, 63, 128])
    fun `getPublicKeyFromSecretKey throws for invalid key sizes`(size: Int) {
        assertThrows(IllegalArgumentException::class.java) {
            crypto.getPublicKeyFromSecretKey(ByteArray(size))
        }
    }

    @Test
    fun `getPublicKeyFromSecretKey produces consistent results for same seed`() {
        // Use a deterministic fixed seed for reproducibility
        val seed = ByteArray(CryptoProvider.ED25519_SEED_BYTES) { index -> index.toByte() }

        val publicKey1 = crypto.getPublicKeyFromSecretKey(seed)
        val publicKey2 = crypto.getPublicKeyFromSecretKey(seed)

        assertArrayEquals(publicKey1, publicKey2)
    }

    @Suppress("DEPRECATION")
    @Test
    fun `deprecated extractPublicKeyFromSecretKey delegates to new method`() {
        val keyPair = crypto.generateSigningKeyPair()

        val deprecatedResult = crypto.extractPublicKeyFromSecretKey(keyPair.secretKey.asBytes)
        val newResult = crypto.getPublicKeyFromSecretKey(keyPair.secretKey.asBytes)

        assertArrayEquals(keyPair.publicKey.asBytes, deprecatedResult)
        assertArrayEquals(newResult, deprecatedResult)
    }
}
