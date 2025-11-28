package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SignatureServiceTest {
    private lateinit var secureStorage: InMemorySecureStorage
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var identityManager: IdentityManager
    private lateinit var signatureService: SignatureService

    @BeforeEach
    fun setUp() {
        secureStorage = InMemorySecureStorage()
        cryptoProvider = CryptoProvider()
        identityManager = IdentityManager(secureStorage, cryptoProvider)
        signatureService = SignatureService(identityManager, cryptoProvider)
    }

    @AfterEach
    fun tearDown() {
        identityManager.clearCache()
    }

    @Test
    fun `signMessage creates valid signature`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()

        val signature = signatureService.signMessage(message)

        assertEquals(CryptoProvider.ED25519_SIGNATURE_BYTES, signature.size)
    }

    @Test
    fun `signMessage fails without identity`() {
        val message = "Test message".toByteArray()

        assertThrows<SignatureException> {
            signatureService.signMessage(message)
        }
    }

    @Test
    fun `verifyMessage returns true for valid signature`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val signature = signatureService.signMessage(message)
        val publicKey = identityManager.getPublicKey()

        val isValid = signatureService.verifyMessage(message, signature, publicKey)

        assertTrue(isValid)
    }

    @Test
    fun `verifyMessage returns false for tampered message`() {
        identityManager.initialize()
        val message = "Original message".toByteArray()
        val signature = signatureService.signMessage(message)
        val publicKey = identityManager.getPublicKey()
        val tamperedMessage = "Tampered message".toByteArray()

        val isValid = signatureService.verifyMessage(tamperedMessage, signature, publicKey)

        assertFalse(isValid)
    }

    @Test
    fun `verifyMessage returns false for tampered signature`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val signature = signatureService.signMessage(message)
        val publicKey = identityManager.getPublicKey()

        // Tamper with signature
        val tamperedSignature = signature.copyOf()
        tamperedSignature[0] = (tamperedSignature[0].toInt() xor 0xFF).toByte()

        val isValid = signatureService.verifyMessage(message, tamperedSignature, publicKey)

        assertFalse(isValid)
    }

    @Test
    fun `verifyMessage returns false for wrong public key`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val signature = signatureService.signMessage(message)

        // Generate different key pair
        val otherKeyPair = cryptoProvider.generateSigningKeyPair()
        val wrongPublicKey = otherKeyPair.publicKey.asBytes

        val isValid = signatureService.verifyMessage(message, signature, wrongPublicKey)

        assertFalse(isValid)
    }

    @Test
    fun `verifyMessage returns false for invalid public key size`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val signature = signatureService.signMessage(message)
        val invalidPublicKey = ByteArray(16) // Wrong size

        val isValid = signatureService.verifyMessage(message, signature, invalidPublicKey)

        assertFalse(isValid)
    }

    @Test
    fun `verifyMessage returns false for invalid signature size`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val publicKey = identityManager.getPublicKey()
        val invalidSignature = ByteArray(32) // Wrong size

        val isValid = signatureService.verifyMessage(message, invalidSignature, publicKey)

        assertFalse(isValid)
    }

    @Test
    fun `sign creates SignedData with valid components`() {
        identityManager.initialize()
        val data = "Test data".toByteArray()

        val signedData = signatureService.sign(data)

        assertArrayEquals(data, signedData.data)
        assertEquals(CryptoProvider.ED25519_SIGNATURE_BYTES, signedData.signature.size)
        assertArrayEquals(identityManager.getPublicKey(), signedData.signerPublicKey)
    }

    @Test
    fun `verify returns true for valid SignedData`() {
        identityManager.initialize()
        val data = "Test data".toByteArray()
        val signedData = signatureService.sign(data)

        val isValid = signatureService.verify(signedData)

        assertTrue(isValid)
    }

    @Test
    fun `verify returns false for tampered SignedData`() {
        identityManager.initialize()
        val data = "Test data".toByteArray()
        val signedData = signatureService.sign(data)

        // Tamper with data
        val tamperedSignedData = SignedData(
            data = "Tampered data".toByteArray(),
            signature = signedData.signature,
            signerPublicKey = signedData.signerPublicKey
        )

        val isValid = signatureService.verify(tamperedSignedData)

        assertFalse(isValid)
    }

    @Test
    fun `requireValidSignature succeeds for valid signature`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val signature = signatureService.signMessage(message)
        val publicKey = identityManager.getPublicKey()

        // Should not throw
        signatureService.requireValidSignature(message, signature, publicKey)
    }

    @Test
    fun `requireValidSignature throws for invalid signature`() {
        identityManager.initialize()
        val message = "Hello, World!".toByteArray()
        val signature = signatureService.signMessage(message)
        val publicKey = identityManager.getPublicKey()
        val tamperedMessage = "Tampered message".toByteArray()

        assertThrows<SignatureVerificationException> {
            signatureService.requireValidSignature(tamperedMessage, signature, publicKey)
        }
    }

    @Test
    fun `requireValid succeeds for valid SignedData`() {
        identityManager.initialize()
        val signedData = signatureService.sign("Test data".toByteArray())

        // Should not throw
        signatureService.requireValid(signedData)
    }

    @Test
    fun `requireValid throws for invalid SignedData`() {
        identityManager.initialize()
        val signedData = signatureService.sign("Test data".toByteArray())

        val tamperedSignedData = SignedData(
            data = "Tampered data".toByteArray(),
            signature = signedData.signature,
            signerPublicKey = signedData.signerPublicKey
        )

        assertThrows<SignatureVerificationException> {
            signatureService.requireValid(tamperedSignedData)
        }
    }

    @Test
    fun `signatures from different identities are not interchangeable`() {
        // Create first identity and sign
        identityManager.initialize()
        val message = "Test message".toByteArray()
        val signature1 = signatureService.signMessage(message)
        val publicKey1 = identityManager.getPublicKey().copyOf()

        // Create second identity
        identityManager.generateNewIdentity()
        val publicKey2 = identityManager.getPublicKey()

        // Verify signature1 with wrong public key
        assertFalse(signatureService.verifyMessage(message, signature1, publicKey2))

        // Verify signature1 with correct public key
        assertTrue(signatureService.verifyMessage(message, signature1, publicKey1))
    }

    @Test
    fun `SignedData equals and hashCode work correctly`() {
        val data = "Test".toByteArray()
        val signature = ByteArray(64)
        val publicKey = ByteArray(32)

        val signedData1 = SignedData(data, signature, publicKey)
        val signedData2 = SignedData(data.copyOf(), signature.copyOf(), publicKey.copyOf())
        val signedData3 = SignedData("Different".toByteArray(), signature, publicKey)

        assertEquals(signedData1, signedData2)
        assertEquals(signedData1.hashCode(), signedData2.hashCode())
        assertNotEquals(signedData1, signedData3)
    }

    @Test
    fun `SignedData makes defensive copies on construction`() {
        val data = "Test".toByteArray()
        val signature = ByteArray(64) { it.toByte() }
        val publicKey = ByteArray(32) { it.toByte() }

        val signedData = SignedData(data, signature, publicKey)

        // Modify original arrays
        data[0] = 0xFF.toByte()
        signature[0] = 0xFF.toByte()
        publicKey[0] = 0xFF.toByte()

        // SignedData should retain original values
        assertEquals('T'.code.toByte(), signedData.data[0])
        assertEquals(0.toByte(), signedData.signature[0])
        assertEquals(0.toByte(), signedData.signerPublicKey[0])
    }

    @Test
    fun `SignedData returns copies from accessors`() {
        val signedData = SignedData(
            "Test".toByteArray(),
            ByteArray(64) { it.toByte() },
            ByteArray(32) { it.toByte() }
        )

        // Get arrays and modify them
        val data = signedData.data
        val signature = signedData.signature
        val publicKey = signedData.signerPublicKey

        data[0] = 0xFF.toByte()
        signature[0] = 0xFF.toByte()
        publicKey[0] = 0xFF.toByte()

        // Getting the arrays again should return original values
        assertEquals('T'.code.toByte(), signedData.data[0])
        assertEquals(0.toByte(), signedData.signature[0])
        assertEquals(0.toByte(), signedData.signerPublicKey[0])
    }

    @Test
    fun `SignedData equals is unaffected by external array modification`() {
        val data = "Test".toByteArray()
        val signature = ByteArray(64)
        val publicKey = ByteArray(32)

        val signedData1 = SignedData(data, signature, publicKey)
        val signedData2 = SignedData(data.copyOf(), signature.copyOf(), publicKey.copyOf())

        // Modify original arrays
        data[0] = 0xFF.toByte()
        signature[0] = 0xFF.toByte()
        publicKey[0] = 0xFF.toByte()

        // Equality should still hold
        assertEquals(signedData1, signedData2)
        assertEquals(signedData1.hashCode(), signedData2.hashCode())
    }

    @Test
    fun `SignedData toString does not leak sensitive data`() {
        val signedData = SignedData(
            "Secret data".toByteArray(),
            ByteArray(64),
            ByteArray(32)
        )

        val str = signedData.toString()

        // Should not contain actual data content
        assertFalse(str.contains("Secret"))
        // Should contain size information
        assertTrue(str.contains("dataSize="))
        assertTrue(str.contains("signatureSize="))
        assertTrue(str.contains("publicKeySize="))
    }

    @Test
    fun `signMessage throws for invalid private key size`() {
        // Create a mock storage that returns invalid key size
        val invalidStorage = object : SecureStorage {
            override fun store(keyId: String, data: ByteArray): Boolean = true
            override fun retrieve(keyId: String): ByteArray? = ByteArray(16) // Invalid size
            override fun delete(keyId: String): Boolean = true
            override fun exists(keyId: String): Boolean = true
        }

        val invalidIdentityManager = IdentityManager(invalidStorage, cryptoProvider)
        val serviceWithInvalidKey = SignatureService(invalidIdentityManager, cryptoProvider)

        assertThrows<SignatureException> {
            serviceWithInvalidKey.signMessage("Test".toByteArray())
        }
    }

    @Test
    fun `can verify messages signed with raw CryptoProvider`() {
        identityManager.initialize()
        val privateKey = identityManager.getPrivateKey()!!
        val publicKey = identityManager.getPublicKey()

        // Sign using raw CryptoProvider
        val message = "Test message".toByteArray()
        val secretKey = com.goterl.lazysodium.utils.Key.fromBytes(privateKey)
        val signature = cryptoProvider.sign(message, secretKey)

        // Verify using SignatureService
        assertTrue(signatureService.verifyMessage(message, signature, publicKey))
    }
}
