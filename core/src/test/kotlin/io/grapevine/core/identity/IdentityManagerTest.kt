package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class IdentityManagerTest {
    private lateinit var secureStorage: InMemorySecureStorage
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var identityManager: IdentityManager

    @TempDir
    lateinit var tempDir: Path

    @BeforeEach
    fun setUp() {
        secureStorage = InMemorySecureStorage()
        cryptoProvider = CryptoProvider()
        identityManager = IdentityManager(secureStorage, cryptoProvider)
    }

    @AfterEach
    fun tearDown() {
        identityManager.clearCache()
    }

    @Test
    fun `hasIdentity returns false when no identity exists`() {
        assertFalse(identityManager.hasIdentity())
    }

    @Test
    fun `initialize generates new identity when none exists`() {
        val identity = identityManager.initialize()

        assertNotNull(identity)
        assertEquals(32, identity.publicKey.size)
        assertTrue(identityManager.hasIdentity())
    }

    @Test
    fun `initialize returns existing identity when one exists`() {
        val firstIdentity = identityManager.initialize()
        identityManager.clearCache()

        val secondIdentity = identityManager.initialize()

        assertArrayEquals(firstIdentity.publicKey, secondIdentity.publicKey)
    }

    @Test
    fun `getPrivateKey returns valid key after initialization`() {
        identityManager.initialize()

        val privateKey = identityManager.getPrivateKey()

        assertNotNull(privateKey)
        assertEquals(64, privateKey!!.size) // Ed25519 private key is 64 bytes
    }

    @Test
    fun `getPublicKey returns valid key after initialization`() {
        identityManager.initialize()

        val publicKey = identityManager.getPublicKey()

        assertEquals(32, publicKey.size)
    }

    @Test
    fun `generateNewIdentity creates fresh identity`() {
        val firstIdentity = identityManager.generateNewIdentity()
        val secondIdentity = identityManager.generateNewIdentity()

        // Public keys should be different
        assertFalse(firstIdentity.publicKey.contentEquals(secondIdentity.publicKey))
    }

    @Test
    fun `deleteIdentity removes identity from storage`() {
        identityManager.initialize()
        assertTrue(identityManager.hasIdentity())

        val deleted = identityManager.deleteIdentity()

        assertTrue(deleted)
        assertFalse(identityManager.hasIdentity())
    }

    @Test
    fun `private key can be used for signing`() {
        identityManager.initialize()

        val privateKey = identityManager.getPrivateKey()!!
        val publicKey = identityManager.getPublicKey()

        // Use the keys for signing
        val message = "Test message".toByteArray()
        val secretKey = com.goterl.lazysodium.utils.Key.fromBytes(privateKey)
        val pubKey = com.goterl.lazysodium.utils.Key.fromBytes(publicKey)

        val signature = cryptoProvider.sign(message, secretKey)
        val verified = cryptoProvider.verify(message, signature, pubKey)

        assertTrue(verified)
    }

    @Test
    fun `identity shortId is consistent`() {
        val identity = identityManager.initialize()
        val shortId = identity.shortId

        identityManager.clearCache()

        val reloadedIdentity = identityManager.initialize()

        assertEquals(shortId, reloadedIdentity.shortId)
    }

    @Test
    fun `exportBackup creates valid backup file`() {
        identityManager.initialize()
        val backupFile = tempDir.resolve("backup.gvbk").toFile()

        identityManager.exportBackup("testPassword", backupFile)

        assertTrue(backupFile.exists())
        assertTrue(identityManager.isValidBackupFile(backupFile))
    }

    @Test
    fun `exportBackup fails when no identity exists`() {
        val backupFile = tempDir.resolve("backup.gvbk").toFile()

        assertThrows<IdentityException> {
            identityManager.exportBackup("testPassword", backupFile)
        }
    }

    @Test
    fun `importBackup restores identity correctly`() {
        // Create and export identity
        val originalIdentity = identityManager.initialize()
        val originalPrivateKey = identityManager.getPrivateKey()!!.copyOf()
        val backupFile = tempDir.resolve("backup.gvbk").toFile()
        identityManager.exportBackup("testPassword", backupFile)

        // Delete identity and clear cache
        identityManager.deleteIdentity()
        assertFalse(identityManager.hasIdentity())

        // Import from backup
        val importedIdentity = identityManager.importBackup(backupFile, "testPassword")

        assertArrayEquals(originalIdentity.publicKey, importedIdentity.publicKey)
        assertEquals(originalIdentity.shortId, importedIdentity.shortId)
        assertTrue(identityManager.hasIdentity())
        assertArrayEquals(originalPrivateKey, identityManager.getPrivateKey())
    }

    @Test
    fun `importBackup fails with wrong password`() {
        identityManager.initialize()
        val backupFile = tempDir.resolve("backup.gvbk").toFile()
        identityManager.exportBackup("correctPassword", backupFile)

        identityManager.deleteIdentity()

        assertThrows<IdentityBackupException> {
            identityManager.importBackup(backupFile, "wrongPassword")
        }
    }

    @Test
    fun `importBackup replaces existing identity`() {
        // Create first identity
        val firstIdentity = identityManager.initialize()
        val backupFile = tempDir.resolve("backup.gvbk").toFile()
        identityManager.exportBackup("password", backupFile)

        // Create a new identity (different from the backed up one)
        identityManager.generateNewIdentity()
        val secondIdentity = identityManager.getIdentity()
        assertFalse(firstIdentity.publicKey.contentEquals(secondIdentity.publicKey))

        // Import should restore the first identity
        val importedIdentity = identityManager.importBackup(backupFile, "password")

        assertArrayEquals(firstIdentity.publicKey, importedIdentity.publicKey)
        assertArrayEquals(firstIdentity.publicKey, identityManager.getIdentity().publicKey)
    }

    @Test
    fun `isValidBackupFile returns false for non-backup files`() {
        val notBackup = tempDir.resolve("notbackup.txt").toFile()
        notBackup.writeText("This is not a backup")

        assertFalse(identityManager.isValidBackupFile(notBackup))
    }

    @Test
    fun `exported identity can be used for signing after import`() {
        // Create identity and export
        identityManager.initialize()
        val backupFile = tempDir.resolve("backup.gvbk").toFile()
        identityManager.exportBackup("password", backupFile)

        // Delete and reimport
        identityManager.deleteIdentity()
        identityManager.importBackup(backupFile, "password")

        // Verify signing still works
        val privateKey = identityManager.getPrivateKey()!!
        val publicKey = identityManager.getPublicKey()

        val message = "Test message".toByteArray()
        val secretKey = com.goterl.lazysodium.utils.Key.fromBytes(privateKey)
        val pubKey = com.goterl.lazysodium.utils.Key.fromBytes(publicKey)

        val signature = cryptoProvider.sign(message, secretKey)
        val verified = cryptoProvider.verify(message, signature, pubKey)

        assertTrue(verified)
    }
}

/**
 * In-memory implementation of SecureStorage for testing.
 */
class InMemorySecureStorage : SecureStorage {
    private val storage = mutableMapOf<String, ByteArray>()

    override fun store(key: String, value: ByteArray): Boolean {
        storage[key] = value.copyOf()
        return true
    }

    override fun retrieve(key: String): ByteArray? {
        return storage[key]?.copyOf()
    }

    override fun delete(key: String): Boolean {
        return storage.remove(key) != null
    }

    override fun exists(key: String): Boolean {
        return storage.containsKey(key)
    }

    fun clear() {
        storage.clear()
    }
}
