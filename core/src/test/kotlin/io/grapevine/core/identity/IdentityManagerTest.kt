package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

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

    @Test
    fun `getPrivateKey returns defensive copy`() {
        identityManager.initialize()

        val key1 = identityManager.getPrivateKey()!!
        val key2 = identityManager.getPrivateKey()!!

        // Keys should be equal in content
        assertArrayEquals(key1, key2)

        // But different references
        assertNotSame(key1, key2)

        // Modifying one should not affect the other
        key1.fill(0)
        assertFalse(key1.contentEquals(key2))

        // And should not affect what getPrivateKey returns
        val key3 = identityManager.getPrivateKey()!!
        assertArrayEquals(key2, key3)
    }

    @Test
    fun `getPublicKey returns defensive copy`() {
        identityManager.initialize()

        val key1 = identityManager.getPublicKey()
        val key2 = identityManager.getPublicKey()

        // Keys should be equal in content
        assertArrayEquals(key1, key2)

        // But different references
        assertNotSame(key1, key2)

        // Modifying one should not affect the other
        key1.fill(0)
        assertFalse(key1.contentEquals(key2))
    }

    @Test
    fun `close clears cached data`() {
        identityManager.initialize()
        assertNotNull(identityManager.getPrivateKey())

        identityManager.close()

        // After close, should reload from storage
        assertTrue(identityManager.hasIdentity())
        assertNotNull(identityManager.getPrivateKey())
    }

    // Concurrency tests

    @Test
    fun `concurrent initialization returns same identity`() {
        val threadCount = 10
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val identities = mutableListOf<Identity>()
        val errors = AtomicReference<Throwable?>()
        val lock = Object()

        val executor = Executors.newFixedThreadPool(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    barrier.await() // Ensure all threads start at the same time
                    val identity = identityManager.initialize()
                    synchronized(lock) {
                        identities.add(identity)
                    }
                } catch (e: Throwable) {
                    errors.compareAndSet(null, e)
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(10, TimeUnit.SECONDS)
        executor.shutdown()

        assertNull(errors.get(), "Unexpected error: ${errors.get()}")
        assertEquals(threadCount, identities.size)

        // All identities should have the same public key
        val firstPubKey = identities[0].publicKey
        identities.forEach { identity ->
            assertArrayEquals(firstPubKey, identity.publicKey)
        }
    }

    @Test
    fun `concurrent getPrivateKey calls are thread-safe`() {
        identityManager.initialize()

        val threadCount = 20
        val iterations = 100
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val errors = AtomicReference<Throwable?>()
        val successCount = AtomicInteger(0)

        val executor = Executors.newFixedThreadPool(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    barrier.await()
                    repeat(iterations) {
                        val key = identityManager.getPrivateKey()
                        assertNotNull(key)
                        assertEquals(64, key!!.size)
                    }
                    successCount.incrementAndGet()
                } catch (e: Throwable) {
                    errors.compareAndSet(null, e)
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()

        assertNull(errors.get(), "Unexpected error: ${errors.get()}")
        assertEquals(threadCount, successCount.get())
    }

    @Test
    fun `concurrent getIdentity calls are thread-safe`() {
        val threadCount = 20
        val iterations = 100
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val errors = AtomicReference<Throwable?>()
        val identities = mutableListOf<Identity>()
        val lock = Object()

        val executor = Executors.newFixedThreadPool(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    barrier.await()
                    repeat(iterations) {
                        val identity = identityManager.getIdentity()
                        synchronized(lock) {
                            identities.add(identity)
                        }
                    }
                } catch (e: Throwable) {
                    errors.compareAndSet(null, e)
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()

        assertNull(errors.get(), "Unexpected error: ${errors.get()}")
        assertEquals(threadCount * iterations, identities.size)

        // All identities should be the same
        val firstPubKey = identities[0].publicKey
        identities.forEach { identity ->
            assertArrayEquals(firstPubKey, identity.publicKey)
        }
    }

    @Test
    fun `concurrent reads and clearCache are thread-safe`() {
        identityManager.initialize()
        val expectedPublicKey = identityManager.getPublicKey()

        val threadCount = 10
        val iterations = 50
        val barrier = CyclicBarrier(threadCount + 1) // +1 for the clear thread
        val latch = CountDownLatch(threadCount + 1)
        val errors = AtomicReference<Throwable?>()

        val executor = Executors.newFixedThreadPool(threadCount + 1)

        // Readers
        repeat(threadCount) {
            executor.submit {
                try {
                    barrier.await()
                    repeat(iterations) {
                        val identity = identityManager.getIdentity()
                        assertArrayEquals(expectedPublicKey, identity.publicKey)
                    }
                } catch (e: Throwable) {
                    errors.compareAndSet(null, e)
                } finally {
                    latch.countDown()
                }
            }
        }

        // Cache clearer
        executor.submit {
            try {
                barrier.await()
                repeat(iterations) {
                    identityManager.clearCache()
                    Thread.sleep(1) // Give readers a chance
                }
            } catch (e: Throwable) {
                errors.compareAndSet(null, e)
            } finally {
                latch.countDown()
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()

        assertNull(errors.get(), "Unexpected error: ${errors.get()}")
    }

    @Test
    fun `loadIdentity throws when storage returns malformed key`() {
        // Store a malformed key (invalid size - neither 32-byte seed nor 64-byte secret key)
        secureStorage.store(SecureStorage.PRIVATE_KEY_ID, ByteArray(16))

        assertThrows<IdentityException> {
            identityManager.loadIdentity()
        }
    }

    @Test
    fun `sign produces valid signature`() {
        identityManager.initialize()
        val message = "Test message".toByteArray()

        val signature = identityManager.sign(message)

        assertEquals(64, signature.size) // Ed25519 signature is 64 bytes
    }

    @Test
    fun `sign and verify roundtrip succeeds`() {
        identityManager.initialize()
        val message = "Test message".toByteArray()
        val publicKey = identityManager.getPublicKey()

        val signature = identityManager.sign(message)
        val verified = identityManager.verify(message, signature, publicKey)

        assertTrue(verified)
    }

    @Test
    fun `verify fails with wrong public key`() {
        identityManager.initialize()
        val message = "Test message".toByteArray()

        val signature = identityManager.sign(message)

        // Create a different identity manager to get a different key
        val otherManager = IdentityManager(InMemorySecureStorage(), cryptoProvider)
        otherManager.initialize()
        val wrongPublicKey = otherManager.getPublicKey()

        val verified = identityManager.verify(message, signature, wrongPublicKey)

        assertFalse(verified)
    }

    @Test
    fun `verify fails with tampered message`() {
        identityManager.initialize()
        val message = "Test message".toByteArray()
        val tamperedMessage = "Tampered message".toByteArray()
        val publicKey = identityManager.getPublicKey()

        val signature = identityManager.sign(message)
        val verified = identityManager.verify(tamperedMessage, signature, publicKey)

        assertFalse(verified)
    }

    @Test
    fun `sign throws when no identity exists`() {
        val message = "Test message".toByteArray()

        assertThrows<IdentityException> {
            identityManager.sign(message)
        }
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
