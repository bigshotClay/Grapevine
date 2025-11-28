package io.grapevine.core.identity

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tests for [JvmSecureStorage] - a KeyStore-backed secure storage implementation.
 */
class JvmSecureStorageTest {

    @TempDir
    lateinit var tempDir: File

    private lateinit var storage: JvmSecureStorage

    @BeforeEach
    fun setup() {
        storage = JvmSecureStorage(tempDir.absolutePath)
    }

    @AfterEach
    fun cleanup() {
        // Clean up keystore file and entries directory
        File(tempDir, "grapevine.keystore").delete()
        File(tempDir, "entries").deleteRecursively()
    }

    @Nested
    inner class StoreAndRetrieveTests {

        @Test
        fun `store and retrieve simple value`() {
            val key = "test-key"
            val value = "Hello, World!".toByteArray()

            val stored = storage.store(key, value)
            assertTrue(stored, "Store should return true")

            val retrieved = storage.retrieve(key)
            assertNotNull(retrieved, "Retrieved value should not be null")
            assertArrayEquals(value, retrieved, "Retrieved value should match stored value")
        }

        @Test
        fun `store and retrieve binary data`() {
            val key = "binary-key"
            val value = ByteArray(256) { it.toByte() }

            val stored = storage.store(key, value)
            assertTrue(stored)

            val retrieved = storage.retrieve(key)
            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `store and retrieve empty value`() {
            val key = "empty-key"
            val value = ByteArray(0)

            val stored = storage.store(key, value)
            assertTrue(stored)

            val retrieved = storage.retrieve(key)
            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `retrieve nonexistent key returns null`() {
            val retrieved = storage.retrieve("nonexistent")
            assertNull(retrieved)
        }

        @Test
        fun `overwrite existing value`() {
            val key = "overwrite-key"
            val value1 = "First value".toByteArray()
            val value2 = "Second value".toByteArray()

            storage.store(key, value1)
            storage.store(key, value2)

            val retrieved = storage.retrieve(key)
            assertNotNull(retrieved)
            assertArrayEquals(value2, retrieved)
        }
    }

    @Nested
    inner class DeleteTests {

        @Test
        fun `delete existing key returns true`() {
            val key = "delete-key"
            storage.store(key, "test".toByteArray())

            val deleted = storage.delete(key)
            assertTrue(deleted)

            val retrieved = storage.retrieve(key)
            assertNull(retrieved)
        }

        @Test
        fun `delete nonexistent key returns false`() {
            val deleted = storage.delete("nonexistent")
            assertFalse(deleted)
        }
    }

    @Nested
    inner class ExistsTests {

        @Test
        fun `exists returns true for stored key`() {
            val key = "exists-key"
            storage.store(key, "test".toByteArray())

            assertTrue(storage.exists(key))
        }

        @Test
        fun `exists returns false for nonexistent key`() {
            assertFalse(storage.exists("nonexistent"))
        }

        @Test
        fun `exists returns false after delete`() {
            val key = "exists-delete-key"
            storage.store(key, "test".toByteArray())
            storage.delete(key)

            assertFalse(storage.exists(key))
        }
    }

    @Nested
    inner class PersistenceTests {

        @Test
        fun `values persist across instances`() {
            val key = "persist-key"
            val value = "Persistent value".toByteArray()

            storage.store(key, value)

            // Create new storage instance pointing to same directory
            val newStorage = JvmSecureStorage(tempDir.absolutePath)
            val retrieved = newStorage.retrieve(key)

            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `keystore file is created`() {
            val keystoreFile = File(tempDir, "grapevine.keystore")

            // Store something to trigger keystore creation
            storage.store("trigger", "value".toByteArray())

            assertTrue(keystoreFile.exists(), "Keystore file should be created")
        }

        @Test
        fun `entries directory is created`() {
            val entriesDir = File(tempDir, "entries")

            // Store something to trigger entries creation
            storage.store("trigger", "value".toByteArray())

            assertTrue(entriesDir.exists(), "Entries directory should be created")
            assertTrue(entriesDir.isDirectory, "Entries should be a directory")
        }

        @Test
        fun `encrypted data files are created in entries directory`() {
            storage.store("test-key", "value".toByteArray())

            val entriesDir = File(tempDir, "entries")
            val encFiles = entriesDir.listFiles { _, name -> name.endsWith(".enc") }

            assertNotNull(encFiles)
            assertEquals(1, encFiles?.size, "Should have one encrypted file")
        }
    }

    @Nested
    inner class MultipleKeysTests {

        @Test
        fun `store and retrieve multiple keys`() {
            val entries = mapOf(
                "key1" to "value1".toByteArray(),
                "key2" to "value2".toByteArray(),
                "key3" to "value3".toByteArray()
            )

            entries.forEach { (k, v) ->
                assertTrue(storage.store(k, v))
            }

            entries.forEach { (k, v) ->
                val retrieved = storage.retrieve(k)
                assertNotNull(retrieved)
                assertArrayEquals(v, retrieved)
            }
        }

        @Test
        fun `delete one key does not affect others`() {
            storage.store("keep", "kept".toByteArray())
            storage.store("delete", "deleted".toByteArray())

            storage.delete("delete")

            assertNotNull(storage.retrieve("keep"))
            assertNull(storage.retrieve("delete"))
        }
    }

    @Nested
    inner class EdgeCasesTests {

        @Test
        fun `handle key with special characters`() {
            val key = "key-with_special.chars:123"
            val value = "special".toByteArray()

            storage.store(key, value)
            val retrieved = storage.retrieve(key)

            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `handle key with unicode characters`() {
            val key = "key-with-émojis-🎉-日本語"
            val value = "unicode key".toByteArray()

            storage.store(key, value)
            val retrieved = storage.retrieve(key)

            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `handle very long key`() {
            val key = "a".repeat(1000)
            val value = "long key".toByteArray()

            storage.store(key, value)
            val retrieved = storage.retrieve(key)

            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }

        @Test
        fun `handle large value`() {
            val key = "large-value"
            val value = ByteArray(1024 * 1024) { (it % 256).toByte() } // 1MB

            storage.store(key, value)
            val retrieved = storage.retrieve(key)

            assertNotNull(retrieved)
            assertArrayEquals(value, retrieved)
        }
    }

    @Nested
    inner class ConcurrencyTests {

        @Test
        fun `concurrent stores to different keys`() {
            val threadCount = 10
            val executor = Executors.newFixedThreadPool(threadCount)
            val latch = CountDownLatch(threadCount)
            val successCount = AtomicInteger(0)

            repeat(threadCount) { i ->
                executor.submit {
                    try {
                        val key = "concurrent-key-$i"
                        val value = "value-$i".toByteArray()
                        if (storage.store(key, value)) {
                            successCount.incrementAndGet()
                        }
                    } finally {
                        latch.countDown()
                    }
                }
            }

            latch.await(30, TimeUnit.SECONDS)
            executor.shutdown()

            assertEquals(threadCount, successCount.get(), "All stores should succeed")

            // Verify all values can be retrieved
            repeat(threadCount) { i ->
                val retrieved = storage.retrieve("concurrent-key-$i")
                assertNotNull(retrieved, "Value for key $i should exist")
                assertArrayEquals("value-$i".toByteArray(), retrieved)
            }
        }

        @Test
        fun `concurrent stores and retrieves to same key`() {
            val key = "contended-key"
            val iterations = 100
            val executor = Executors.newFixedThreadPool(4)
            val latch = CountDownLatch(iterations * 2)
            val errorCount = AtomicInteger(0)

            // Concurrent stores
            repeat(iterations) { i ->
                executor.submit {
                    try {
                        storage.store(key, "value-$i".toByteArray())
                    } catch (e: Exception) {
                        errorCount.incrementAndGet()
                    } finally {
                        latch.countDown()
                    }
                }
            }

            // Concurrent retrieves
            repeat(iterations) {
                executor.submit {
                    try {
                        storage.retrieve(key)
                    } catch (e: Exception) {
                        errorCount.incrementAndGet()
                    } finally {
                        latch.countDown()
                    }
                }
            }

            latch.await(30, TimeUnit.SECONDS)
            executor.shutdown()

            assertEquals(0, errorCount.get(), "No errors should occur during concurrent access")

            // Final value should be retrievable
            val finalValue = storage.retrieve(key)
            assertNotNull(finalValue, "Final value should exist")
        }

        @Test
        fun `concurrent deletes do not cause errors`() {
            val key = "delete-concurrent-key"
            storage.store(key, "value".toByteArray())

            val threadCount = 5
            val executor = Executors.newFixedThreadPool(threadCount)
            val latch = CountDownLatch(threadCount)
            val errorCount = AtomicInteger(0)

            repeat(threadCount) {
                executor.submit {
                    try {
                        storage.delete(key)
                    } catch (e: Exception) {
                        errorCount.incrementAndGet()
                    } finally {
                        latch.countDown()
                    }
                }
            }

            latch.await(10, TimeUnit.SECONDS)
            executor.shutdown()

            assertEquals(0, errorCount.get(), "No errors should occur during concurrent deletes")
            assertFalse(storage.exists(key), "Key should be deleted")
        }
    }

    @Nested
    inner class RecoveryTests {

        @Test
        fun `handles corrupted entry file gracefully`() {
            val key = "corrupt-key"
            storage.store(key, "valid value".toByteArray())

            // Corrupt the entry file
            val entriesDir = Path.of(tempDir.absolutePath, "entries")
            val encFiles = Files.list(entriesDir).filter { it.toString().endsWith(".enc") }.toList()
            assertFalse(encFiles.isEmpty(), "Should have entry files")
            Files.write(encFiles[0], byteArrayOf(0, 1, 2, 3, 4)) // Write invalid data

            // Create new instance and try to retrieve
            val newStorage = JvmSecureStorage(tempDir.absolutePath)
            val retrieved = newStorage.retrieve(key)

            // Should return null (decryption fails) but not throw
            assertNull(retrieved)
        }

        @Test
        fun `handles missing entry file gracefully`() {
            val key = "missing-file-key"
            storage.store(key, "value".toByteArray())

            // Delete the entry file but keep the key in keystore
            val entriesDir = Path.of(tempDir.absolutePath, "entries")
            Files.list(entriesDir).filter { it.toString().endsWith(".enc") }.forEach { Files.delete(it) }

            val retrieved = storage.retrieve(key)
            assertNull(retrieved, "Should return null for missing entry file")
        }
    }
}
