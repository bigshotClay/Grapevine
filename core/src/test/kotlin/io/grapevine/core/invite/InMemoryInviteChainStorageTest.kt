package io.grapevine.core.invite

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class InMemoryInviteChainStorageTest {
    private lateinit var storage: InMemoryInviteChainStorage
    private val random = SecureRandom()

    @BeforeEach
    fun setUp() {
        storage = InMemoryInviteChainStorage()
    }

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

    private fun generateHash(): ByteArray {
        val hash = ByteArray(32)
        random.nextBytes(hash)
        return hash
    }

    private fun createRecord(
        id: String = "record-${random.nextInt()}",
        sequenceNumber: Long = 0,
        inviterPublicKey: ByteArray = generatePublicKey(),
        inviteePublicKey: ByteArray = generatePublicKey(),
        previousHash: ByteArray? = null,
        blockHash: ByteArray = generateHash(),
        inviterSignature: ByteArray = generateSignature(),
        inviteeSignature: ByteArray = generateSignature(),
        tokenCode: String = "token-${random.nextInt()}",
        timestamp: Long = System.currentTimeMillis(),
        message: String? = null,
        createdAt: Long = System.currentTimeMillis()
    ): InviteChainRecord {
        val effectivePreviousHash = if (sequenceNumber > 0 && previousHash == null) {
            generateHash()
        } else {
            previousHash
        }
        return InviteChainRecord(
            id = id,
            sequenceNumber = sequenceNumber,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = effectivePreviousHash,
            blockHash = blockHash,
            inviterSignature = inviterSignature,
            inviteeSignature = inviteeSignature,
            tokenCode = tokenCode,
            timestamp = timestamp,
            message = message,
            createdAt = createdAt
        )
    }

    // ==================== Save and Retrieve Tests ====================

    @Test
    fun `saveRecord stores record`() {
        val record = createRecord()
        storage.saveRecord(record)

        val retrieved = storage.getById(record.id)
        assertNotNull(retrieved)
        assertEquals(record.id, retrieved?.id)
    }

    @Test
    fun `getById returns null for non-existent id`() {
        assertNull(storage.getById("non-existent"))
    }

    @Test
    fun `saveRecord replaces existing record with same id`() {
        val record1 = createRecord(id = "same-id", message = "first")
        val record2 = createRecord(id = "same-id", message = "second")

        storage.saveRecord(record1)
        storage.saveRecord(record2)

        assertEquals(1, storage.count())
        assertEquals("second", storage.getById("same-id")?.message)
    }

    // ==================== Block Hash Query Tests ====================

    @Test
    fun `getByBlockHash retrieves record`() {
        val blockHash = generateHash()
        val record = createRecord(blockHash = blockHash)
        storage.saveRecord(record)

        val retrieved = storage.getByBlockHash(blockHash)
        assertNotNull(retrieved)
        assertTrue(retrieved!!.blockHash.contentEquals(blockHash))
    }

    @Test
    fun `getByBlockHash returns null for non-existent hash`() {
        assertNull(storage.getByBlockHash(generateHash()))
    }

    @Test
    fun `existsByBlockHash returns true for existing hash`() {
        val blockHash = generateHash()
        val record = createRecord(blockHash = blockHash)
        storage.saveRecord(record)

        assertTrue(storage.existsByBlockHash(blockHash))
    }

    @Test
    fun `existsByBlockHash returns false for non-existent hash`() {
        assertFalse(storage.existsByBlockHash(generateHash()))
    }

    // ==================== Inviter Query Tests ====================

    @Test
    fun `getByInviter returns records for inviter`() {
        val inviterKey = generatePublicKey()
        val record1 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 0)
        val record2 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 1)
        val record3 = createRecord() // Different inviter

        storage.saveRecord(record1)
        storage.saveRecord(record2)
        storage.saveRecord(record3)

        val byInviter = storage.getByInviter(inviterKey)
        assertEquals(2, byInviter.size)
        assertTrue(byInviter.all { it.inviterPublicKey.contentEquals(inviterKey) })
    }

    @Test
    fun `getByInviter returns empty list for unknown inviter`() {
        assertTrue(storage.getByInviter(generatePublicKey()).isEmpty())
    }

    @Test
    fun `getByInviter returns records ordered by sequence number`() {
        val inviterKey = generatePublicKey()
        val record0 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 0)
        val record1 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 1)
        val record2 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 2)

        // Save in non-sequential order
        storage.saveRecord(record2)
        storage.saveRecord(record0)
        storage.saveRecord(record1)

        val byInviter = storage.getByInviter(inviterKey)
        assertEquals(0, byInviter[0].sequenceNumber)
        assertEquals(1, byInviter[1].sequenceNumber)
        assertEquals(2, byInviter[2].sequenceNumber)
    }

    @Test
    fun `getLatestByInviter returns highest sequence number`() {
        val inviterKey = generatePublicKey()
        val record0 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 0)
        val record1 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 1)
        val record2 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 2)

        storage.saveRecord(record0)
        storage.saveRecord(record2)
        storage.saveRecord(record1)

        val latest = storage.getLatestByInviter(inviterKey)
        assertNotNull(latest)
        assertEquals(2, latest!!.sequenceNumber)
    }

    @Test
    fun `getLatestByInviter returns null for unknown inviter`() {
        assertNull(storage.getLatestByInviter(generatePublicKey()))
    }

    // ==================== Invitee Query Tests ====================

    @Test
    fun `getByInvitee returns records for invitee`() {
        val inviteeKey = generatePublicKey()
        val record = createRecord(inviteePublicKey = inviteeKey)
        storage.saveRecord(record)

        val byInvitee = storage.getByInvitee(inviteeKey)
        assertEquals(1, byInvitee.size)
        assertTrue(byInvitee[0].inviteePublicKey.contentEquals(inviteeKey))
    }

    @Test
    fun `getByInvitee returns records ordered by timestamp`() {
        val inviteeKey = generatePublicKey()
        val older = createRecord(inviteePublicKey = inviteeKey, timestamp = 1000)
        val newer = createRecord(inviteePublicKey = inviteeKey, timestamp = 2000)

        storage.saveRecord(newer)
        storage.saveRecord(older)

        val byInvitee = storage.getByInvitee(inviteeKey)
        assertEquals(1000, byInvitee[0].timestamp)
        assertEquals(2000, byInvitee[1].timestamp)
    }

    @Test
    fun `getInviteFor returns earliest invite for invitee`() {
        val inviteeKey = generatePublicKey()
        val older = createRecord(inviteePublicKey = inviteeKey, timestamp = 1000)
        val newer = createRecord(inviteePublicKey = inviteeKey, timestamp = 2000)

        storage.saveRecord(newer)
        storage.saveRecord(older)

        val invite = storage.getInviteFor(inviteeKey)
        assertNotNull(invite)
        assertEquals(1000, invite!!.timestamp)
    }

    @Test
    fun `getInviteFor returns null for unknown invitee`() {
        assertNull(storage.getInviteFor(generatePublicKey()))
    }

    @Test
    fun `hasBeenInvited returns true for invited user`() {
        val inviteeKey = generatePublicKey()
        storage.saveRecord(createRecord(inviteePublicKey = inviteeKey))

        assertTrue(storage.hasBeenInvited(inviteeKey))
    }

    @Test
    fun `hasBeenInvited returns false for unknown user`() {
        assertFalse(storage.hasBeenInvited(generatePublicKey()))
    }

    // ==================== Sequence Query Tests ====================

    @Test
    fun `getBySequence retrieves specific record`() {
        val inviterKey = generatePublicKey()
        val record0 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 0)
        val record1 = createRecord(inviterPublicKey = inviterKey, sequenceNumber = 1)

        storage.saveRecord(record0)
        storage.saveRecord(record1)

        val retrieved = storage.getBySequence(inviterKey, 1)
        assertNotNull(retrieved)
        assertEquals(1, retrieved!!.sequenceNumber)
    }

    @Test
    fun `getBySequence returns null for non-existent sequence`() {
        val inviterKey = generatePublicKey()
        storage.saveRecord(createRecord(inviterPublicKey = inviterKey, sequenceNumber = 0))

        assertNull(storage.getBySequence(inviterKey, 99))
    }

    // ==================== Sequence Conflict Tests ====================

    @Test
    fun `saveRecord throws on sequence conflict`() {
        val inviterKey = generatePublicKey()
        val record1 = createRecord(id = "id1", inviterPublicKey = inviterKey, sequenceNumber = 0)
        val record2 = createRecord(id = "id2", inviterPublicKey = inviterKey, sequenceNumber = 0)

        storage.saveRecord(record1)

        val exception = assertThrows<SequenceConflictException> {
            storage.saveRecord(record2)
        }
        assertEquals(0L, exception.sequenceNumber)
        assertEquals("id1", exception.existingRecordId)
    }

    @Test
    fun `saveRecord allows same sequence for different inviters`() {
        val inviter1 = generatePublicKey()
        val inviter2 = generatePublicKey()
        val record1 = createRecord(inviterPublicKey = inviter1, sequenceNumber = 0)
        val record2 = createRecord(inviterPublicKey = inviter2, sequenceNumber = 0)

        storage.saveRecord(record1)
        storage.saveRecord(record2) // Should not throw

        assertEquals(2, storage.count())
    }

    // ==================== Count Tests ====================

    @Test
    fun `getInviteeCount returns correct count`() {
        val inviterKey = generatePublicKey()
        storage.saveRecord(createRecord(inviterPublicKey = inviterKey, sequenceNumber = 0))
        storage.saveRecord(createRecord(inviterPublicKey = inviterKey, sequenceNumber = 1))
        storage.saveRecord(createRecord()) // Different inviter

        assertEquals(2, storage.getInviteeCount(inviterKey))
    }

    @Test
    fun `getInviteeCount returns zero for unknown inviter`() {
        assertEquals(0, storage.getInviteeCount(generatePublicKey()))
    }

    @Test
    fun `count returns total records`() {
        assertEquals(0, storage.count())

        storage.saveRecord(createRecord())
        assertEquals(1, storage.count())

        storage.saveRecord(createRecord())
        assertEquals(2, storage.count())
    }

    // ==================== Delete Tests ====================

    @Test
    fun `delete removes record`() {
        val record = createRecord()
        storage.saveRecord(record)

        assertTrue(storage.delete(record.id))
        assertNull(storage.getById(record.id))
        assertEquals(0, storage.count())
    }

    @Test
    fun `delete returns false for non-existent record`() {
        assertFalse(storage.delete("non-existent"))
    }

    @Test
    fun `delete removes from all indexes`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val blockHash = generateHash()
        val record = createRecord(
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            blockHash = blockHash,
            sequenceNumber = 0
        )

        storage.saveRecord(record)
        storage.delete(record.id)

        assertNull(storage.getByBlockHash(blockHash))
        assertTrue(storage.getByInviter(inviterKey).isEmpty())
        assertTrue(storage.getByInvitee(inviteeKey).isEmpty())
        assertNull(storage.getBySequence(inviterKey, 0))
    }

    // ==================== Clear Tests ====================

    @Test
    fun `clear removes all records`() {
        storage.saveRecord(createRecord())
        storage.saveRecord(createRecord())

        storage.clear()

        assertEquals(0, storage.count())
        assertTrue(storage.getAll().isEmpty())
    }

    // ==================== GetAll Tests ====================

    @Test
    fun `getAll returns all records ordered by timestamp and id`() {
        val record1 = createRecord(id = "bbb", timestamp = 1000)
        val record2 = createRecord(id = "aaa", timestamp = 1000) // Same timestamp, different id
        val record3 = createRecord(id = "ccc", timestamp = 2000)

        storage.saveRecord(record3)
        storage.saveRecord(record1)
        storage.saveRecord(record2)

        val all = storage.getAll()
        assertEquals(3, all.size)
        // First by timestamp, then by id
        assertEquals(1000, all[0].timestamp)
        assertEquals(1000, all[1].timestamp)
        assertEquals("aaa", all[0].id) // alphabetically first
        assertEquals("bbb", all[1].id)
        assertEquals(2000, all[2].timestamp)
    }

    // ==================== Defensive Copy Tests ====================

    @Test
    fun `getById returns defensive copy`() {
        val record = createRecord()
        storage.saveRecord(record)

        val retrieved1 = storage.getById(record.id)
        val retrieved2 = storage.getById(record.id)

        assertNotSame(retrieved1, retrieved2)
    }

    @Test
    fun `saveRecord stores defensive copy`() {
        val inviterKey = generatePublicKey()
        val originalKey = inviterKey.copyOf()
        val record = createRecord(inviterPublicKey = inviterKey)

        storage.saveRecord(record)

        // Mutate original
        inviterKey.fill(0)

        // Stored version should be unaffected
        val retrieved = storage.getById(record.id)
        assertTrue(retrieved!!.inviterPublicKey.contentEquals(originalKey))
    }

    @Test
    fun `modifying retrieved byte arrays does not affect storage`() {
        val record = createRecord()
        storage.saveRecord(record)

        val retrieved = storage.getById(record.id)
        val originalKey = retrieved!!.inviterPublicKey.copyOf()
        retrieved.inviterPublicKey.fill(0)

        val retrievedAgain = storage.getById(record.id)
        assertTrue(retrievedAgain!!.inviterPublicKey.contentEquals(originalKey))
    }

    // ==================== Concurrency Tests ====================

    @Test
    fun `concurrent saves are thread-safe`() {
        val executor = Executors.newFixedThreadPool(10)
        val latch = CountDownLatch(100)
        val successCount = AtomicInteger(0)
        val inviterKey = generatePublicKey()

        try {
            repeat(100) { i ->
                executor.submit {
                    try {
                        // Different inviters to avoid sequence conflicts
                        val record = createRecord(sequenceNumber = 0)
                        storage.saveRecord(record)
                        successCount.incrementAndGet()
                    } catch (e: Exception) {
                        // Expected for conflicts
                    } finally {
                        latch.countDown()
                    }
                }
            }

            assertTrue(latch.await(10, TimeUnit.SECONDS))
            assertEquals(100, successCount.get())
            assertEquals(100, storage.count())
        } finally {
            executor.shutdown()
        }
    }

    @Test
    fun `concurrent reads during writes are safe`() {
        val executor = Executors.newFixedThreadPool(10)
        val latch = CountDownLatch(200)

        try {
            // Pre-populate
            repeat(50) {
                storage.saveRecord(createRecord())
            }

            // Concurrent reads and writes
            repeat(100) {
                executor.submit {
                    try {
                        storage.saveRecord(createRecord())
                    } finally {
                        latch.countDown()
                    }
                }
                executor.submit {
                    try {
                        storage.getAll()
                        storage.count()
                    } finally {
                        latch.countDown()
                    }
                }
            }

            assertTrue(latch.await(10, TimeUnit.SECONDS))
            assertEquals(150, storage.count())
        } finally {
            executor.shutdown()
        }
    }

    // ==================== Exists Tests ====================

    @Test
    fun `exists returns true for existing record`() {
        val record = createRecord()
        storage.saveRecord(record)

        assertTrue(storage.exists(record.id))
    }

    @Test
    fun `exists returns false for non-existent record`() {
        assertFalse(storage.exists("non-existent"))
    }
}
