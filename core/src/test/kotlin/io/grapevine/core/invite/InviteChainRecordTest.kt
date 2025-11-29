package io.grapevine.core.invite

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom

class InviteChainRecordTest {
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
        return InviteChainRecord(
            id = id,
            sequenceNumber = sequenceNumber,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = previousHash,
            blockHash = blockHash,
            inviterSignature = inviterSignature,
            inviteeSignature = inviteeSignature,
            tokenCode = tokenCode,
            timestamp = timestamp,
            message = message,
            createdAt = createdAt
        )
    }

    // ==================== Creation Tests ====================

    @Test
    fun `creates record with valid parameters`() {
        val record = createRecord()
        assertNotNull(record)
        assertEquals(0, record.sequenceNumber)
    }

    @Test
    fun `creates first block without previous hash`() {
        val record = createRecord(sequenceNumber = 0, previousHash = null)
        assertTrue(record.isFirstBlock)
        assertNull(record.previousHash)
    }

    @Test
    fun `creates non-first block with previous hash`() {
        val record = createRecord(sequenceNumber = 1, previousHash = generateHash())
        assertFalse(record.isFirstBlock)
        assertNotNull(record.previousHash)
    }

    @Test
    fun `stores optional message`() {
        val record = createRecord(message = "Welcome to the network!")
        assertEquals("Welcome to the network!", record.message)
    }

    @Test
    fun `trims whitespace from message`() {
        val record = createRecord(message = "  Hello  ")
        assertEquals("Hello", record.message)
    }

    @Test
    fun `null message when empty after trim`() {
        val record = createRecord(message = "   ")
        assertNull(record.message)
    }

    // ==================== Validation Tests ====================

    @Test
    fun `throws for blank id`() {
        assertThrows<IllegalArgumentException> {
            createRecord(id = "   ")
        }
    }

    @Test
    fun `throws for negative sequence number`() {
        assertThrows<IllegalArgumentException> {
            createRecord(sequenceNumber = -1)
        }
    }

    @Test
    fun `throws for wrong inviter key size`() {
        assertThrows<IllegalArgumentException> {
            createRecord(inviterPublicKey = ByteArray(16))
        }
    }

    @Test
    fun `throws for wrong invitee key size`() {
        assertThrows<IllegalArgumentException> {
            createRecord(inviteePublicKey = ByteArray(64))
        }
    }

    @Test
    fun `throws for wrong previous hash size`() {
        assertThrows<IllegalArgumentException> {
            createRecord(sequenceNumber = 1, previousHash = ByteArray(16))
        }
    }

    @Test
    fun `throws for wrong block hash size`() {
        assertThrows<IllegalArgumentException> {
            createRecord(blockHash = ByteArray(64))
        }
    }

    @Test
    fun `throws for wrong inviter signature size`() {
        assertThrows<IllegalArgumentException> {
            createRecord(inviterSignature = ByteArray(32))
        }
    }

    @Test
    fun `throws for wrong invitee signature size`() {
        assertThrows<IllegalArgumentException> {
            createRecord(inviteeSignature = ByteArray(128))
        }
    }

    @Test
    fun `throws for blank token code`() {
        assertThrows<IllegalArgumentException> {
            createRecord(tokenCode = "   ")
        }
    }

    @Test
    fun `throws for zero timestamp`() {
        assertThrows<IllegalArgumentException> {
            createRecord(timestamp = 0)
        }
    }

    @Test
    fun `throws for negative timestamp`() {
        assertThrows<IllegalArgumentException> {
            createRecord(timestamp = -1)
        }
    }

    @Test
    fun `throws for zero createdAt`() {
        assertThrows<IllegalArgumentException> {
            createRecord(createdAt = 0)
        }
    }

    @Test
    fun `throws when inviter equals invitee`() {
        val key = generatePublicKey()
        assertThrows<IllegalArgumentException> {
            createRecord(inviterPublicKey = key, inviteePublicKey = key)
        }
    }

    @Test
    fun `throws when first block has previous hash`() {
        assertThrows<IllegalArgumentException> {
            createRecord(sequenceNumber = 0, previousHash = generateHash())
        }
    }

    @Test
    fun `throws when non-first block has no previous hash`() {
        assertThrows<IllegalArgumentException> {
            createRecord(sequenceNumber = 1, previousHash = null)
        }
    }

    // ==================== Defensive Copy Tests ====================

    @Test
    fun `inviterPublicKey returns defensive copy`() {
        val record = createRecord()
        val key1 = record.inviterPublicKey
        val key2 = record.inviterPublicKey
        assertNotSame(key1, key2)
        assertTrue(key1.contentEquals(key2))
    }

    @Test
    fun `inviteePublicKey returns defensive copy`() {
        val record = createRecord()
        val key1 = record.inviteePublicKey
        key1.fill(0)
        val key2 = record.inviteePublicKey
        assertFalse(key1.contentEquals(key2))
    }

    @Test
    fun `previousHash returns defensive copy`() {
        val record = createRecord(sequenceNumber = 1, previousHash = generateHash())
        val hash1 = record.previousHash
        val hash2 = record.previousHash
        assertNotSame(hash1, hash2)
    }

    @Test
    fun `blockHash returns defensive copy`() {
        val record = createRecord()
        val hash1 = record.blockHash
        val hash2 = record.blockHash
        assertNotSame(hash1, hash2)
    }

    @Test
    fun `constructor creates defensive copies`() {
        val inviterKey = generatePublicKey()
        val originalKey = inviterKey.copyOf()
        val record = createRecord(inviterPublicKey = inviterKey)

        // Mutate the original array
        inviterKey.fill(0)

        // Record should still have original values
        assertTrue(record.inviterPublicKey.contentEquals(originalKey))
    }

    // ==================== Copy Tests ====================

    @Test
    fun `copy creates deep copy of byte arrays`() {
        val record = createRecord(sequenceNumber = 1, previousHash = generateHash())
        val copy = record.copy()

        assertNotSame(record, copy)
        assertEquals(record.id, copy.id)
        assertTrue(record.inviterPublicKey.contentEquals(copy.inviterPublicKey))
        assertNotSame(record.inviterPublicKey, copy.inviterPublicKey)
    }

    @Test
    fun `copy with changed fields`() {
        val record = createRecord()
        val newId = "new-id"
        val copy = record.copy(id = newId)

        assertEquals(newId, copy.id)
        assertEquals(record.sequenceNumber, copy.sequenceNumber)
    }

    // ==================== Equality Tests ====================

    @Test
    fun `equals returns true for identical records`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()
        val blockHash = generateHash()
        val inviterSig = generateSignature()
        val inviteeSig = generateSignature()
        val tokenCode = "token-123"
        val timestamp = 12345L
        val createdAt = 67890L

        val record1 = InviteChainRecord(
            id = "id",
            sequenceNumber = 0,
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            previousHash = null,
            blockHash = blockHash,
            inviterSignature = inviterSig,
            inviteeSignature = inviteeSig,
            tokenCode = tokenCode,
            timestamp = timestamp,
            createdAt = createdAt
        )
        val record2 = InviteChainRecord(
            id = "id",
            sequenceNumber = 0,
            inviterPublicKey = inviterKey.copyOf(),
            inviteePublicKey = inviteeKey.copyOf(),
            previousHash = null,
            blockHash = blockHash.copyOf(),
            inviterSignature = inviterSig.copyOf(),
            inviteeSignature = inviteeSig.copyOf(),
            tokenCode = tokenCode,
            timestamp = timestamp,
            createdAt = createdAt
        )

        assertEquals(record1, record2)
        assertEquals(record1.hashCode(), record2.hashCode())
    }

    @Test
    fun `equals returns false for different ids`() {
        val record1 = createRecord(id = "id1")
        val record2 = createRecord(id = "id2")
        assertNotEquals(record1, record2)
    }

    @Test
    fun `equals returns false for different block hashes`() {
        val inviterKey = generatePublicKey()
        val inviteeKey = generatePublicKey()

        val record1 = createRecord(
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            blockHash = generateHash()
        )
        val record2 = createRecord(
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            blockHash = generateHash()
        )
        assertNotEquals(record1, record2)
    }

    // ==================== Base64 Serialization Tests ====================

    @Test
    fun `inviterPublicKeyBase64 is consistent`() {
        val record = createRecord()
        val base64_1 = record.inviterPublicKeyBase64
        val base64_2 = record.inviterPublicKeyBase64
        assertEquals(base64_1, base64_2)
    }

    @Test
    fun `blockHashBase64 produces valid Base64`() {
        val record = createRecord()
        val base64 = record.blockHashBase64
        assertNotNull(base64)
        assertTrue(base64.isNotEmpty())
        // URL-safe Base64 should not contain + or /
        assertFalse(base64.contains('+'))
        assertFalse(base64.contains('/'))
    }

    @Test
    fun `previousHashBase64 is null for first block`() {
        val record = createRecord(sequenceNumber = 0, previousHash = null)
        assertNull(record.previousHashBase64)
    }

    // ==================== toString Tests ====================

    @Test
    fun `toString is redacted`() {
        val record = createRecord()
        val str = record.toString()
        assertTrue(str.contains("<redacted>"))
        assertFalse(str.contains(record.inviterPublicKeyBase64))
    }

    @Test
    fun `toDebugString shows partial fingerprints`() {
        val record = createRecord()
        val debug = record.toDebugString()
        assertTrue(debug.contains("..."))
        assertTrue(debug.contains("seq="))
    }

    // ==================== Constant Time Comparison Tests ====================

    @Test
    fun `constantTimeEquals returns true for equal arrays`() {
        val arr = generateHash()
        assertTrue(InviteChainRecord.constantTimeEquals(arr, arr.copyOf()))
    }

    @Test
    fun `constantTimeEquals returns false for different arrays`() {
        val arr1 = generateHash()
        val arr2 = generateHash()
        assertFalse(InviteChainRecord.constantTimeEquals(arr1, arr2))
    }

    @Test
    fun `constantTimeEquals returns false for different lengths`() {
        assertFalse(InviteChainRecord.constantTimeEquals(ByteArray(32), ByteArray(64)))
    }
}
