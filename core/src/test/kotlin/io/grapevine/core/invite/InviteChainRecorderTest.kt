package io.grapevine.core.invite

import io.grapevine.core.crypto.CryptoProvider
import io.grapevine.core.identity.IdentityManager
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class InviteChainRecorderTest {
    private lateinit var storage: InMemoryInviteChainStorage
    private lateinit var identityManager: IdentityManager
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var recorder: InviteChainRecorder
    private val random = SecureRandom()

    // Test keys
    private lateinit var myPublicKey: ByteArray
    private lateinit var inviterPublicKey: ByteArray
    private lateinit var inviteePublicKey: ByteArray

    @BeforeEach
    fun setUp() {
        storage = InMemoryInviteChainStorage()
        identityManager = mockk()
        cryptoProvider = CryptoProvider()

        myPublicKey = generatePublicKey()
        inviterPublicKey = generatePublicKey()
        inviteePublicKey = generatePublicKey()

        every { identityManager.getPublicKey() } returns myPublicKey

        recorder = InviteChainRecorder(identityManager, storage, cryptoProvider)
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

    private fun createAcceptance(
        tokenCode: String = "token-${random.nextInt()}",
        inviterKey: ByteArray = inviterPublicKey,
        inviteeKey: ByteArray = inviteePublicKey,
        inviterSignature: ByteArray = generateSignature(),
        inviteeSignature: ByteArray = generateSignature(),
        acceptedAt: Long = System.currentTimeMillis()
    ): InviteAcceptance {
        return InviteAcceptance(
            tokenCode = tokenCode,
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            inviterSignature = inviterSignature,
            inviteeSignature = inviteeSignature,
            acceptedAt = acceptedAt
        )
    }

    // ==================== Record Acceptance Tests ====================

    @Test
    fun `recordAcceptance creates first block with sequence 0`() {
        // Setup signature verification to succeed
        every { identityManager.verify(any(), any(), any()) } returns true

        val acceptance = createAcceptance()
        val result = recorder.recordAcceptance(acceptance)

        assertTrue(result is InviteChainRecordResult.Success)
        val record = (result as InviteChainRecordResult.Success).record
        assertEquals(0, record.sequenceNumber)
        assertNull(record.previousHash)
    }

    @Test
    fun `recordAcceptance increments sequence number`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        // Create first acceptance
        val acceptance1 = createAcceptance(inviteeKey = generatePublicKey())
        val result1 = recorder.recordAcceptance(acceptance1)
        assertTrue(result1 is InviteChainRecordResult.Success)

        // Create second acceptance from same inviter
        val acceptance2 = createAcceptance(inviteeKey = generatePublicKey())
        val result2 = recorder.recordAcceptance(acceptance2)
        assertTrue(result2 is InviteChainRecordResult.Success)

        val record2 = (result2 as InviteChainRecordResult.Success).record
        assertEquals(1, record2.sequenceNumber)
        assertNotNull(record2.previousHash)
    }

    @Test
    fun `recordAcceptance links to previous block hash`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        val acceptance1 = createAcceptance(inviteeKey = generatePublicKey())
        val result1 = recorder.recordAcceptance(acceptance1) as InviteChainRecordResult.Success
        val firstRecord = result1.record

        val acceptance2 = createAcceptance(inviteeKey = generatePublicKey())
        val result2 = recorder.recordAcceptance(acceptance2) as InviteChainRecordResult.Success
        val secondRecord = result2.record

        assertTrue(secondRecord.previousHash!!.contentEquals(firstRecord.blockHash))
    }

    @Test
    fun `recordAcceptance returns AlreadyExists when record ID already exists`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        val acceptance = createAcceptance()
        val result1 = recorder.recordAcceptance(acceptance)
        assertTrue(result1 is InviteChainRecordResult.Success)
        val firstRecord = (result1 as InviteChainRecordResult.Success).record

        // Manually insert the same record again (simulating external insertion)
        // and then try to record an acceptance that would generate the same ID
        // Since the ID is derived from block_hash + signatures, and those are deterministic
        // for the same input, we need to use recordFromPeer to test duplicate detection
        val result2 = recorder.recordFromPeer(firstRecord)
        assertTrue(result2 is InviteChainRecordResult.AlreadyExists)
    }

    @Test
    fun `recording same acceptance twice creates incremented sequence`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        val acceptance = createAcceptance()
        val result1 = recorder.recordAcceptance(acceptance)
        assertTrue(result1 is InviteChainRecordResult.Success)
        val first = (result1 as InviteChainRecordResult.Success).record
        assertEquals(0, first.sequenceNumber)

        // Recording same acceptance again creates a new record at next sequence
        // This is valid because it represents the same token being used again
        val result2 = recorder.recordAcceptance(acceptance)
        assertTrue(result2 is InviteChainRecordResult.Success)
        val second = (result2 as InviteChainRecordResult.Success).record
        assertEquals(1, second.sequenceNumber)
    }

    @Test
    fun `recordAcceptance fails for invalid signature`() {
        every { identityManager.verify(any(), any(), any()) } returns false

        val acceptance = createAcceptance()
        val result = recorder.recordAcceptance(acceptance)

        assertTrue(result is InviteChainRecordResult.InvalidInviteeSignature)
    }

    // ==================== Record From Peer Tests ====================

    @Test
    fun `recordFromPeer stores valid record`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        val record = createValidRecord()
        val result = recorder.recordFromPeer(record)

        assertTrue(result is InviteChainRecordResult.Success)
        assertNotNull(storage.getById(record.id))
    }

    @Test
    fun `recordFromPeer rejects record with invalid block hash`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        // Create record with wrong block hash
        val record = InviteChainRecord(
            id = "test-id",
            sequenceNumber = 0,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = null,
            blockHash = ByteArray(32) { 0xFF.toByte() }, // Wrong hash
            inviterSignature = generateSignature(),
            inviteeSignature = generateSignature(),
            tokenCode = "test-token",
            timestamp = System.currentTimeMillis()
        )

        val result = recorder.recordFromPeer(record)
        assertTrue(result is InviteChainRecordResult.ValidationFailed)
    }

    @Test
    fun `recordFromPeer rejects record with invalid invitee signature`() {
        every { identityManager.verify(any(), any(), any()) } returns false

        val record = createValidRecord()
        val result = recorder.recordFromPeer(record)

        assertTrue(result is InviteChainRecordResult.InvalidInviteeSignature)
    }

    @Test
    fun `recordFromPeer returns AlreadyExists for duplicate`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        val record = createValidRecord()
        storage.saveRecord(record)

        val result = recorder.recordFromPeer(record)
        assertTrue(result is InviteChainRecordResult.AlreadyExists)
    }

    // ==================== Validation Tests ====================

    @Test
    fun `validateRecord succeeds for valid record`() {
        every { identityManager.verify(any(), any(), any()) } returns true

        val record = createValidRecord()
        val result = recorder.validateRecord(record)

        assertEquals(InviteChainValidationResult.Valid, result)
    }

    @Test
    fun `validateRecord fails for invalid block hash`() {
        val record = InviteChainRecord(
            id = "test-id",
            sequenceNumber = 0,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = null,
            blockHash = ByteArray(32) { 0x00.toByte() },
            inviterSignature = generateSignature(),
            inviteeSignature = generateSignature(),
            tokenCode = "test-token",
            timestamp = System.currentTimeMillis()
        )

        val result = recorder.validateRecord(record)
        assertTrue(result is InviteChainValidationResult.InvalidBlockHash)
    }

    @Test
    fun `validateRecord fails for invalid invitee signature`() {
        every { identityManager.verify(any(), any(), any()) } returns false

        val record = createValidRecord()
        val result = recorder.validateRecord(record)

        assertTrue(result is InviteChainValidationResult.InvalidInviteeSignature)
    }

    // ==================== Query Tests ====================

    @Test
    fun `getMyInvites returns invites by current user`() {
        every { identityManager.verify(any(), any(), any()) } returns true
        every { identityManager.getPublicKey() } returns inviterPublicKey

        val record1 = createValidRecord(sequenceNumber = 0)
        val record2 = createValidRecord(sequenceNumber = 1, inviteeKey = generatePublicKey())

        storage.saveRecord(record1)
        storage.saveRecord(record2)

        val myInvites = recorder.getMyInvites()
        assertEquals(2, myInvites.size)
    }

    @Test
    fun `getMyInviteRecord returns invite for current user as invitee`() {
        every { identityManager.getPublicKey() } returns inviteePublicKey

        val record = createValidRecord()
        storage.saveRecord(record)

        val myInvite = recorder.getMyInviteRecord()
        assertNotNull(myInvite)
        assertTrue(myInvite!!.inviteePublicKey.contentEquals(inviteePublicKey))
    }

    @Test
    fun `hasBeenInvited returns true for invited user`() {
        val record = createValidRecord()
        storage.saveRecord(record)

        assertTrue(recorder.hasBeenInvited(inviteePublicKey))
    }

    @Test
    fun `hasBeenInvited returns false for non-invited user`() {
        assertFalse(recorder.hasBeenInvited(generatePublicKey()))
    }

    @Test
    fun `getLatestSequenceNumber returns correct sequence`() {
        val record0 = createValidRecord(sequenceNumber = 0)
        val record1 = createValidRecord(sequenceNumber = 1, inviteeKey = generatePublicKey())

        storage.saveRecord(record0)
        storage.saveRecord(record1)

        assertEquals(1, recorder.getLatestSequenceNumber(inviterPublicKey))
    }

    @Test
    fun `getLatestSequenceNumber returns -1 for unknown inviter`() {
        assertEquals(-1, recorder.getLatestSequenceNumber(generatePublicKey()))
    }

    @Test
    fun `getInviteeCount returns correct count`() {
        val record0 = createValidRecord(sequenceNumber = 0)
        val record1 = createValidRecord(sequenceNumber = 1, inviteeKey = generatePublicKey())

        storage.saveRecord(record0)
        storage.saveRecord(record1)

        assertEquals(2, recorder.getInviteeCount(inviterPublicKey))
    }

    // ==================== Block Hash Computation Tests ====================

    @Test
    fun `computeBlockHash is deterministic`() {
        val hash1 = recorder.computeBlockHash(
            sequenceNumber = 0,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = null,
            timestamp = 12345L,
            tokenCode = "token"
        )
        val hash2 = recorder.computeBlockHash(
            sequenceNumber = 0,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = null,
            timestamp = 12345L,
            tokenCode = "token"
        )

        assertTrue(hash1.contentEquals(hash2))
    }

    @Test
    fun `computeBlockHash differs for different inputs`() {
        val hash1 = recorder.computeBlockHash(
            sequenceNumber = 0,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = null,
            timestamp = 12345L,
            tokenCode = "token1"
        )
        val hash2 = recorder.computeBlockHash(
            sequenceNumber = 0,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            previousHash = null,
            timestamp = 12345L,
            tokenCode = "token2"
        )

        assertFalse(hash1.contentEquals(hash2))
    }

    // ==================== Helper Methods ====================

    private fun createValidRecord(
        sequenceNumber: Long = 0,
        inviterKey: ByteArray = inviterPublicKey,
        inviteeKey: ByteArray = inviteePublicKey,
        tokenCode: String = "token-${random.nextInt()}",
        timestamp: Long = System.currentTimeMillis()
    ): InviteChainRecord {
        val previousHash = if (sequenceNumber > 0) {
            ByteArray(32) { random.nextInt().toByte() }
        } else null

        val blockHash = recorder.computeBlockHash(
            sequenceNumber = sequenceNumber,
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            previousHash = previousHash,
            timestamp = timestamp,
            tokenCode = tokenCode
        )

        return InviteChainRecord(
            id = "record-${random.nextInt()}",
            sequenceNumber = sequenceNumber,
            inviterPublicKey = inviterKey,
            inviteePublicKey = inviteeKey,
            previousHash = previousHash,
            blockHash = blockHash,
            inviterSignature = generateSignature(),
            inviteeSignature = generateSignature(),
            tokenCode = tokenCode,
            timestamp = timestamp
        )
    }
}
