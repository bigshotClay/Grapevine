package io.grapevine.core.invite

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class InMemoryInviteAcceptanceStorageTest {
    private lateinit var storage: InMemoryInviteAcceptanceStorage
    private val random = SecureRandom()

    @BeforeEach
    fun setUp() {
        storage = InMemoryInviteAcceptanceStorage()
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
        inviterPublicKey: ByteArray = generatePublicKey(),
        inviteePublicKey: ByteArray = generatePublicKey(),
        acceptedAt: Long = System.currentTimeMillis()
    ): InviteAcceptance {
        return InviteAcceptance(
            tokenCode = tokenCode,
            inviterPublicKey = inviterPublicKey,
            inviteePublicKey = inviteePublicKey,
            inviterSignature = generateSignature(),
            inviteeSignature = generateSignature(),
            acceptedAt = acceptedAt
        )
    }

    // ==================== Save and Retrieve Tests ====================

    @Test
    fun `saveAcceptance stores acceptance`() {
        val acceptance = createAcceptance()

        storage.saveAcceptance(acceptance)

        val retrieved = storage.getAcceptance(acceptance.tokenCode)
        assertNotNull(retrieved)
        assertEquals(acceptance.tokenCode, retrieved?.tokenCode)
    }

    @Test
    fun `getAcceptance returns null for non-existent token`() {
        val retrieved = storage.getAcceptance("non-existent")
        assertNull(retrieved)
    }

    @Test
    fun `saveAcceptance replaces existing acceptance`() {
        val acceptance1 = createAcceptance(tokenCode = "code")
        val acceptance2 = createAcceptance(tokenCode = "code")

        storage.saveAcceptance(acceptance1)
        storage.saveAcceptance(acceptance2)

        assertEquals(1, storage.getAllAcceptances().size)
    }

    // ==================== Query by Public Key Tests ====================

    @Test
    fun `getAcceptancesByInviter returns acceptances by inviter`() {
        val inviterKey = generatePublicKey()
        val acceptance1 = createAcceptance(inviterPublicKey = inviterKey)
        val acceptance2 = createAcceptance(inviterPublicKey = inviterKey)
        val acceptance3 = createAcceptance() // Different inviter

        storage.saveAcceptance(acceptance1)
        storage.saveAcceptance(acceptance2)
        storage.saveAcceptance(acceptance3)

        val byInviter = storage.getAcceptancesByInviter(inviterKey)

        assertEquals(2, byInviter.size)
        assertTrue(byInviter.all { it.inviterPublicKey.contentEquals(inviterKey) })
    }

    @Test
    fun `getAcceptancesByInvitee returns acceptances by invitee`() {
        val inviteeKey = generatePublicKey()
        val acceptance1 = createAcceptance(inviteePublicKey = inviteeKey)
        val acceptance2 = createAcceptance() // Different invitee

        storage.saveAcceptance(acceptance1)
        storage.saveAcceptance(acceptance2)

        val byInvitee = storage.getAcceptancesByInvitee(inviteeKey)

        assertEquals(1, byInvitee.size)
        assertTrue(byInvitee[0].inviteePublicKey.contentEquals(inviteeKey))
    }

    @Test
    fun `getMyInvite returns first acceptance for invitee`() {
        val inviteeKey = generatePublicKey()
        val acceptance = createAcceptance(inviteePublicKey = inviteeKey)

        storage.saveAcceptance(acceptance)

        val myInvite = storage.getMyInvite(inviteeKey)

        assertNotNull(myInvite)
        assertTrue(myInvite!!.inviteePublicKey.contentEquals(inviteeKey))
    }

    @Test
    fun `getMyInvite returns null when not invited`() {
        val inviteeKey = generatePublicKey()
        assertNull(storage.getMyInvite(inviteeKey))
    }

    @Test
    fun `hasBeenInvited returns true for invited user`() {
        val inviteeKey = generatePublicKey()
        val acceptance = createAcceptance(inviteePublicKey = inviteeKey)

        storage.saveAcceptance(acceptance)

        assertTrue(storage.hasBeenInvited(inviteeKey))
    }

    @Test
    fun `hasBeenInvited returns false for non-invited user`() {
        val inviteeKey = generatePublicKey()
        assertFalse(storage.hasBeenInvited(inviteeKey))
    }

    // ==================== Ordering Tests ====================

    @Test
    fun `getAcceptancesByInviter returns newest first`() {
        val inviterKey = generatePublicKey()
        val older = createAcceptance(inviterPublicKey = inviterKey, acceptedAt = 1000)
        val newer = createAcceptance(inviterPublicKey = inviterKey, acceptedAt = 2000)

        storage.saveAcceptance(older)
        storage.saveAcceptance(newer)

        val byInviter = storage.getAcceptancesByInviter(inviterKey)

        assertEquals(2000, byInviter[0].acceptedAt)
        assertEquals(1000, byInviter[1].acceptedAt)
    }

    @Test
    fun `getAllAcceptances returns newest first`() {
        val older = createAcceptance(acceptedAt = 1000)
        val newer = createAcceptance(acceptedAt = 2000)

        storage.saveAcceptance(older)
        storage.saveAcceptance(newer)

        val all = storage.getAllAcceptances()

        assertEquals(2000, all[0].acceptedAt)
        assertEquals(1000, all[1].acceptedAt)
    }

    // ==================== Delete Tests ====================

    @Test
    fun `deleteAcceptance removes acceptance`() {
        val acceptance = createAcceptance()
        storage.saveAcceptance(acceptance)

        val deleted = storage.deleteAcceptance(acceptance.tokenCode)

        assertTrue(deleted)
        assertNull(storage.getAcceptance(acceptance.tokenCode))
    }

    @Test
    fun `deleteAcceptance returns false for non-existent token`() {
        val deleted = storage.deleteAcceptance("non-existent")
        assertFalse(deleted)
    }

    // ==================== Existence Check Tests ====================

    @Test
    fun `hasAcceptance returns true for existing acceptance`() {
        val acceptance = createAcceptance()
        storage.saveAcceptance(acceptance)

        assertTrue(storage.hasAcceptance(acceptance.tokenCode))
    }

    @Test
    fun `hasAcceptance returns false for non-existent acceptance`() {
        assertFalse(storage.hasAcceptance("non-existent"))
    }

    // ==================== Count Tests ====================

    @Test
    fun `getInviteeCount returns correct count`() {
        val inviterKey = generatePublicKey()
        storage.saveAcceptance(createAcceptance(inviterPublicKey = inviterKey))
        storage.saveAcceptance(createAcceptance(inviterPublicKey = inviterKey))
        storage.saveAcceptance(createAcceptance()) // Different inviter

        assertEquals(2, storage.getInviteeCount(inviterKey))
    }

    @Test
    fun `getInviteeCount returns zero for unknown inviter`() {
        assertEquals(0, storage.getInviteeCount(generatePublicKey()))
    }

    // ==================== Clear Tests ====================

    @Test
    fun `clearAll removes all acceptances`() {
        storage.saveAcceptance(createAcceptance())
        storage.saveAcceptance(createAcceptance())

        storage.clearAll()

        assertTrue(storage.getAllAcceptances().isEmpty())
    }

    // ==================== Defensive Copy Tests ====================

    @Test
    fun `getAcceptance returns defensive copy`() {
        val acceptance = createAcceptance()
        storage.saveAcceptance(acceptance)

        val retrieved1 = storage.getAcceptance(acceptance.tokenCode)
        val retrieved2 = storage.getAcceptance(acceptance.tokenCode)

        assertNotSame(retrieved1, retrieved2)
    }

    @Test
    fun `saveAcceptance stores defensive copy`() {
        val inviterKey = generatePublicKey()
        val acceptance = createAcceptance(inviterPublicKey = inviterKey)

        storage.saveAcceptance(acceptance)

        // Modify the original key (simulating external modification)
        inviterKey.fill(0)

        // Stored version should be unaffected
        val retrieved = storage.getAcceptance(acceptance.tokenCode)
        assertFalse(retrieved!!.inviterPublicKey.all { it == 0.toByte() })
    }
}
