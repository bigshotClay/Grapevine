package io.grapevine.core.genesis

import io.grapevine.core.identity.Identity
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class GenesisManagerTest {
    private lateinit var storage: InMemoryGenesisStorage
    private lateinit var genesisManager: GenesisManager

    @BeforeEach
    fun setUp() {
        storage = InMemoryGenesisStorage()
        genesisManager = GenesisManager(storage)
    }

    private fun generatePublicKey(): ByteArray {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        return key
    }

    private fun createIdentity(publicKey: ByteArray = generatePublicKey(), displayName: String? = null): Identity {
        return Identity(
            publicKey = publicKey,
            displayName = displayName,
            createdAt = System.currentTimeMillis()
        )
    }

    // ==================== Basic Operations ====================

    @Test
    fun `hasGenesis returns false when no genesis exists`() {
        assertFalse(genesisManager.hasGenesis())
    }

    @Test
    fun `hasGenesis returns true after bootstrap`() {
        val identity = createIdentity()
        genesisManager.bootstrapAsGenesis(identity)

        assertTrue(genesisManager.hasGenesis())
    }

    @Test
    fun `getGenesisInfo returns null when no genesis exists`() {
        assertNull(genesisManager.getGenesisInfo())
    }

    @Test
    fun `getGenesisInfo returns genesis info after bootstrap`() {
        val publicKey = generatePublicKey()
        val identity = createIdentity(publicKey, "Genesis User")

        genesisManager.bootstrapAsGenesis(identity, "Founder")

        val genesisInfo = genesisManager.getGenesisInfo()
        assertNotNull(genesisInfo)
        assertArrayEquals(publicKey, genesisInfo!!.publicKey)
        assertEquals("Founder", genesisInfo.displayName)
        assertTrue(genesisInfo.createdAt > 0)
    }

    // ==================== Bootstrap Operations ====================

    @Test
    fun `bootstrapAsGenesis succeeds with valid identity`() {
        val identity = createIdentity(displayName = "Test User")

        val result = genesisManager.bootstrapAsGenesis(identity, "Network Founder")

        assertTrue(result is GenesisResult.Success)
        val success = result as GenesisResult.Success
        assertEquals("Network Founder", success.genesisInfo.displayName)
    }

    @Test
    fun `bootstrapAsGenesis uses identity displayName if none provided`() {
        val identity = createIdentity(displayName = "Identity Name")

        val result = genesisManager.bootstrapAsGenesis(identity)

        assertTrue(result is GenesisResult.Success)
        val success = result as GenesisResult.Success
        assertEquals("Identity Name", success.genesisInfo.displayName)
    }

    @Test
    fun `bootstrapAsGenesis returns AlreadyExists when genesis exists`() {
        val identity1 = createIdentity()
        val identity2 = createIdentity()

        // First bootstrap should succeed
        val result1 = genesisManager.bootstrapAsGenesis(identity1, "First")
        assertTrue(result1 is GenesisResult.Success)

        // Second bootstrap should return AlreadyExists
        val result2 = genesisManager.bootstrapAsGenesis(identity2, "Second")
        assertTrue(result2 is GenesisResult.AlreadyExists)

        val alreadyExists = result2 as GenesisResult.AlreadyExists
        assertEquals("First", alreadyExists.existingGenesis.displayName)
    }

    @Test
    fun `Identity class requires valid 32-byte public key`() {
        // The Identity class validates public key size at construction time,
        // so invalid sizes are rejected before reaching GenesisManager.
        // This test verifies that Identity enforces the constraint.
        val invalidKey = ByteArray(16) // Should be 32
        SecureRandom().nextBytes(invalidKey)

        assertThrows(IllegalArgumentException::class.java) {
            Identity(
                publicKey = invalidKey,
                displayName = "Invalid",
                createdAt = System.currentTimeMillis()
            )
        }
    }

    // ==================== Genesis User Identification ====================

    @Test
    fun `isGenesisUser returns false when no genesis exists`() {
        val publicKey = generatePublicKey()
        assertFalse(genesisManager.isGenesisUser(publicKey))
    }

    @Test
    fun `isGenesisUser returns true for genesis public key`() {
        val publicKey = generatePublicKey()
        val identity = createIdentity(publicKey)

        genesisManager.bootstrapAsGenesis(identity)

        assertTrue(genesisManager.isGenesisUser(publicKey))
    }

    @Test
    fun `isGenesisUser returns false for non-genesis public key`() {
        val genesisKey = generatePublicKey()
        val otherKey = generatePublicKey()
        val identity = createIdentity(genesisKey)

        genesisManager.bootstrapAsGenesis(identity)

        assertFalse(genesisManager.isGenesisUser(otherKey))
    }

    // ==================== Validation ====================

    @Test
    fun `validateNetworkState returns valid for fresh network`() {
        val result = genesisManager.validateNetworkState()

        assertTrue(result.isValid)
        assertFalse(result.hasGenesis)
        assertTrue(result.issues.isEmpty())
    }

    @Test
    fun `validateNetworkState returns valid for proper genesis`() {
        val identity = createIdentity()
        genesisManager.bootstrapAsGenesis(identity)

        val result = genesisManager.validateNetworkState()

        assertTrue(result.isValid)
        assertTrue(result.hasGenesis)
        assertTrue(result.issues.isEmpty())
    }

    // ==================== GenesisInfo Tests ====================

    @Test
    fun `GenesisInfo equality works correctly`() {
        val publicKey = generatePublicKey()
        val info1 = GenesisInfo(publicKey, "Test", 12345L)
        val info2 = GenesisInfo(publicKey.copyOf(), "Test", 12345L)
        val info3 = GenesisInfo(generatePublicKey(), "Test", 12345L)

        assertEquals(info1, info2)
        assertNotEquals(info1, info3)
    }

    @Test
    fun `GenesisInfo hashCode is consistent`() {
        val publicKey = generatePublicKey()
        val info1 = GenesisInfo(publicKey, "Test", 12345L)
        val info2 = GenesisInfo(publicKey.copyOf(), "Test", 12345L)

        assertEquals(info1.hashCode(), info2.hashCode())
    }

    @Test
    fun `GenesisInfo toString does not expose full public key`() {
        val publicKey = generatePublicKey()
        val info = GenesisInfo(publicKey, "Test", 12345L)

        val str = info.toString()

        // Should contain truncated key (first 4 bytes = 8 hex chars)
        assertTrue(str.contains("..."))
        // Should not contain full 64-char hex key
        val fullHex = publicKey.joinToString("") { "%02x".format(it) }
        assertFalse(str.contains(fullHex))
    }

    // ==================== InMemoryGenesisStorage Tests ====================

    @Test
    fun `InMemoryGenesisStorage stores and retrieves genesis info`() {
        val publicKey = generatePublicKey()
        val info = GenesisInfo(publicKey, "Test", System.currentTimeMillis())

        storage.setGenesis(info)

        assertTrue(storage.hasGenesis())
        val retrieved = storage.getGenesisInfo()
        assertNotNull(retrieved)
        assertEquals(info, retrieved)
    }

    @Test
    fun `InMemoryGenesisStorage returns defensive copies`() {
        val publicKey = generatePublicKey()
        val info = GenesisInfo(publicKey, "Test", System.currentTimeMillis())

        storage.setGenesis(info)

        val retrieved1 = storage.getGenesisInfo()!!
        val retrieved2 = storage.getGenesisInfo()!!

        // Should be equal but not same reference
        assertEquals(retrieved1, retrieved2)
        assertNotSame(retrieved1.publicKey, retrieved2.publicKey)
    }

    @Test
    fun `InMemoryGenesisStorage throws when setting genesis twice`() {
        val info1 = GenesisInfo(generatePublicKey(), "First", System.currentTimeMillis())
        val info2 = GenesisInfo(generatePublicKey(), "Second", System.currentTimeMillis())

        storage.setGenesis(info1)

        assertThrows(GenesisException::class.java) {
            storage.setGenesis(info2)
        }
    }

    @Test
    fun `InMemoryGenesisStorage clearGenesis removes genesis`() {
        val info = GenesisInfo(generatePublicKey(), "Test", System.currentTimeMillis())

        storage.setGenesis(info)
        assertTrue(storage.hasGenesis())

        storage.clearGenesis()
        assertFalse(storage.hasGenesis())
        assertNull(storage.getGenesisInfo())
    }

    @Test
    fun `InMemoryGenesisStorage can set genesis after clear`() {
        val info1 = GenesisInfo(generatePublicKey(), "First", System.currentTimeMillis())
        val info2 = GenesisInfo(generatePublicKey(), "Second", System.currentTimeMillis())

        storage.setGenesis(info1)
        storage.clearGenesis()
        storage.setGenesis(info2)

        val retrieved = storage.getGenesisInfo()
        assertEquals("Second", retrieved?.displayName)
    }
}
