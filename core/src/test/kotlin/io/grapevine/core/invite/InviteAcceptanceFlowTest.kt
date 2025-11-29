package io.grapevine.core.invite

import io.grapevine.core.crypto.CryptoProvider
import io.grapevine.core.identity.IdentityManager
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Tests for the invite acceptance flow (FR-5).
 *
 * These tests verify:
 * - New users can redeem invites
 * - Counter-signatures are created correctly
 * - Error cases are handled properly
 */
class InviteAcceptanceFlowTest {
    // Inviter (Alice) setup
    private lateinit var aliceSecureStorage: InMemorySecureStorage
    private lateinit var aliceIdentityManager: IdentityManager
    private lateinit var aliceTokenStorage: InMemoryInviteTokenStorage
    private lateinit var aliceAcceptanceStorage: InMemoryInviteAcceptanceStorage
    private lateinit var aliceInviteManager: InviteManager

    // Invitee (Bob) setup
    private lateinit var bobSecureStorage: InMemorySecureStorage
    private lateinit var bobIdentityManager: IdentityManager
    private lateinit var bobTokenStorage: InMemoryInviteTokenStorage
    private lateinit var bobAcceptanceStorage: InMemoryInviteAcceptanceStorage
    private lateinit var bobInviteManager: InviteManager

    private val cryptoProvider = CryptoProvider()

    @BeforeEach
    fun setUp() {
        // Setup Alice (inviter)
        aliceSecureStorage = InMemorySecureStorage()
        aliceIdentityManager = IdentityManager(aliceSecureStorage, cryptoProvider)
        aliceIdentityManager.initialize()
        aliceTokenStorage = InMemoryInviteTokenStorage()
        aliceAcceptanceStorage = InMemoryInviteAcceptanceStorage()
        aliceInviteManager = InviteManager(
            aliceIdentityManager,
            aliceTokenStorage,
            aliceAcceptanceStorage,
            cryptoProvider
        )

        // Setup Bob (invitee)
        bobSecureStorage = InMemorySecureStorage()
        bobIdentityManager = IdentityManager(bobSecureStorage, cryptoProvider)
        bobIdentityManager.initialize()
        bobTokenStorage = InMemoryInviteTokenStorage()
        bobAcceptanceStorage = InMemoryInviteAcceptanceStorage()
        bobInviteManager = InviteManager(
            bobIdentityManager,
            bobTokenStorage,
            bobAcceptanceStorage,
            cryptoProvider
        )
    }

    @AfterEach
    fun tearDown() {
        aliceIdentityManager.clearCache()
        bobIdentityManager.clearCache()
    }

    // ==================== Basic Acceptance Tests ====================

    @Test
    fun `acceptInvite succeeds with valid token from storage`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken(message = "Welcome!")
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Simulate sharing: copy token to Bob's storage
        bobTokenStorage.saveToken(token)

        // Bob accepts the invite
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)

        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance

        // Verify acceptance data
        assertEquals(token.tokenCode, acceptance.tokenCode)
        assertArrayEquals(aliceIdentityManager.getPublicKey(), acceptance.inviterPublicKey)
        assertArrayEquals(bobIdentityManager.getPublicKey(), acceptance.inviteePublicKey)
        assertEquals("Welcome!", acceptance.message)
    }

    @Test
    fun `acceptInvite creates valid counter-signature`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Simulate sharing
        bobTokenStorage.saveToken(token)

        // Bob accepts
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance

        // Verify Bob's counter-signature is valid
        assertTrue(bobInviteManager.verifyAcceptanceSignatures(acceptance))
    }

    @Test
    fun `acceptInvite increments token usage count`() {
        // Alice creates a token with max uses
        val genResult = aliceInviteManager.generateToken(maxUses = 5)
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        assertEquals(0, aliceTokenStorage.getToken(token.tokenCode)?.currentUses)

        // Simulate sharing
        bobTokenStorage.saveToken(token)

        // Bob accepts
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)

        // Bob's storage should show incremented usage
        assertEquals(1, bobTokenStorage.getToken(token.tokenCode)?.currentUses)
    }

    @Test
    fun `acceptInvite stores acceptance record`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Simulate sharing
        bobTokenStorage.saveToken(token)

        // Bob accepts
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)

        // Bob should have an acceptance record
        val myInvite = bobInviteManager.getMyInvite()
        assertNotNull(myInvite)
        assertEquals(token.tokenCode, myInvite?.tokenCode)
    }

    // ==================== Shareable String Acceptance Tests ====================

    @Test
    fun `acceptInvite works with shareable string when token in storage`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken(message = "Join me!")
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Create shareable string
        val shareable = aliceInviteManager.toShareableString(token)

        // Simulate sharing: token also needs to be in Bob's storage for full validation
        bobTokenStorage.saveToken(token)

        // Bob accepts using shareable string
        val acceptResult = bobInviteManager.acceptInvite(shareable)

        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance
        assertEquals("Join me!", acceptance.message)
    }

    @Test
    fun `acceptInvite with external token rejects unverifiable tokens`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Create shareable string
        val shareable = aliceInviteManager.toShareableString(token)

        // Bob accepts WITHOUT having token in storage (external acceptance)
        // This simulates receiving a token from outside the local network
        val acceptResult = bobInviteManager.acceptInvite(shareable)

        // Security: External tokens cannot be verified without full token data
        // in local storage, so they are rejected to prevent forgery attacks
        assertTrue(acceptResult is InviteAcceptanceResult.TokenNotFound)
    }

    @Test
    fun `acceptInvite fails with invalid shareable format`() {
        val acceptResult = bobInviteManager.acceptInvite("invalid-format")
        assertTrue(acceptResult is InviteAcceptanceResult.Error)
    }

    // ==================== Error Cases ====================

    @Test
    fun `acceptInvite fails for non-existent token in storage`() {
        val acceptResult = bobInviteManager.acceptInviteFromStorage("non-existent-token")
        assertTrue(acceptResult is InviteAcceptanceResult.TokenNotFound)
    }

    @Test
    fun `acceptInvite fails for expired token`() {
        // Alice creates a token that expires immediately
        val genResult = aliceInviteManager.generateToken(expiresInMillis = 1)
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Wait for expiration
        Thread.sleep(10)

        // Simulate sharing
        bobTokenStorage.saveToken(token)

        // Bob tries to accept
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.TokenExpired)
    }

    @Test
    fun `acceptInvite fails for exhausted token`() {
        // Alice creates a single-use token
        val genResult = aliceInviteManager.generateToken(maxUses = 1)
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Simulate sharing to Bob
        bobTokenStorage.saveToken(token)

        // Bob accepts (uses up the token)
        val acceptResult1 = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult1 is InviteAcceptanceResult.Success)

        // Setup Carol (another invitee)
        val carolSecureStorage = InMemorySecureStorage()
        val carolIdentityManager = IdentityManager(carolSecureStorage, cryptoProvider)
        carolIdentityManager.initialize()
        val carolAcceptanceStorage = InMemoryInviteAcceptanceStorage()
        val carolInviteManager = InviteManager(
            carolIdentityManager,
            bobTokenStorage, // Share Bob's storage (which has the exhausted token)
            carolAcceptanceStorage,
            cryptoProvider
        )

        // Carol tries to accept the same token
        val acceptResult2 = carolInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult2 is InviteAcceptanceResult.TokenExhausted)

        carolIdentityManager.clearCache()
    }

    @Test
    fun `acceptInvite fails for self-invite`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Alice tries to accept her own invite
        val acceptResult = aliceInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.SelfInvite)
    }

    @Test
    fun `acceptInvite fails if already a member`() {
        // Alice creates two tokens
        val genResult1 = aliceInviteManager.generateToken()
        assertTrue(genResult1 is TokenGenerationResult.Success)
        val token1 = (genResult1 as TokenGenerationResult.Success).token

        val genResult2 = aliceInviteManager.generateToken()
        assertTrue(genResult2 is TokenGenerationResult.Success)
        val token2 = (genResult2 as TokenGenerationResult.Success).token

        // Simulate sharing both tokens
        bobTokenStorage.saveToken(token1)
        bobTokenStorage.saveToken(token2)

        // Bob accepts the first invite
        val acceptResult1 = bobInviteManager.acceptInviteFromStorage(token1.tokenCode)
        assertTrue(acceptResult1 is InviteAcceptanceResult.Success)

        // Bob tries to accept the second invite
        val acceptResult2 = bobInviteManager.acceptInviteFromStorage(token2.tokenCode)
        assertTrue(acceptResult2 is InviteAcceptanceResult.AlreadyMember)
    }

    @Test
    fun `acceptInvite fails for tampered token signature`() {
        // Alice creates a token
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Tamper with the token
        val tamperedToken = InviteToken(
            tokenCode = token.tokenCode,
            inviterPublicKey = token.inviterPublicKey,
            signature = ByteArray(64), // Invalid signature
            createdAt = token.createdAt,
            expiresAt = token.expiresAt,
            maxUses = token.maxUses,
            currentUses = token.currentUses,
            message = token.message
        )
        bobTokenStorage.saveToken(tamperedToken)

        // Bob tries to accept
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.InvalidSignature)
    }

    // ==================== Query Tests ====================

    @Test
    fun `getMyInvitees returns users invited by current user`() {
        // Alice creates tokens
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Bob accepts (using shared storage for simplicity)
        bobTokenStorage.saveToken(token)
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance

        // Sync the acceptance to Alice's storage
        aliceAcceptanceStorage.saveAcceptance(acceptance)

        // Alice should see Bob in her invitees
        val invitees = aliceInviteManager.getMyInvitees()
        assertEquals(1, invitees.size)
        assertArrayEquals(bobIdentityManager.getPublicKey(), invitees[0].inviteePublicKey)
    }

    @Test
    fun `getMyInviteeCount returns correct count`() {
        // Initially no invitees
        assertEquals(0, aliceInviteManager.getMyInviteeCount())

        // After inviting Bob
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        bobTokenStorage.saveToken(token)
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance

        // Sync acceptance to Alice
        aliceAcceptanceStorage.saveAcceptance(acceptance)

        assertEquals(1, aliceInviteManager.getMyInviteeCount())
    }

    @Test
    fun `hasBeenInvited returns true after accepting invite`() {
        // Initially not invited
        assertFalse(bobInviteManager.hasBeenInvited())

        // After accepting invite
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        bobTokenStorage.saveToken(token)
        bobInviteManager.acceptInviteFromStorage(token.tokenCode)

        assertTrue(bobInviteManager.hasBeenInvited())
    }

    // ==================== Signature Verification Tests ====================

    @Test
    fun `verifyAcceptanceSignatures validates invitee counter-signature`() {
        // Create a valid acceptance
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        bobTokenStorage.saveToken(token)
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance

        // Verify with any manager (uses the same crypto)
        assertTrue(aliceInviteManager.verifyAcceptanceSignatures(acceptance))
    }

    @Test
    fun `verifyAcceptanceSignatures fails for tampered acceptance`() {
        // Create a valid acceptance
        val genResult = aliceInviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        bobTokenStorage.saveToken(token)
        val acceptResult = bobInviteManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Success)
        val acceptance = (acceptResult as InviteAcceptanceResult.Success).acceptance

        // Tamper with the acceptance
        val tamperedAcceptance = acceptance.copy(inviteeSignature = ByteArray(64))

        assertFalse(aliceInviteManager.verifyAcceptanceSignatures(tamperedAcceptance))
    }

    // ==================== Backward Compatibility Tests ====================

    @Test
    fun `InviteManager without acceptance storage allows token generation but rejects acceptance`() {
        // Create manager without acceptance storage (backward compatible for token generation)
        val manager = InviteManager(
            aliceIdentityManager,
            aliceTokenStorage,
            cryptoProvider
        )

        // Token generation should still work
        val genResult = manager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Acceptance-related queries return empty/default values
        assertTrue(manager.getMyInvitees().isEmpty())
        assertNull(manager.getMyInvite())
        assertEquals(0, manager.getMyInviteeCount())
        assertFalse(manager.hasBeenInvited())

        // Set up Bob to try accepting using manager without acceptance storage
        val bobManager = InviteManager(
            bobIdentityManager,
            bobTokenStorage,
            cryptoProvider
        )
        bobTokenStorage.saveToken(token)

        // Acceptance should fail because storage is required
        val acceptResult = bobManager.acceptInviteFromStorage(token.tokenCode)
        assertTrue(acceptResult is InviteAcceptanceResult.Error)
        assertTrue((acceptResult as InviteAcceptanceResult.Error).message.contains("storage"))
    }
}
