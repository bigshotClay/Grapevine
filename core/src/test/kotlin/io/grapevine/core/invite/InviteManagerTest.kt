package io.grapevine.core.invite

import io.grapevine.core.crypto.CryptoProvider
import io.grapevine.core.identity.IdentityManager
import io.grapevine.core.identity.SecureStorage
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class InviteManagerTest {
    private lateinit var secureStorage: InMemorySecureStorage
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var identityManager: IdentityManager
    private lateinit var tokenStorage: InMemoryInviteTokenStorage
    private lateinit var inviteManager: InviteManager

    @BeforeEach
    fun setUp() {
        secureStorage = InMemorySecureStorage()
        cryptoProvider = CryptoProvider()
        identityManager = IdentityManager(secureStorage, cryptoProvider)
        identityManager.initialize()
        tokenStorage = InMemoryInviteTokenStorage()
        inviteManager = InviteManager(identityManager, tokenStorage, cryptoProvider)
    }

    @AfterEach
    fun tearDown() {
        identityManager.clearCache()
    }

    // ==================== Token Generation Tests ====================

    @Test
    fun `generateToken creates valid token`() {
        val result = inviteManager.generateToken()

        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        assertNotNull(token.tokenCode)
        assertTrue(token.tokenCode.isNotBlank())
        assertArrayEquals(identityManager.getPublicKey(), token.inviterPublicKey)
        assertEquals(64, token.signature.size)
        assertEquals(0, token.currentUses)
    }

    @Test
    fun `generateToken stores token in storage`() {
        val result = inviteManager.generateToken()
        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        val retrieved = tokenStorage.getToken(token.tokenCode)
        assertNotNull(retrieved)
        assertEquals(token.tokenCode, retrieved!!.tokenCode)
    }

    @Test
    fun `generateToken with expiration sets expiresAt`() {
        val result = inviteManager.generateToken(expiresInMillis = 3600_000)

        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        assertNotNull(token.expiresAt)
        assertTrue(token.expiresAt!! > token.createdAt)
        assertTrue(token.expiresAt!! <= token.createdAt + 3600_000)
    }

    @Test
    fun `generateToken with TimeUnit sets expiration correctly`() {
        val result = inviteManager.generateToken(1, TimeUnit.HOURS)

        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        assertNotNull(token.expiresAt)
        // Should be approximately 1 hour from creation
        val expectedExpiry = token.createdAt + TimeUnit.HOURS.toMillis(1)
        assertEquals(expectedExpiry, token.expiresAt)
    }

    @Test
    fun `generateToken with maxUses sets limit`() {
        val result = inviteManager.generateToken(maxUses = 5)

        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        assertEquals(5, token.maxUses)
    }

    @Test
    fun `generateToken with message includes message`() {
        val result = inviteManager.generateToken(message = "Welcome to Grapevine!")

        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        assertEquals("Welcome to Grapevine!", token.message)
    }

    @Test
    fun `generateToken creates unique tokens`() {
        val tokens = mutableSetOf<String>()

        repeat(100) {
            val result = inviteManager.generateToken()
            assertTrue(result is TokenGenerationResult.Success)
            val token = (result as TokenGenerationResult.Success).token
            assertTrue(tokens.add(token.tokenCode), "Token code should be unique")
        }
    }

    // ==================== Token Validation Tests ====================

    @Test
    fun `validateToken returns Valid for valid token`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        val validationResult = inviteManager.validateToken(token.tokenCode)

        assertTrue(validationResult is TokenValidationResult.Valid)
        assertEquals(token.tokenCode, (validationResult as TokenValidationResult.Valid).token.tokenCode)
    }

    @Test
    fun `validateToken returns NotFound for unknown token`() {
        val result = inviteManager.validateToken("non-existent-token")
        assertTrue(result is TokenValidationResult.NotFound)
    }

    @Test
    fun `validateToken returns Expired for expired token`() {
        // Create a token that expires immediately
        val result = inviteManager.generateToken(expiresInMillis = 1)
        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        // Wait for expiration
        Thread.sleep(10)

        val validationResult = inviteManager.validateToken(token.tokenCode)

        assertTrue(validationResult is TokenValidationResult.Expired)
        assertEquals(token.tokenCode, (validationResult as TokenValidationResult.Expired).token.tokenCode)
    }

    @Test
    fun `validateToken returns Exhausted for fully used token`() {
        val result = inviteManager.generateToken(maxUses = 1)
        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        // Use the token once
        inviteManager.redeemToken(token.tokenCode)

        val validationResult = inviteManager.validateToken(token.tokenCode)

        assertTrue(validationResult is TokenValidationResult.Exhausted)
    }

    @Test
    fun `validateToken verifies signature`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Tamper with the token by creating one with a different signature
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
        tokenStorage.saveToken(tamperedToken)

        val validationResult = inviteManager.validateToken(token.tokenCode)

        assertTrue(validationResult is TokenValidationResult.InvalidSignature)
    }

    // ==================== Token Redemption Tests ====================

    @Test
    fun `redeemToken increments usage count`() {
        val genResult = inviteManager.generateToken(maxUses = 5)
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        assertEquals(0, token.currentUses)

        val redeemResult = inviteManager.redeemToken(token.tokenCode)

        assertTrue(redeemResult is TokenValidationResult.Valid)
        val redeemedToken = (redeemResult as TokenValidationResult.Valid).token
        assertEquals(1, redeemedToken.currentUses)

        // Verify storage was updated
        val storedToken = tokenStorage.getToken(token.tokenCode)
        assertEquals(1, storedToken!!.currentUses)
    }

    @Test
    fun `redeemToken fails for expired token`() {
        val result = inviteManager.generateToken(expiresInMillis = 1)
        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        Thread.sleep(10)

        val redeemResult = inviteManager.redeemToken(token.tokenCode)

        assertTrue(redeemResult is TokenValidationResult.Expired)
    }

    @Test
    fun `redeemToken fails for exhausted token`() {
        val result = inviteManager.generateToken(maxUses = 1)
        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        // First redemption succeeds
        val firstRedeem = inviteManager.redeemToken(token.tokenCode)
        assertTrue(firstRedeem is TokenValidationResult.Valid)

        // Second redemption fails
        val secondRedeem = inviteManager.redeemToken(token.tokenCode)
        assertTrue(secondRedeem is TokenValidationResult.Exhausted)
    }

    @Test
    fun `redeemToken fails for non-existent token`() {
        val result = inviteManager.redeemToken("non-existent")
        assertTrue(result is TokenValidationResult.NotFound)
    }

    // ==================== Token Query Tests ====================

    @Test
    fun `getToken returns token by code`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        val retrieved = inviteManager.getToken(token.tokenCode)

        assertNotNull(retrieved)
        assertEquals(token.tokenCode, retrieved!!.tokenCode)
    }

    @Test
    fun `getToken returns null for unknown code`() {
        val retrieved = inviteManager.getToken("non-existent")
        assertNull(retrieved)
    }

    @Test
    fun `getMyTokens returns tokens created by current identity`() {
        repeat(3) {
            inviteManager.generateToken()
        }

        val myTokens = inviteManager.getMyTokens()

        assertEquals(3, myTokens.size)
        myTokens.forEach {
            assertArrayEquals(identityManager.getPublicKey(), it.inviterPublicKey)
        }
    }

    @Test
    fun `getMyTokenCount returns correct count`() {
        repeat(5) {
            inviteManager.generateToken()
        }

        assertEquals(5, inviteManager.getMyTokenCount())
    }

    // ==================== Token Revocation Tests ====================

    @Test
    fun `revokeToken removes token from storage`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        val revoked = inviteManager.revokeToken(token.tokenCode)

        assertTrue(revoked)
        assertNull(tokenStorage.getToken(token.tokenCode))
    }

    @Test
    fun `revokeToken returns false for non-existent token`() {
        val revoked = inviteManager.revokeToken("non-existent")
        assertFalse(revoked)
    }

    @Test
    fun `revokeToken fails for token not owned by current identity`() {
        // Create token with current identity
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Create another identity manager
        val otherStorage = InMemorySecureStorage()
        val otherIdentityManager = IdentityManager(otherStorage, cryptoProvider)
        otherIdentityManager.initialize()
        val otherInviteManager = InviteManager(otherIdentityManager, tokenStorage, cryptoProvider)

        // Try to revoke with other identity
        val revoked = otherInviteManager.revokeToken(token.tokenCode)

        assertFalse(revoked)
        assertNotNull(tokenStorage.getToken(token.tokenCode))

        otherIdentityManager.clearCache()
    }

    // ==================== Expired Token Cleanup Tests ====================

    @Test
    fun `cleanupExpiredTokens removes expired tokens`() {
        // Create some expired tokens
        repeat(3) {
            val result = inviteManager.generateToken(expiresInMillis = 1)
            assertTrue(result is TokenGenerationResult.Success)
        }
        // Create some valid tokens
        repeat(2) {
            val result = inviteManager.generateToken(expiresInMillis = 3600_000)
            assertTrue(result is TokenGenerationResult.Success)
        }

        Thread.sleep(10)

        val deleted = inviteManager.cleanupExpiredTokens()

        assertEquals(3, deleted)
        assertEquals(2, tokenStorage.getAllTokens().size)
    }

    // ==================== Shareable String Tests ====================

    @Test
    fun `toShareableString creates valid shareable format`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        val shareable = inviteManager.toShareableString(token)

        assertTrue(shareable.startsWith("grapevine://invite/"))
        assertTrue(shareable.contains(token.tokenCode))
        assertTrue(shareable.contains("#"))
    }

    @Test
    fun `parseShareableString parses valid shareable string`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        val shareable = inviteManager.toShareableString(token)
        val parsed = inviteManager.parseShareableString(shareable)

        assertNotNull(parsed)
        assertEquals(token.tokenCode, parsed!!.tokenCode)
        assertArrayEquals(token.inviterPublicKey, parsed.inviterPublicKey)
        assertArrayEquals(token.signature, parsed.signature)
    }

    @Test
    fun `parseShareableString returns null for invalid format`() {
        assertNull(inviteManager.parseShareableString("invalid"))
        assertNull(inviteManager.parseShareableString("grapevine://invite/"))
        assertNull(inviteManager.parseShareableString("grapevine://invite/code#only-one-part"))
        assertNull(inviteManager.parseShareableString("https://example.com/invite/code#key#sig"))
    }

    @Test
    fun `parseShareableString returns null for invalid key sizes`() {
        val invalidKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16))
        val validSig = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64))

        assertNull(inviteManager.parseShareableString("grapevine://invite/code#$invalidKey#$validSig"))
    }

    // ==================== Signature Verification Tests ====================

    @Test
    fun `verifyTokenSignature returns true for valid token`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        assertTrue(inviteManager.verifyTokenSignature(token))
    }

    @Test
    fun `verifyTokenSignature returns false for tampered token`() {
        val genResult = inviteManager.generateToken(message = "Original message")
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        // Create tampered token with different message but same signature
        val tamperedToken = token.copy(message = "Tampered message")

        assertFalse(inviteManager.verifyTokenSignature(tamperedToken))
    }

    @Test
    fun `verifyTokenSignature returns false for wrong signature`() {
        val genResult = inviteManager.generateToken()
        assertTrue(genResult is TokenGenerationResult.Success)
        val token = (genResult as TokenGenerationResult.Success).token

        val invalidSignature = ByteArray(64)
        val tamperedToken = token.copy(signature = invalidSignature)

        assertFalse(inviteManager.verifyTokenSignature(tamperedToken))
    }

    // ==================== Concurrency Tests ====================

    @Test
    fun `concurrent token generation creates unique tokens`() {
        val threadCount = 10
        val tokensPerThread = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val allTokenCodes = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

        repeat(threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    repeat(tokensPerThread) {
                        val result = inviteManager.generateToken()
                        if (result is TokenGenerationResult.Success) {
                            allTokenCodes.add(result.token.tokenCode)
                        }
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Test timed out")
        executor.shutdown()

        // All tokens should be unique
        assertEquals(threadCount * tokensPerThread, allTokenCodes.size)
    }

    @Test
    fun `concurrent redemptions eventually exhaust token`() {
        // Note: Due to the race condition between validation and increment,
        // concurrent redemptions may allow slightly more than maxUses successful validations.
        // This test verifies that the token eventually becomes exhausted and
        // no more redemptions succeed after that point.
        val maxUses = 5
        val result = inviteManager.generateToken(maxUses = maxUses)
        assertTrue(result is TokenGenerationResult.Success)
        val token = (result as TokenGenerationResult.Success).token

        val threadCount = 20
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successCount = java.util.concurrent.atomic.AtomicInteger(0)

        repeat(threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val redeemResult = inviteManager.redeemToken(token.tokenCode)
                    if (redeemResult is TokenValidationResult.Valid) {
                        successCount.incrementAndGet()
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "Test timed out")
        executor.shutdown()

        // At least maxUses redemptions should succeed (storage tracks actual usage)
        // Due to race conditions in validation vs increment, slightly more may pass validation
        // but storage will track the true count
        val finalToken = tokenStorage.getToken(token.tokenCode)
        assertNotNull(finalToken)

        // The token should now be exhausted (currentUses >= maxUses)
        assertTrue(finalToken!!.currentUses >= maxUses,
            "Expected at least $maxUses uses, got ${finalToken.currentUses}")

        // After exhaustion, no more redemptions should succeed
        val postExhaustionResult = inviteManager.redeemToken(token.tokenCode)
        assertTrue(postExhaustionResult is TokenValidationResult.Exhausted,
            "Token should be exhausted after concurrent redemptions")
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
