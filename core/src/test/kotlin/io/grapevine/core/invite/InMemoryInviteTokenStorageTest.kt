package io.grapevine.core.invite

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class InMemoryInviteTokenStorageTest {
    private lateinit var storage: InMemoryInviteTokenStorage
    private val random = SecureRandom()

    @BeforeEach
    fun setUp() {
        storage = InMemoryInviteTokenStorage()
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

    private fun createToken(
        tokenCode: String = "token-${System.nanoTime()}",
        publicKey: ByteArray = generatePublicKey(),
        createdAt: Long = System.currentTimeMillis(),
        expiresAt: Long? = null,
        maxUses: Int? = null,
        currentUses: Int = 0
    ): InviteToken {
        return InviteToken(
            tokenCode = tokenCode,
            inviterPublicKey = publicKey,
            signature = generateSignature(),
            createdAt = createdAt,
            expiresAt = expiresAt,
            maxUses = maxUses,
            currentUses = currentUses
        )
    }

    // ==================== Basic Operations ====================

    @Test
    fun `saveToken stores token correctly`() {
        val token = createToken(tokenCode = "test-token")
        storage.saveToken(token)

        val retrieved = storage.getToken("test-token")
        assertNotNull(retrieved)
        assertEquals(token.tokenCode, retrieved!!.tokenCode)
    }

    @Test
    fun `getToken returns null for non-existent token`() {
        val result = storage.getToken("non-existent")
        assertNull(result)
    }

    @Test
    fun `hasToken returns true for existing token`() {
        val token = createToken(tokenCode = "test-token")
        storage.saveToken(token)

        assertTrue(storage.hasToken("test-token"))
    }

    @Test
    fun `hasToken returns false for non-existent token`() {
        assertFalse(storage.hasToken("non-existent"))
    }

    @Test
    fun `deleteToken removes existing token`() {
        val token = createToken(tokenCode = "test-token")
        storage.saveToken(token)

        val deleted = storage.deleteToken("test-token")

        assertTrue(deleted)
        assertFalse(storage.hasToken("test-token"))
    }

    @Test
    fun `deleteToken returns false for non-existent token`() {
        val deleted = storage.deleteToken("non-existent")
        assertFalse(deleted)
    }

    @Test
    fun `clearAll removes all tokens`() {
        val token1 = createToken(tokenCode = "token-1")
        val token2 = createToken(tokenCode = "token-2")
        storage.saveToken(token1)
        storage.saveToken(token2)

        storage.clearAll()

        assertFalse(storage.hasToken("token-1"))
        assertFalse(storage.hasToken("token-2"))
        assertTrue(storage.getAllTokens().isEmpty())
    }

    // ==================== Query by Inviter ====================

    @Test
    fun `getTokensByInviter returns only tokens from that inviter`() {
        val publicKey1 = generatePublicKey()
        val publicKey2 = generatePublicKey()

        val token1 = createToken(tokenCode = "token-1", publicKey = publicKey1)
        val token2 = createToken(tokenCode = "token-2", publicKey = publicKey1)
        val token3 = createToken(tokenCode = "token-3", publicKey = publicKey2)

        storage.saveToken(token1)
        storage.saveToken(token2)
        storage.saveToken(token3)

        val tokens = storage.getTokensByInviter(publicKey1)

        assertEquals(2, tokens.size)
        assertTrue(tokens.all { it.inviterPublicKey.contentEquals(publicKey1) })
    }

    @Test
    fun `getTokensByInviter returns tokens sorted by createdAt descending`() {
        val publicKey = generatePublicKey()
        val now = System.currentTimeMillis()

        val token1 = createToken(tokenCode = "token-1", publicKey = publicKey, createdAt = now - 2000)
        val token2 = createToken(tokenCode = "token-2", publicKey = publicKey, createdAt = now)
        val token3 = createToken(tokenCode = "token-3", publicKey = publicKey, createdAt = now - 1000)

        storage.saveToken(token1)
        storage.saveToken(token2)
        storage.saveToken(token3)

        val tokens = storage.getTokensByInviter(publicKey)

        assertEquals("token-2", tokens[0].tokenCode)
        assertEquals("token-3", tokens[1].tokenCode)
        assertEquals("token-1", tokens[2].tokenCode)
    }

    @Test
    fun `getTokensByInviter returns empty list for unknown inviter`() {
        val tokens = storage.getTokensByInviter(generatePublicKey())
        assertTrue(tokens.isEmpty())
    }

    @Test
    fun `getTokenCountByInviter returns correct count`() {
        val publicKey = generatePublicKey()

        storage.saveToken(createToken(tokenCode = "token-1", publicKey = publicKey))
        storage.saveToken(createToken(tokenCode = "token-2", publicKey = publicKey))
        storage.saveToken(createToken(tokenCode = "token-3", publicKey = generatePublicKey()))

        assertEquals(2, storage.getTokenCountByInviter(publicKey))
    }

    @Test
    fun `getTokenCountByInviter returns zero for unknown inviter`() {
        assertEquals(0, storage.getTokenCountByInviter(generatePublicKey()))
    }

    // ==================== Get All Tokens ====================

    @Test
    fun `getAllTokens returns all tokens sorted by createdAt descending`() {
        val now = System.currentTimeMillis()

        val token1 = createToken(tokenCode = "token-1", createdAt = now - 2000)
        val token2 = createToken(tokenCode = "token-2", createdAt = now)
        val token3 = createToken(tokenCode = "token-3", createdAt = now - 1000)

        storage.saveToken(token1)
        storage.saveToken(token2)
        storage.saveToken(token3)

        val tokens = storage.getAllTokens()

        assertEquals(3, tokens.size)
        assertEquals("token-2", tokens[0].tokenCode)
        assertEquals("token-3", tokens[1].tokenCode)
        assertEquals("token-1", tokens[2].tokenCode)
    }

    @Test
    fun `getAllTokens returns empty list when no tokens`() {
        assertTrue(storage.getAllTokens().isEmpty())
    }

    // ==================== Usage Count ====================

    @Test
    fun `incrementUsageCount increases count by one`() {
        val token = createToken(tokenCode = "test-token", currentUses = 5)
        storage.saveToken(token)

        val updated = storage.incrementUsageCount("test-token")

        assertNotNull(updated)
        assertEquals(6, updated!!.currentUses)
    }

    @Test
    fun `incrementUsageCount updates stored token`() {
        val token = createToken(tokenCode = "test-token", currentUses = 0)
        storage.saveToken(token)

        storage.incrementUsageCount("test-token")

        val retrieved = storage.getToken("test-token")
        assertEquals(1, retrieved!!.currentUses)
    }

    @Test
    fun `incrementUsageCount returns null for non-existent token`() {
        val result = storage.incrementUsageCount("non-existent")
        assertNull(result)
    }

    // ==================== Expired Token Cleanup ====================

    @Test
    fun `deleteExpiredTokens removes only expired tokens`() {
        val now = System.currentTimeMillis()

        val expired1 = createToken(tokenCode = "expired-1", createdAt = now - 3000, expiresAt = now - 1000)
        val expired2 = createToken(tokenCode = "expired-2", createdAt = now - 2000, expiresAt = now - 500)
        val valid = createToken(tokenCode = "valid", expiresAt = now + 1000)
        val noExpiry = createToken(tokenCode = "no-expiry", expiresAt = null)

        storage.saveToken(expired1)
        storage.saveToken(expired2)
        storage.saveToken(valid)
        storage.saveToken(noExpiry)

        val deleted = storage.deleteExpiredTokens(now)

        assertEquals(2, deleted)
        assertFalse(storage.hasToken("expired-1"))
        assertFalse(storage.hasToken("expired-2"))
        assertTrue(storage.hasToken("valid"))
        assertTrue(storage.hasToken("no-expiry"))
    }

    @Test
    fun `deleteExpiredTokens returns zero when no expired tokens`() {
        val future = System.currentTimeMillis() + 1000
        storage.saveToken(createToken(tokenCode = "token-1", expiresAt = future))
        storage.saveToken(createToken(tokenCode = "token-2", expiresAt = null))

        val deleted = storage.deleteExpiredTokens()

        assertEquals(0, deleted)
    }

    // ==================== Defensive Copy Tests ====================

    @Test
    fun `getToken returns defensive copy`() {
        val token = createToken(tokenCode = "test-token")
        storage.saveToken(token)

        val retrieved1 = storage.getToken("test-token")
        val retrieved2 = storage.getToken("test-token")

        assertNotSame(retrieved1, retrieved2)
        assertNotSame(retrieved1!!.inviterPublicKey, retrieved2!!.inviterPublicKey)
    }

    @Test
    fun `getTokensByInviter returns defensive copies`() {
        val publicKey = generatePublicKey()
        storage.saveToken(createToken(tokenCode = "token-1", publicKey = publicKey))

        val tokens1 = storage.getTokensByInviter(publicKey)
        val tokens2 = storage.getTokensByInviter(publicKey)

        assertNotSame(tokens1[0], tokens2[0])
    }

    @Test
    fun `getAllTokens returns defensive copies`() {
        storage.saveToken(createToken(tokenCode = "test-token"))

        val tokens1 = storage.getAllTokens()
        val tokens2 = storage.getAllTokens()

        assertNotSame(tokens1[0], tokens2[0])
    }

    // ==================== Concurrency Tests ====================

    @Test
    fun `concurrent saves and reads are thread-safe`() {
        val threadCount = 10
        val tokensPerThread = 100
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)

        // Each thread saves tokens with a unique prefix
        repeat(threadCount) { threadIndex ->
            executor.submit {
                try {
                    startLatch.await()
                    repeat(tokensPerThread) { tokenIndex ->
                        val token = createToken(tokenCode = "thread-$threadIndex-token-$tokenIndex")
                        storage.saveToken(token)

                        // Also read while writing
                        storage.getToken(token.tokenCode)
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Test timed out")
        executor.shutdown()

        // Verify all tokens were saved
        val allTokens = storage.getAllTokens()
        assertEquals(threadCount * tokensPerThread, allTokens.size)
    }

    @Test
    fun `concurrent incrementUsageCount is thread-safe`() {
        val token = createToken(tokenCode = "test-token", currentUses = 0)
        storage.saveToken(token)

        val threadCount = 100
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val successCount = AtomicInteger(0)

        repeat(threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    val result = storage.incrementUsageCount("test-token")
                    if (result != null) {
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

        assertEquals(threadCount, successCount.get())

        val finalToken = storage.getToken("test-token")
        assertEquals(threadCount, finalToken!!.currentUses)
    }

    @Test
    fun `concurrent delete operations are thread-safe`() {
        // Pre-populate with tokens
        val tokenCount = 100
        repeat(tokenCount) {
            storage.saveToken(createToken(tokenCode = "token-$it"))
        }

        val threadCount = 10
        val executor = Executors.newFixedThreadPool(threadCount)
        val startLatch = CountDownLatch(1)
        val doneLatch = CountDownLatch(threadCount)
        val deleteCount = AtomicInteger(0)

        // Each thread tries to delete all tokens
        repeat(threadCount) {
            executor.submit {
                try {
                    startLatch.await()
                    repeat(tokenCount) { index ->
                        if (storage.deleteToken("token-$index")) {
                            deleteCount.incrementAndGet()
                        }
                    }
                } finally {
                    doneLatch.countDown()
                }
            }
        }

        startLatch.countDown()
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS), "Test timed out")
        executor.shutdown()

        // Each token should be deleted exactly once
        assertEquals(tokenCount, deleteCount.get())
        assertTrue(storage.getAllTokens().isEmpty())
    }
}
