package io.grapevine.core.invite

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * In-memory implementation of [InviteTokenStorage] for testing purposes.
 *
 * This implementation stores invite tokens in memory and is not persistent.
 * For production use, use a persistent implementation backed by database.
 *
 * ## Thread Safety
 * This implementation is thread-safe using read-write locks.
 */
class InMemoryInviteTokenStorage : InviteTokenStorage {
    private val lock = ReentrantReadWriteLock()
    private val tokens = mutableMapOf<String, InviteToken>()

    override fun saveToken(token: InviteToken): Unit = lock.write {
        // Store a defensive copy
        tokens[token.tokenCode] = token.copy()
    }

    override fun getToken(tokenCode: String): InviteToken? = lock.read {
        tokens[tokenCode]?.copy()
    }

    override fun getTokensByInviter(inviterPublicKey: ByteArray): List<InviteToken> = lock.read {
        tokens.values
            .filter { it.inviterPublicKey.contentEquals(inviterPublicKey) }
            .sortedByDescending { it.createdAt }
            .map { it.copy() }
    }

    override fun getAllTokens(): List<InviteToken> = lock.read {
        tokens.values
            .sortedByDescending { it.createdAt }
            .map { it.copy() }
    }

    override fun deleteToken(tokenCode: String): Boolean = lock.write {
        tokens.remove(tokenCode) != null
    }

    override fun incrementUsageCount(tokenCode: String): InviteToken? = lock.write {
        val existing = tokens[tokenCode] ?: return@write null
        val updated = existing.withIncrementedUseCount()
        tokens[tokenCode] = updated
        updated.copy()
    }

    override fun hasToken(tokenCode: String): Boolean = lock.read {
        tokens.containsKey(tokenCode)
    }

    override fun deleteExpiredTokens(currentTime: Long): Int = lock.write {
        val expiredCodes = tokens.values
            .filter { it.isExpired(currentTime) }
            .map { it.tokenCode }

        expiredCodes.forEach { tokens.remove(it) }
        expiredCodes.size
    }

    override fun getTokenCountByInviter(inviterPublicKey: ByteArray): Int = lock.read {
        tokens.values.count { it.inviterPublicKey.contentEquals(inviterPublicKey) }
    }

    override fun clearAll(): Unit = lock.write {
        tokens.clear()
    }
}
