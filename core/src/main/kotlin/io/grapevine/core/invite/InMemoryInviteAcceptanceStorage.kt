package io.grapevine.core.invite

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * In-memory implementation of [InviteAcceptanceStorage] for testing purposes.
 *
 * This implementation stores invite acceptances in memory and is not persistent.
 * For production use, use a persistent implementation backed by database.
 *
 * ## Thread Safety
 * This implementation is thread-safe using read-write locks. All operations are atomic.
 *
 * ## Defensive Copying
 * All stored and returned [InviteAcceptance] objects are deep-copied to prevent
 * external mutation of stored state. The [InviteAcceptance.copy] method performs
 * deep copies of all ByteArray fields (public keys and signatures).
 *
 * ## Deterministic Behavior
 * Query methods return results sorted by [InviteAcceptance.acceptedAt] descending
 * (most recent first), with [InviteAcceptance.tokenCode] as tie-breaker for equal
 * timestamps.
 *
 * ## Input Validation
 * Public key parameters are validated to be exactly 32 bytes (Ed25519 key size).
 * Token code parameters are validated to be non-blank.
 *
 * ## Performance Characteristics
 * - Save/Get/Delete by tokenCode: O(1)
 * - Queries by public key: O(n) where n is total acceptances
 * - For large datasets, consider a persistent implementation with indexed queries
 */
class InMemoryInviteAcceptanceStorage : InviteAcceptanceStorage {
    private val lock = ReentrantReadWriteLock()
    private val acceptances = mutableMapOf<String, InviteAcceptance>()

    companion object {
        /** Expected size of Ed25519 public keys in bytes */
        private const val PUBLIC_KEY_SIZE = 32
    }

    override fun saveAcceptance(acceptance: InviteAcceptance): Boolean = lock.write {
        val isNew = !acceptances.containsKey(acceptance.tokenCode)
        // Store a defensive copy
        acceptances[acceptance.tokenCode] = acceptance.copy()
        isNew
    }

    override fun getAcceptance(tokenCode: String): InviteAcceptance? {
        requireValidTokenCode(tokenCode)
        return lock.read {
            acceptances[tokenCode]?.copy()
        }
    }

    override fun getAcceptancesByInviter(inviterPublicKey: ByteArray): List<InviteAcceptance> {
        requireValidPublicKey(inviterPublicKey, "inviterPublicKey")
        return lock.read {
            acceptances.values
                .filter { it.inviterPublicKey.contentEquals(inviterPublicKey) }
                .sortedWith(ACCEPTANCE_COMPARATOR)
                .map { it.copy() }
        }
    }

    override fun getAcceptancesByInvitee(inviteePublicKey: ByteArray): List<InviteAcceptance> {
        requireValidPublicKey(inviteePublicKey, "inviteePublicKey")
        return lock.read {
            acceptances.values
                .filter { it.inviteePublicKey.contentEquals(inviteePublicKey) }
                .sortedWith(ACCEPTANCE_COMPARATOR)
                .map { it.copy() }
        }
    }

    override fun getMyInvite(inviteePublicKey: ByteArray): InviteAcceptance? {
        requireValidPublicKey(inviteePublicKey, "inviteePublicKey")
        return lock.read {
            // Return the most recent acceptance for deterministic behavior
            acceptances.values
                .filter { it.inviteePublicKey.contentEquals(inviteePublicKey) }
                .maxWithOrNull(ACCEPTANCE_COMPARATOR.reversed())
                ?.copy()
        }
    }

    override fun hasBeenInvited(publicKey: ByteArray): Boolean {
        requireValidPublicKey(publicKey, "publicKey")
        return lock.read {
            acceptances.values.any { it.inviteePublicKey.contentEquals(publicKey) }
        }
    }

    override fun getAllAcceptances(): List<InviteAcceptance> = lock.read {
        acceptances.values
            .sortedWith(ACCEPTANCE_COMPARATOR)
            .map { it.copy() }
    }

    override fun deleteAcceptance(tokenCode: String): Boolean {
        requireValidTokenCode(tokenCode)
        return lock.write {
            acceptances.remove(tokenCode) != null
        }
    }

    override fun hasAcceptance(tokenCode: String): Boolean {
        requireValidTokenCode(tokenCode)
        return lock.read {
            acceptances.containsKey(tokenCode)
        }
    }

    override fun getInviteeCount(inviterPublicKey: ByteArray): Int {
        requireValidPublicKey(inviterPublicKey, "inviterPublicKey")
        return lock.read {
            acceptances.values.count { it.inviterPublicKey.contentEquals(inviterPublicKey) }
        }
    }

    override fun clearAll(): Unit = lock.write {
        acceptances.clear()
    }

    // ==================== Validation Helpers ====================

    private fun requireValidPublicKey(key: ByteArray, paramName: String) {
        require(key.size == PUBLIC_KEY_SIZE) {
            "$paramName must be exactly $PUBLIC_KEY_SIZE bytes, got ${key.size}"
        }
    }

    private fun requireValidTokenCode(tokenCode: String) {
        require(tokenCode.isNotBlank()) {
            "tokenCode cannot be blank"
        }
    }
}

/**
 * Comparator for sorting acceptances: newest first (descending acceptedAt),
 * with tokenCode as tie-breaker (ascending) for deterministic ordering.
 */
private val ACCEPTANCE_COMPARATOR: Comparator<InviteAcceptance> =
    compareByDescending<InviteAcceptance> { it.acceptedAt }
        .thenBy { it.tokenCode }
