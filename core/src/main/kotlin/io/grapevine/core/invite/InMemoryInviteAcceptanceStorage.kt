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
 * This implementation is thread-safe using read-write locks.
 *
 * ## Defensive Copying
 * All stored and returned [InviteAcceptance] objects are deep-copied to prevent
 * external mutation of stored state. The [InviteAcceptance.copy] method performs
 * deep copies of all ByteArray fields (public keys and signatures).
 *
 * ## Deterministic Behavior
 * Query methods return results sorted by [InviteAcceptance.acceptedAt] descending
 * (most recent first) to ensure deterministic ordering.
 */
class InMemoryInviteAcceptanceStorage : InviteAcceptanceStorage {
    private val lock = ReentrantReadWriteLock()
    private val acceptances = mutableMapOf<String, InviteAcceptance>()

    override fun saveAcceptance(acceptance: InviteAcceptance): Unit = lock.write {
        // Store a defensive copy
        acceptances[acceptance.tokenCode] = acceptance.copy()
    }

    override fun getAcceptance(tokenCode: String): InviteAcceptance? = lock.read {
        acceptances[tokenCode]?.copy()
    }

    override fun getAcceptancesByInviter(inviterPublicKey: ByteArray): List<InviteAcceptance> = lock.read {
        acceptances.values
            .filter { it.inviterPublicKey.contentEquals(inviterPublicKey) }
            .sortedByDescending { it.acceptedAt }
            .map { it.copy() }
    }

    override fun getAcceptancesByInvitee(inviteePublicKey: ByteArray): List<InviteAcceptance> = lock.read {
        acceptances.values
            .filter { it.inviteePublicKey.contentEquals(inviteePublicKey) }
            .sortedByDescending { it.acceptedAt }
            .map { it.copy() }
    }

    override fun getMyInvite(inviteePublicKey: ByteArray): InviteAcceptance? = lock.read {
        // Return the most recent acceptance for deterministic behavior
        acceptances.values
            .filter { it.inviteePublicKey.contentEquals(inviteePublicKey) }
            .maxByOrNull { it.acceptedAt }
            ?.copy()
    }

    override fun hasBeenInvited(publicKey: ByteArray): Boolean = lock.read {
        acceptances.values.any { it.inviteePublicKey.contentEquals(publicKey) }
    }

    override fun getAllAcceptances(): List<InviteAcceptance> = lock.read {
        acceptances.values
            .sortedByDescending { it.acceptedAt }
            .map { it.copy() }
    }

    override fun deleteAcceptance(tokenCode: String): Boolean = lock.write {
        acceptances.remove(tokenCode) != null
    }

    override fun hasAcceptance(tokenCode: String): Boolean = lock.read {
        acceptances.containsKey(tokenCode)
    }

    override fun getInviteeCount(inviterPublicKey: ByteArray): Int = lock.read {
        acceptances.values.count { it.inviterPublicKey.contentEquals(inviterPublicKey) }
    }

    override fun clearAll(): Unit = lock.write {
        acceptances.clear()
    }
}
