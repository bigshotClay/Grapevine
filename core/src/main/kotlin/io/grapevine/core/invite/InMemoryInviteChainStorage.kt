package io.grapevine.core.invite

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Thread-safe in-memory implementation of [InviteChainStorage].
 *
 * This implementation is intended for testing and development. For production use,
 * use a SQLDelight-backed implementation for persistence.
 *
 * ## Thread Safety
 * All operations are protected by a [ReentrantReadWriteLock], ensuring thread-safe
 * access for concurrent reads and exclusive writes.
 *
 * ## Defensive Copying
 * All records are deep-copied on write and read to prevent external mutation.
 *
 * ## Performance Characteristics
 * - O(1): getById, exists, delete, saveRecord (amortized)
 * - O(n): getByInviter, getByInvitee, getAll, count, clear
 *
 * Where n is the total number of records.
 */
class InMemoryInviteChainStorage : InviteChainStorage {

    private val lock = ReentrantReadWriteLock()

    // Primary storage by ID
    private val recordsById = mutableMapOf<String, InviteChainRecord>()

    // Index by block hash (Base64 encoded for map key)
    private val recordsByBlockHash = mutableMapOf<String, InviteChainRecord>()

    // Index by inviter public key (Base64 encoded) -> list of record IDs
    private val recordIdsByInviter = mutableMapOf<String, MutableList<String>>()

    // Index by invitee public key (Base64 encoded) -> list of record IDs
    private val recordIdsByInvitee = mutableMapOf<String, MutableList<String>>()

    // Index by (inviter, sequence) for uniqueness check
    private val recordIdBySequence = mutableMapOf<String, String>()

    override fun saveRecord(record: InviteChainRecord) = lock.write {
        val defensiveCopy = record.copy()
        val inviterKey = defensiveCopy.inviterPublicKeyBase64
        val inviteeKey = defensiveCopy.inviteePublicKeyBase64
        val sequenceKey = "$inviterKey:${defensiveCopy.sequenceNumber}"

        // Check for sequence conflict (different record at same sequence)
        val existingIdAtSequence = recordIdBySequence[sequenceKey]
        if (existingIdAtSequence != null && existingIdAtSequence != defensiveCopy.id) {
            throw SequenceConflictException(
                inviterPublicKey = defensiveCopy.inviterPublicKey,
                sequenceNumber = defensiveCopy.sequenceNumber,
                existingRecordId = existingIdAtSequence
            )
        }

        // Remove old record if exists (for update case)
        val existingRecord = recordsById[defensiveCopy.id]
        if (existingRecord != null) {
            removeFromIndexes(existingRecord)
        }

        // Store new record
        recordsById[defensiveCopy.id] = defensiveCopy
        recordsByBlockHash[defensiveCopy.blockHashBase64] = defensiveCopy

        // Update inviter index
        recordIdsByInviter.getOrPut(inviterKey) { mutableListOf() }.add(defensiveCopy.id)

        // Update invitee index
        recordIdsByInvitee.getOrPut(inviteeKey) { mutableListOf() }.add(defensiveCopy.id)

        // Update sequence index
        recordIdBySequence[sequenceKey] = defensiveCopy.id
    }

    override fun getById(id: String): InviteChainRecord? = lock.read {
        recordsById[id]?.copy()
    }

    override fun getByBlockHash(blockHash: ByteArray): InviteChainRecord? = lock.read {
        val hashKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(blockHash)
        recordsByBlockHash[hashKey]?.copy()
    }

    override fun getByInviter(inviterPublicKey: ByteArray): List<InviteChainRecord> = lock.read {
        val inviterKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterPublicKey)
        val recordIds = recordIdsByInviter[inviterKey] ?: return@read emptyList()

        recordIds
            .mapNotNull { recordsById[it] }
            .sortedBy { it.sequenceNumber }
            .map { it.copy() }
    }

    override fun getByInvitee(inviteePublicKey: ByteArray): List<InviteChainRecord> = lock.read {
        val inviteeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteePublicKey)
        val recordIds = recordIdsByInvitee[inviteeKey] ?: return@read emptyList()

        recordIds
            .mapNotNull { recordsById[it] }
            .sortedBy { it.timestamp }
            .map { it.copy() }
    }

    override fun getBySequence(inviterPublicKey: ByteArray, sequenceNumber: Long): InviteChainRecord? = lock.read {
        val inviterKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterPublicKey)
        val sequenceKey = "$inviterKey:$sequenceNumber"
        val recordId = recordIdBySequence[sequenceKey] ?: return@read null
        recordsById[recordId]?.copy()
    }

    override fun getLatestByInviter(inviterPublicKey: ByteArray): InviteChainRecord? = lock.read {
        val inviterKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterPublicKey)
        val recordIds = recordIdsByInviter[inviterKey] ?: return@read null

        recordIds
            .mapNotNull { recordsById[it] }
            .maxByOrNull { it.sequenceNumber }
            ?.copy()
    }

    override fun getInviteFor(inviteePublicKey: ByteArray): InviteChainRecord? = lock.read {
        val inviteeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviteePublicKey)
        val recordIds = recordIdsByInvitee[inviteeKey] ?: return@read null

        // Return earliest by timestamp (should typically be only one)
        recordIds
            .mapNotNull { recordsById[it] }
            .minByOrNull { it.timestamp }
            ?.copy()
    }

    override fun getInviteeCount(inviterPublicKey: ByteArray): Int = lock.read {
        val inviterKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(inviterPublicKey)
        recordIdsByInviter[inviterKey]?.size ?: 0
    }

    override fun hasBeenInvited(publicKey: ByteArray): Boolean = lock.read {
        val key = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)
        !recordIdsByInvitee[key].isNullOrEmpty()
    }

    override fun exists(id: String): Boolean = lock.read {
        recordsById.containsKey(id)
    }

    override fun existsByBlockHash(blockHash: ByteArray): Boolean = lock.read {
        val hashKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(blockHash)
        recordsByBlockHash.containsKey(hashKey)
    }

    override fun delete(id: String): Boolean = lock.write {
        val record = recordsById.remove(id) ?: return@write false
        removeFromIndexes(record)
        true
    }

    override fun getAll(): List<InviteChainRecord> = lock.read {
        recordsById.values
            .sortedWith(compareBy({ it.timestamp }, { it.id }))
            .map { it.copy() }
    }

    override fun count(): Int = lock.read {
        recordsById.size
    }

    override fun clear() = lock.write {
        recordsById.clear()
        recordsByBlockHash.clear()
        recordIdsByInviter.clear()
        recordIdsByInvitee.clear()
        recordIdBySequence.clear()
    }

    /**
     * Removes a record from all indexes. Must be called within write lock.
     */
    private fun removeFromIndexes(record: InviteChainRecord) {
        val inviterKey = record.inviterPublicKeyBase64
        val inviteeKey = record.inviteePublicKeyBase64
        val sequenceKey = "$inviterKey:${record.sequenceNumber}"

        recordsByBlockHash.remove(record.blockHashBase64)
        recordIdsByInviter[inviterKey]?.remove(record.id)
        recordIdsByInvitee[inviteeKey]?.remove(record.id)
        recordIdBySequence.remove(sequenceKey)

        // Clean up empty lists
        if (recordIdsByInviter[inviterKey]?.isEmpty() == true) {
            recordIdsByInviter.remove(inviterKey)
        }
        if (recordIdsByInvitee[inviteeKey]?.isEmpty() == true) {
            recordIdsByInvitee.remove(inviteeKey)
        }
    }
}
