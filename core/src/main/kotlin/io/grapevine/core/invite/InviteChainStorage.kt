package io.grapevine.core.invite

/**
 * Storage interface for invite chain records.
 *
 * Implementations must be thread-safe and return defensive copies of all
 * records containing mutable fields (e.g., ByteArray).
 *
 * ## Query Semantics
 * - All query methods return records ordered by sequence_number ascending,
 *   with timestamp as secondary sort (ascending) for records from different chains.
 * - Empty results are returned as empty lists, not null.
 *
 * ## Chain Integrity
 * The storage layer is responsible for enforcing chain integrity:
 * - Unique constraint on (inviter_public_key, sequence_number)
 * - Each inviter can only have one block per sequence number
 * - The first block for an inviter must have sequence_number = 0
 */
interface InviteChainStorage {

    /**
     * Saves an invite chain record.
     *
     * If a record with the same ID already exists, it is replaced.
     * Implementations should enforce the unique constraint on
     * (inviter_public_key, sequence_number).
     *
     * @param record The record to save
     * @throws InviteChainStorageException if a sequence conflict occurs or storage fails
     */
    fun saveRecord(record: InviteChainRecord)

    /**
     * Gets a record by its unique ID.
     *
     * @param id The record ID
     * @return The record, or null if not found
     */
    fun getById(id: String): InviteChainRecord?

    /**
     * Gets a record by block hash.
     *
     * @param blockHash The block hash (32 bytes)
     * @return The record, or null if not found
     */
    fun getByBlockHash(blockHash: ByteArray): InviteChainRecord?

    /**
     * Gets all records where the given public key is the inviter.
     *
     * @param inviterPublicKey The inviter's Ed25519 public key (32 bytes)
     * @return List of records ordered by sequence_number ascending
     */
    fun getByInviter(inviterPublicKey: ByteArray): List<InviteChainRecord>

    /**
     * Gets all records where the given public key is the invitee.
     *
     * @param inviteePublicKey The invitee's Ed25519 public key (32 bytes)
     * @return List of records ordered by timestamp ascending
     */
    fun getByInvitee(inviteePublicKey: ByteArray): List<InviteChainRecord>

    /**
     * Gets a specific record by inviter and sequence number.
     *
     * @param inviterPublicKey The inviter's public key
     * @param sequenceNumber The sequence number
     * @return The record, or null if not found
     */
    fun getBySequence(inviterPublicKey: ByteArray, sequenceNumber: Long): InviteChainRecord?

    /**
     * Gets the latest (highest sequence number) record for an inviter.
     *
     * @param inviterPublicKey The inviter's public key
     * @return The latest record, or null if the inviter has no records
     */
    fun getLatestByInviter(inviterPublicKey: ByteArray): InviteChainRecord?

    /**
     * Gets the invite record for an invitee (how they joined the network).
     *
     * Each user can only be invited once, so this returns at most one record.
     * If multiple records exist (data corruption), returns the earliest by timestamp.
     *
     * @param inviteePublicKey The invitee's public key
     * @return The record showing how this user was invited, or null if not found
     */
    fun getInviteFor(inviteePublicKey: ByteArray): InviteChainRecord?

    /**
     * Gets the count of users invited by the given public key.
     *
     * @param inviterPublicKey The inviter's public key
     * @return The count of invitees
     */
    fun getInviteeCount(inviterPublicKey: ByteArray): Int

    /**
     * Checks if a user has been invited (has an invite record as invitee).
     *
     * @param publicKey The public key to check
     * @return true if the user has been invited
     */
    fun hasBeenInvited(publicKey: ByteArray): Boolean

    /**
     * Checks if a record with the given ID exists.
     *
     * @param id The record ID
     * @return true if the record exists
     */
    fun exists(id: String): Boolean

    /**
     * Checks if a record with the given block hash exists.
     *
     * @param blockHash The block hash
     * @return true if a record with this hash exists
     */
    fun existsByBlockHash(blockHash: ByteArray): Boolean

    /**
     * Deletes a record by ID.
     *
     * @param id The record ID
     * @return true if the record was deleted, false if not found
     */
    fun delete(id: String): Boolean

    /**
     * Gets all records in the storage.
     *
     * Use with caution - may be expensive for large datasets.
     *
     * @return All records ordered by timestamp ascending
     */
    fun getAll(): List<InviteChainRecord>

    /**
     * Gets the total count of records.
     *
     * @return Total number of records
     */
    fun count(): Int

    /**
     * Clears all records from storage.
     *
     * Use with caution - primarily for testing.
     */
    fun clear()
}

/**
 * Exception thrown by InviteChainStorage operations.
 */
open class InviteChainStorageException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Exception thrown when a sequence number conflict occurs.
 */
class SequenceConflictException(
    val inviterPublicKey: ByteArray,
    val sequenceNumber: Long,
    val existingRecordId: String
) : InviteChainStorageException(
    "Sequence conflict: inviter already has a record at sequence $sequenceNumber (existing: $existingRecordId)"
)
