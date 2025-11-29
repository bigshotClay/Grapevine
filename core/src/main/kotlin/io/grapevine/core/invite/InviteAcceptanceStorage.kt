package io.grapevine.core.invite

/**
 * Storage interface for invite acceptances.
 *
 * Implementations should persist accepted invites durably and support
 * efficient lookup by token code and public keys.
 *
 * ## Thread Safety
 * Implementations MUST be thread-safe. All methods may be called concurrently
 * from multiple threads. Individual operations (save, get, delete) MUST be atomic.
 *
 * ## Defensive Copying Contract
 * Implementations MUST NOT expose internal mutable state:
 * - All returned [InviteAcceptance] instances MUST be defensive copies
 * - All [ByteArray] parameters MUST be copied on write (not stored by reference)
 * - Callers may safely mutate returned objects without affecting storage
 *
 * The [InviteAcceptance.copy] method performs deep copies of all byte arrays
 * and should be used by implementations.
 *
 * ## Blocking I/O
 * Methods in this interface are synchronous and may perform blocking I/O
 * (database queries, file operations). Callers SHOULD NOT invoke these methods
 * from UI threads or performance-critical paths. Consider wrapping calls in
 * `withContext(Dispatchers.IO)` when using coroutines.
 *
 * ## Key Size Requirements
 * All public key parameters ([ByteArray]) MUST be exactly 32 bytes (Ed25519).
 * Implementations SHOULD validate key sizes and throw [IllegalArgumentException]
 * for invalid inputs.
 *
 * ## Sorting Guarantees
 * Methods returning lists specify "newest first" ordering by [InviteAcceptance.acceptedAt].
 * For acceptances with equal timestamps, implementations SHOULD use [InviteAcceptance.tokenCode]
 * as a secondary sort key (lexicographic ascending) for deterministic ordering.
 *
 * ## Error Handling
 * - [IllegalArgumentException]: Invalid parameters (wrong key size, blank token code)
 * - [InviteAcceptanceStorageException]: Storage/IO errors (database unavailable, corruption)
 *
 * @see InviteAcceptance
 * @see InMemoryInviteAcceptanceStorage
 */
interface InviteAcceptanceStorage {
    /**
     * Saves an invite acceptance to storage.
     *
     * If an acceptance for this token already exists, it will be replaced.
     * The operation is atomic - either the full acceptance is saved or nothing changes.
     *
     * @param acceptance The acceptance to save (will be defensively copied)
     * @return true if this was a new insert, false if it replaced an existing acceptance
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun saveAcceptance(acceptance: InviteAcceptance): Boolean

    /**
     * Retrieves an acceptance by its token code.
     *
     * @param tokenCode The unique token code
     * @return A defensive copy of the acceptance if found, null otherwise
     * @throws IllegalArgumentException if tokenCode is blank
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun getAcceptance(tokenCode: String): InviteAcceptance?

    /**
     * Gets all acceptances where the given user was the inviter.
     *
     * Results are sorted by [InviteAcceptance.acceptedAt] descending (newest first),
     * with [InviteAcceptance.tokenCode] as tie-breaker.
     *
     * @param inviterPublicKey The inviter's Ed25519 public key (must be exactly 32 bytes)
     * @return List of defensive copies, newest first. Empty list if none found.
     * @throws IllegalArgumentException if inviterPublicKey is not 32 bytes
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun getAcceptancesByInviter(inviterPublicKey: ByteArray): List<InviteAcceptance>

    /**
     * Gets all acceptances where the given user was the invitee.
     *
     * Results are sorted by [InviteAcceptance.acceptedAt] descending (newest first),
     * with [InviteAcceptance.tokenCode] as tie-breaker.
     *
     * @param inviteePublicKey The invitee's Ed25519 public key (must be exactly 32 bytes)
     * @return List of defensive copies, newest first. Empty list if none found.
     * @throws IllegalArgumentException if inviteePublicKey is not 32 bytes
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun getAcceptancesByInvitee(inviteePublicKey: ByteArray): List<InviteAcceptance>

    /**
     * Gets the acceptance that brought a user into the network (their invite).
     *
     * A user should have exactly one acceptance as an invitee (unless they are genesis).
     * If multiple acceptances exist (anomaly), returns the most recent by [InviteAcceptance.acceptedAt].
     *
     * @param inviteePublicKey The user's Ed25519 public key (must be exactly 32 bytes)
     * @return A defensive copy of the acceptance that invited this user, or null if not found
     * @throws IllegalArgumentException if inviteePublicKey is not 32 bytes
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun getMyInvite(inviteePublicKey: ByteArray): InviteAcceptance?

    /**
     * Checks if a user has been invited (has an acceptance record as invitee).
     *
     * @param publicKey The user's Ed25519 public key (must be exactly 32 bytes)
     * @return true if the user has been invited, false otherwise
     * @throws IllegalArgumentException if publicKey is not 32 bytes
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun hasBeenInvited(publicKey: ByteArray): Boolean

    /**
     * Gets all acceptances in storage.
     *
     * Results are sorted by [InviteAcceptance.acceptedAt] descending (newest first),
     * with [InviteAcceptance.tokenCode] as tie-breaker.
     *
     * **Warning**: This may return a large number of results. For production use,
     * consider implementing pagination or streaming alternatives.
     *
     * @return List of defensive copies of all acceptances, newest first
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun getAllAcceptances(): List<InviteAcceptance>

    /**
     * Deletes an acceptance by its token code.
     *
     * @param tokenCode The unique token code
     * @return true if an acceptance was deleted, false if not found
     * @throws IllegalArgumentException if tokenCode is blank
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun deleteAcceptance(tokenCode: String): Boolean

    /**
     * Checks if an acceptance exists for a token.
     *
     * @param tokenCode The unique token code
     * @return true if an acceptance exists, false otherwise
     * @throws IllegalArgumentException if tokenCode is blank
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun hasAcceptance(tokenCode: String): Boolean

    /**
     * Gets the count of users invited by a specific inviter.
     *
     * @param inviterPublicKey The inviter's Ed25519 public key (must be exactly 32 bytes)
     * @return The number of users this inviter has invited
     * @throws IllegalArgumentException if inviterPublicKey is not 32 bytes
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun getInviteeCount(inviterPublicKey: ByteArray): Int

    /**
     * Clears all acceptances from storage.
     *
     * **WARNING**: This is a destructive operation that permanently deletes all data.
     * Intended only for testing or administrative reset scenarios.
     *
     * @throws InviteAcceptanceStorageException if storage operation fails
     */
    fun clearAll()
}

/**
 * Exception thrown for invite acceptance storage errors.
 *
 * This exception indicates a storage-level failure (I/O error, database unavailable,
 * data corruption) rather than a logical error (invalid parameters).
 *
 * ## When to Throw
 * - Database connection failures
 * - File I/O errors
 * - Data corruption or deserialization failures
 * - Transaction rollback failures
 *
 * ## When NOT to Throw
 * - Invalid parameters (use [IllegalArgumentException])
 * - Item not found (return null or false)
 * - Business logic violations (use domain-specific result types)
 *
 * @param message Description of the storage error
 * @param cause The underlying exception, if any
 */
class InviteAcceptanceStorageException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
