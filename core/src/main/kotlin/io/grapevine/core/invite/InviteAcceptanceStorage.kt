package io.grapevine.core.invite

/**
 * Storage interface for invite acceptances.
 *
 * Implementations should persist accepted invites durably and support
 * efficient lookup by token code and public keys.
 *
 * ## Thread Safety
 * Implementations must be thread-safe.
 */
interface InviteAcceptanceStorage {
    /**
     * Saves an invite acceptance to storage.
     *
     * If an acceptance for this token already exists, it will be replaced.
     *
     * @param acceptance The acceptance to save
     */
    fun saveAcceptance(acceptance: InviteAcceptance)

    /**
     * Retrieves an acceptance by its token code.
     *
     * @param tokenCode The unique token code
     * @return The acceptance if found, null otherwise
     */
    fun getAcceptance(tokenCode: String): InviteAcceptance?

    /**
     * Gets all acceptances where the given user was the inviter.
     *
     * @param inviterPublicKey The inviter's public key (32 bytes)
     * @return List of acceptances where this user invited others, newest first
     */
    fun getAcceptancesByInviter(inviterPublicKey: ByteArray): List<InviteAcceptance>

    /**
     * Gets all acceptances where the given user was the invitee.
     *
     * @param inviteePublicKey The invitee's public key (32 bytes)
     * @return List of acceptances where this user was invited, newest first
     */
    fun getAcceptancesByInvitee(inviteePublicKey: ByteArray): List<InviteAcceptance>

    /**
     * Gets the acceptance that brought a user into the network (their invite).
     *
     * A user should have exactly one acceptance as an invitee (unless they are genesis).
     *
     * @param inviteePublicKey The user's public key (32 bytes)
     * @return The acceptance that invited this user, or null if not found
     */
    fun getMyInvite(inviteePublicKey: ByteArray): InviteAcceptance?

    /**
     * Checks if a user has been invited (has an acceptance record as invitee).
     *
     * @param publicKey The user's public key (32 bytes)
     * @return true if the user has been invited, false otherwise
     */
    fun hasBeenInvited(publicKey: ByteArray): Boolean

    /**
     * Gets all acceptances in storage.
     *
     * @return List of all acceptances, newest first
     */
    fun getAllAcceptances(): List<InviteAcceptance>

    /**
     * Deletes an acceptance by its token code.
     *
     * @param tokenCode The unique token code
     * @return true if an acceptance was deleted, false if not found
     */
    fun deleteAcceptance(tokenCode: String): Boolean

    /**
     * Checks if an acceptance exists for a token.
     *
     * @param tokenCode The unique token code
     * @return true if an acceptance exists, false otherwise
     */
    fun hasAcceptance(tokenCode: String): Boolean

    /**
     * Gets the count of users invited by a specific inviter.
     *
     * @param inviterPublicKey The inviter's public key (32 bytes)
     * @return The number of users this inviter has invited
     */
    fun getInviteeCount(inviterPublicKey: ByteArray): Int

    /**
     * Clears all acceptances from storage.
     *
     * WARNING: This is a destructive operation that should only be used
     * for testing or reset scenarios.
     */
    fun clearAll()
}

/**
 * Exception thrown for invite acceptance storage errors.
 */
class InviteAcceptanceStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)
