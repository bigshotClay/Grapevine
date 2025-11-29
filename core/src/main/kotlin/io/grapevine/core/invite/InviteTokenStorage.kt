package io.grapevine.core.invite

/**
 * Storage interface for invite tokens.
 *
 * Implementations should persist invite tokens durably and support
 * efficient lookup by token code and inviter public key.
 *
 * ## Thread Safety
 * Implementations must be thread-safe.
 */
interface InviteTokenStorage {
    /**
     * Saves an invite token to storage.
     *
     * If a token with the same code already exists, it will be replaced.
     *
     * @param token The token to save
     */
    fun saveToken(token: InviteToken)

    /**
     * Retrieves a token by its code.
     *
     * @param tokenCode The unique token code
     * @return The token if found, null otherwise
     */
    fun getToken(tokenCode: String): InviteToken?

    /**
     * Gets all tokens created by a specific inviter.
     *
     * @param inviterPublicKey The inviter's public key (32 bytes)
     * @return List of tokens created by this inviter, newest first
     */
    fun getTokensByInviter(inviterPublicKey: ByteArray): List<InviteToken>

    /**
     * Gets all tokens in storage.
     *
     * @return List of all tokens, newest first
     */
    fun getAllTokens(): List<InviteToken>

    /**
     * Deletes a token by its code.
     *
     * @param tokenCode The unique token code
     * @return true if a token was deleted, false if not found
     */
    fun deleteToken(tokenCode: String): Boolean

    /**
     * Updates a token's usage count.
     *
     * @param tokenCode The unique token code
     * @return The updated token, or null if not found
     */
    fun incrementUsageCount(tokenCode: String): InviteToken?

    /**
     * Checks if a token exists.
     *
     * @param tokenCode The unique token code
     * @return true if the token exists, false otherwise
     */
    fun hasToken(tokenCode: String): Boolean

    /**
     * Deletes all expired tokens.
     *
     * @param currentTime The current time in milliseconds
     * @return The number of tokens deleted
     */
    fun deleteExpiredTokens(currentTime: Long = System.currentTimeMillis()): Int

    /**
     * Gets the count of tokens created by a specific inviter.
     *
     * @param inviterPublicKey The inviter's public key (32 bytes)
     * @return The number of tokens created by this inviter
     */
    fun getTokenCountByInviter(inviterPublicKey: ByteArray): Int

    /**
     * Clears all tokens from storage.
     *
     * WARNING: This is a destructive operation that should only be used
     * for testing or reset scenarios.
     */
    fun clearAll()
}

/**
 * Exception thrown for invite token storage errors.
 */
class InviteTokenStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)
