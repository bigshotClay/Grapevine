package io.grapevine.core.identity

/**
 * Interface for platform-specific secure storage operations.
 * Implementations should use the OS-provided secure storage:
 * - Windows: Credential Manager
 * - macOS: Keychain
 * - Linux: Secret Service API / libsecret
 */
interface SecureStorage {
    /**
     * Stores a secret securely.
     *
     * @param key The identifier for the secret
     * @param value The secret data to store
     * @return true if storage was successful, false otherwise
     */
    fun store(key: String, value: ByteArray): Boolean

    /**
     * Retrieves a secret from secure storage.
     *
     * @param key The identifier for the secret
     * @return The secret data, or null if not found
     */
    fun retrieve(key: String): ByteArray?

    /**
     * Deletes a secret from secure storage.
     *
     * @param key The identifier for the secret
     * @return true if deletion was successful, false otherwise
     */
    fun delete(key: String): Boolean

    /**
     * Checks if a secret exists in secure storage.
     *
     * @param key The identifier for the secret
     * @return true if the secret exists, false otherwise
     */
    fun exists(key: String): Boolean

    companion object {
        const val PRIVATE_KEY_ID = "grapevine.identity.private_key"
    }
}
