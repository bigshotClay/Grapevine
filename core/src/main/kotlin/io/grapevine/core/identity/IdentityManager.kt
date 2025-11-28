package io.grapevine.core.identity

import com.goterl.lazysodium.utils.Key
import io.grapevine.core.crypto.CryptoProvider
import org.slf4j.LoggerFactory
import java.io.Closeable
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Manages user identity creation, storage, and retrieval.
 *
 * On first launch, automatically generates a new Ed25519 key pair
 * and stores the private key securely using the OS secure storage.
 *
 * ## Thread Safety
 * This class is thread-safe. All public methods that access cached data
 * return defensive copies to prevent callers from modifying internal state.
 *
 * ## Resource Management
 * Implements [Closeable] to allow explicit cleanup of sensitive data from memory.
 * Call [close] when the manager is no longer needed to zero cached private keys.
 *
 * ## Security Notes
 * - Private keys are zeroed from memory when possible, but JVM garbage collection
 *   may retain copies. For high-security requirements, consider native secure memory.
 * - Callers receiving byte arrays from [getPrivateKey] are responsible for zeroing
 *   them after use. Prefer using [sign] which handles key cleanup internally.
 *
 * @property secureStorage The secure storage implementation for persisting private keys
 * @property cryptoProvider The cryptographic provider for key generation and signing
 * @property identityBackup The backup handler for import/export operations
 */
class IdentityManager(
    private val secureStorage: SecureStorage,
    private val cryptoProvider: CryptoProvider = CryptoProvider(),
    private val identityBackup: IdentityBackup = IdentityBackup()
) : Closeable {
    private val logger = LoggerFactory.getLogger(IdentityManager::class.java)
    private val lock = ReentrantReadWriteLock()

    @Volatile private var cachedPrivateKey: ByteArray? = null
    @Volatile private var cachedIdentity: Identity? = null

    /**
     * Initializes the identity manager.
     * If no identity exists, generates a new key pair.
     *
     * This method is idempotent - calling it multiple times after initialization
     * will simply return the cached identity.
     *
     * @return The current identity
     * @throws IdentityException if loading an existing identity fails due to invalid key format
     */
    fun initialize(): Identity {
        // Fast path: check if already initialized
        cachedIdentity?.let { return it }

        // Acquire write lock for the actual initialization
        // We recheck existence inside the write lock to avoid race conditions
        return lock.write {
            // Double-check: another thread may have initialized while we waited
            cachedIdentity?.let { return@write it }

            logger.info("Initializing identity manager")

            // Check existence while holding write lock to prevent race conditions
            if (hasIdentityInternal()) {
                logger.info("Loading existing identity")
                loadIdentityInternal()
            } else {
                logger.info("No existing identity found, generating new key pair")
                generateNewIdentityInternal()
            }
        }
    }

    /**
     * Checks if an identity already exists in secure storage.
     *
     * @return true if a private key exists in secure storage, false otherwise
     */
    fun hasIdentity(): Boolean = lock.read {
        hasIdentityInternal()
    }

    private fun hasIdentityInternal(): Boolean {
        return secureStorage.exists(SecureStorage.PRIVATE_KEY_ID)
    }

    /**
     * Gets the current identity, initializing if necessary.
     *
     * If no identity is cached, this method will:
     * 1. Load an existing identity from secure storage if one exists, or
     * 2. Generate a new identity if none exists
     *
     * @return The current identity
     * @throws IdentityException if loading fails due to invalid key format,
     *         or if generation/storage fails
     */
    fun getIdentity(): Identity {
        // Fast path: check volatile field first
        cachedIdentity?.let { return it }
        return initialize()
    }

    /**
     * Gets a copy of the private key bytes for signing operations.
     * Returns null if no identity exists.
     *
     * IMPORTANT: The caller receives a defensive copy of the private key.
     * The caller is responsible for zeroing this copy when done.
     *
     * @return A copy of the private key bytes, or null if no identity exists
     */
    fun getPrivateKey(): ByteArray? {
        // Fast path: check volatile field first (no lock)
        cachedPrivateKey?.let { return it.copyOf() }

        // Acquire write lock to populate cache if missing
        return lock.write {
            // Double-check: another thread may have populated the cache
            cachedPrivateKey?.let { return@write it.copyOf() }

            val key = secureStorage.retrieve(SecureStorage.PRIVATE_KEY_ID)
            if (key != null) {
                // Store a defensive copy in cache
                cachedPrivateKey = key.copyOf()
            }
            // Return a copy, not the cached reference
            cachedPrivateKey?.copyOf()
        }
    }

    /**
     * Gets a copy of the public key bytes.
     *
     * @return A copy of the public key bytes
     * @throws IdentityException if no identity exists and generation fails
     */
    fun getPublicKey(): ByteArray {
        return getIdentity().publicKey.copyOf()
    }

    /**
     * Signs data using the current identity's private key.
     *
     * This is the preferred method for signing operations as it handles
     * private key retrieval and cleanup internally, reducing the risk
     * of accidental key exposure.
     *
     * @param data The data to sign
     * @return The Ed25519 signature bytes (64 bytes)
     * @throws IdentityException if no identity exists
     */
    fun sign(data: ByteArray): ByteArray {
        val privateKey = getPrivateKey()
            ?: throw IdentityException("No identity available for signing")

        return try {
            cryptoProvider.sign(data, Key.fromBytes(privateKey))
        } finally {
            // Zero the private key copy after use
            privateKey.fill(0)
        }
    }

    /**
     * Verifies a signature against data using a public key.
     *
     * @param data The original data that was signed
     * @param signature The signature to verify
     * @param publicKey The public key to verify against
     * @return true if the signature is valid, false otherwise
     */
    fun verify(data: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        return cryptoProvider.verify(data, signature, Key.fromBytes(publicKey))
    }

    /**
     * Generates a new identity with a fresh Ed25519 key pair.
     * This will overwrite any existing identity.
     *
     * WARNING: This is a destructive operation. Any existing identity
     * will be permanently replaced. Consider calling [exportBackup] first
     * if the current identity needs to be preserved.
     *
     * @return The newly created identity
     * @throws IdentityException if storing the new private key fails
     */
    fun generateNewIdentity(): Identity = lock.write {
        generateNewIdentityInternal()
    }

    private fun generateNewIdentityInternal(): Identity {
        logger.info("Generating new Ed25519 key pair")

        // Clear any existing cached data first
        clearCacheInternal()

        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        // Store private key securely
        val stored = secureStorage.store(SecureStorage.PRIVATE_KEY_ID, privateKey)
        if (!stored) {
            throw IdentityException("Failed to store private key in secure storage")
        }

        // Create and cache identity (store defensive copies)
        val identity = Identity(
            publicKey = publicKey.copyOf(),
            createdAt = System.currentTimeMillis()
        )

        cachedPrivateKey = privateKey.copyOf()
        cachedIdentity = identity

        logger.info("New identity created with short ID: ${identity.shortId}")
        return identity
    }

    /**
     * Loads an existing identity from secure storage.
     *
     * This method explicitly loads from storage, replacing any cached identity.
     * For most use cases, prefer [getIdentity] which handles caching automatically.
     *
     * @return The loaded identity
     * @throws IdentityException if no identity exists in storage or the key format is invalid
     */
    fun loadIdentity(): Identity = lock.write {
        loadIdentityInternal()
    }

    private fun loadIdentityInternal(): Identity {
        val privateKey = secureStorage.retrieve(SecureStorage.PRIVATE_KEY_ID)
            ?: throw IdentityException("No identity found in secure storage")

        // Delegate public key extraction to CryptoProvider
        val publicKey = try {
            cryptoProvider.extractPublicKeyFromSecretKey(privateKey)
        } catch (e: IllegalArgumentException) {
            throw IdentityException("Invalid private key format: ${e.message}", e)
        }

        val identity = Identity(
            publicKey = publicKey.copyOf(),
            createdAt = System.currentTimeMillis() // We don't persist createdAt yet
        )

        // Store defensive copies in cache
        cachedPrivateKey = privateKey.copyOf()
        cachedIdentity = identity

        logger.info("Identity loaded with short ID: ${identity.shortId}")
        return identity
    }

    /**
     * Clears the cached identity and private key from memory.
     * Does not delete from secure storage.
     *
     * The cached private key is securely zeroed before being released.
     */
    fun clearCache() = lock.write {
        clearCacheInternal()
    }

    private fun clearCacheInternal() {
        cachedPrivateKey?.fill(0) // Securely clear the private key from memory
        cachedPrivateKey = null
        cachedIdentity = null
    }

    /**
     * Deletes the identity from secure storage.
     * This is a destructive operation and cannot be undone.
     *
     * The cache is cleared first to ensure sensitive data is removed from memory
     * regardless of whether the storage deletion succeeds.
     *
     * @return true if deletion was successful
     */
    fun deleteIdentity(): Boolean = lock.write {
        logger.warn("Deleting identity from secure storage")
        clearCacheInternal()
        secureStorage.delete(SecureStorage.PRIVATE_KEY_ID)
    }

    /**
     * Exports the current identity to an encrypted backup file.
     *
     * @param password User-provided password for encryption
     * @param outputFile The file to write the backup to
     * @throws IdentityException if no identity exists
     * @throws IdentityBackupException if backup fails
     */
    fun exportBackup(password: String, outputFile: java.io.File) {
        // Get copies outside of any lock to avoid holding locks during I/O
        val privateKey = getPrivateKey()
            ?: throw IdentityException("No identity to export")
        val identity = getIdentity()

        try {
            logger.info("Exporting identity backup to ${outputFile.absolutePath}")
            identityBackup.exportBackup(privateKey, identity, password, outputFile)
        } finally {
            // Zero our copy of the private key
            privateKey.fill(0)
        }
    }

    /**
     * Imports an identity from an encrypted backup file.
     * This will replace the current identity.
     *
     * @param backupFile The backup file to import
     * @param password The password used to encrypt the backup
     * @return The restored identity
     * @throws IdentityBackupException if decryption fails or backup is corrupted
     * @throws IdentityException if storing the imported key fails
     */
    fun importBackup(backupFile: java.io.File, password: String): Identity {
        logger.info("Importing identity backup from ${backupFile.absolutePath}")

        // Perform I/O outside of write lock
        val backupData = identityBackup.importBackup(backupFile, password)

        try {
            return lock.write {
                // Clear existing cache first
                clearCacheInternal()

                // Store the private key
                val stored = secureStorage.store(SecureStorage.PRIVATE_KEY_ID, backupData.privateKey)
                if (!stored) {
                    throw IdentityException("Failed to store imported private key in secure storage")
                }

                // Create and cache the identity (store defensive copies)
                val identity = backupData.toIdentity()
                cachedPrivateKey = backupData.privateKey.copyOf()
                cachedIdentity = identity

                logger.info("Identity imported successfully with short ID: ${identity.shortId}")
                identity
            }
        } finally {
            // Zero the backup data's private key to minimize exposure
            backupData.privateKey.fill(0)
        }
    }

    /**
     * Validates a backup file without importing it.
     *
     * @param backupFile The backup file to validate
     * @return true if the file appears to be a valid Grapevine backup
     */
    fun isValidBackupFile(backupFile: java.io.File): Boolean {
        return identityBackup.isValidBackupFile(backupFile)
    }

    /**
     * Closes this manager and clears all sensitive data from memory.
     *
     * After calling this method, the manager can still be used - it will
     * reload from secure storage as needed. This is primarily useful for
     * explicitly clearing sensitive data when the manager is no longer needed.
     */
    override fun close() {
        clearCache()
    }
}

/**
 * Exception thrown when identity operations fail.
 */
class IdentityException(message: String, cause: Throwable? = null) : Exception(message, cause)
