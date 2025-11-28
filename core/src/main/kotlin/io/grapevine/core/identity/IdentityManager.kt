package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.slf4j.LoggerFactory

/**
 * Manages user identity creation, storage, and retrieval.
 *
 * On first launch, automatically generates a new Ed25519 key pair
 * and stores the private key securely using the OS secure storage.
 */
class IdentityManager(
    private val secureStorage: SecureStorage,
    private val cryptoProvider: CryptoProvider = CryptoProvider(),
    private val identityBackup: IdentityBackup = IdentityBackup(cryptoProvider)
) {
    private val logger = LoggerFactory.getLogger(IdentityManager::class.java)

    private var cachedPrivateKey: ByteArray? = null
    private var cachedIdentity: Identity? = null

    /**
     * Initializes the identity manager.
     * If no identity exists, generates a new key pair.
     *
     * @return The current identity
     */
    fun initialize(): Identity {
        logger.info("Initializing identity manager")

        return if (hasIdentity()) {
            logger.info("Loading existing identity")
            loadIdentity()
        } else {
            logger.info("No existing identity found, generating new key pair")
            generateNewIdentity()
        }
    }

    /**
     * Checks if an identity already exists in secure storage.
     */
    fun hasIdentity(): Boolean {
        return secureStorage.exists(SecureStorage.PRIVATE_KEY_ID)
    }

    /**
     * Gets the current identity, initializing if necessary.
     */
    fun getIdentity(): Identity {
        return cachedIdentity ?: initialize()
    }

    /**
     * Gets the private key bytes for signing operations.
     * Returns null if no identity exists.
     */
    fun getPrivateKey(): ByteArray? {
        if (cachedPrivateKey != null) {
            return cachedPrivateKey
        }

        cachedPrivateKey = secureStorage.retrieve(SecureStorage.PRIVATE_KEY_ID)
        return cachedPrivateKey
    }

    /**
     * Gets the public key bytes.
     */
    fun getPublicKey(): ByteArray {
        return getIdentity().publicKey
    }

    /**
     * Generates a new identity with a fresh Ed25519 key pair.
     * This will overwrite any existing identity.
     *
     * @return The newly created identity
     */
    fun generateNewIdentity(): Identity {
        logger.info("Generating new Ed25519 key pair")

        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        // Store private key securely
        val stored = secureStorage.store(SecureStorage.PRIVATE_KEY_ID, privateKey)
        if (!stored) {
            throw IdentityException("Failed to store private key in secure storage")
        }

        // Create and cache identity
        val identity = Identity(
            publicKey = publicKey,
            createdAt = System.currentTimeMillis()
        )

        cachedPrivateKey = privateKey
        cachedIdentity = identity

        logger.info("New identity created with short ID: ${identity.shortId}")
        return identity
    }

    /**
     * Loads an existing identity from secure storage.
     *
     * @return The loaded identity
     * @throws IdentityException if the identity cannot be loaded
     */
    fun loadIdentity(): Identity {
        val privateKey = secureStorage.retrieve(SecureStorage.PRIVATE_KEY_ID)
            ?: throw IdentityException("No identity found in secure storage")

        // Derive public key from private key
        // Ed25519 private keys contain the public key in the last 32 bytes
        val publicKey = if (privateKey.size == 64) {
            privateKey.copyOfRange(32, 64)
        } else {
            throw IdentityException("Invalid private key format")
        }

        val identity = Identity(
            publicKey = publicKey,
            createdAt = System.currentTimeMillis() // We don't persist createdAt yet
        )

        cachedPrivateKey = privateKey
        cachedIdentity = identity

        logger.info("Identity loaded with short ID: ${identity.shortId}")
        return identity
    }

    /**
     * Clears the cached identity and private key.
     * Does not delete from secure storage.
     */
    fun clearCache() {
        cachedPrivateKey?.fill(0) // Securely clear the private key from memory
        cachedPrivateKey = null
        cachedIdentity = null
    }

    /**
     * Deletes the identity from secure storage.
     * This is a destructive operation and cannot be undone.
     *
     * @return true if deletion was successful
     */
    fun deleteIdentity(): Boolean {
        logger.warn("Deleting identity from secure storage")
        clearCache()
        return secureStorage.delete(SecureStorage.PRIVATE_KEY_ID)
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
        val privateKey = getPrivateKey()
            ?: throw IdentityException("No identity to export")
        val identity = getIdentity()

        logger.info("Exporting identity backup to ${outputFile.absolutePath}")
        identityBackup.exportBackup(privateKey, identity, password, outputFile)
    }

    /**
     * Imports an identity from an encrypted backup file.
     * This will replace the current identity.
     *
     * @param backupFile The backup file to import
     * @param password The password used to encrypt the backup
     * @return The restored identity
     * @throws IdentityBackupException if import fails
     */
    fun importBackup(backupFile: java.io.File, password: String): Identity {
        logger.info("Importing identity backup from ${backupFile.absolutePath}")

        val backupData = identityBackup.importBackup(backupFile, password)

        // Store the private key
        val stored = secureStorage.store(SecureStorage.PRIVATE_KEY_ID, backupData.privateKey)
        if (!stored) {
            throw IdentityException("Failed to store imported private key in secure storage")
        }

        // Create and cache the identity
        val identity = backupData.toIdentity()
        cachedPrivateKey = backupData.privateKey
        cachedIdentity = identity

        logger.info("Identity imported successfully with short ID: ${identity.shortId}")
        return identity
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
}

/**
 * Exception thrown when identity operations fail.
 */
class IdentityException(message: String, cause: Throwable? = null) : Exception(message, cause)
