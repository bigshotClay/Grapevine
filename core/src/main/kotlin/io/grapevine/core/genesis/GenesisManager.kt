package io.grapevine.core.genesis

import io.grapevine.core.identity.Identity
import org.slf4j.LoggerFactory

/**
 * Manages the genesis user bootstrap mechanism for Grapevine.
 *
 * The genesis user is the first user who creates the network. They serve as:
 * - The root of the trust chain
 * - The initial contact point for new users
 * - The foundation from which all other users are invited
 *
 * ## Design Principles
 * - Single-user bootstrap: the first user IS the network
 * - No external infrastructure required
 * - Genesis user's device serves as the initial contact point
 * - As users are invited, the network grows organically
 *
 * ## Usage
 * ```kotlin
 * val genesisManager = GenesisManager(storage)
 *
 * // Check if this is a new network needing genesis
 * if (!genesisManager.hasGenesis()) {
 *     // Bootstrap as genesis user
 *     val result = genesisManager.bootstrapAsGenesis(identity, "Founder")
 * }
 *
 * // Check if current user is genesis
 * if (genesisManager.isGenesisUser(myPublicKey)) {
 *     // Genesis-specific actions
 * }
 * ```
 *
 * @property storage The storage backend for persisting genesis state
 */
class GenesisManager(
    private val storage: GenesisStorage
) {
    private val logger = LoggerFactory.getLogger(GenesisManager::class.java)

    /**
     * Checks if a genesis user exists in the network.
     *
     * @return true if a genesis user has been established, false otherwise
     */
    fun hasGenesis(): Boolean {
        return storage.hasGenesis()
    }

    /**
     * Gets the genesis user's identity if one exists.
     *
     * @return The genesis user's [GenesisInfo], or null if no genesis exists
     */
    fun getGenesisInfo(): GenesisInfo? {
        return storage.getGenesisInfo()
    }

    /**
     * Checks if the given public key belongs to the genesis user.
     *
     * @param publicKey The public key to check (32 bytes Ed25519)
     * @return true if this is the genesis user's public key
     */
    fun isGenesisUser(publicKey: ByteArray): Boolean {
        val genesisInfo = storage.getGenesisInfo() ?: return false
        return genesisInfo.publicKey.contentEquals(publicKey)
    }

    /**
     * Bootstraps the current user as the genesis user of a new network.
     *
     * This should only be called when:
     * 1. No existing network is detected
     * 2. The user explicitly chooses to create a new network
     *
     * The genesis user becomes the root of the trust chain and can invite
     * other users to join the network.
     *
     * This method is safe to call concurrently - if another thread wins the race,
     * this will return [GenesisResult.AlreadyExists] with the existing genesis info.
     *
     * @param identity The identity of the user becoming genesis
     * @param displayName Optional display name for the genesis user
     * @return [GenesisResult] indicating success or failure
     */
    fun bootstrapAsGenesis(
        identity: Identity,
        displayName: String? = null
    ): GenesisResult {
        logger.info("Attempting to bootstrap as genesis user")

        // Check if genesis already exists (early check to avoid unnecessary work)
        if (hasGenesis()) {
            logger.warn("Cannot bootstrap: genesis user already exists")
            return GenesisResult.AlreadyExists(getGenesisInfo()!!)
        }

        // Create genesis info
        val genesisInfo = GenesisInfo(
            publicKey = identity.publicKey.copyOf(),
            displayName = displayName ?: identity.displayName,
            createdAt = System.currentTimeMillis()
        )

        // Store genesis info - handle race condition where another thread may have
        // set genesis between our check and this call
        return try {
            storage.setGenesis(genesisInfo)
            logger.info("Successfully bootstrapped as genesis user")
            GenesisResult.Success(genesisInfo)
        } catch (e: GenesisException) {
            // Another thread won the race - return the existing genesis info
            logger.info("Genesis was set by another thread, returning existing genesis")
            val existingGenesis = storage.getGenesisInfo()
            if (existingGenesis != null) {
                GenesisResult.AlreadyExists(existingGenesis)
            } else {
                // Unexpected state: exception thrown but no genesis exists
                logger.error("GenesisException thrown but no genesis found", e)
                GenesisResult.Error("Unexpected state: ${e.message}")
            }
        } catch (e: Exception) {
            logger.error("Failed to store genesis info", e)
            GenesisResult.Error("Failed to store genesis info: ${e.message}")
        }
    }

    /**
     * Validates that the current network state is consistent.
     *
     * Checks:
     * - Genesis user exists if there are any invite blocks
     * - Genesis user's public key is valid
     *
     * @return [ValidationResult] with details about any issues found
     */
    fun validateNetworkState(): ValidationResult {
        val genesisInfo = getGenesisInfo()

        if (genesisInfo == null) {
            // No genesis is fine for a fresh install
            return ValidationResult(
                isValid = true,
                hasGenesis = false,
                issues = emptyList()
            )
        }

        val issues = mutableListOf<String>()

        // Validate public key size
        if (genesisInfo.publicKey.size != 32) {
            issues.add("Genesis public key has invalid size: ${genesisInfo.publicKey.size}")
        }

        // Validate timestamp
        if (genesisInfo.createdAt <= 0) {
            issues.add("Genesis has invalid creation timestamp")
        }

        if (genesisInfo.createdAt > System.currentTimeMillis()) {
            issues.add("Genesis creation timestamp is in the future")
        }

        return ValidationResult(
            isValid = issues.isEmpty(),
            hasGenesis = true,
            issues = issues
        )
    }
}

/**
 * Information about the genesis user.
 *
 * @property publicKey The Ed25519 public key of the genesis user (32 bytes)
 * @property displayName Optional display name of the genesis user
 * @property createdAt Unix timestamp (milliseconds) when genesis was established
 */
data class GenesisInfo(
    val publicKey: ByteArray,
    val displayName: String?,
    val createdAt: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GenesisInfo

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (displayName != other.displayName) return false
        if (createdAt != other.createdAt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + createdAt.hashCode()
        return result
    }

    override fun toString(): String {
        val keyPrefix = publicKey.take(4).joinToString("") { "%02x".format(it) }
        return "GenesisInfo(publicKey=$keyPrefix..., displayName=$displayName, createdAt=$createdAt)"
    }
}

/**
 * Result of a genesis bootstrap operation.
 */
sealed class GenesisResult {
    /**
     * Genesis was successfully established.
     */
    data class Success(val genesisInfo: GenesisInfo) : GenesisResult()

    /**
     * A genesis user already exists in the network.
     */
    data class AlreadyExists(val existingGenesis: GenesisInfo) : GenesisResult()

    /**
     * An error occurred during bootstrap.
     */
    data class Error(val message: String) : GenesisResult()
}

/**
 * Result of network state validation.
 */
data class ValidationResult(
    val isValid: Boolean,
    val hasGenesis: Boolean,
    val issues: List<String>
)

/**
 * Exception thrown for genesis-related errors.
 */
class GenesisException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Storage interface for genesis user data.
 *
 * Implementations should persist genesis information durably.
 */
interface GenesisStorage {
    /**
     * Checks if a genesis user has been established.
     */
    fun hasGenesis(): Boolean

    /**
     * Gets the genesis user information.
     *
     * @return [GenesisInfo] or null if no genesis exists
     */
    fun getGenesisInfo(): GenesisInfo?

    /**
     * Sets the genesis user information.
     *
     * @param genesisInfo The genesis information to store
     * @throws GenesisException if genesis already exists or storage fails
     */
    fun setGenesis(genesisInfo: GenesisInfo)

    /**
     * Clears the genesis information.
     *
     * WARNING: This is a destructive operation that should only be used
     * for testing or network reset scenarios.
     */
    fun clearGenesis()
}
