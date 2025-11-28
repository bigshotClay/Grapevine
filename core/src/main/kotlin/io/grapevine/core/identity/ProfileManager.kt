package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.slf4j.LoggerFactory
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Manages user profile data (display name, avatar, bio).
 *
 * Profile changes are tracked and can be broadcast to the network
 * through the provided listener callback.
 *
 * ## Thread Safety
 * This class is thread-safe. Profile field updates are synchronized,
 * and listeners are stored in a [CopyOnWriteArrayList] to allow safe
 * concurrent iteration and modification.
 *
 * ## Listener Lifecycle
 * Listeners are held with strong references. Callers are responsible for
 * calling [removeProfileListener] to prevent memory leaks when listeners
 * are no longer needed.
 *
 * ## Profile Data
 * - Display name: NFC-normalized, trimmed, max 64 Unicode codepoints
 * - Avatar hash: 64-character lowercase hex SHA-256 hash
 * - Bio: NFC-normalized, trimmed, max 500 Unicode codepoints
 */
class ProfileManager(
    private val identityManager: IdentityManager,
    private val cryptoProvider: CryptoProvider
) {
    private val logger = LoggerFactory.getLogger(ProfileManager::class.java)
    private val profileListeners = CopyOnWriteArrayList<ProfileUpdateListener>()

    // Lock for profile field access
    private val lock = Any()

    // Cached profile data (guarded by lock)
    @Volatile private var displayName: String? = null
    @Volatile private var avatarHash: String? = null
    @Volatile private var bio: String? = null

    /**
     * Gets the current profile data.
     *
     * The returned Profile contains a defensive copy of the public key.
     *
     * @return A Profile object containing current profile fields
     */
    fun getProfile(): Profile = synchronized(lock) {
        Profile(
            publicKey = identityManager.getPublicKey().copyOf(),
            displayName = displayName,
            avatarHash = avatarHash,
            bio = bio
        )
    }

    /**
     * Updates the display name.
     *
     * The name is trimmed before storage. Validation is performed on the trimmed value.
     *
     * @param name The new display name (null to clear, max 64 Unicode codepoints after trimming)
     * @throws IllegalArgumentException if trimmed name exceeds max length
     */
    fun setDisplayName(name: String?) {
        val trimmed = name?.trim()?.takeIf { it.isNotEmpty() }
        if (trimmed != null) {
            val codePointCount = trimmed.codePointCount(0, trimmed.length)
            require(codePointCount <= Identity.MAX_DISPLAY_NAME_LENGTH) {
                "Display name must be at most ${Identity.MAX_DISPLAY_NAME_LENGTH} characters (got $codePointCount)"
            }
        }

        val shouldNotify = synchronized(lock) {
            val oldName = displayName
            displayName = trimmed
            oldName != displayName
        }

        if (shouldNotify) {
            logger.debug("Display name updated")
            notifyProfileUpdate()
        }
    }

    /**
     * Updates the avatar.
     *
     * The image data is hashed using SHA-256. The caller may modify the input
     * array after this call without affecting the stored hash.
     *
     * @param imageData The avatar image data (will be hashed for storage)
     * @return The content hash of the avatar (64-character lowercase hex)
     */
    fun setAvatar(imageData: ByteArray): String {
        // Copy to prevent caller modifications during hashing
        val dataCopy = imageData.copyOf()
        val hash = cryptoProvider.sha256(dataCopy)
        val hashString = hash.toHexString()

        val shouldNotify = synchronized(lock) {
            val oldHash = avatarHash
            avatarHash = hashString
            oldHash != avatarHash
        }

        if (shouldNotify) {
            logger.debug("Avatar updated: {}...", hashString.take(8))
            notifyProfileUpdate()
        }

        return hashString
    }

    /**
     * Sets the avatar hash directly (when image data is stored elsewhere).
     *
     * @param hash The content hash of the avatar image (null or empty to clear).
     *             Must be a 64-character lowercase hex string (SHA-256 format) if provided.
     * @throws IllegalArgumentException if hash is non-empty and not valid SHA-256 hex format
     */
    fun setAvatarHash(hash: String?) {
        val normalizedHash = hash?.takeIf { it.isNotEmpty() }?.lowercase()
        if (normalizedHash != null) {
            require(AVATAR_HASH_PATTERN.matches(normalizedHash)) {
                "Avatar hash must be a 64-character lowercase hex string (SHA-256)"
            }
        }

        val shouldNotify = synchronized(lock) {
            val oldHash = avatarHash
            avatarHash = normalizedHash
            oldHash != avatarHash
        }

        if (shouldNotify) {
            logger.debug("Avatar hash updated: {}...", normalizedHash?.take(8) ?: "cleared")
            notifyProfileUpdate()
        }
    }

    /**
     * Clears the avatar.
     */
    fun clearAvatar() {
        val shouldNotify = synchronized(lock) {
            if (avatarHash != null) {
                avatarHash = null
                true
            } else {
                false
            }
        }

        if (shouldNotify) {
            logger.debug("Avatar cleared")
            notifyProfileUpdate()
        }
    }

    /**
     * Updates the bio.
     *
     * The bio is trimmed before storage. Validation is performed on the trimmed value.
     *
     * @param newBio The new bio text (null to clear, max 500 Unicode codepoints after trimming)
     * @throws IllegalArgumentException if trimmed bio exceeds max length
     */
    fun setBio(newBio: String?) {
        val trimmed = newBio?.trim()?.takeIf { it.isNotEmpty() }
        if (trimmed != null) {
            val codePointCount = trimmed.codePointCount(0, trimmed.length)
            require(codePointCount <= Identity.MAX_BIO_LENGTH) {
                "Bio must be at most ${Identity.MAX_BIO_LENGTH} characters (got $codePointCount)"
            }
        }

        val shouldNotify = synchronized(lock) {
            val oldBio = bio
            bio = trimmed
            oldBio != bio
        }

        if (shouldNotify) {
            logger.debug("Bio updated")
            notifyProfileUpdate()
        }
    }

    /**
     * Updates multiple profile fields at once.
     *
     * All validations are performed before any fields are updated.
     * Values are trimmed before storage.
     *
     * @param displayName The new display name (null to keep current, empty to clear)
     * @param avatarHash The new avatar hash (null to keep current, empty to clear).
     *                   Must be a 64-character hex string if non-empty.
     * @param bio The new bio (null to keep current, empty to clear)
     * @throws IllegalArgumentException if any validation fails
     */
    fun updateProfile(
        displayName: String? = null,
        avatarHash: String? = null,
        bio: String? = null
    ) {
        // Pre-process and validate all inputs before making changes
        val newDisplayName = displayName?.let { name ->
            val trimmed = name.trim().takeIf { it.isNotEmpty() }
            if (trimmed != null) {
                val codePointCount = trimmed.codePointCount(0, trimmed.length)
                require(codePointCount <= Identity.MAX_DISPLAY_NAME_LENGTH) {
                    "Display name must be at most ${Identity.MAX_DISPLAY_NAME_LENGTH} characters (got $codePointCount)"
                }
            }
            trimmed
        }

        val newAvatarHash = avatarHash?.let { hash ->
            val normalized = hash.takeIf { it.isNotEmpty() }?.lowercase()
            if (normalized != null) {
                require(AVATAR_HASH_PATTERN.matches(normalized)) {
                    "Avatar hash must be a 64-character lowercase hex string (SHA-256)"
                }
            }
            normalized
        }

        val newBio = bio?.let { bioText ->
            val trimmed = bioText.trim().takeIf { it.isNotEmpty() }
            if (trimmed != null) {
                val codePointCount = trimmed.codePointCount(0, trimmed.length)
                require(codePointCount <= Identity.MAX_BIO_LENGTH) {
                    "Bio must be at most ${Identity.MAX_BIO_LENGTH} characters (got $codePointCount)"
                }
            }
            trimmed
        }

        // Apply changes atomically
        val shouldNotify = synchronized(lock) {
            var changed = false

            if (displayName != null && this.displayName != newDisplayName) {
                this.displayName = newDisplayName
                changed = true
            }

            if (avatarHash != null && this.avatarHash != newAvatarHash) {
                this.avatarHash = newAvatarHash
                changed = true
            }

            if (bio != null && this.bio != newBio) {
                this.bio = newBio
                changed = true
            }

            changed
        }

        if (shouldNotify) {
            logger.debug("Profile updated")
            notifyProfileUpdate()
        }
    }

    /**
     * Creates an Identity object with current profile data.
     *
     * The returned Identity contains a defensive copy of the public key.
     *
     * @return An Identity with profile fields populated
     */
    fun createIdentityWithProfile(): Identity {
        val identity = identityManager.getIdentity()
        return synchronized(lock) {
            Identity(
                publicKey = identity.publicKey.copyOf(),
                displayName = displayName,
                avatarHash = avatarHash,
                bio = bio,
                createdAt = identity.createdAt
            )
        }
    }

    /**
     * Loads profile data from an existing Identity.
     *
     * This does not trigger listener notifications.
     *
     * @param identity The identity containing profile data
     */
    fun loadFromIdentity(identity: Identity) {
        synchronized(lock) {
            displayName = identity.displayName
            avatarHash = identity.avatarHash
            bio = identity.bio
        }
        logger.debug("Profile loaded from identity: {}", identity.shortId)
    }

    /**
     * Adds a listener for profile updates.
     *
     * The listener is held with a strong reference. Call [removeProfileListener]
     * when the listener is no longer needed to prevent memory leaks.
     */
    fun addProfileListener(listener: ProfileUpdateListener) {
        profileListeners.add(listener)
    }

    /**
     * Removes a profile update listener.
     *
     * @return true if the listener was found and removed
     */
    fun removeProfileListener(listener: ProfileUpdateListener): Boolean {
        return profileListeners.remove(listener)
    }

    private fun notifyProfileUpdate() {
        val profile = getProfile()
        // CopyOnWriteArrayList provides safe iteration during concurrent modification
        for (listener in profileListeners) {
            try {
                listener.onProfileUpdated(profile)
            } catch (e: Exception) {
                logger.error("Error notifying profile listener: {}", listener::class.simpleName, e)
            }
        }
    }

    /**
     * Listener interface for profile updates.
     */
    interface ProfileUpdateListener {
        /**
         * Called when profile data is updated.
         *
         * @param profile The updated profile
         */
        fun onProfileUpdated(profile: Profile)
    }

    companion object {
        /** Regex pattern for valid avatar hash (lowercase hex string, 64 chars for SHA-256) */
        private val AVATAR_HASH_PATTERN = Regex("^[a-f0-9]{64}$")
    }
}

/**
 * Represents a user's profile data.
 *
 * Note: This class stores the public key as a ByteArray. Callers should not
 * modify the array after construction. Use [publicKey].copyOf() if you need
 * to modify the key.
 */
data class Profile(
    val publicKey: ByteArray,
    val displayName: String?,
    val avatarHash: String?,
    val bio: String?
) {
    /**
     * Returns the public key as a URL-safe Base64-encoded string (no padding).
     * Matches the encoding used by [Identity.publicKeyBase64].
     */
    val publicKeyBase64: String
        get() = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)

    /**
     * Returns a short identifier derived from the public key.
     * URL-safe and matches [Identity.shortId].
     */
    val shortId: String
        get() = publicKeyBase64.take(8)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Profile

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (displayName != other.displayName) return false
        if (avatarHash != other.avatarHash) return false
        if (bio != other.bio) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + (avatarHash?.hashCode() ?: 0)
        result = 31 * result + (bio?.hashCode() ?: 0)
        return result
    }

    /**
     * Returns a safe string representation that does not leak the full public key.
     * Shows shortId instead of full key bytes. Bio is truncated if long.
     */
    override fun toString(): String {
        val safeBio = bio?.let { b ->
            val escaped = b.replace("\n", "\\n").replace("\r", "\\r")
            if (escaped.length > 40) "${escaped.take(37)}..." else escaped
        }
        val safeAvatarHash = avatarHash?.let { "${it.take(8)}..." } ?: "none"
        return "Profile(shortId=$shortId, displayName=$displayName, avatarHash=$safeAvatarHash, bio=$safeBio)"
    }
}

/**
 * Converts a ByteArray to a lowercase hex string.
 */
internal fun ByteArray.toHexString(): String {
    return joinToString("") { "%02x".format(it) }
}
