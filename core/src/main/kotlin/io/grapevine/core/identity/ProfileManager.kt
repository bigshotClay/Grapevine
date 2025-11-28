package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.slf4j.LoggerFactory

/**
 * Manages user profile data (display name, avatar, bio).
 *
 * Profile changes are tracked and can be broadcast to the network
 * through the provided listener callback.
 */
class ProfileManager(
    private val identityManager: IdentityManager,
    private val cryptoProvider: CryptoProvider = CryptoProvider()
) {
    private val logger = LoggerFactory.getLogger(ProfileManager::class.java)
    private val profileListeners = mutableListOf<ProfileUpdateListener>()

    // Cached profile data
    private var displayName: String? = null
    private var avatarHash: String? = null
    private var bio: String? = null

    /**
     * Gets the current profile data.
     *
     * @return A Profile object containing current profile fields
     */
    fun getProfile(): Profile {
        return Profile(
            publicKey = identityManager.getPublicKey(),
            displayName = displayName,
            avatarHash = avatarHash,
            bio = bio
        )
    }

    /**
     * Updates the display name.
     *
     * @param name The new display name (null to clear, max 64 characters)
     * @throws IllegalArgumentException if name exceeds max length
     */
    fun setDisplayName(name: String?) {
        require(name == null || name.length <= Identity.MAX_DISPLAY_NAME_LENGTH) {
            "Display name must be at most ${Identity.MAX_DISPLAY_NAME_LENGTH} characters"
        }

        val oldName = displayName
        displayName = name?.trim()?.takeIf { it.isNotEmpty() }

        if (oldName != displayName) {
            logger.info("Display name updated: $displayName")
            notifyProfileUpdate()
        }
    }

    /**
     * Updates the avatar.
     *
     * @param imageData The avatar image data (will be hashed for storage)
     * @return The content hash of the avatar
     */
    fun setAvatar(imageData: ByteArray): String {
        val hash = cryptoProvider.sha256(imageData)
        val hashString = hash.toHexString()

        val oldHash = avatarHash
        avatarHash = hashString

        if (oldHash != avatarHash) {
            logger.info("Avatar updated: $hashString")
            notifyProfileUpdate()
        }

        return hashString
    }

    /**
     * Sets the avatar hash directly (when image data is stored elsewhere).
     *
     * @param hash The content hash of the avatar image (null to clear)
     */
    fun setAvatarHash(hash: String?) {
        val oldHash = avatarHash
        avatarHash = hash

        if (oldHash != avatarHash) {
            logger.info("Avatar hash updated: $hash")
            notifyProfileUpdate()
        }
    }

    /**
     * Clears the avatar.
     */
    fun clearAvatar() {
        if (avatarHash != null) {
            avatarHash = null
            logger.info("Avatar cleared")
            notifyProfileUpdate()
        }
    }

    /**
     * Updates the bio.
     *
     * @param newBio The new bio text (null to clear, max 500 characters)
     * @throws IllegalArgumentException if bio exceeds max length
     */
    fun setBio(newBio: String?) {
        require(newBio == null || newBio.length <= Identity.MAX_BIO_LENGTH) {
            "Bio must be at most ${Identity.MAX_BIO_LENGTH} characters"
        }

        val oldBio = bio
        bio = newBio?.trim()?.takeIf { it.isNotEmpty() }

        if (oldBio != bio) {
            logger.info("Bio updated")
            notifyProfileUpdate()
        }
    }

    /**
     * Updates multiple profile fields at once.
     *
     * @param displayName The new display name (null to keep current, empty to clear)
     * @param avatarHash The new avatar hash (null to keep current, empty to clear)
     * @param bio The new bio (null to keep current, empty to clear)
     */
    fun updateProfile(
        displayName: String? = null,
        avatarHash: String? = null,
        bio: String? = null
    ) {
        var changed = false

        displayName?.let { name ->
            require(name.isEmpty() || name.length <= Identity.MAX_DISPLAY_NAME_LENGTH) {
                "Display name must be at most ${Identity.MAX_DISPLAY_NAME_LENGTH} characters"
            }
            val newName = name.trim().takeIf { it.isNotEmpty() }
            if (this.displayName != newName) {
                this.displayName = newName
                changed = true
            }
        }

        avatarHash?.let { hash ->
            val newHash = hash.takeIf { it.isNotEmpty() }
            if (this.avatarHash != newHash) {
                this.avatarHash = newHash
                changed = true
            }
        }

        bio?.let { newBio ->
            require(newBio.isEmpty() || newBio.length <= Identity.MAX_BIO_LENGTH) {
                "Bio must be at most ${Identity.MAX_BIO_LENGTH} characters"
            }
            val trimmedBio = newBio.trim().takeIf { it.isNotEmpty() }
            if (this.bio != trimmedBio) {
                this.bio = trimmedBio
                changed = true
            }
        }

        if (changed) {
            logger.info("Profile updated")
            notifyProfileUpdate()
        }
    }

    /**
     * Creates an Identity object with current profile data.
     *
     * @return An Identity with profile fields populated
     */
    fun createIdentityWithProfile(): Identity {
        val identity = identityManager.getIdentity()
        return Identity(
            publicKey = identity.publicKey,
            displayName = displayName,
            avatarHash = avatarHash,
            bio = bio,
            createdAt = identity.createdAt
        )
    }

    /**
     * Loads profile data from an existing Identity.
     *
     * @param identity The identity containing profile data
     */
    fun loadFromIdentity(identity: Identity) {
        displayName = identity.displayName
        avatarHash = identity.avatarHash
        bio = identity.bio
        logger.info("Profile loaded from identity: ${identity.shortId}")
    }

    /**
     * Adds a listener for profile updates.
     */
    fun addProfileListener(listener: ProfileUpdateListener) {
        profileListeners.add(listener)
    }

    /**
     * Removes a profile update listener.
     */
    fun removeProfileListener(listener: ProfileUpdateListener) {
        profileListeners.remove(listener)
    }

    private fun notifyProfileUpdate() {
        val profile = getProfile()
        profileListeners.forEach { listener ->
            try {
                listener.onProfileUpdated(profile)
            } catch (e: Exception) {
                logger.error("Error notifying profile listener", e)
            }
        }
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
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
}

/**
 * Represents a user's profile data.
 */
data class Profile(
    val publicKey: ByteArray,
    val displayName: String?,
    val avatarHash: String?,
    val bio: String?
) {
    /**
     * Returns the public key as a Base64-encoded string.
     */
    val publicKeyBase64: String
        get() = java.util.Base64.getEncoder().encodeToString(publicKey)

    /**
     * Returns a short identifier derived from the public key.
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
}
