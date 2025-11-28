package io.grapevine.core.identity

import kotlinx.serialization.Serializable
import java.util.Base64

/**
 * Represents a user identity in the Grapevine network.
 *
 * @property publicKey The Ed25519 public key (32 bytes)
 * @property displayName User-chosen display name (optional, max 64 characters)
 * @property avatarHash Content hash of avatar image (optional)
 * @property bio User biography text (optional, max 500 characters)
 * @property createdAt Timestamp of identity creation (Unix epoch milliseconds)
 */
@Serializable
data class Identity(
    val publicKey: ByteArray,
    val displayName: String? = null,
    val avatarHash: String? = null,
    val bio: String? = null,
    val createdAt: Long = System.currentTimeMillis()
) {
    /**
     * Returns the public key as a Base64-encoded string.
     */
    val publicKeyBase64: String
        get() = Base64.getEncoder().encodeToString(publicKey)

    /**
     * Returns a short identifier derived from the public key.
     * This is the first 8 characters of the Base64-encoded public key.
     */
    val shortId: String
        get() = publicKeyBase64.take(8)

    init {
        require(publicKey.size == 32) { "Public key must be 32 bytes" }
        require(displayName == null || displayName.length <= MAX_DISPLAY_NAME_LENGTH) {
            "Display name must be at most $MAX_DISPLAY_NAME_LENGTH characters"
        }
        require(bio == null || bio.length <= MAX_BIO_LENGTH) {
            "Bio must be at most $MAX_BIO_LENGTH characters"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Identity

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (displayName != other.displayName) return false
        if (avatarHash != other.avatarHash) return false
        if (bio != other.bio) return false
        if (createdAt != other.createdAt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + (avatarHash?.hashCode() ?: 0)
        result = 31 * result + (bio?.hashCode() ?: 0)
        result = 31 * result + createdAt.hashCode()
        return result
    }

    companion object {
        const val MAX_DISPLAY_NAME_LENGTH = 64
        const val MAX_BIO_LENGTH = 500
        const val PUBLIC_KEY_SIZE = 32

        /**
         * Creates an Identity from a Base64-encoded public key string.
         */
        fun fromPublicKeyBase64(
            publicKeyBase64: String,
            displayName: String? = null,
            avatarHash: String? = null,
            bio: String? = null,
            createdAt: Long = System.currentTimeMillis()
        ): Identity {
            val publicKey = Base64.getDecoder().decode(publicKeyBase64)
            return Identity(publicKey, displayName, avatarHash, bio, createdAt)
        }
    }
}
