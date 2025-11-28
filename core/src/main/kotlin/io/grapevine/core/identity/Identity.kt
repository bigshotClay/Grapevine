package io.grapevine.core.identity

import io.grapevine.core.serialization.ByteArraySerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.Base64

/**
 * Represents a user identity in the Grapevine network.
 *
 * This class is immutable. The [publicKey] getter returns a defensive copy
 * to prevent external mutation of the internal state.
 *
 * ## Equality semantics
 * Two identities are equal if they have the same public key, display name,
 * avatar hash, and bio. The [createdAt] timestamp is metadata and is NOT
 * included in equality comparisons, allowing the same identity with different
 * creation timestamps to be considered equal.
 *
 * ## Copy semantics
 * The Kotlin-generated `copy()` method performs a shallow copy of the byte array.
 * Use [deepCopy] for a fully independent copy with its own byte array.
 *
 * @property publicKey The Ed25519 public key (32 bytes). Returns a defensive copy.
 * @property displayName User-chosen display name (optional, max 64 Unicode codepoints)
 * @property avatarHash Content hash of avatar image (optional, hex string)
 * @property bio User biography text (optional, max 500 characters)
 * @property createdAt Timestamp of identity creation (Unix epoch milliseconds). NOT included in equals/hashCode.
 */
@Serializable
class Identity private constructor(
    @Serializable(with = ByteArraySerializer::class)
    @SerialName("publicKey")
    private val _publicKey: ByteArray,
    val displayName: String?,
    val avatarHash: String?,
    val bio: String?,
    val createdAt: Long
) {
    /**
     * Returns the public key as a defensive copy.
     * Modifying the returned array will not affect this Identity.
     */
    val publicKey: ByteArray
        get() = _publicKey.copyOf()

    /**
     * Returns the public key as a URL-safe Base64-encoded string (no padding).
     * Cached for performance.
     */
    val publicKeyBase64: String by lazy {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_publicKey)
    }

    /**
     * Returns a short identifier derived from the public key.
     * This is the first 8 characters of the URL-safe Base64-encoded public key.
     * Safe for use in URLs, filenames, and logs.
     */
    val shortId: String by lazy {
        publicKeyBase64.take(8)
    }

    init {
        require(_publicKey.size == PUBLIC_KEY_SIZE) {
            "Public key must be $PUBLIC_KEY_SIZE bytes"
        }
        // Note: displayName and bio are already trimmed by the factory
        // Validation here checks the trimmed values
        if (displayName != null) {
            val codePointCount = displayName.codePointCount(0, displayName.length)
            require(codePointCount <= MAX_DISPLAY_NAME_LENGTH) {
                "Display name must be at most $MAX_DISPLAY_NAME_LENGTH characters (got $codePointCount)"
            }
        }
        validateAvatarHash(avatarHash)
        if (bio != null) {
            require(bio.length <= MAX_BIO_LENGTH) {
                "Bio must be at most $MAX_BIO_LENGTH characters"
            }
        }
    }

    /**
     * Creates a fully independent deep copy of this Identity.
     * Unlike [copy], this creates a new byte array for the public key.
     */
    fun deepCopy(): Identity = Identity(
        _publicKey = _publicKey.copyOf(),
        displayName = displayName,
        avatarHash = avatarHash,
        bio = bio,
        createdAt = createdAt
    )

    /**
     * Creates a copy with the specified fields changed.
     * The public key is deep-copied to maintain immutability.
     */
    fun copy(
        publicKey: ByteArray = this._publicKey,
        displayName: String? = this.displayName,
        avatarHash: String? = this.avatarHash,
        bio: String? = this.bio,
        createdAt: Long = this.createdAt
    ): Identity = Identity(
        publicKey = publicKey.copyOf(),
        displayName = displayName,
        avatarHash = avatarHash,
        bio = bio,
        createdAt = createdAt
    )

    /**
     * Compares this Identity to another.
     * Note: [createdAt] is NOT included in equality comparison.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Identity

        if (!_publicKey.contentEquals(other._publicKey)) return false
        if (displayName != other.displayName) return false
        if (avatarHash != other.avatarHash) return false
        if (bio != other.bio) return false
        // createdAt intentionally excluded - it's metadata

        return true
    }

    /**
     * Returns hash code based on public key, display name, avatar hash, and bio.
     * Note: [createdAt] is NOT included in hash code.
     */
    override fun hashCode(): Int {
        var result = _publicKey.contentHashCode()
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + (avatarHash?.hashCode() ?: 0)
        result = 31 * result + (bio?.hashCode() ?: 0)
        // createdAt intentionally excluded - it's metadata
        return result
    }

    /**
     * Returns a safe string representation that does not leak the full public key.
     * Shows shortId instead of full key bytes.
     */
    override fun toString(): String {
        val truncatedBio = bio?.let {
            if (it.length > 40) "${it.take(37)}..." else it
        }
        return "Identity(shortId=$shortId, displayName=$displayName, avatarHash=$avatarHash, bio=$truncatedBio, createdAt=$createdAt)"
    }

    companion object {
        /** Maximum length for display name in Unicode codepoints */
        const val MAX_DISPLAY_NAME_LENGTH = 64
        /** Maximum length for bio in characters */
        const val MAX_BIO_LENGTH = 500
        /** Ed25519 public key size in bytes */
        const val PUBLIC_KEY_SIZE = 32
        /** Regex pattern for valid avatar hash (hex string, 64 chars for SHA-256) */
        private val AVATAR_HASH_PATTERN = Regex("^[a-fA-F0-9]{64}$")

        /**
         * Creates a new Identity with the given parameters.
         * The public key is defensively copied.
         *
         * @param publicKey Ed25519 public key (32 bytes)
         * @param displayName Optional display name (max 64 Unicode codepoints, cannot be blank)
         * @param avatarHash Optional avatar hash (64-character hex string)
         * @param bio Optional biography (max 500 characters)
         * @param createdAt Creation timestamp (defaults to current time)
         */
        operator fun invoke(
            publicKey: ByteArray,
            displayName: String? = null,
            avatarHash: String? = null,
            bio: String? = null,
            createdAt: Long = System.currentTimeMillis()
        ): Identity = Identity(
            _publicKey = publicKey.copyOf(),
            displayName = displayName?.trim()?.takeIf { it.isNotEmpty() },
            avatarHash = avatarHash,
            bio = bio?.trim()?.takeIf { it.isNotEmpty() },
            createdAt = createdAt
        )

        /**
         * Creates an Identity from a Base64-encoded public key string.
         * Supports both standard and URL-safe Base64 encoding.
         */
        fun fromPublicKeyBase64(
            publicKeyBase64: String,
            displayName: String? = null,
            avatarHash: String? = null,
            bio: String? = null,
            createdAt: Long = System.currentTimeMillis()
        ): Identity {
            // Try URL-safe decoder first, fall back to standard
            val publicKey = try {
                Base64.getUrlDecoder().decode(publicKeyBase64)
            } catch (e: IllegalArgumentException) {
                Base64.getDecoder().decode(publicKeyBase64)
            }
            return invoke(publicKey, displayName, avatarHash, bio, createdAt)
        }

        private fun validateAvatarHash(avatarHash: String?) {
            if (avatarHash == null) return
            require(AVATAR_HASH_PATTERN.matches(avatarHash)) {
                "Avatar hash must be a 64-character hex string (SHA-256)"
            }
        }
    }
}
