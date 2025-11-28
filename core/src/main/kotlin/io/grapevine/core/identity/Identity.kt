package io.grapevine.core.identity

import kotlinx.serialization.Serializable
import java.text.Normalizer
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
 * Use [copy] to create a modified copy - it deep-copies the public key by default.
 * Use [deepCopy] for a fully independent copy with no changes.
 *
 * ## Serialization and Canonicalization
 * All text fields are stored and serialized in canonical form:
 * - [displayName] and [bio]: NFC-normalized and trimmed (empty becomes null)
 * - [avatarHash]: lowercase hex
 *
 * The factory methods ([invoke], [fromPublicKeyBase64]) normalize inputs before storage.
 * Deserialization also normalizes to handle non-canonical external data gracefully.
 * This ensures serialize -> deserialize -> serialize produces identical output (idempotent).
 *
 * @property publicKey The Ed25519 public key (32 bytes). Returns a defensive copy.
 * @property displayName User-chosen display name (optional, max 64 Unicode codepoints, NFC normalized)
 * @property avatarHash Content hash of avatar image (optional, 64-char lowercase hex string)
 * @property bio User biography text (optional, max 500 Unicode codepoints)
 * @property createdAt Timestamp of identity creation (Unix epoch milliseconds). NOT included in equals/hashCode.
 */
@Serializable(with = IdentitySerializer::class)
class Identity private constructor(
    private val _publicKey: ByteArray,
    private val _displayName: String?,
    private val _avatarHash: String?,
    private val _bio: String?,
    val createdAt: Long
) {
    /**
     * Returns the public key as a defensive copy.
     * Modifying the returned array will not affect this Identity.
     */
    val publicKey: ByteArray
        get() = _publicKey.copyOf()

    /**
     * The display name (NFC-normalized, trimmed).
     * Always in canonical form - factory and custom serializer ensure normalization.
     */
    val displayName: String? get() = _displayName

    /**
     * The avatar hash (lowercase hex).
     * Always in canonical form - factory and custom serializer ensure normalization.
     */
    val avatarHash: String? get() = _avatarHash

    /**
     * The bio (NFC-normalized, trimmed).
     * Always in canonical form - factory and custom serializer ensure normalization.
     */
    val bio: String? get() = _bio

    /**
     * Returns the public key as a URL-safe Base64-encoded string (no padding).
     * Cached for performance.
     */
    val publicKeyBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_publicKey)
    }

    /**
     * Returns a short identifier derived from the public key.
     * This is the first 8 characters of the URL-safe Base64-encoded public key.
     * Safe for use in URLs, filenames, and logs.
     *
     * Note: This is for human-friendly display only. With 8 base64 chars (~48 bits),
     * collisions are possible in large datasets. Use full [publicKey] for unique identification.
     */
    val shortId: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        publicKeyBase64.take(8)
    }

    init {
        require(_publicKey.size == PUBLIC_KEY_SIZE) {
            "Public key must be $PUBLIC_KEY_SIZE bytes"
        }

        // Validate the backing fields (which should already be normalized by factory/serializer)
        _displayName?.let { name ->
            requireNoControlChars(name, "Display name")
            val codePointCount = name.codePointCount(0, name.length)
            require(codePointCount <= MAX_DISPLAY_NAME_LENGTH) {
                "Display name must be at most $MAX_DISPLAY_NAME_LENGTH characters (got $codePointCount)"
            }
        }
        validateAvatarHash(_avatarHash)
        _bio?.let { bioText ->
            val bioCodePoints = bioText.codePointCount(0, bioText.length)
            require(bioCodePoints <= MAX_BIO_LENGTH) {
                "Bio must be at most $MAX_BIO_LENGTH characters (got $bioCodePoints)"
            }
        }
    }

    /**
     * Creates a fully independent deep copy of this Identity.
     * All fields are copied; the public key byte array is cloned.
     */
    fun deepCopy(): Identity = Identity(
        _publicKey = _publicKey.copyOf(),
        _displayName = displayName,
        _avatarHash = avatarHash,
        _bio = bio,
        createdAt = createdAt
    )

    /**
     * Creates a copy with the specified fields changed.
     * The public key is deep-copied by default to maintain immutability.
     *
     * New values are normalized before storage to maintain canonical form.
     * Default values (from current instance) are already canonical.
     *
     * @param publicKey New public key (defensively copied). Defaults to a copy of current key.
     * @param displayName New display name. Pass current value to keep, null to clear.
     * @param avatarHash New avatar hash. Pass current value to keep, null to clear.
     * @param bio New bio. Pass current value to keep, null to clear.
     * @param createdAt New creation timestamp.
     */
    fun copy(
        publicKey: ByteArray = this._publicKey,
        displayName: String? = this.displayName,
        avatarHash: String? = this.avatarHash,
        bio: String? = this.bio,
        createdAt: Long = this.createdAt
    ): Identity = Identity(
        _publicKey = publicKey.copyOf(),
        _displayName = displayName?.let { normalizeText(it) },
        _avatarHash = avatarHash?.lowercase(),
        _bio = bio?.let { normalizeText(it) },
        createdAt = createdAt
    )

    /**
     * Compares this Identity to another.
     * Note: [createdAt] is NOT included in equality comparison as it is metadata.
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
     * Note: [createdAt] is NOT included in hash code as it is metadata.
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
     * Shows shortId instead of full key bytes. Bio is truncated if long (using codepoints).
     */
    override fun toString(): String {
        val safeBio = bio?.let { b ->
            val escaped = b.replace("\n", "\\n").replace("\r", "\\r")
            val codePointCount = escaped.codePointCount(0, escaped.length)
            if (codePointCount > 40) {
                // Take first 37 codepoints, not chars
                val endIndex = escaped.offsetByCodePoints(0, 37.coerceAtMost(codePointCount))
                "${escaped.substring(0, endIndex)}..."
            } else {
                escaped
            }
        }
        val safeAvatarHash = avatarHash?.let { "${it.take(8)}..." } ?: "none"
        return "Identity(shortId=$shortId, displayName=$displayName, avatarHash=$safeAvatarHash, bio=$safeBio, createdAt=$createdAt)"
    }

    companion object {
        /** Maximum length for display name in Unicode codepoints */
        const val MAX_DISPLAY_NAME_LENGTH = 64
        /** Maximum length for bio in Unicode codepoints */
        const val MAX_BIO_LENGTH = 500
        /** Ed25519 public key size in bytes */
        const val PUBLIC_KEY_SIZE = 32
        /** Regex pattern for valid avatar hash (lowercase hex string, 64 chars for SHA-256) */
        private val AVATAR_HASH_PATTERN = Regex("^[a-f0-9]{64}$")
        /** Control characters to reject in display names (C0 and C1 control codes only) */
        private val CONTROL_CHAR_PATTERN = Regex("[\\p{Cc}]")

        /**
         * Creates a new Identity with the given parameters.
         * The public key is defensively copied. Display name and bio are
         * NFC-normalized and trimmed. Avatar hash is lowercased.
         *
         * Normalization is applied before storage, ensuring both runtime values and
         * serialized data are in canonical form.
         *
         * @param publicKey Ed25519 public key (32 bytes)
         * @param displayName Optional display name (max 64 Unicode codepoints, cannot be blank)
         * @param avatarHash Optional avatar hash (64-character hex string, will be lowercased)
         * @param bio Optional biography (max 500 Unicode codepoints)
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
            _displayName = displayName?.let { normalizeText(it) },
            _avatarHash = avatarHash?.lowercase(),
            _bio = bio?.let { normalizeText(it) },
            createdAt = createdAt
        )

        /**
         * Creates an Identity from a Base64-encoded public key string.
         * Supports both standard and URL-safe Base64 encoding.
         *
         * @throws IllegalArgumentException if the base64 string is invalid or decodes to wrong length
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

        /**
         * Normalizes text: NFC normalization and trim whitespace.
         * Returns null if result is empty.
         */
        private fun normalizeText(text: String): String? {
            val normalized = Normalizer.normalize(text, Normalizer.Form.NFC).trim()
            return normalized.takeIf { it.isNotEmpty() }
        }

        /**
         * Validates that text contains no control characters.
         */
        private fun requireNoControlChars(text: String, fieldName: String) {
            require(!CONTROL_CHAR_PATTERN.containsMatchIn(text)) {
                "$fieldName contains invalid control characters"
            }
        }

        private fun validateAvatarHash(avatarHash: String?) {
            if (avatarHash == null) return
            require(AVATAR_HASH_PATTERN.matches(avatarHash)) {
                "Avatar hash must be a 64-character lowercase hex string (SHA-256)"
            }
        }
    }
}
