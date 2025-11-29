package io.grapevine.core.invite

import java.security.MessageDigest
import java.util.Base64

/**
 * Represents an accepted invite with counter-signature from the invitee.
 *
 * When a new user accepts an invite:
 * 1. They create a new identity (or use existing one)
 * 2. They validate the invite token's signature from the inviter
 * 3. They counter-sign the invite block with their own private key
 *
 * This creates a cryptographic link between the inviter and invitee,
 * forming the foundation of the trust chain.
 *
 * ## Cryptographic Details
 * - **Algorithm**: Ed25519 (RFC 8032)
 * - **Public Key**: 32 bytes (256 bits)
 * - **Signature**: 64 bytes (512 bits)
 * - **Encoding**: URL-safe Base64 without padding for serialization
 *
 * ## Invite Block Schema
 * The acceptance creates a complete invite block containing:
 * - `inviterPublicKey`: Ed25519 public key of the inviting user
 * - `inviteePublicKey`: Ed25519 public key of the invited user
 * - `inviterSignature`: Inviter's signature over the original token data
 * - `inviteeSignature`: Invitee's counter-signature (proof of acceptance)
 * - `tokenCode`: The unique invite token code
 * - `acceptedAt`: Unix epoch milliseconds when the invite was accepted
 *
 * ## Immutability and Thread Safety
 * This class is immutable and thread-safe. All [ByteArray] fields are stored as
 * private copies and returned as defensive copies via getters. The [copy] method
 * performs deep copies of all byte arrays.
 *
 * ## Security Notes
 * - **Do not use [equals] for signature verification** - use [constantTimeEquals] or
 *   the cryptographic library's verify method to prevent timing attacks.
 * - **Do not log instances directly** - [toString] is redacted but still reveals
 *   partial key fingerprints. Use explicit formatting for audit logs.
 * - Signature verification should be performed using Libsodium's verify functions,
 *   not by comparing signature bytes directly.
 *
 * @property tokenCode The unique invite token code that was redeemed
 * @property inviterPublicKey The Ed25519 public key of the inviter (32 bytes)
 * @property inviteePublicKey The Ed25519 public key of the invitee (32 bytes)
 * @property inviterSignature The inviter's signature on the token (64 bytes)
 * @property inviteeSignature The invitee's counter-signature (64 bytes)
 * @property acceptedAt Unix timestamp in milliseconds when the invite was accepted (must be > 0)
 * @property message Optional message from the inviter
 */
class InviteAcceptance private constructor(
    val tokenCode: String,
    private val _inviterPublicKey: ByteArray,
    private val _inviteePublicKey: ByteArray,
    private val _inviterSignature: ByteArray,
    private val _inviteeSignature: ByteArray,
    val acceptedAt: Long,
    val message: String?
) {
    /**
     * Returns the inviter's public key as a defensive copy.
     */
    val inviterPublicKey: ByteArray
        get() = _inviterPublicKey.copyOf()

    /**
     * Returns the invitee's public key as a defensive copy.
     */
    val inviteePublicKey: ByteArray
        get() = _inviteePublicKey.copyOf()

    /**
     * Returns the inviter's signature as a defensive copy.
     */
    val inviterSignature: ByteArray
        get() = _inviterSignature.copyOf()

    /**
     * Returns the invitee's counter-signature as a defensive copy.
     */
    val inviteeSignature: ByteArray
        get() = _inviteeSignature.copyOf()

    /**
     * Returns the inviter's public key as a URL-safe Base64-encoded string.
     */
    val inviterPublicKeyBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviterPublicKey)
    }

    /**
     * Returns the invitee's public key as a URL-safe Base64-encoded string.
     */
    val inviteePublicKeyBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviteePublicKey)
    }

    /**
     * Creates a copy with the specified fields changed.
     *
     * **Deep Copy Semantics**: All [ByteArray] parameters are deep-copied using [ByteArray.copyOf].
     * Default values reference the internal backing arrays, which are then copied in the constructor.
     * This ensures the returned instance is fully independent of this instance and any input arrays.
     *
     * @param tokenCode The token code (default: this instance's value)
     * @param inviterPublicKey The inviter's public key (default: this instance's value, will be copied)
     * @param inviteePublicKey The invitee's public key (default: this instance's value, will be copied)
     * @param inviterSignature The inviter's signature (default: this instance's value, will be copied)
     * @param inviteeSignature The invitee's signature (default: this instance's value, will be copied)
     * @param acceptedAt The acceptance timestamp (default: this instance's value)
     * @param message The optional message (default: this instance's value)
     * @return A new [InviteAcceptance] instance with the specified changes
     */
    fun copy(
        tokenCode: String = this.tokenCode,
        inviterPublicKey: ByteArray = this._inviterPublicKey,
        inviteePublicKey: ByteArray = this._inviteePublicKey,
        inviterSignature: ByteArray = this._inviterSignature,
        inviteeSignature: ByteArray = this._inviteeSignature,
        acceptedAt: Long = this.acceptedAt,
        message: String? = this.message
    ): InviteAcceptance = InviteAcceptance(
        tokenCode = tokenCode,
        _inviterPublicKey = inviterPublicKey.copyOf(),
        _inviteePublicKey = inviteePublicKey.copyOf(),
        _inviterSignature = inviterSignature.copyOf(),
        _inviteeSignature = inviteeSignature.copyOf(),
        acceptedAt = acceptedAt,
        message = message
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InviteAcceptance

        if (tokenCode != other.tokenCode) return false
        if (!_inviterPublicKey.contentEquals(other._inviterPublicKey)) return false
        if (!_inviteePublicKey.contentEquals(other._inviteePublicKey)) return false
        if (!_inviterSignature.contentEquals(other._inviterSignature)) return false
        if (!_inviteeSignature.contentEquals(other._inviteeSignature)) return false
        if (acceptedAt != other.acceptedAt) return false
        if (message != other.message) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tokenCode.hashCode()
        result = 31 * result + _inviterPublicKey.contentHashCode()
        result = 31 * result + _inviteePublicKey.contentHashCode()
        result = 31 * result + _inviterSignature.contentHashCode()
        result = 31 * result + _inviteeSignature.contentHashCode()
        result = 31 * result + acceptedAt.hashCode()
        result = 31 * result + (message?.hashCode() ?: 0)
        return result
    }

    /**
     * Returns a redacted string representation suitable for logging.
     *
     * **Security**: This method intentionally redacts sensitive data. Public keys are
     * shown as short fingerprints (first 4 bytes hex). Do not rely on this output
     * for debugging cryptographic issues - use explicit hex encoding of specific fields.
     */
    override fun toString(): String {
        return "InviteAcceptance(token=<redacted>, inviter=<redacted>, invitee=<redacted>, acceptedAt=$acceptedAt)"
    }

    /**
     * Returns a debug string with partial key fingerprints.
     *
     * **Warning**: This reveals partial identity information. Use only for debugging,
     * never in production logs.
     */
    fun toDebugString(): String {
        val inviterPrefix = _inviterPublicKey.take(4).joinToString("") { "%02x".format(it) }
        val inviteePrefix = _inviteePublicKey.take(4).joinToString("") { "%02x".format(it) }
        return "InviteAcceptance(token=${tokenCode.take(8)}..., inviter=$inviterPrefix..., invitee=$inviteePrefix..., acceptedAt=$acceptedAt)"
    }

    // ==================== Serialization Helpers ====================

    /**
     * Returns the inviter's signature as a URL-safe Base64-encoded string.
     */
    val inviterSignatureBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviterSignature)
    }

    /**
     * Returns the invitee's signature as a URL-safe Base64-encoded string.
     */
    val inviteeSignatureBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviteeSignature)
    }

    /**
     * Converts this acceptance to a map suitable for database storage.
     *
     * All byte arrays are encoded as URL-safe Base64 without padding.
     * Use [fromMap] to reconstruct the acceptance.
     *
     * @return A map with string keys and serializable values
     */
    fun toMap(): Map<String, Any?> = mapOf(
        "tokenCode" to tokenCode,
        "inviterPublicKey" to inviterPublicKeyBase64,
        "inviteePublicKey" to inviteePublicKeyBase64,
        "inviterSignature" to inviterSignatureBase64,
        "inviteeSignature" to inviteeSignatureBase64,
        "acceptedAt" to acceptedAt,
        "message" to message
    )

    companion object {
        /** Ed25519 public key size in bytes */
        const val PUBLIC_KEY_SIZE = 32

        /** Ed25519 signature size in bytes */
        const val SIGNATURE_SIZE = 64

        /**
         * Creates a new InviteAcceptance with the given parameters.
         *
         * All byte arrays are defensively copied.
         *
         * @param tokenCode The unique token code
         * @param inviterPublicKey Ed25519 public key of the inviter (32 bytes)
         * @param inviteePublicKey Ed25519 public key of the invitee (32 bytes)
         * @param inviterSignature Ed25519 signature from the inviter (64 bytes)
         * @param inviteeSignature Ed25519 counter-signature from the invitee (64 bytes)
         * @param acceptedAt Acceptance timestamp (defaults to current time)
         * @param message Optional message from the inviter
         * @throws IllegalArgumentException if parameters are invalid
         */
        operator fun invoke(
            tokenCode: String,
            inviterPublicKey: ByteArray,
            inviteePublicKey: ByteArray,
            inviterSignature: ByteArray,
            inviteeSignature: ByteArray,
            acceptedAt: Long = System.currentTimeMillis(),
            message: String? = null
        ): InviteAcceptance {
            require(tokenCode.isNotBlank()) { "Token code cannot be blank" }
            require(inviterPublicKey.size == PUBLIC_KEY_SIZE) {
                "Inviter public key must be $PUBLIC_KEY_SIZE bytes, got ${inviterPublicKey.size}"
            }
            require(inviteePublicKey.size == PUBLIC_KEY_SIZE) {
                "Invitee public key must be $PUBLIC_KEY_SIZE bytes, got ${inviteePublicKey.size}"
            }
            require(inviterSignature.size == SIGNATURE_SIZE) {
                "Inviter signature must be $SIGNATURE_SIZE bytes, got ${inviterSignature.size}"
            }
            require(inviteeSignature.size == SIGNATURE_SIZE) {
                "Invitee signature must be $SIGNATURE_SIZE bytes, got ${inviteeSignature.size}"
            }
            require(acceptedAt > 0) { "Accepted timestamp must be positive" }
            require(!inviterPublicKey.contentEquals(inviteePublicKey)) {
                "Inviter and invitee cannot be the same user"
            }

            return InviteAcceptance(
                tokenCode = tokenCode,
                _inviterPublicKey = inviterPublicKey.copyOf(),
                _inviteePublicKey = inviteePublicKey.copyOf(),
                _inviterSignature = inviterSignature.copyOf(),
                _inviteeSignature = inviteeSignature.copyOf(),
                acceptedAt = acceptedAt,
                message = message?.trim()?.takeIf { it.isNotEmpty() }
            )
        }

        /**
         * Creates an InviteAcceptance from Base64-encoded keys and signatures.
         *
         * @param tokenCode The unique token code
         * @param inviterPublicKeyBase64 Base64-encoded public key of inviter
         * @param inviteePublicKeyBase64 Base64-encoded public key of invitee
         * @param inviterSignatureBase64 Base64-encoded signature from inviter
         * @param inviteeSignatureBase64 Base64-encoded counter-signature from invitee
         * @param acceptedAt Acceptance timestamp
         * @param message Optional message from inviter
         */
        fun fromBase64(
            tokenCode: String,
            inviterPublicKeyBase64: String,
            inviteePublicKeyBase64: String,
            inviterSignatureBase64: String,
            inviteeSignatureBase64: String,
            acceptedAt: Long = System.currentTimeMillis(),
            message: String? = null
        ): InviteAcceptance {
            val inviterPublicKey = decodeBase64(inviterPublicKeyBase64, "inviterPublicKey")
            val inviteePublicKey = decodeBase64(inviteePublicKeyBase64, "inviteePublicKey")
            val inviterSignature = decodeBase64(inviterSignatureBase64, "inviterSignature")
            val inviteeSignature = decodeBase64(inviteeSignatureBase64, "inviteeSignature")
            return invoke(
                tokenCode = tokenCode,
                inviterPublicKey = inviterPublicKey,
                inviteePublicKey = inviteePublicKey,
                inviterSignature = inviterSignature,
                inviteeSignature = inviteeSignature,
                acceptedAt = acceptedAt,
                message = message
            )
        }

        /**
         * Creates an InviteAcceptance from a map (e.g., from database storage).
         *
         * Expected keys:
         * - `tokenCode`: String
         * - `inviterPublicKey`: String (Base64)
         * - `inviteePublicKey`: String (Base64)
         * - `inviterSignature`: String (Base64)
         * - `inviteeSignature`: String (Base64)
         * - `acceptedAt`: Long
         * - `message`: String? (optional)
         *
         * @param map The map containing acceptance data
         * @return The reconstructed [InviteAcceptance]
         * @throws IllegalArgumentException if required fields are missing or invalid
         */
        fun fromMap(map: Map<String, Any?>): InviteAcceptance {
            val tokenCode = map["tokenCode"] as? String
                ?: throw IllegalArgumentException("Missing required field: tokenCode")
            val inviterPublicKeyBase64 = map["inviterPublicKey"] as? String
                ?: throw IllegalArgumentException("Missing required field: inviterPublicKey")
            val inviteePublicKeyBase64 = map["inviteePublicKey"] as? String
                ?: throw IllegalArgumentException("Missing required field: inviteePublicKey")
            val inviterSignatureBase64 = map["inviterSignature"] as? String
                ?: throw IllegalArgumentException("Missing required field: inviterSignature")
            val inviteeSignatureBase64 = map["inviteeSignature"] as? String
                ?: throw IllegalArgumentException("Missing required field: inviteeSignature")
            val acceptedAt = (map["acceptedAt"] as? Number)?.toLong()
                ?: throw IllegalArgumentException("Missing required field: acceptedAt")
            val message = map["message"] as? String

            return fromBase64(
                tokenCode = tokenCode,
                inviterPublicKeyBase64 = inviterPublicKeyBase64,
                inviteePublicKeyBase64 = inviteePublicKeyBase64,
                inviterSignatureBase64 = inviterSignatureBase64,
                inviteeSignatureBase64 = inviteeSignatureBase64,
                acceptedAt = acceptedAt,
                message = message
            )
        }

        /**
         * Decodes a Base64 string (URL-safe or standard) to bytes.
         *
         * Handles both URL-safe (RFC 4648 §5) and standard Base64 encodings,
         * with or without padding.
         *
         * @param encoded The Base64-encoded string
         * @param fieldName Name of the field for error messages
         * @return The decoded bytes
         * @throws IllegalArgumentException if the string is not valid Base64
         */
        private fun decodeBase64(encoded: String, fieldName: String = "field"): ByteArray {
            val normalized = normalizeBase64(encoded)
            return try {
                Base64.getDecoder().decode(normalized)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException(
                    "Invalid Base64 encoding for $fieldName: ${e.message}",
                    e
                )
            }
        }

        /**
         * Normalizes a Base64 string from URL-safe to standard encoding with padding.
         */
        private fun normalizeBase64(encoded: String): String {
            // Convert URL-safe characters to standard Base64
            var normalized = encoded
                .replace('-', '+')
                .replace('_', '/')

            // Add padding if necessary
            val paddingNeeded = (4 - normalized.length % 4) % 4
            normalized += "=".repeat(paddingNeeded)

            return normalized
        }

        /**
         * Performs constant-time comparison of two byte arrays.
         *
         * **Security**: Use this method (or the cryptographic library's verify)
         * when comparing signatures or other security-sensitive data to prevent
         * timing attacks. Do not use [contentEquals] for security comparisons.
         *
         * @param a First byte array
         * @param b Second byte array
         * @return true if arrays are equal, false otherwise
         */
        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            return MessageDigest.isEqual(a, b)
        }
    }
}

/**
 * Result of accepting an invite.
 */
sealed class InviteAcceptanceResult {
    /**
     * Invite was successfully accepted.
     *
     * @property acceptance The completed invite acceptance with counter-signature
     */
    data class Success(val acceptance: InviteAcceptance) : InviteAcceptanceResult()

    /**
     * The invite token was not found.
     */
    data object TokenNotFound : InviteAcceptanceResult()

    /**
     * The invite token has expired.
     *
     * @property expiredAt The timestamp when the token expired
     */
    data class TokenExpired(val expiredAt: Long) : InviteAcceptanceResult()

    /**
     * The invite token has reached its maximum usage count.
     *
     * @property maxUses The maximum allowed uses
     */
    data class TokenExhausted(val maxUses: Int) : InviteAcceptanceResult()

    /**
     * The inviter's signature on the token is invalid.
     *
     * @property reason Description of why signature verification failed
     */
    data class InvalidSignature(val reason: String) : InviteAcceptanceResult()

    /**
     * The user is already a member of the network.
     *
     * @property existingAcceptance The existing acceptance record
     */
    data class AlreadyMember(val existingAcceptance: InviteAcceptance) : InviteAcceptanceResult()

    /**
     * The user cannot invite themselves.
     */
    data object SelfInvite : InviteAcceptanceResult()

    /**
     * An error occurred during acceptance.
     *
     * @property message Description of the error
     */
    data class Error(val message: String) : InviteAcceptanceResult()
}
