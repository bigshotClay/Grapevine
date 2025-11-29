package io.grapevine.core.invite

import java.util.Base64

/**
 * Represents an invite token that can be shared to allow new users to join the network.
 *
 * An invite token is a cryptographically secure, shareable credential that contains:
 * - A unique token code for identification
 * - The inviter's public key to establish the trust chain
 * - Optional expiration and usage limits
 *
 * ## Token Format
 * The token code is a URL-safe Base64-encoded string derived from:
 * - Inviter's public key
 * - Creation timestamp
 * - Random nonce
 *
 * ## Sharing
 * Tokens can be shared as:
 * - Plain text (the token code itself)
 * - Full invite URL
 * - QR code (encoded from text or URL)
 *
 * ## Security
 * - The token is signed by the inviter to prevent forgery
 * - Expiration and usage limits provide additional control
 * - Each token is unique and can be tracked/revoked
 *
 * @property tokenCode The unique, URL-safe token code for sharing
 * @property inviterPublicKey The Ed25519 public key of the inviter (32 bytes)
 * @property signature The inviter's signature over the token data
 * @property createdAt Unix timestamp (milliseconds) when the token was created
 * @property expiresAt Unix timestamp (milliseconds) when the token expires, or null for no expiration
 * @property maxUses Maximum number of times this token can be used, or null for unlimited
 * @property currentUses Number of times this token has been used
 * @property message Optional message from the inviter to the invitee
 */
class InviteToken private constructor(
    val tokenCode: String,
    private val _inviterPublicKey: ByteArray,
    private val _signature: ByteArray,
    val createdAt: Long,
    val expiresAt: Long?,
    val maxUses: Int?,
    val currentUses: Int,
    val message: String?
) {
    /**
     * Returns the inviter's public key as a defensive copy.
     */
    val inviterPublicKey: ByteArray
        get() = _inviterPublicKey.copyOf()

    /**
     * Returns the signature as a defensive copy.
     */
    val signature: ByteArray
        get() = _signature.copyOf()

    /**
     * Returns the inviter's public key as a URL-safe Base64-encoded string.
     */
    val inviterPublicKeyBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviterPublicKey)
    }

    /**
     * Checks if this token has expired.
     *
     * @param currentTime The current time in milliseconds (defaults to system time)
     * @return true if the token has expired, false otherwise
     */
    fun isExpired(currentTime: Long = System.currentTimeMillis()): Boolean {
        return expiresAt != null && currentTime >= expiresAt
    }

    /**
     * Checks if this token has reached its maximum usage count.
     *
     * @return true if the token cannot be used anymore, false otherwise
     */
    fun isExhausted(): Boolean {
        return maxUses != null && currentUses >= maxUses
    }

    /**
     * Checks if this token is currently valid for use.
     *
     * A token is valid if it is neither expired nor exhausted.
     *
     * @param currentTime The current time in milliseconds (defaults to system time)
     * @return true if the token can be used, false otherwise
     */
    fun isValid(currentTime: Long = System.currentTimeMillis()): Boolean {
        return !isExpired(currentTime) && !isExhausted()
    }

    /**
     * Returns the number of remaining uses, or null if unlimited.
     */
    fun remainingUses(): Int? {
        return maxUses?.let { max -> (max - currentUses).coerceAtLeast(0) }
    }

    /**
     * Creates a copy of this token with an incremented use count.
     */
    fun withIncrementedUseCount(): InviteToken {
        return copy(currentUses = currentUses + 1)
    }

    /**
     * Creates a copy with the specified fields changed.
     */
    fun copy(
        tokenCode: String = this.tokenCode,
        inviterPublicKey: ByteArray = this._inviterPublicKey,
        signature: ByteArray = this._signature,
        createdAt: Long = this.createdAt,
        expiresAt: Long? = this.expiresAt,
        maxUses: Int? = this.maxUses,
        currentUses: Int = this.currentUses,
        message: String? = this.message
    ): InviteToken = InviteToken(
        tokenCode = tokenCode,
        _inviterPublicKey = inviterPublicKey.copyOf(),
        _signature = signature.copyOf(),
        createdAt = createdAt,
        expiresAt = expiresAt,
        maxUses = maxUses,
        currentUses = currentUses,
        message = message
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InviteToken

        if (tokenCode != other.tokenCode) return false
        if (!_inviterPublicKey.contentEquals(other._inviterPublicKey)) return false
        if (!_signature.contentEquals(other._signature)) return false
        if (createdAt != other.createdAt) return false
        if (expiresAt != other.expiresAt) return false
        if (maxUses != other.maxUses) return false
        if (currentUses != other.currentUses) return false
        if (message != other.message) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tokenCode.hashCode()
        result = 31 * result + _inviterPublicKey.contentHashCode()
        result = 31 * result + _signature.contentHashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (expiresAt?.hashCode() ?: 0)
        result = 31 * result + (maxUses ?: 0)
        result = 31 * result + currentUses
        result = 31 * result + (message?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        val keyPrefix = _inviterPublicKey.take(4).joinToString("") { "%02x".format(it) }
        val expiresStr = expiresAt?.let { "expiresAt=$it" } ?: "noExpiration"
        val usesStr = maxUses?.let { "uses=$currentUses/$it" } ?: "unlimitedUses"
        return "InviteToken(code=${tokenCode.take(12)}..., inviter=$keyPrefix..., $expiresStr, $usesStr)"
    }

    companion object {
        /** Length of the token code in bytes before Base64 encoding */
        const val TOKEN_CODE_BYTES = 32

        /** Ed25519 public key size in bytes */
        const val PUBLIC_KEY_SIZE = 32

        /** Ed25519 signature size in bytes */
        const val SIGNATURE_SIZE = 64

        /** Maximum message length in Unicode codepoints */
        const val MAX_MESSAGE_LENGTH = 256

        /**
         * Creates a new InviteToken with the given parameters.
         *
         * The inviter public key and signature are defensively copied.
         *
         * @param tokenCode The unique token code
         * @param inviterPublicKey Ed25519 public key (32 bytes)
         * @param signature Ed25519 signature (64 bytes)
         * @param createdAt Creation timestamp (defaults to current time)
         * @param expiresAt Expiration timestamp, or null for no expiration
         * @param maxUses Maximum usage count, or null for unlimited
         * @param currentUses Current usage count (defaults to 0)
         * @param message Optional message from inviter
         * @throws IllegalArgumentException if parameters are invalid
         */
        operator fun invoke(
            tokenCode: String,
            inviterPublicKey: ByteArray,
            signature: ByteArray,
            createdAt: Long = System.currentTimeMillis(),
            expiresAt: Long? = null,
            maxUses: Int? = null,
            currentUses: Int = 0,
            message: String? = null
        ): InviteToken {
            require(tokenCode.isNotBlank()) { "Token code cannot be blank" }
            require(inviterPublicKey.size == PUBLIC_KEY_SIZE) {
                "Inviter public key must be $PUBLIC_KEY_SIZE bytes, got ${inviterPublicKey.size}"
            }
            require(signature.size == SIGNATURE_SIZE) {
                "Signature must be $SIGNATURE_SIZE bytes, got ${signature.size}"
            }
            require(createdAt > 0) { "Created timestamp must be positive" }
            expiresAt?.let { exp ->
                require(exp > createdAt) { "Expiration must be after creation time" }
            }
            maxUses?.let { max ->
                require(max > 0) { "Max uses must be positive" }
            }
            require(currentUses >= 0) { "Current uses cannot be negative" }
            message?.let { msg ->
                val codePointCount = msg.codePointCount(0, msg.length)
                require(codePointCount <= MAX_MESSAGE_LENGTH) {
                    "Message must be at most $MAX_MESSAGE_LENGTH characters, got $codePointCount"
                }
            }

            return InviteToken(
                tokenCode = tokenCode,
                _inviterPublicKey = inviterPublicKey.copyOf(),
                _signature = signature.copyOf(),
                createdAt = createdAt,
                expiresAt = expiresAt,
                maxUses = maxUses,
                currentUses = currentUses,
                message = message?.trim()?.takeIf { it.isNotEmpty() }
            )
        }

        /**
         * Creates an InviteToken from Base64-encoded keys.
         *
         * @param tokenCode The unique token code
         * @param inviterPublicKeyBase64 Base64-encoded public key (URL-safe or standard)
         * @param signatureBase64 Base64-encoded signature (URL-safe or standard)
         * @param createdAt Creation timestamp
         * @param expiresAt Expiration timestamp, or null for no expiration
         * @param maxUses Maximum usage count, or null for unlimited
         * @param currentUses Current usage count
         * @param message Optional message from inviter
         */
        fun fromBase64(
            tokenCode: String,
            inviterPublicKeyBase64: String,
            signatureBase64: String,
            createdAt: Long = System.currentTimeMillis(),
            expiresAt: Long? = null,
            maxUses: Int? = null,
            currentUses: Int = 0,
            message: String? = null
        ): InviteToken {
            val inviterPublicKey = decodeBase64(inviterPublicKeyBase64)
            val signature = decodeBase64(signatureBase64)
            return invoke(
                tokenCode = tokenCode,
                inviterPublicKey = inviterPublicKey,
                signature = signature,
                createdAt = createdAt,
                expiresAt = expiresAt,
                maxUses = maxUses,
                currentUses = currentUses,
                message = message
            )
        }

        /**
         * Decodes a Base64 string (URL-safe or standard) to bytes.
         */
        private fun decodeBase64(encoded: String): ByteArray {
            return try {
                Base64.getUrlDecoder().decode(encoded)
            } catch (e: IllegalArgumentException) {
                Base64.getDecoder().decode(encoded)
            }
        }
    }
}

/**
 * Result of validating an invite token.
 */
sealed class TokenValidationResult {
    /**
     * Token is valid and can be used.
     */
    data class Valid(val token: InviteToken) : TokenValidationResult()

    /**
     * Token has expired.
     */
    data class Expired(val token: InviteToken, val expiredAt: Long) : TokenValidationResult()

    /**
     * Token has reached its maximum usage count.
     */
    data class Exhausted(val token: InviteToken, val maxUses: Int) : TokenValidationResult()

    /**
     * Token was not found.
     */
    data object NotFound : TokenValidationResult()

    /**
     * Token signature is invalid.
     */
    data class InvalidSignature(val reason: String) : TokenValidationResult()

    /**
     * Token has been revoked.
     */
    data class Revoked(val token: InviteToken) : TokenValidationResult()
}

/**
 * Result of generating an invite token.
 */
sealed class TokenGenerationResult {
    /**
     * Token was generated successfully.
     */
    data class Success(val token: InviteToken) : TokenGenerationResult()

    /**
     * User is not authorized to generate invites.
     */
    data class Unauthorized(val reason: String) : TokenGenerationResult()

    /**
     * An error occurred during token generation.
     */
    data class Error(val message: String) : TokenGenerationResult()
}
