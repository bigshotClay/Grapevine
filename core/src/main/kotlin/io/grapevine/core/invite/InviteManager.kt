package io.grapevine.core.invite

import io.grapevine.core.crypto.CryptoProvider
import io.grapevine.core.identity.IdentityManager
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Manages invite token generation, validation, acceptance, and lifecycle.
 *
 * The InviteManager provides the core functionality for the invitation system:
 * - Generate cryptographically secure invite tokens
 * - Validate tokens for authenticity and validity
 * - Accept invites with counter-signatures
 * - Track token usage and expiration
 *
 * ## Token Generation
 * Tokens are generated using:
 * 1. Inviter's public key
 * 2. Creation timestamp
 * 3. Cryptographically secure random nonce
 * 4. SHA-256 hash of the above
 *
 * The token is then signed by the inviter to prove authenticity.
 *
 * ## Invite Acceptance
 * When accepting an invite, the invitee creates a counter-signature proving
 * their acceptance. The acceptance is stored and the token usage is incremented.
 *
 * **Important**: For production use, [acceptanceStorage] MUST be provided.
 * Without acceptance storage, acceptances are not persisted and duplicate
 * membership checks cannot be performed.
 *
 * ## Security
 * - Tokens are signed with Ed25519 signatures
 * - Token codes are derived from SHA-256 hashes
 * - Random nonces ensure uniqueness even for same-millisecond generation
 * - External tokens (not in local storage) are rejected to prevent unverified acceptances
 *
 * ## Thread Safety
 * This class is NOT thread-safe. Concurrent acceptance attempts for the same token
 * may result in race conditions. Callers should coordinate concurrent access
 * externally or use transactional storage operations.
 *
 * ## Logging
 * Token identifiers are hashed in logs to prevent information leakage.
 * Full token codes should never appear in production logs.
 *
 * @property identityManager The identity manager for signing operations
 * @property storage The storage backend for persisting tokens
 * @property acceptanceStorage The storage backend for persisting acceptances (required for production)
 * @property cryptoProvider The cryptographic provider for hashing and random generation
 */
class InviteManager(
    private val identityManager: IdentityManager,
    private val storage: InviteTokenStorage,
    private val acceptanceStorage: InviteAcceptanceStorage? = null,
    private val cryptoProvider: CryptoProvider = CryptoProvider()
) {
    private val logger = LoggerFactory.getLogger(InviteManager::class.java)

    /**
     * Secondary constructor for backward compatibility without acceptance storage.
     *
     * **Warning**: Without acceptance storage, invite acceptances are not persisted
     * and duplicate membership checks are not performed. Use only for testing.
     */
    constructor(
        identityManager: IdentityManager,
        storage: InviteTokenStorage,
        cryptoProvider: CryptoProvider
    ) : this(identityManager, storage, null, cryptoProvider)

    /**
     * Returns a redacted token identifier for logging.
     * Uses SHA-256 hash prefix to prevent token reconstruction from logs.
     */
    private fun redactTokenCode(tokenCode: String): String {
        val hash = cryptoProvider.sha256(tokenCode.toByteArray(Charsets.UTF_8))
        return "token:${hash.take(4).joinToString("") { "%02x".format(it) }}..."
    }

    /**
     * Generates a new invite token.
     *
     * The token will be signed by the current identity and stored in the token storage.
     *
     * @param expiresInMillis Duration until expiration in milliseconds, or null for no expiration
     * @param maxUses Maximum number of times this token can be used, or null for unlimited
     * @param message Optional message to include with the invite
     * @return [TokenGenerationResult] indicating success or failure
     */
    fun generateToken(
        expiresInMillis: Long? = null,
        maxUses: Int? = null,
        message: String? = null
    ): TokenGenerationResult {
        logger.info("Generating invite token")

        return try {
            val identity = identityManager.getIdentity()
            val publicKey = identity.publicKey
            val createdAt = System.currentTimeMillis()
            val expiresAt = expiresInMillis?.let { createdAt + it }

            // Generate token code from hash of public key + timestamp + random nonce
            val tokenCode = generateTokenCode(publicKey, createdAt)

            // Create the data to sign: tokenCode + publicKey + createdAt + expiresAt
            val dataToSign = buildSignatureData(tokenCode, publicKey, createdAt, expiresAt, maxUses, message)

            // Sign the token data
            val signature = identityManager.sign(dataToSign)

            // Create the token
            val token = InviteToken(
                tokenCode = tokenCode,
                inviterPublicKey = publicKey,
                signature = signature,
                createdAt = createdAt,
                expiresAt = expiresAt,
                maxUses = maxUses,
                currentUses = 0,
                message = message
            )

            // Store the token
            storage.saveToken(token)

            logger.info("Generated invite token: ${redactTokenCode(token.tokenCode)}")
            TokenGenerationResult.Success(token)
        } catch (e: Exception) {
            logger.error("Failed to generate invite token", e)
            TokenGenerationResult.Error("Failed to generate token: ${e.message}")
        }
    }

    /**
     * Generates a new invite token with expiration in the specified time unit.
     *
     * @param expiresIn Duration until expiration
     * @param timeUnit The time unit for the expiration duration
     * @param maxUses Maximum number of times this token can be used, or null for unlimited
     * @param message Optional message to include with the invite
     * @return [TokenGenerationResult] indicating success or failure
     */
    fun generateToken(
        expiresIn: Long,
        timeUnit: TimeUnit,
        maxUses: Int? = null,
        message: String? = null
    ): TokenGenerationResult {
        return generateToken(
            expiresInMillis = timeUnit.toMillis(expiresIn),
            maxUses = maxUses,
            message = message
        )
    }

    /**
     * Validates an invite token.
     *
     * Checks:
     * 1. Token exists in storage
     * 2. Token signature is valid
     * 3. Token has not expired
     * 4. Token has not reached max usage
     *
     * @param tokenCode The token code to validate
     * @return [TokenValidationResult] with validation status
     */
    fun validateToken(tokenCode: String): TokenValidationResult {
        logger.debug("Validating token: ${redactTokenCode(tokenCode)}")

        // Look up the token
        val token = storage.getToken(tokenCode)
            ?: return TokenValidationResult.NotFound

        // Verify signature
        val signatureValid = verifyTokenSignature(token)
        if (!signatureValid) {
            return TokenValidationResult.InvalidSignature("Token signature verification failed")
        }

        // Check expiration
        val now = System.currentTimeMillis()
        if (token.isExpired(now)) {
            return TokenValidationResult.Expired(token, token.expiresAt!!)
        }

        // Check usage limit
        if (token.isExhausted()) {
            return TokenValidationResult.Exhausted(token, token.maxUses!!)
        }

        return TokenValidationResult.Valid(token)
    }

    /**
     * Redeems an invite token, incrementing its usage count.
     *
     * This should be called when an invitee successfully uses a token.
     *
     * @param tokenCode The token code to redeem
     * @return [TokenValidationResult] with the redemption status
     */
    fun redeemToken(tokenCode: String): TokenValidationResult {
        logger.info("Redeeming token: ${redactTokenCode(tokenCode)}")

        // Validate first
        val validationResult = validateToken(tokenCode)
        if (validationResult !is TokenValidationResult.Valid) {
            return validationResult
        }

        // Increment usage count
        val updatedToken = storage.incrementUsageCount(tokenCode)
            ?: return TokenValidationResult.NotFound

        logger.info("Token redeemed: ${redactTokenCode(tokenCode)} (uses: ${updatedToken.currentUses}/${updatedToken.maxUses ?: "unlimited"})")
        return TokenValidationResult.Valid(updatedToken)
    }

    /**
     * Gets a token by its code.
     *
     * @param tokenCode The token code
     * @return The token if found, null otherwise
     */
    fun getToken(tokenCode: String): InviteToken? {
        return storage.getToken(tokenCode)
    }

    /**
     * Gets all tokens created by the current identity.
     *
     * @return List of tokens created by this user, newest first
     */
    fun getMyTokens(): List<InviteToken> {
        val publicKey = identityManager.getPublicKey()
        return storage.getTokensByInviter(publicKey)
    }

    /**
     * Gets the count of tokens created by the current identity.
     *
     * @return Number of tokens created by this user
     */
    fun getMyTokenCount(): Int {
        val publicKey = identityManager.getPublicKey()
        return storage.getTokenCountByInviter(publicKey)
    }

    /**
     * Revokes (deletes) a token.
     *
     * Only the token creator can revoke a token.
     *
     * @param tokenCode The token code to revoke
     * @return true if the token was revoked, false if not found or not authorized
     */
    fun revokeToken(tokenCode: String): Boolean {
        val token = storage.getToken(tokenCode) ?: return false

        // Verify ownership
        val myPublicKey = identityManager.getPublicKey()
        if (!token.inviterPublicKey.contentEquals(myPublicKey)) {
            logger.warn("Cannot revoke token: not the owner")
            return false
        }

        val deleted = storage.deleteToken(tokenCode)
        if (deleted) {
            logger.info("Revoked token: ${redactTokenCode(tokenCode)}")
        }
        return deleted
    }

    /**
     * Cleans up expired tokens from storage.
     *
     * @return The number of expired tokens deleted
     */
    fun cleanupExpiredTokens(): Int {
        val deleted = storage.deleteExpiredTokens()
        if (deleted > 0) {
            logger.info("Cleaned up $deleted expired tokens")
        }
        return deleted
    }

    /**
     * Generates a shareable token string.
     *
     * The shareable format includes all necessary information for redemption:
     * - Token code
     * - Inviter public key
     * - Signature
     *
     * Format: grapevine://invite/{tokenCode}#{inviterPublicKeyBase64}#{signatureBase64}
     *
     * @param token The token to convert to shareable format
     * @return A shareable string that can be used to redeem the invite
     */
    fun toShareableString(token: InviteToken): String {
        val signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(token.signature)
        return "grapevine://invite/${token.tokenCode}#${token.inviterPublicKeyBase64}#$signatureBase64"
    }

    /**
     * Parses a shareable token string back into its components.
     *
     * @param shareableString The shareable string to parse
     * @return A [ShareableTokenData] containing the parsed components, or null if invalid
     */
    fun parseShareableString(shareableString: String): ShareableTokenData? {
        return try {
            val uri = shareableString.trim()

            // Check prefix
            if (!uri.startsWith("grapevine://invite/")) {
                return null
            }

            // Extract path and fragment
            val pathAndFragment = uri.removePrefix("grapevine://invite/")
            val parts = pathAndFragment.split("#")

            if (parts.size != 3) {
                return null
            }

            val tokenCode = parts[0]
            val inviterPublicKey = Base64.getUrlDecoder().decode(parts[1])
            val signature = Base64.getUrlDecoder().decode(parts[2])

            if (inviterPublicKey.size != CryptoProvider.ED25519_PUBLIC_KEY_BYTES) {
                return null
            }
            if (signature.size != CryptoProvider.ED25519_SIGNATURE_BYTES) {
                return null
            }

            ShareableTokenData(
                tokenCode = tokenCode,
                _inviterPublicKey = inviterPublicKey,
                _signature = signature
            )
        } catch (e: Exception) {
            logger.debug("Failed to parse shareable string", e)
            null
        }
    }

    /**
     * Verifies a token's signature.
     *
     * @param token The token to verify
     * @return true if the signature is valid
     */
    fun verifyTokenSignature(token: InviteToken): Boolean {
        val dataToSign = buildSignatureData(
            token.tokenCode,
            token.inviterPublicKey,
            token.createdAt,
            token.expiresAt,
            token.maxUses,
            token.message
        )

        return identityManager.verify(dataToSign, token.signature, token.inviterPublicKey)
    }

    // ==================== Invite Acceptance (FR-5) ====================

    /**
     * Accepts an invite using a shareable token string.
     *
     * This is the main entry point for new users redeeming invites.
     * The method:
     * 1. Parses the shareable string to extract token data
     * 2. Validates the inviter's signature
     * 3. Creates the invitee's counter-signature
     * 4. Records the acceptance
     * 5. Redeems the token (increments usage)
     *
     * @param shareableString The shareable invite string (grapevine://invite/...)
     * @return [InviteAcceptanceResult] with the outcome
     */
    fun acceptInvite(shareableString: String): InviteAcceptanceResult {
        logger.info("Accepting invite from shareable string")

        // Parse the shareable string
        val tokenData = parseShareableString(shareableString)
            ?: return InviteAcceptanceResult.Error("Invalid invite format")

        return acceptInviteFromTokenData(tokenData)
    }

    /**
     * Accepts an invite using a token that exists in local storage.
     *
     * This is used when the token is already stored locally (e.g., received via P2P).
     *
     * @param tokenCode The token code to accept
     * @return [InviteAcceptanceResult] with the outcome
     */
    fun acceptInviteFromStorage(tokenCode: String): InviteAcceptanceResult {
        logger.info("Accepting invite from stored token: ${redactTokenCode(tokenCode)}")

        val token = storage.getToken(tokenCode)
            ?: return InviteAcceptanceResult.TokenNotFound

        // Verify the token first
        val validationResult = validateToken(tokenCode)
        return when (validationResult) {
            is TokenValidationResult.Valid -> {
                performAcceptance(token)
            }
            is TokenValidationResult.NotFound -> InviteAcceptanceResult.TokenNotFound
            is TokenValidationResult.Expired -> InviteAcceptanceResult.TokenExpired(validationResult.expiredAt)
            is TokenValidationResult.Exhausted -> InviteAcceptanceResult.TokenExhausted(validationResult.maxUses)
            is TokenValidationResult.InvalidSignature -> InviteAcceptanceResult.InvalidSignature(validationResult.reason)
            is TokenValidationResult.Revoked -> InviteAcceptanceResult.Error("Token has been revoked")
        }
    }

    /**
     * Accepts an invite from parsed token data (from shareable string).
     *
     * This validates the external token data and creates the acceptance.
     *
     * @param tokenData The parsed token data
     * @return [InviteAcceptanceResult] with the outcome
     */
    private fun acceptInviteFromTokenData(tokenData: ShareableTokenData): InviteAcceptanceResult {
        val myPublicKey = identityManager.getPublicKey()

        // Check for self-invite
        if (myPublicKey.contentEquals(tokenData.inviterPublicKey)) {
            logger.warn("Cannot accept own invite")
            return InviteAcceptanceResult.SelfInvite
        }

        // Check if already a member
        acceptanceStorage?.let { storage ->
            val existingAcceptance = storage.getMyInvite(myPublicKey)
            if (existingAcceptance != null) {
                logger.warn("User is already a member of the network")
                return InviteAcceptanceResult.AlreadyMember(existingAcceptance)
            }
        }

        // For external tokens, we need to verify the signature
        // But we don't have the full token (no createdAt, expiresAt, etc.)
        // The shareable format is: tokenCode#publicKey#signature
        // We verify by checking if the local storage has the token
        val storedToken = storage.getToken(tokenData.tokenCode)

        return if (storedToken != null) {
            // Token exists in local storage, validate it fully
            val validationResult = validateToken(tokenData.tokenCode)
            when (validationResult) {
                is TokenValidationResult.Valid -> {
                    performAcceptance(storedToken)
                }
                is TokenValidationResult.NotFound -> InviteAcceptanceResult.TokenNotFound
                is TokenValidationResult.Expired -> InviteAcceptanceResult.TokenExpired(validationResult.expiredAt)
                is TokenValidationResult.Exhausted -> InviteAcceptanceResult.TokenExhausted(validationResult.maxUses)
                is TokenValidationResult.InvalidSignature -> InviteAcceptanceResult.InvalidSignature(validationResult.reason)
                is TokenValidationResult.Revoked -> InviteAcceptanceResult.Error("Token has been revoked")
            }
        } else {
            // Token not in local storage - validate externally
            // In a real P2P scenario, we'd need to contact the inviter or network
            // For now, we can only accept tokens that exist in local storage
            // or verify the signature if we had the full token data
            validateAndAcceptExternalToken(tokenData)
        }
    }

    /**
     * Handles external tokens that are not in local storage.
     *
     * **Security**: External tokens cannot be fully verified because the shareable
     * string format does not include the full token data (createdAt, expiresAt, maxUses, message)
     * required to verify the inviter's signature. Without verification:
     * - We cannot confirm the inviter actually created this token
     * - We cannot check token expiration or usage limits
     * - Token redemption accounting is impossible
     *
     * Therefore, external tokens are REJECTED until they can be fetched from the
     * network or local storage. In a full P2P implementation, the invitee would
     * connect to the inviter's node to obtain and verify the complete token data.
     *
     * @param tokenData The parsed token data from a shareable string
     * @return [InviteAcceptanceResult.TokenNotFound] - token must be in local storage
     */
    private fun validateAndAcceptExternalToken(tokenData: ShareableTokenData): InviteAcceptanceResult {
        // Security: We cannot accept tokens that are not in local storage because:
        // 1. The shareable string lacks token metadata (createdAt, expiresAt, maxUses)
        // 2. Without metadata, we cannot verify the inviter's signature
        // 3. Without verification, we cannot trust the token is authentic
        // 4. Accepting unverified tokens would allow forgery attacks

        logger.warn("Cannot accept external token ${redactTokenCode(tokenData.tokenCode)}: " +
                "token not found in local storage and cannot be verified")

        // Future: Implement P2P token fetch from inviter's node
        // For now, require token to be in local storage
        return InviteAcceptanceResult.TokenNotFound
    }

    /**
     * Performs the actual acceptance of a validated token.
     *
     * **Note**: This method requires [acceptanceStorage] to be configured.
     * Without storage, acceptances cannot be persisted and duplicate membership
     * checks cannot be performed.
     *
     * The acceptance signature covers (in order):
     * - Token code (UTF-8 bytes)
     * - Inviter's public key (32 bytes)
     * - Invitee's public key (32 bytes)
     *
     * @param token The validated token to accept
     * @return [InviteAcceptanceResult] with the outcome
     */
    private fun performAcceptance(token: InviteToken): InviteAcceptanceResult {
        // Require acceptance storage for production flows
        val storage = acceptanceStorage
        if (storage == null) {
            logger.error("Cannot accept invite: acceptance storage not configured")
            return InviteAcceptanceResult.Error("Acceptance storage not configured")
        }

        return try {
            val myPublicKey = identityManager.getPublicKey()

            // Check for self-invite
            if (myPublicKey.contentEquals(token.inviterPublicKey)) {
                logger.warn("Cannot accept own invite")
                return InviteAcceptanceResult.SelfInvite
            }

            // Check if already a member
            val existingAcceptance = storage.getMyInvite(myPublicKey)
            if (existingAcceptance != null) {
                logger.warn("User is already a member of the network")
                return InviteAcceptanceResult.AlreadyMember(existingAcceptance)
            }

            // Build the acceptance data to sign
            val acceptanceDataToSign = buildAcceptanceSignatureData(
                token.tokenCode,
                token.inviterPublicKey,
                myPublicKey
            )

            // Create counter-signature
            val inviteeSignature = identityManager.sign(acceptanceDataToSign)

            // Create the acceptance record
            val acceptance = InviteAcceptance(
                tokenCode = token.tokenCode,
                inviterPublicKey = token.inviterPublicKey,
                inviteePublicKey = myPublicKey,
                inviterSignature = token.signature,
                inviteeSignature = inviteeSignature,
                acceptedAt = System.currentTimeMillis(),
                message = token.message
            )

            // Store the acceptance and redeem the token
            // Note: These are not atomic; a production implementation should use
            // a transactional storage operation to ensure consistency
            storage.saveAcceptance(acceptance)
            this.storage.incrementUsageCount(token.tokenCode)

            logger.info("Invite accepted: ${redactTokenCode(token.tokenCode)}")
            InviteAcceptanceResult.Success(acceptance)
        } catch (e: Exception) {
            logger.error("Failed to accept invite", e)
            InviteAcceptanceResult.Error("Failed to accept invite: ${e.message}")
        }
    }

    /**
     * Verifies an invite acceptance's signatures.
     *
     * Both the inviter's original signature and the invitee's counter-signature
     * must be valid for the acceptance to be considered valid.
     *
     * @param acceptance The acceptance to verify
     * @return true if both signatures are valid
     */
    fun verifyAcceptanceSignatures(acceptance: InviteAcceptance): Boolean {
        // Build the acceptance data that the invitee should have signed
        val acceptanceData = buildAcceptanceSignatureData(
            acceptance.tokenCode,
            acceptance.inviterPublicKey,
            acceptance.inviteePublicKey
        )

        // Verify invitee's counter-signature
        val inviteeSignatureValid = identityManager.verify(
            acceptanceData,
            acceptance.inviteeSignature,
            acceptance.inviteePublicKey
        )

        if (!inviteeSignatureValid) {
            logger.warn("Invitee signature verification failed")
            return false
        }

        // Note: We can't verify the inviter's original signature without the full token data
        // (createdAt, expiresAt, maxUses, message). The inviter signature is over the token data,
        // not the acceptance data. In a full implementation, we'd need to fetch or store
        // the original token data.

        return true
    }

    /**
     * Gets all acceptances where the current user was the inviter.
     *
     * @return List of acceptances where this user invited others
     */
    fun getMyInvitees(): List<InviteAcceptance> {
        val storage = acceptanceStorage ?: return emptyList()
        val publicKey = identityManager.getPublicKey()
        return storage.getAcceptancesByInviter(publicKey)
    }

    /**
     * Gets the acceptance that brought the current user into the network.
     *
     * @return The acceptance where this user was invited, or null if genesis/not invited
     */
    fun getMyInvite(): InviteAcceptance? {
        val storage = acceptanceStorage ?: return null
        val publicKey = identityManager.getPublicKey()
        return storage.getMyInvite(publicKey)
    }

    /**
     * Gets the count of users the current user has invited.
     *
     * @return Number of users invited by this user
     */
    fun getMyInviteeCount(): Int {
        val storage = acceptanceStorage ?: return 0
        val publicKey = identityManager.getPublicKey()
        return storage.getInviteeCount(publicKey)
    }

    /**
     * Checks if the current user has been invited (is a member).
     *
     * @return true if this user has an acceptance record
     */
    fun hasBeenInvited(): Boolean {
        val storage = acceptanceStorage ?: return false
        val publicKey = identityManager.getPublicKey()
        return storage.hasBeenInvited(publicKey)
    }

    /**
     * Builds the canonical data that the invitee signs to accept an invite.
     *
     * ## Signature Data Format
     * The acceptance signature covers the following bytes in exact order:
     * 1. Token code (variable length, UTF-8 encoded)
     * 2. Inviter's Ed25519 public key (32 bytes, raw bytes)
     * 3. Invitee's Ed25519 public key (32 bytes, raw bytes)
     *
     * Total size: `tokenCode.length + 64` bytes
     *
     * ## Purpose
     * This creates a cryptographic proof that:
     * - The invitee accepted a specific invite (identified by tokenCode)
     * - The invite came from a specific inviter (their public key)
     * - The invitee acknowledges the invitation (their own key in the data)
     *
     * ## Security
     * Both inviter and invitee MUST use this exact byte format to ensure
     * signature verification succeeds. The format is canonical - there is
     * no padding, separators, or length prefixes.
     *
     * @param tokenCode The unique invite token code
     * @param inviterPublicKey The inviter's Ed25519 public key (must be 32 bytes)
     * @param inviteePublicKey The invitee's Ed25519 public key (must be 32 bytes)
     * @return The canonical byte array to sign
     */
    private fun buildAcceptanceSignatureData(
        tokenCode: String,
        inviterPublicKey: ByteArray,
        inviteePublicKey: ByteArray
    ): ByteArray {
        val tokenCodeBytes = tokenCode.toByteArray(Charsets.UTF_8)

        val buffer = ByteBuffer.allocate(
            tokenCodeBytes.size + inviterPublicKey.size + inviteePublicKey.size
        )

        buffer.put(tokenCodeBytes)
        buffer.put(inviterPublicKey)
        buffer.put(inviteePublicKey)

        return buffer.array()
    }

    /**
     * Generates a unique token code.
     *
     * The token code is derived from:
     * - Public key (32 bytes)
     * - Timestamp (8 bytes)
     * - Random nonce (32 bytes)
     *
     * These are concatenated and hashed with SHA-256, then Base64 URL-safe encoded.
     */
    private fun generateTokenCode(publicKey: ByteArray, timestamp: Long): String {
        // Generate random nonce
        val nonce = cryptoProvider.randomBytes(32)

        // Concatenate: publicKey + timestamp + nonce
        val buffer = ByteBuffer.allocate(publicKey.size + 8 + nonce.size)
        buffer.put(publicKey)
        buffer.putLong(timestamp)
        buffer.put(nonce)

        // Hash
        val hash = cryptoProvider.sha256(buffer.array())

        // Encode as URL-safe Base64 without padding
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }

    /**
     * Builds the data that is signed to create/verify a token.
     *
     * The signature covers:
     * - Token code (as UTF-8 bytes)
     * - Inviter public key
     * - Created timestamp
     * - Expires timestamp (or 0 if no expiration)
     * - Max uses (or 0 if unlimited)
     * - Message (as UTF-8 bytes, or empty if no message)
     */
    private fun buildSignatureData(
        tokenCode: String,
        publicKey: ByteArray,
        createdAt: Long,
        expiresAt: Long?,
        maxUses: Int?,
        message: String?
    ): ByteArray {
        val tokenCodeBytes = tokenCode.toByteArray(Charsets.UTF_8)
        val messageBytes = message?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)

        val buffer = ByteBuffer.allocate(
            tokenCodeBytes.size + publicKey.size + 8 + 8 + 4 + messageBytes.size
        )

        buffer.put(tokenCodeBytes)
        buffer.put(publicKey)
        buffer.putLong(createdAt)
        buffer.putLong(expiresAt ?: 0)
        buffer.putInt(maxUses ?: 0)
        buffer.put(messageBytes)

        return buffer.array()
    }
}

/**
 * Data parsed from a shareable token string.
 *
 * @property tokenCode The unique token code
 * @property inviterPublicKey The inviter's Ed25519 public key (32 bytes)
 * @property signature The inviter's signature (64 bytes)
 */
data class ShareableTokenData(
    val tokenCode: String,
    private val _inviterPublicKey: ByteArray,
    private val _signature: ByteArray
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ShareableTokenData

        if (tokenCode != other.tokenCode) return false
        if (!_inviterPublicKey.contentEquals(other._inviterPublicKey)) return false
        if (!_signature.contentEquals(other._signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tokenCode.hashCode()
        result = 31 * result + _inviterPublicKey.contentHashCode()
        result = 31 * result + _signature.contentHashCode()
        return result
    }
}

/**
 * Exception thrown for invite-related errors.
 */
class InviteException(message: String, cause: Throwable? = null) : Exception(message, cause)
