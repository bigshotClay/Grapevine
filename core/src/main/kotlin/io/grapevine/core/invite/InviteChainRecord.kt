package io.grapevine.core.invite

import java.security.MessageDigest
import java.util.Base64

/**
 * Represents a recorded invite in the distributed invite chain.
 *
 * An InviteChainRecord captures a complete, dual-signed invite transaction
 * that has been recorded in the TrustChain. This differs from [InviteAcceptance]
 * in that it includes blockchain-specific metadata such as sequence numbers,
 * block hashes, and chain linking information.
 *
 * ## Dual Signature Requirement
 * Every recorded invite block MUST contain two valid signatures:
 * 1. **Inviter's signature**: Proves the inviter authorized the invitation
 * 2. **Invitee's counter-signature**: Proves the invitee accepted the invitation
 *
 * A block without both signatures is considered incomplete and should not be
 * recorded in the chain.
 *
 * ## Chain Structure
 * Each user maintains their own invite chain:
 * - Genesis user's first block has sequence_number = 0 and null previous_hash
 * - Each subsequent invite increments sequence_number
 * - previous_hash links to the inviter's previous block
 *
 * ## Block Hash Computation
 * The block_hash is computed over:
 * - sequence_number (8 bytes, big-endian)
 * - inviter_public_key (32 bytes)
 * - invitee_public_key (32 bytes)
 * - previous_hash (32 bytes, or zeros if null)
 * - timestamp (8 bytes, big-endian)
 * - token_code (UTF-8 bytes)
 *
 * ## Immutability and Thread Safety
 * This class is immutable and thread-safe. All [ByteArray] fields are stored
 * as private copies and returned as defensive copies.
 *
 * @property id Unique identifier for this record (typically SHA-256 of block_hash + signatures)
 * @property sequenceNumber Position in the inviter's chain (0-based)
 * @property inviterPublicKey Ed25519 public key of the inviter (32 bytes)
 * @property inviteePublicKey Ed25519 public key of the invitee (32 bytes)
 * @property previousHash Hash of the previous block in inviter's chain (32 bytes, or null for first block)
 * @property blockHash Hash of this block's content (32 bytes)
 * @property inviterSignature Inviter's Ed25519 signature over block content (64 bytes)
 * @property inviteeSignature Invitee's counter-signature over block content (64 bytes)
 * @property tokenCode The invite token code that was redeemed
 * @property timestamp Unix epoch milliseconds when the invite was created
 * @property message Optional message from the inviter
 * @property createdAt Unix epoch milliseconds when this record was created locally
 */
class InviteChainRecord private constructor(
    val id: String,
    val sequenceNumber: Long,
    private val _inviterPublicKey: ByteArray,
    private val _inviteePublicKey: ByteArray,
    private val _previousHash: ByteArray?,
    private val _blockHash: ByteArray,
    private val _inviterSignature: ByteArray,
    private val _inviteeSignature: ByteArray,
    val tokenCode: String,
    val timestamp: Long,
    val message: String?,
    val createdAt: Long
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
     * Returns the previous block hash as a defensive copy, or null if this is the first block.
     */
    val previousHash: ByteArray?
        get() = _previousHash?.copyOf()

    /**
     * Returns the block hash as a defensive copy.
     */
    val blockHash: ByteArray
        get() = _blockHash.copyOf()

    /**
     * Returns the inviter's signature as a defensive copy.
     */
    val inviterSignature: ByteArray
        get() = _inviterSignature.copyOf()

    /**
     * Returns the invitee's signature as a defensive copy.
     */
    val inviteeSignature: ByteArray
        get() = _inviteeSignature.copyOf()

    /**
     * Returns true if this is the first block in the inviter's chain.
     */
    val isFirstBlock: Boolean
        get() = sequenceNumber == 0L && _previousHash == null

    // ==================== Base64 Serialization ====================

    /**
     * Returns the inviter's public key as URL-safe Base64.
     */
    val inviterPublicKeyBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviterPublicKey)
    }

    /**
     * Returns the invitee's public key as URL-safe Base64.
     */
    val inviteePublicKeyBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviteePublicKey)
    }

    /**
     * Returns the previous hash as URL-safe Base64, or null.
     */
    val previousHashBase64: String? by lazy(LazyThreadSafetyMode.PUBLICATION) {
        _previousHash?.let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
    }

    /**
     * Returns the block hash as URL-safe Base64.
     */
    val blockHashBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_blockHash)
    }

    /**
     * Returns the inviter's signature as URL-safe Base64.
     */
    val inviterSignatureBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviterSignature)
    }

    /**
     * Returns the invitee's signature as URL-safe Base64.
     */
    val inviteeSignatureBase64: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        Base64.getUrlEncoder().withoutPadding().encodeToString(_inviteeSignature)
    }

    // ==================== Copy & Equality ====================

    /**
     * Creates a copy with the specified fields changed.
     *
     * All [ByteArray] parameters are deep-copied.
     */
    fun copy(
        id: String = this.id,
        sequenceNumber: Long = this.sequenceNumber,
        inviterPublicKey: ByteArray = this._inviterPublicKey,
        inviteePublicKey: ByteArray = this._inviteePublicKey,
        previousHash: ByteArray? = this._previousHash,
        blockHash: ByteArray = this._blockHash,
        inviterSignature: ByteArray = this._inviterSignature,
        inviteeSignature: ByteArray = this._inviteeSignature,
        tokenCode: String = this.tokenCode,
        timestamp: Long = this.timestamp,
        message: String? = this.message,
        createdAt: Long = this.createdAt
    ): InviteChainRecord = InviteChainRecord(
        id = id,
        sequenceNumber = sequenceNumber,
        _inviterPublicKey = inviterPublicKey.copyOf(),
        _inviteePublicKey = inviteePublicKey.copyOf(),
        _previousHash = previousHash?.copyOf(),
        _blockHash = blockHash.copyOf(),
        _inviterSignature = inviterSignature.copyOf(),
        _inviteeSignature = inviteeSignature.copyOf(),
        tokenCode = tokenCode,
        timestamp = timestamp,
        message = message,
        createdAt = createdAt
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InviteChainRecord

        if (id != other.id) return false
        if (sequenceNumber != other.sequenceNumber) return false
        if (!_inviterPublicKey.contentEquals(other._inviterPublicKey)) return false
        if (!_inviteePublicKey.contentEquals(other._inviteePublicKey)) return false
        if (_previousHash != null) {
            if (other._previousHash == null) return false
            if (!_previousHash.contentEquals(other._previousHash)) return false
        } else if (other._previousHash != null) return false
        if (!_blockHash.contentEquals(other._blockHash)) return false
        if (!_inviterSignature.contentEquals(other._inviterSignature)) return false
        if (!_inviteeSignature.contentEquals(other._inviteeSignature)) return false
        if (tokenCode != other.tokenCode) return false
        if (timestamp != other.timestamp) return false
        if (message != other.message) return false
        if (createdAt != other.createdAt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + _inviterPublicKey.contentHashCode()
        result = 31 * result + _inviteePublicKey.contentHashCode()
        result = 31 * result + (_previousHash?.contentHashCode() ?: 0)
        result = 31 * result + _blockHash.contentHashCode()
        result = 31 * result + _inviterSignature.contentHashCode()
        result = 31 * result + _inviteeSignature.contentHashCode()
        result = 31 * result + tokenCode.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + (message?.hashCode() ?: 0)
        result = 31 * result + createdAt.hashCode()
        return result
    }

    /**
     * Returns a redacted string representation suitable for logging.
     */
    override fun toString(): String {
        return "InviteChainRecord(id=${id.take(8)}..., seq=$sequenceNumber, " +
                "inviter=<redacted>, invitee=<redacted>, timestamp=$timestamp)"
    }

    /**
     * Returns a debug string with partial key fingerprints.
     */
    fun toDebugString(): String {
        val inviterPrefix = _inviterPublicKey.take(4).joinToString("") { "%02x".format(it) }
        val inviteePrefix = _inviteePublicKey.take(4).joinToString("") { "%02x".format(it) }
        return "InviteChainRecord(id=${id.take(8)}..., seq=$sequenceNumber, " +
                "inviter=$inviterPrefix..., invitee=$inviteePrefix..., " +
                "timestamp=$timestamp, token=${tokenCode.take(8)}...)"
    }

    companion object {
        /** Ed25519 public key size in bytes */
        const val PUBLIC_KEY_SIZE = 32

        /** Ed25519 signature size in bytes */
        const val SIGNATURE_SIZE = 64

        /** SHA-256 hash size in bytes */
        const val HASH_SIZE = 32

        /**
         * Creates a new InviteChainRecord with validation.
         *
         * @throws IllegalArgumentException if any parameter is invalid
         */
        operator fun invoke(
            id: String,
            sequenceNumber: Long,
            inviterPublicKey: ByteArray,
            inviteePublicKey: ByteArray,
            previousHash: ByteArray?,
            blockHash: ByteArray,
            inviterSignature: ByteArray,
            inviteeSignature: ByteArray,
            tokenCode: String,
            timestamp: Long,
            message: String? = null,
            createdAt: Long = System.currentTimeMillis()
        ): InviteChainRecord {
            require(id.isNotBlank()) { "ID cannot be blank" }
            require(sequenceNumber >= 0) { "Sequence number must be non-negative" }
            require(inviterPublicKey.size == PUBLIC_KEY_SIZE) {
                "Inviter public key must be $PUBLIC_KEY_SIZE bytes, got ${inviterPublicKey.size}"
            }
            require(inviteePublicKey.size == PUBLIC_KEY_SIZE) {
                "Invitee public key must be $PUBLIC_KEY_SIZE bytes, got ${inviteePublicKey.size}"
            }
            require(previousHash == null || previousHash.size == HASH_SIZE) {
                "Previous hash must be $HASH_SIZE bytes or null, got ${previousHash?.size}"
            }
            require(blockHash.size == HASH_SIZE) {
                "Block hash must be $HASH_SIZE bytes, got ${blockHash.size}"
            }
            require(inviterSignature.size == SIGNATURE_SIZE) {
                "Inviter signature must be $SIGNATURE_SIZE bytes, got ${inviterSignature.size}"
            }
            require(inviteeSignature.size == SIGNATURE_SIZE) {
                "Invitee signature must be $SIGNATURE_SIZE bytes, got ${inviteeSignature.size}"
            }
            require(tokenCode.isNotBlank()) { "Token code cannot be blank" }
            require(timestamp > 0) { "Timestamp must be positive" }
            require(createdAt > 0) { "Created timestamp must be positive" }
            require(!inviterPublicKey.contentEquals(inviteePublicKey)) {
                "Inviter and invitee cannot be the same user"
            }

            // Validate chain linking: first block must have sequence 0 and no previous hash
            if (sequenceNumber == 0L) {
                require(previousHash == null) {
                    "First block (sequence 0) must not have a previous hash"
                }
            } else {
                require(previousHash != null) {
                    "Non-first block (sequence $sequenceNumber) must have a previous hash"
                }
            }

            return InviteChainRecord(
                id = id,
                sequenceNumber = sequenceNumber,
                _inviterPublicKey = inviterPublicKey.copyOf(),
                _inviteePublicKey = inviteePublicKey.copyOf(),
                _previousHash = previousHash?.copyOf(),
                _blockHash = blockHash.copyOf(),
                _inviterSignature = inviterSignature.copyOf(),
                _inviteeSignature = inviteeSignature.copyOf(),
                tokenCode = tokenCode,
                timestamp = timestamp,
                message = message?.trim()?.takeIf { it.isNotEmpty() },
                createdAt = createdAt
            )
        }

        /**
         * Creates an InviteChainRecord from an InviteAcceptance.
         *
         * This is used to convert a local acceptance into a chain record after
         * determining the sequence number and computing the block hash.
         *
         * @param acceptance The acceptance to convert
         * @param sequenceNumber The position in the inviter's chain
         * @param previousHash Hash of the previous block, or null for first block
         * @param computeBlockHash Function to compute the block hash
         * @param generateId Function to generate a unique ID (defaults to hash-based)
         * @return A new InviteChainRecord
         */
        fun fromAcceptance(
            acceptance: InviteAcceptance,
            sequenceNumber: Long,
            previousHash: ByteArray?,
            computeBlockHash: (Long, ByteArray, ByteArray, ByteArray?, Long, String) -> ByteArray,
            generateId: (ByteArray, ByteArray, ByteArray) -> String = ::defaultGenerateId
        ): InviteChainRecord {
            val blockHash = computeBlockHash(
                sequenceNumber,
                acceptance.inviterPublicKey,
                acceptance.inviteePublicKey,
                previousHash,
                acceptance.acceptedAt,
                acceptance.tokenCode
            )

            val id = generateId(blockHash, acceptance.inviterSignature, acceptance.inviteeSignature)

            return invoke(
                id = id,
                sequenceNumber = sequenceNumber,
                inviterPublicKey = acceptance.inviterPublicKey,
                inviteePublicKey = acceptance.inviteePublicKey,
                previousHash = previousHash,
                blockHash = blockHash,
                inviterSignature = acceptance.inviterSignature,
                inviteeSignature = acceptance.inviteeSignature,
                tokenCode = acceptance.tokenCode,
                timestamp = acceptance.acceptedAt,
                message = acceptance.message,
                createdAt = System.currentTimeMillis()
            )
        }

        /**
         * Default ID generation: SHA-256 of block_hash || inviter_signature || invitee_signature,
         * encoded as URL-safe Base64.
         */
        private fun defaultGenerateId(
            blockHash: ByteArray,
            inviterSignature: ByteArray,
            inviteeSignature: ByteArray
        ): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(blockHash)
            digest.update(inviterSignature)
            digest.update(inviteeSignature)
            val hash = digest.digest()
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
        }

        /**
         * Performs constant-time comparison of two byte arrays.
         */
        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            return MessageDigest.isEqual(a, b)
        }
    }
}

/**
 * Result of recording an invite block in the chain.
 */
sealed class InviteChainRecordResult {
    /**
     * Block was successfully recorded.
     */
    data class Success(val record: InviteChainRecord) : InviteChainRecordResult()

    /**
     * Block already exists in the chain.
     */
    data class AlreadyExists(val existingRecord: InviteChainRecord) : InviteChainRecordResult()

    /**
     * Block validation failed.
     */
    data class ValidationFailed(val reason: String) : InviteChainRecordResult()

    /**
     * Inviter's signature is invalid.
     */
    data class InvalidInviterSignature(val reason: String) : InviteChainRecordResult()

    /**
     * Invitee's counter-signature is invalid.
     */
    data class InvalidInviteeSignature(val reason: String) : InviteChainRecordResult()

    /**
     * Chain linking is invalid (previous hash mismatch).
     */
    data class InvalidChainLink(val reason: String) : InviteChainRecordResult()

    /**
     * Sequence number conflict (same sequence already used).
     */
    data class SequenceConflict(val existingRecord: InviteChainRecord) : InviteChainRecordResult()

    /**
     * Storage error occurred.
     */
    data class StorageError(val message: String) : InviteChainRecordResult()
}

/**
 * Result of validating an invite chain record.
 */
sealed class InviteChainValidationResult {
    /**
     * Record is valid.
     */
    data object Valid : InviteChainValidationResult()

    /**
     * Inviter's signature is invalid.
     */
    data class InvalidInviterSignature(val reason: String) : InviteChainValidationResult()

    /**
     * Invitee's counter-signature is invalid.
     */
    data class InvalidInviteeSignature(val reason: String) : InviteChainValidationResult()

    /**
     * Block hash does not match computed hash.
     */
    data class InvalidBlockHash(val expected: ByteArray, val actual: ByteArray) : InviteChainValidationResult()

    /**
     * Chain linking is invalid.
     */
    data class InvalidChainLink(val reason: String) : InviteChainValidationResult()

    /**
     * Record structure is invalid.
     */
    data class InvalidStructure(val reason: String) : InviteChainValidationResult()
}
