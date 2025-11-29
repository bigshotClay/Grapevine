package io.grapevine.core.invite

import io.grapevine.core.crypto.CryptoProvider
import io.grapevine.core.identity.IdentityManager
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.util.Base64

/**
 * Records and validates invite blocks in the distributed invite chain.
 *
 * The InviteChainRecorder is responsible for:
 * - Recording dual-signed invite blocks after acceptance
 * - Validating incoming invite blocks from peers
 * - Computing block hashes for chain integrity
 * - Maintaining chain linking (previous hash references)
 *
 * ## Recording Flow
 * 1. An [InviteAcceptance] is created when a user accepts an invite
 * 2. The recorder computes the block hash and determines the sequence number
 * 3. Both signatures are verified
 * 4. The record is stored locally
 * 5. The block is propagated to the network (via TrustChain)
 *
 * ## Validation
 * When receiving invite blocks from peers:
 * 1. Verify the block hash matches the content
 * 2. Verify both signatures (inviter and invitee)
 * 3. Verify chain linking (previous hash exists or is genesis)
 * 4. Store the validated record
 *
 * ## Thread Safety
 * This class is NOT thread-safe. Concurrent operations should be coordinated
 * externally. The underlying storage is thread-safe.
 *
 * @property identityManager For signature verification
 * @property storage For persisting invite chain records
 * @property cryptoProvider For cryptographic operations
 */
class InviteChainRecorder(
    private val identityManager: IdentityManager,
    private val storage: InviteChainStorage,
    private val cryptoProvider: CryptoProvider = CryptoProvider()
) {
    private val logger = LoggerFactory.getLogger(InviteChainRecorder::class.java)

    /**
     * Records a completed invite acceptance to the chain.
     *
     * This should be called after an invite has been fully accepted
     * (both parties have signed). The recorder will:
     * 1. Determine the sequence number for the inviter's chain
     * 2. Get the previous block hash (if any)
     * 3. Compute the block hash
     * 4. Verify both signatures
     * 5. Store the record
     *
     * @param acceptance The completed invite acceptance
     * @return [InviteChainRecordResult] with the outcome
     */
    fun recordAcceptance(acceptance: InviteAcceptance): InviteChainRecordResult {
        logger.info("Recording invite acceptance for token ${redactTokenCode(acceptance.tokenCode)}")

        return try {
            // Verify both signatures before recording
            val signatureValidation = verifyAcceptanceSignatures(acceptance)
            if (signatureValidation !is InviteChainValidationResult.Valid) {
                return when (signatureValidation) {
                    is InviteChainValidationResult.InvalidInviteeSignature ->
                        InviteChainRecordResult.InvalidInviteeSignature(signatureValidation.reason)
                    else ->
                        InviteChainRecordResult.ValidationFailed("Signature verification failed")
                }
            }

            // Determine sequence number and previous hash
            val latestRecord = storage.getLatestByInviter(acceptance.inviterPublicKey)
            val sequenceNumber = (latestRecord?.sequenceNumber ?: -1) + 1
            val previousHash = latestRecord?.blockHash

            // Compute block hash
            val blockHash = computeBlockHash(
                sequenceNumber = sequenceNumber,
                inviterPublicKey = acceptance.inviterPublicKey,
                inviteePublicKey = acceptance.inviteePublicKey,
                previousHash = previousHash,
                timestamp = acceptance.acceptedAt,
                tokenCode = acceptance.tokenCode
            )

            // Generate record ID
            val id = generateRecordId(blockHash, acceptance.inviterSignature, acceptance.inviteeSignature)

            // Check if already recorded
            val existingRecord = storage.getById(id)
            if (existingRecord != null) {
                logger.debug("Record already exists: ${id.take(8)}...")
                return InviteChainRecordResult.AlreadyExists(existingRecord)
            }

            // Create the record
            val record = InviteChainRecord(
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

            // Store the record
            storage.saveRecord(record)

            logger.info("Recorded invite: ${record.toDebugString()}")
            InviteChainRecordResult.Success(record)

        } catch (e: SequenceConflictException) {
            val existing = storage.getBySequence(e.inviterPublicKey, e.sequenceNumber)
            if (existing != null) {
                InviteChainRecordResult.SequenceConflict(existing)
            } else {
                InviteChainRecordResult.StorageError("Sequence conflict: ${e.message}")
            }
        } catch (e: Exception) {
            logger.error("Failed to record acceptance", e)
            InviteChainRecordResult.StorageError("Failed to record: ${e.message}")
        }
    }

    /**
     * Records an invite chain record received from a peer.
     *
     * This validates the incoming record before storing:
     * 1. Verify block hash matches content
     * 2. Verify both signatures
     * 3. Verify chain linking
     *
     * @param record The record to validate and store
     * @return [InviteChainRecordResult] with the outcome
     */
    fun recordFromPeer(record: InviteChainRecord): InviteChainRecordResult {
        logger.info("Recording invite from peer: ${record.id.take(8)}...")

        // Validate the record
        val validation = validateRecord(record)
        if (validation !is InviteChainValidationResult.Valid) {
            return when (validation) {
                is InviteChainValidationResult.InvalidInviterSignature ->
                    InviteChainRecordResult.InvalidInviterSignature(validation.reason)
                is InviteChainValidationResult.InvalidInviteeSignature ->
                    InviteChainRecordResult.InvalidInviteeSignature(validation.reason)
                is InviteChainValidationResult.InvalidBlockHash ->
                    InviteChainRecordResult.ValidationFailed("Block hash mismatch")
                is InviteChainValidationResult.InvalidChainLink ->
                    InviteChainRecordResult.InvalidChainLink(validation.reason)
                is InviteChainValidationResult.InvalidStructure ->
                    InviteChainRecordResult.ValidationFailed(validation.reason)
                is InviteChainValidationResult.Valid ->
                    InviteChainRecordResult.ValidationFailed("Unexpected validation state")
            }
        }

        // Check if already exists
        val existingRecord = storage.getById(record.id)
        if (existingRecord != null) {
            return InviteChainRecordResult.AlreadyExists(existingRecord)
        }

        // Check for block hash collision
        if (storage.existsByBlockHash(record.blockHash)) {
            val existing = storage.getByBlockHash(record.blockHash)
            if (existing != null && existing.id != record.id) {
                return InviteChainRecordResult.ValidationFailed("Block hash already exists with different ID")
            }
        }

        return try {
            storage.saveRecord(record)
            logger.info("Recorded peer invite: ${record.toDebugString()}")
            InviteChainRecordResult.Success(record)
        } catch (e: SequenceConflictException) {
            val existing = storage.getBySequence(e.inviterPublicKey, e.sequenceNumber)
            if (existing != null) {
                InviteChainRecordResult.SequenceConflict(existing)
            } else {
                InviteChainRecordResult.StorageError("Sequence conflict: ${e.message}")
            }
        } catch (e: Exception) {
            logger.error("Failed to record peer invite", e)
            InviteChainRecordResult.StorageError("Failed to store: ${e.message}")
        }
    }

    /**
     * Validates an invite chain record.
     *
     * @param record The record to validate
     * @return [InviteChainValidationResult] with validation outcome
     */
    fun validateRecord(record: InviteChainRecord): InviteChainValidationResult {
        // Verify block hash
        val computedHash = computeBlockHash(
            sequenceNumber = record.sequenceNumber,
            inviterPublicKey = record.inviterPublicKey,
            inviteePublicKey = record.inviteePublicKey,
            previousHash = record.previousHash,
            timestamp = record.timestamp,
            tokenCode = record.tokenCode
        )

        if (!InviteChainRecord.constantTimeEquals(computedHash, record.blockHash)) {
            return InviteChainValidationResult.InvalidBlockHash(computedHash, record.blockHash)
        }

        // Verify chain linking
        if (record.sequenceNumber > 0) {
            val previousRecord = storage.getBySequence(record.inviterPublicKey, record.sequenceNumber - 1)
            if (previousRecord == null) {
                // Previous block doesn't exist locally - we might not have synced it yet
                // For now, we'll accept it but log a warning
                logger.warn("Previous block not found for sequence ${record.sequenceNumber - 1}")
            } else {
                val expectedPreviousHash = previousRecord.blockHash
                if (record.previousHash == null) {
                    return InviteChainValidationResult.InvalidChainLink(
                        "Non-genesis block missing previous hash"
                    )
                }
                val recordPreviousHash = record.previousHash
                if (!InviteChainRecord.constantTimeEquals(recordPreviousHash!!, expectedPreviousHash)) {
                    return InviteChainValidationResult.InvalidChainLink(
                        "Previous hash mismatch: expected ${previousRecord.blockHashBase64.take(8)}..."
                    )
                }
            }
        }

        // Verify invitee's counter-signature
        val signatureData = buildSignatureData(
            record.tokenCode,
            record.inviterPublicKey,
            record.inviteePublicKey
        )

        val inviteeSignatureValid = identityManager.verify(
            signatureData,
            record.inviteeSignature,
            record.inviteePublicKey
        )

        if (!inviteeSignatureValid) {
            return InviteChainValidationResult.InvalidInviteeSignature(
                "Invitee counter-signature verification failed"
            )
        }

        return InviteChainValidationResult.Valid
    }

    /**
     * Verifies the signatures in an InviteAcceptance.
     *
     * Only verifies the invitee's counter-signature since we don't have
     * the full token data needed to verify the inviter's original signature.
     *
     * @param acceptance The acceptance to verify
     * @return [InviteChainValidationResult] with validation outcome
     */
    fun verifyAcceptanceSignatures(acceptance: InviteAcceptance): InviteChainValidationResult {
        val signatureData = buildSignatureData(
            acceptance.tokenCode,
            acceptance.inviterPublicKey,
            acceptance.inviteePublicKey
        )

        val inviteeSignatureValid = identityManager.verify(
            signatureData,
            acceptance.inviteeSignature,
            acceptance.inviteePublicKey
        )

        if (!inviteeSignatureValid) {
            return InviteChainValidationResult.InvalidInviteeSignature(
                "Invitee counter-signature verification failed"
            )
        }

        return InviteChainValidationResult.Valid
    }

    /**
     * Gets all invite records where the current user is the inviter.
     *
     * @return List of records ordered by sequence number
     */
    fun getMyInvites(): List<InviteChainRecord> {
        val publicKey = identityManager.getPublicKey()
        return storage.getByInviter(publicKey)
    }

    /**
     * Gets the invite record for how the current user joined the network.
     *
     * @return The invite record, or null if user is genesis or not found
     */
    fun getMyInviteRecord(): InviteChainRecord? {
        val publicKey = identityManager.getPublicKey()
        return storage.getInviteFor(publicKey)
    }

    /**
     * Gets all invite records for a specific inviter.
     *
     * @param inviterPublicKey The inviter's public key
     * @return List of records ordered by sequence number
     */
    fun getInvitesBy(inviterPublicKey: ByteArray): List<InviteChainRecord> {
        return storage.getByInviter(inviterPublicKey)
    }

    /**
     * Gets the invite record for a specific user.
     *
     * @param publicKey The user's public key
     * @return The invite record, or null if not found
     */
    fun getInviteFor(publicKey: ByteArray): InviteChainRecord? {
        return storage.getInviteFor(publicKey)
    }

    /**
     * Checks if a user has been invited to the network.
     *
     * @param publicKey The user's public key
     * @return true if an invite record exists for this user as invitee
     */
    fun hasBeenInvited(publicKey: ByteArray): Boolean {
        return storage.hasBeenInvited(publicKey)
    }

    /**
     * Gets the count of users invited by a specific inviter.
     *
     * @param inviterPublicKey The inviter's public key
     * @return Count of invitees
     */
    fun getInviteeCount(inviterPublicKey: ByteArray): Int {
        return storage.getInviteeCount(inviterPublicKey)
    }

    /**
     * Gets the latest sequence number for an inviter.
     *
     * @param inviterPublicKey The inviter's public key
     * @return The latest sequence number, or -1 if no records exist
     */
    fun getLatestSequenceNumber(inviterPublicKey: ByteArray): Long {
        return storage.getLatestByInviter(inviterPublicKey)?.sequenceNumber ?: -1
    }

    /**
     * Gets a record by its ID.
     *
     * @param id The record ID
     * @return The record, or null if not found
     */
    fun getRecord(id: String): InviteChainRecord? {
        return storage.getById(id)
    }

    /**
     * Gets a record by its block hash.
     *
     * @param blockHash The block hash
     * @return The record, or null if not found
     */
    fun getRecordByBlockHash(blockHash: ByteArray): InviteChainRecord? {
        return storage.getByBlockHash(blockHash)
    }

    // ==================== Private Helpers ====================

    /**
     * Computes the block hash for an invite block.
     *
     * Hash covers (in order):
     * - sequence_number (8 bytes, big-endian)
     * - inviter_public_key (32 bytes)
     * - invitee_public_key (32 bytes)
     * - previous_hash (32 bytes, or zeros if null)
     * - timestamp (8 bytes, big-endian)
     * - token_code (UTF-8 bytes)
     */
    internal fun computeBlockHash(
        sequenceNumber: Long,
        inviterPublicKey: ByteArray,
        inviteePublicKey: ByteArray,
        previousHash: ByteArray?,
        timestamp: Long,
        tokenCode: String
    ): ByteArray {
        val tokenCodeBytes = tokenCode.toByteArray(Charsets.UTF_8)
        val prevHashBytes = previousHash ?: ByteArray(32) // zeros if null

        val buffer = ByteBuffer.allocate(
            8 + // sequence number
            32 + // inviter key
            32 + // invitee key
            32 + // previous hash
            8 + // timestamp
            tokenCodeBytes.size
        )

        buffer.putLong(sequenceNumber)
        buffer.put(inviterPublicKey)
        buffer.put(inviteePublicKey)
        buffer.put(prevHashBytes)
        buffer.putLong(timestamp)
        buffer.put(tokenCodeBytes)

        return cryptoProvider.sha256(buffer.array())
    }

    /**
     * Builds the canonical signature data for acceptance verification.
     *
     * Format: tokenCode (UTF-8) || inviterPublicKey (32 bytes) || inviteePublicKey (32 bytes)
     */
    private fun buildSignatureData(
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
     * Generates a unique record ID from block hash and signatures.
     */
    private fun generateRecordId(
        blockHash: ByteArray,
        inviterSignature: ByteArray,
        inviteeSignature: ByteArray
    ): String {
        val combined = ByteBuffer.allocate(blockHash.size + inviterSignature.size + inviteeSignature.size)
        combined.put(blockHash)
        combined.put(inviterSignature)
        combined.put(inviteeSignature)

        val hash = cryptoProvider.sha256(combined.array())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }

    /**
     * Returns a redacted token code for logging.
     */
    private fun redactTokenCode(tokenCode: String): String {
        val hash = cryptoProvider.sha256(tokenCode.toByteArray(Charsets.UTF_8))
        return "token:${hash.take(4).joinToString("") { "%02x".format(it) }}..."
    }

    companion object {
        private val logger = LoggerFactory.getLogger(InviteChainRecorder::class.java)
    }
}
