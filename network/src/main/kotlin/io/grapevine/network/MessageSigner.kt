package io.grapevine.network

import io.grapevine.core.crypto.CryptoProvider
import org.slf4j.LoggerFactory

/**
 * Handles cryptographic signing and verification of network messages.
 *
 * This class provides application-level message authentication on top of
 * IPv8's transport-level security. All outgoing messages are signed with
 * the user's Ed25519 private key, and all incoming messages are verified
 * against the sender's public key.
 *
 * ## Security Model
 * - Messages are signed using Ed25519 signatures (64 bytes)
 * - Verification failures are logged and result in message rejection
 * - Unsigned messages are rejected by default (configurable)
 *
 * @property privateKey The Ed25519 private key for signing (64 bytes)
 * @property publicKey The Ed25519 public key (32 bytes)
 * @property cryptoProvider The cryptographic provider for signing operations
 */
class MessageSigner(
    private val privateKey: ByteArray,
    private val publicKey: ByteArray,
    private val cryptoProvider: CryptoProvider = CryptoProvider()
) {
    private val logger = LoggerFactory.getLogger(MessageSigner::class.java)

    /**
     * Signs a ping payload.
     *
     * @param timestamp The timestamp to include in the ping
     * @return A signed PingPayload
     */
    fun signPing(timestamp: Long): PingPayload {
        val payload = PingPayload(timestamp)
        val signature = sign(payload.getSignableData())
        return PingPayload(timestamp, signature, publicKey.copyOf())
    }

    /**
     * Signs a pong payload.
     *
     * @param originalTimestamp The timestamp from the original ping
     * @param responseTimestamp The timestamp of the response
     * @return A signed PongPayload
     */
    fun signPong(originalTimestamp: Long, responseTimestamp: Long): PongPayload {
        val payload = PongPayload(originalTimestamp, responseTimestamp)
        val signature = sign(payload.getSignableData())
        return PongPayload(originalTimestamp, responseTimestamp, signature, publicKey.copyOf())
    }

    /**
     * Verifies a ping payload's signature.
     *
     * @param payload The ping payload to verify
     * @return A [VerificationResult] indicating success or failure with details
     */
    fun verifyPing(payload: PingPayload): VerificationResult {
        if (!payload.isSigned()) {
            logger.warn("Ping payload is not signed")
            return VerificationResult.Unsigned
        }

        val isValid = verify(payload.getSignableData(), payload.signature, payload.signerPublicKey)
        return if (isValid) {
            logger.debug("Ping signature verified successfully")
            VerificationResult.Valid
        } else {
            logger.warn("Ping signature verification FAILED")
            VerificationResult.Invalid("Signature does not match payload")
        }
    }

    /**
     * Verifies a pong payload's signature.
     *
     * @param payload The pong payload to verify
     * @return A [VerificationResult] indicating success or failure with details
     */
    fun verifyPong(payload: PongPayload): VerificationResult {
        if (!payload.isSigned()) {
            logger.warn("Pong payload is not signed")
            return VerificationResult.Unsigned
        }

        val isValid = verify(payload.getSignableData(), payload.signature, payload.signerPublicKey)
        return if (isValid) {
            logger.debug("Pong signature verified successfully")
            VerificationResult.Valid
        } else {
            logger.warn("Pong signature verification FAILED")
            VerificationResult.Invalid("Signature does not match payload")
        }
    }

    /**
     * Signs arbitrary data using the private key.
     *
     * @param data The data to sign
     * @return The Ed25519 signature (64 bytes)
     */
    private fun sign(data: ByteArray): ByteArray {
        return cryptoProvider.signRaw(data, privateKey)
    }

    /**
     * Verifies a signature against data and a public key.
     *
     * @param data The original data
     * @param signature The signature to verify
     * @param signerPublicKey The public key to verify against
     * @return true if the signature is valid, false otherwise
     */
    private fun verify(data: ByteArray, signature: ByteArray, signerPublicKey: ByteArray): Boolean {
        if (signerPublicKey.size != CryptoProvider.ED25519_PUBLIC_KEY_BYTES) {
            logger.warn("Invalid public key size: {} bytes", signerPublicKey.size)
            return false
        }
        if (signature.size != CryptoProvider.ED25519_SIGNATURE_BYTES) {
            logger.warn("Invalid signature size: {} bytes", signature.size)
            return false
        }

        return try {
            cryptoProvider.verifyRaw(data, signature, signerPublicKey)
        } catch (e: Exception) {
            logger.error("Exception during signature verification", e)
            false
        }
    }

    companion object {
        /**
         * Creates a MessageSigner from raw key bytes.
         *
         * @param privateKey The Ed25519 private key (64 bytes)
         * @param publicKey The Ed25519 public key (32 bytes)
         * @return A new MessageSigner instance
         */
        fun create(privateKey: ByteArray, publicKey: ByteArray): MessageSigner {
            require(privateKey.size == CryptoProvider.ED25519_SECRET_KEY_BYTES) {
                "Private key must be ${CryptoProvider.ED25519_SECRET_KEY_BYTES} bytes"
            }
            require(publicKey.size == CryptoProvider.ED25519_PUBLIC_KEY_BYTES) {
                "Public key must be ${CryptoProvider.ED25519_PUBLIC_KEY_BYTES} bytes"
            }
            return MessageSigner(privateKey.copyOf(), publicKey.copyOf())
        }
    }
}

/**
 * Result of message signature verification.
 */
sealed class VerificationResult {
    /**
     * Signature is valid.
     */
    object Valid : VerificationResult()

    /**
     * Message was not signed.
     */
    object Unsigned : VerificationResult()

    /**
     * Signature verification failed.
     *
     * @property reason Description of why verification failed
     */
    data class Invalid(val reason: String) : VerificationResult()

    /**
     * Returns true if the verification passed.
     */
    fun isValid(): Boolean = this is Valid

    /**
     * Returns true if the message was properly signed (valid or invalid, but not unsigned).
     */
    fun isSigned(): Boolean = this !is Unsigned
}
