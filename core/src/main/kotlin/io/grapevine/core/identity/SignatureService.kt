package io.grapevine.core.identity

import com.goterl.lazysodium.utils.Key
import io.grapevine.core.crypto.CryptoProvider
import org.slf4j.LoggerFactory

/**
 * Service for signing and verifying messages and data.
 *
 * All outgoing messages should be signed using [signMessage] and all
 * incoming messages should be verified using [verifyMessage].
 */
class SignatureService(
    private val identityManager: IdentityManager,
    private val cryptoProvider: CryptoProvider = CryptoProvider()
) {
    private val logger = LoggerFactory.getLogger(SignatureService::class.java)

    /**
     * Signs a message using the current identity's private key.
     *
     * @param message The message bytes to sign
     * @return The signature bytes (64 bytes for Ed25519)
     * @throws SignatureException if signing fails (e.g., no identity exists)
     */
    fun signMessage(message: ByteArray): ByteArray {
        val privateKey = identityManager.getPrivateKey()
            ?: throw SignatureException("Cannot sign: no identity available")

        return try {
            val secretKey = Key.fromBytes(privateKey)
            val signature = cryptoProvider.sign(message, secretKey)
            logger.debug("Signed message of ${message.size} bytes")
            signature
        } catch (e: Exception) {
            logger.error("Failed to sign message", e)
            throw SignatureException("Failed to sign message: ${e.message}", e)
        }
    }

    /**
     * Signs data and returns a SignedData object containing both
     * the original data, signature, and signer's public key.
     *
     * @param data The data to sign
     * @return A SignedData object containing the data, signature, and public key
     */
    fun sign(data: ByteArray): SignedData {
        val signature = signMessage(data)
        val publicKey = identityManager.getPublicKey()
        return SignedData(data, signature, publicKey)
    }

    /**
     * Verifies a message signature against a public key.
     *
     * @param message The original message bytes
     * @param signature The signature to verify
     * @param publicKey The public key to verify against (32 bytes)
     * @return true if the signature is valid, false otherwise
     */
    fun verifyMessage(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        if (publicKey.size != CryptoProvider.ED25519_PUBLIC_KEY_BYTES) {
            logger.warn("Invalid public key size: ${publicKey.size} bytes, expected ${CryptoProvider.ED25519_PUBLIC_KEY_BYTES}")
            return false
        }

        if (signature.size != CryptoProvider.ED25519_SIGNATURE_BYTES) {
            logger.warn("Invalid signature size: ${signature.size} bytes, expected ${CryptoProvider.ED25519_SIGNATURE_BYTES}")
            return false
        }

        return try {
            val pubKey = Key.fromBytes(publicKey)
            val valid = cryptoProvider.verify(message, signature, pubKey)
            if (!valid) {
                logger.warn("Signature verification failed for message of ${message.size} bytes")
            } else {
                logger.debug("Signature verified for message of ${message.size} bytes")
            }
            valid
        } catch (e: Exception) {
            logger.error("Exception during signature verification", e)
            false
        }
    }

    /**
     * Verifies a SignedData object.
     *
     * @param signedData The signed data to verify
     * @return true if the signature is valid, false otherwise
     */
    fun verify(signedData: SignedData): Boolean {
        return verifyMessage(signedData.data, signedData.signature, signedData.signerPublicKey)
    }

    /**
     * Verifies a message and throws an exception if invalid.
     *
     * @param message The original message bytes
     * @param signature The signature to verify
     * @param publicKey The public key to verify against
     * @throws SignatureVerificationException if the signature is invalid
     */
    fun requireValidSignature(message: ByteArray, signature: ByteArray, publicKey: ByteArray) {
        if (!verifyMessage(message, signature, publicKey)) {
            throw SignatureVerificationException("Invalid signature for message")
        }
    }

    /**
     * Verifies a SignedData object and throws an exception if invalid.
     *
     * @param signedData The signed data to verify
     * @throws SignatureVerificationException if the signature is invalid
     */
    fun requireValid(signedData: SignedData) {
        if (!verify(signedData)) {
            throw SignatureVerificationException("Invalid signature for signed data")
        }
    }
}

/**
 * Container for signed data, including the original data, signature,
 * and the signer's public key.
 */
data class SignedData(
    val data: ByteArray,
    val signature: ByteArray,
    val signerPublicKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignedData

        if (!data.contentEquals(other.data)) return false
        if (!signature.contentEquals(other.signature)) return false
        if (!signerPublicKey.contentEquals(other.signerPublicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + signerPublicKey.contentHashCode()
        return result
    }
}

/**
 * Exception thrown when signing operations fail.
 */
class SignatureException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Exception thrown when signature verification fails.
 */
class SignatureVerificationException(message: String) : Exception(message)
