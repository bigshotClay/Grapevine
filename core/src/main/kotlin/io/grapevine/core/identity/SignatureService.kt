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
     * The private key is expected to be a 64-byte Ed25519 secret key or 32-byte seed
     * as provided by [IdentityManager.getPrivateKey].
     *
     * @param message The message bytes to sign
     * @return The signature bytes (64 bytes for Ed25519)
     * @throws SignatureException if signing fails (e.g., no identity exists or invalid key format)
     */
    fun signMessage(message: ByteArray): ByteArray {
        val privateKey = identityManager.getPrivateKey()
            ?: throw SignatureException("Cannot sign: no identity available")

        return try {
            // Validate private key size before use
            require(
                privateKey.size == CryptoProvider.ED25519_SECRET_KEY_BYTES ||
                    privateKey.size == CryptoProvider.ED25519_SEED_BYTES
            ) {
                "Invalid private key size: expected ${CryptoProvider.ED25519_SECRET_KEY_BYTES} or " +
                    "${CryptoProvider.ED25519_SEED_BYTES} bytes, got ${privateKey.size}"
            }

            val secretKey = Key.fromBytes(privateKey)
            val signature = cryptoProvider.sign(message, secretKey)
            logger.debug("Signed message of {} bytes", message.size)
            signature
        } catch (e: IllegalArgumentException) {
            logger.error("Invalid private key format", e)
            throw SignatureException("Invalid private key format: ${e.message}", e)
        } catch (e: Exception) {
            logger.error("Failed to sign message", e)
            throw SignatureException("Failed to sign message: ${e.message}", e)
        } finally {
            // Zero the private key copy to minimize exposure
            privateKey.fill(0)
        }
    }

    /**
     * Signs data and returns a SignedData object containing both
     * the original data, signature, and signer's public key.
     *
     * @param data The data to sign
     * @return A SignedData object containing the data, signature, and public key
     * @throws SignatureException if signing fails (e.g., no identity exists)
     */
    fun sign(data: ByteArray): SignedData {
        val signature = signMessage(data)
        val publicKey = try {
            identityManager.getPublicKey()
        } catch (e: IdentityException) {
            throw SignatureException("Cannot sign: failed to get public key", e)
        }
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
            logger.warn(
                "Invalid public key size: {} bytes, expected {}",
                publicKey.size,
                CryptoProvider.ED25519_PUBLIC_KEY_BYTES
            )
            return false
        }

        if (signature.size != CryptoProvider.ED25519_SIGNATURE_BYTES) {
            logger.warn(
                "Invalid signature size: {} bytes, expected {}",
                signature.size,
                CryptoProvider.ED25519_SIGNATURE_BYTES
            )
            return false
        }

        return try {
            val pubKey = Key.fromBytes(publicKey)
            val valid = cryptoProvider.verify(message, signature, pubKey)
            if (!valid) {
                logger.warn("Signature verification failed for message of {} bytes", message.size)
            } else {
                logger.debug("Signature verified for message of {} bytes", message.size)
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
 *
 * This class makes defensive copies of all byte arrays on construction
 * to ensure immutability. The internal arrays cannot be modified by
 * external code after construction.
 *
 * @property data A copy of the signed data
 * @property signature A copy of the Ed25519 signature (64 bytes)
 * @property signerPublicKey A copy of the signer's Ed25519 public key (32 bytes)
 */
class SignedData private constructor(
    private val _data: ByteArray,
    private val _signature: ByteArray,
    private val _signerPublicKey: ByteArray
) {
    /** Returns a copy of the signed data. */
    val data: ByteArray get() = _data.copyOf()

    /** Returns a copy of the signature. */
    val signature: ByteArray get() = _signature.copyOf()

    /** Returns a copy of the signer's public key. */
    val signerPublicKey: ByteArray get() = _signerPublicKey.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignedData

        if (!_data.contentEquals(other._data)) return false
        if (!_signature.contentEquals(other._signature)) return false
        if (!_signerPublicKey.contentEquals(other._signerPublicKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = _data.contentHashCode()
        result = 31 * result + _signature.contentHashCode()
        result = 31 * result + _signerPublicKey.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "SignedData(dataSize=${_data.size}, signatureSize=${_signature.size}, publicKeySize=${_signerPublicKey.size})"
    }

    companion object {
        /**
         * Creates a new SignedData instance with defensive copies of all arrays.
         *
         * @param data The data that was signed
         * @param signature The Ed25519 signature (64 bytes)
         * @param signerPublicKey The signer's Ed25519 public key (32 bytes)
         * @return A new SignedData instance
         */
        operator fun invoke(
            data: ByteArray,
            signature: ByteArray,
            signerPublicKey: ByteArray
        ): SignedData = SignedData(
            data.copyOf(),
            signature.copyOf(),
            signerPublicKey.copyOf()
        )
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
