package io.grapevine.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair

/**
 * Provides cryptographic operations using Libsodium via LazySodium.
 *
 * Supports:
 * - Ed25519 signatures for block signing
 * - X25519 key exchange for secure communication
 * - SHA-256 hashing for content addressing
 */
class CryptoProvider {
    private val sodium: LazySodiumJava = LazySodiumJava(SodiumJava())

    /**
     * Generates a new Ed25519 key pair for signing operations.
     *
     * @return A KeyPair containing the public and secret keys
     */
    fun generateSigningKeyPair(): KeyPair {
        return sodium.cryptoSignKeypair()
    }

    /**
     * Generates a new X25519 key pair for key exchange operations.
     *
     * @return A KeyPair containing the public and secret keys
     */
    fun generateBoxKeyPair(): KeyPair {
        return sodium.cryptoBoxKeypair()
    }

    /**
     * Signs a message using Ed25519.
     *
     * @param message The message to sign
     * @param secretKey The secret key to sign with
     * @return The signature bytes
     */
    fun sign(message: ByteArray, secretKey: Key): ByteArray {
        val signature = ByteArray(Sign.ED25519_BYTES)
        sodium.cryptoSignDetached(signature, message, message.size.toLong(), secretKey.asBytes)
        return signature
    }

    /**
     * Verifies an Ed25519 signature.
     *
     * @param message The original message
     * @param signature The signature to verify
     * @param publicKey The public key to verify against
     * @return true if the signature is valid, false otherwise
     */
    fun verify(message: ByteArray, signature: ByteArray, publicKey: Key): Boolean {
        return sodium.cryptoSignVerifyDetached(signature, message, message.size, publicKey.asBytes)
    }

    /**
     * Computes the SHA-256 hash of the given data.
     *
     * @param data The data to hash
     * @return The 32-byte hash
     */
    fun sha256(data: ByteArray): ByteArray {
        val hash = ByteArray(32)
        sodium.cryptoHashSha256(hash, data, data.size.toLong())
        return hash
    }

    /**
     * Performs X25519 key exchange to derive a shared secret.
     *
     * @param ourSecretKey Our secret key
     * @param theirPublicKey Their public key
     * @return The shared secret bytes
     */
    fun keyExchange(ourSecretKey: Key, theirPublicKey: Key): ByteArray {
        val sharedSecret = ByteArray(Box.BEFORENMBYTES)
        sodium.cryptoBoxBeforeNm(sharedSecret, theirPublicKey.asBytes, ourSecretKey.asBytes)
        return sharedSecret
    }

    /**
     * Gets the public key from an Ed25519 secret key or seed.
     *
     * This method supports two input formats:
     * - **64-byte secret key**: The standard libsodium format containing [32-byte seed][32-byte public key].
     *   The public key is extracted directly from the last 32 bytes.
     * - **32-byte seed**: The raw Ed25519 seed. The public key is derived by generating a keypair from the seed.
     *
     * This flexibility accommodates different key storage formats while providing a consistent interface.
     *
     * **Security note**: The returned ByteArray is a copy. Callers handling sensitive key material
     * should consider zeroing arrays when they are no longer needed.
     *
     * @param secretKey Either a 64-byte Ed25519 secret key or a 32-byte seed
     * @return The 32-byte Ed25519 public key (as a new array)
     * @throws IllegalArgumentException if the secret key is not 32 or 64 bytes
     * @see <a href="https://doc.libsodium.org/public-key_cryptography/public-key_signatures">libsodium Ed25519 documentation</a>
     */
    fun getPublicKeyFromSecretKey(secretKey: ByteArray): ByteArray {
        return when (secretKey.size) {
            ED25519_SECRET_KEY_BYTES -> {
                // 64-byte secret key format: [32-byte seed][32-byte public key]
                // Extract the embedded public key
                secretKey.copyOfRange(ED25519_SECRET_KEY_BYTES - ED25519_PUBLIC_KEY_BYTES, ED25519_SECRET_KEY_BYTES)
            }
            ED25519_SEED_BYTES -> {
                // 32-byte seed: derive the keypair and return the public key
                val keyPair = sodium.cryptoSignSeedKeypair(secretKey)
                keyPair.publicKey.asBytes.copyOf()
            }
            else -> throw IllegalArgumentException(
                "Invalid secret key size: expected $ED25519_SECRET_KEY_BYTES or $ED25519_SEED_BYTES bytes, got ${secretKey.size}"
            )
        }
    }

    /**
     * Extracts the public key from an Ed25519 secret key.
     *
     * @deprecated Use [getPublicKeyFromSecretKey] which supports both 64-byte secret keys and 32-byte seeds.
     * @param secretKey The 64-byte Ed25519 secret key
     * @return The 32-byte public key
     * @throws IllegalArgumentException if the secret key is not 64 bytes
     */
    @Deprecated(
        message = "Use getPublicKeyFromSecretKey which supports both 64-byte secret keys and 32-byte seeds",
        replaceWith = ReplaceWith("getPublicKeyFromSecretKey(secretKey)")
    )
    fun extractPublicKeyFromSecretKey(secretKey: ByteArray): ByteArray {
        return getPublicKeyFromSecretKey(secretKey)
    }

    /**
     * Converts Ed25519 public key to X25519 public key for key exchange.
     *
     * @param ed25519PublicKey The Ed25519 public key
     * @return The equivalent X25519 public key
     */
    fun convertEd25519ToX25519PublicKey(ed25519PublicKey: Key): Key {
        val x25519PublicKey = ByteArray(Box.PUBLICKEYBYTES)
        sodium.convertPublicKeyEd25519ToCurve25519(x25519PublicKey, ed25519PublicKey.asBytes)
        return Key.fromBytes(x25519PublicKey)
    }

    /**
     * Converts Ed25519 secret key to X25519 secret key for key exchange.
     *
     * @param ed25519SecretKey The Ed25519 secret key
     * @return The equivalent X25519 secret key
     */
    fun convertEd25519ToX25519SecretKey(ed25519SecretKey: Key): Key {
        val x25519SecretKey = ByteArray(Box.SECRETKEYBYTES)
        sodium.convertSecretKeyEd25519ToCurve25519(x25519SecretKey, ed25519SecretKey.asBytes)
        return Key.fromBytes(x25519SecretKey)
    }

    /**
     * Generates random bytes.
     *
     * @param size The number of random bytes to generate
     * @return The random bytes
     */
    fun randomBytes(size: Int): ByteArray {
        return sodium.randomBytesBuf(size)
    }

    companion object {
        const val ED25519_PUBLIC_KEY_BYTES = Sign.ED25519_PUBLICKEYBYTES
        const val ED25519_SECRET_KEY_BYTES = Sign.ED25519_SECRETKEYBYTES
        const val ED25519_SEED_BYTES = Sign.ED25519_SEEDBYTES
        const val ED25519_SIGNATURE_BYTES = Sign.ED25519_BYTES
        const val X25519_PUBLIC_KEY_BYTES = Box.PUBLICKEYBYTES
        const val X25519_SECRET_KEY_BYTES = Box.SECRETKEYBYTES
        const val SHA256_BYTES = 32
    }
}
