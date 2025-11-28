package io.grapevine.core.identity

import io.grapevine.core.serialization.ByteArraySerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Handles identity backup and restore operations.
 *
 * Backups are encrypted using AES-256-GCM with a key derived from
 * a user-provided password using PBKDF2.
 *
 * ## Backup File Format (Version 1)
 * The backup file has the following structure:
 * - Magic bytes: 4 bytes ("GVBK" - Grapevine Backup)
 * - Version: 1 byte (currently version 1)
 * - Salt: 16 bytes (random, for PBKDF2 key derivation)
 * - IV: 12 bytes (random, for AES-GCM - standard GCM nonce size)
 * - Ciphertext: Variable length (encrypted JSON + 16-byte GCM auth tag)
 *
 * ## Key Representation
 * - Private key: 64 bytes - Ed25519 expanded private key (32-byte seed + 32-byte public key)
 *   This is the format used by libsodium's crypto_sign_seed_keypair output.
 * - Public key: 32 bytes - Ed25519 public key
 *
 * ## Security Notes
 * - PBKDF2-HMAC-SHA256 with 100,000 iterations is used for key derivation
 * - AES-256-GCM provides authenticated encryption with 128-bit auth tag
 * - Sensitive data (keys, plaintext, password chars) is zeroed after use
 * - Note: SecretKeySpec may internally copy key bytes, so complete memory
 *   clearing is not guaranteed. For higher security requirements, consider
 *   using platform keystore APIs or Destroyable SecretKey implementations.
 *
 * ## Version Compatibility
 * The version byte allows future format changes. When PBKDF2 parameters
 * or encryption algorithms change, the version will be incremented.
 */
class IdentityBackup {
    private val secureRandom = SecureRandom()
    private val logger = LoggerFactory.getLogger(IdentityBackup::class.java)
    private val json = Json { prettyPrint = true }

    /**
     * Exports an identity to an encrypted backup file.
     *
     * The file is written atomically (to a temp file first, then moved) to prevent
     * partial writes on crash. On filesystems that don't support atomic moves,
     * falls back to a non-atomic move.
     *
     * @param privateKey The private key to backup (64 bytes - Ed25519 expanded key)
     * @param identity The identity metadata
     * @param password User-provided password for encryption
     * @param outputFile The file to write the backup to
     * @throws IdentityBackupException if backup fails
     */
    fun exportBackup(
        privateKey: ByteArray,
        identity: Identity,
        password: String,
        outputFile: File
    ) {
        require(password.isNotEmpty()) { "Password cannot be empty" }
        require(privateKey.size == PRIVATE_KEY_SIZE) { "Private key must be $PRIVATE_KEY_SIZE bytes" }

        logger.info("Creating identity backup")

        var plaintext: ByteArray? = null
        var passwordChars: CharArray? = null

        try {
            // Ensure parent directory exists
            val parentDir = outputFile.parentFile
            if (parentDir != null && !parentDir.exists()) {
                if (!parentDir.mkdirs()) {
                    throw IdentityBackupException("Failed to create directory: ${parentDir.absolutePath}")
                }
            }

            // Create backup data
            val backupData = BackupData(
                version = BACKUP_VERSION,
                privateKey = privateKey,
                publicKey = identity.publicKey,
                displayName = identity.displayName,
                avatarHash = identity.avatarHash,
                bio = identity.bio,
                createdAt = identity.createdAt
            )

            // Serialize to JSON
            val jsonData = json.encodeToString(backupData)
            plaintext = jsonData.toByteArray(Charsets.UTF_8)

            // Generate salt and IV
            val salt = ByteArray(SALT_SIZE)
            val iv = ByteArray(IV_SIZE)
            secureRandom.nextBytes(salt)
            secureRandom.nextBytes(iv)

            // Derive key from password
            passwordChars = password.toCharArray()
            val key = deriveKey(passwordChars, salt)

            // Encrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, iv))
            val ciphertext = cipher.doFinal(plaintext)

            // Write backup file atomically: temp file -> rename
            val tempFile = File(parentDir ?: outputFile.absoluteFile.parentFile, "${outputFile.name}.tmp")
            try {
                tempFile.outputStream().use { out ->
                    out.write(BACKUP_MAGIC)
                    out.write(byteArrayOf(BACKUP_VERSION.toByte()))
                    out.write(salt)
                    out.write(iv)
                    out.write(ciphertext)
                }
                // Try atomic move first, fall back to regular move if unsupported
                try {
                    Files.move(
                        tempFile.toPath(),
                        outputFile.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                    )
                } catch (e: AtomicMoveNotSupportedException) {
                    logger.debug("Atomic move not supported, falling back to regular move")
                    Files.move(
                        tempFile.toPath(),
                        outputFile.toPath(),
                        StandardCopyOption.REPLACE_EXISTING
                    )
                }
            } catch (e: Exception) {
                tempFile.delete() // Clean up temp file on failure
                throw e
            }

            logger.info("Identity backup created successfully")
        } catch (e: IdentityBackupException) {
            throw e
        } catch (e: Exception) {
            logger.error("Failed to create identity backup", e)
            throw IdentityBackupException("Failed to create backup", e)
        } finally {
            // Zero sensitive data
            plaintext?.fill(0)
            passwordChars?.fill('\u0000')
        }
    }

    /**
     * Imports an identity from an encrypted backup file.
     *
     * @param backupFile The backup file to import
     * @param password The password used to encrypt the backup
     * @return The restored BackupData containing private key and identity info
     * @throws IdentityBackupException if import fails
     */
    fun importBackup(backupFile: File, password: String): BackupData {
        require(password.isNotEmpty()) { "Password cannot be empty" }
        require(backupFile.exists()) { "Backup file does not exist" }

        logger.info("Importing identity backup")

        var plaintext: ByteArray? = null
        var passwordChars: CharArray? = null

        try {
            val data = backupFile.readBytes()

            // Minimum size check: magic + version + salt + iv + at least GCM auth tag
            // (GCM tag is included in ciphertext, so ciphertext must be at least TAG_SIZE)
            if (data.size < BACKUP_MAGIC.size + 1 + SALT_SIZE + IV_SIZE + TAG_SIZE) {
                throw IdentityBackupException("Invalid backup file: too small")
            }

            val magic = data.copyOfRange(0, BACKUP_MAGIC.size)
            if (!magic.contentEquals(BACKUP_MAGIC)) {
                throw IdentityBackupException("Invalid backup file: bad magic bytes")
            }

            // Read version (mask to unsigned byte)
            val version = data[BACKUP_MAGIC.size].toInt() and 0xFF
            if (version != BACKUP_VERSION) {
                throw IdentityBackupException("Unsupported backup version: $version")
            }

            // Extract components
            var offset = BACKUP_MAGIC.size + 1
            val salt = data.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE
            val iv = data.copyOfRange(offset, offset + IV_SIZE)
            offset += IV_SIZE
            val ciphertext = data.copyOfRange(offset, data.size)

            // Derive key from password
            passwordChars = password.toCharArray()
            val key = deriveKey(passwordChars, salt)

            // Decrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, iv))
            plaintext = try {
                cipher.doFinal(ciphertext)
            } catch (e: Exception) {
                throw IdentityBackupException("Invalid password or corrupted backup")
            }

            // Parse JSON
            val jsonData = plaintext.toString(Charsets.UTF_8)
            val backupData = json.decodeFromString<BackupData>(jsonData)

            // Validate key sizes
            if (backupData.privateKey.size != PRIVATE_KEY_SIZE) {
                throw IdentityBackupException("Invalid backup: bad private key size")
            }
            if (backupData.publicKey.size != PUBLIC_KEY_SIZE) {
                throw IdentityBackupException("Invalid backup: bad public key size")
            }

            logger.info("Identity backup imported successfully")
            return backupData
        } catch (e: IdentityBackupException) {
            throw e
        } catch (e: Exception) {
            logger.error("Failed to import identity backup", e)
            throw IdentityBackupException("Failed to import backup", e)
        } finally {
            // Zero sensitive data
            plaintext?.fill(0)
            passwordChars?.fill('\u0000')
        }
    }

    /**
     * Validates a backup file without fully decrypting it.
     * Checks for valid magic bytes indicating a Grapevine backup.
     *
     * @param backupFile The backup file to validate
     * @return true if the file appears to be a valid Grapevine backup
     */
    fun isValidBackupFile(backupFile: File): Boolean {
        if (!backupFile.exists()) return false
        if (backupFile.length() < BACKUP_MAGIC.size + 1 + SALT_SIZE + IV_SIZE + TAG_SIZE) return false

        return try {
            backupFile.inputStream().use { stream ->
                // Read exactly BACKUP_MAGIC.size bytes, checking we got them all
                val magic = stream.readNBytes(BACKUP_MAGIC.size)
                magic.size == BACKUP_MAGIC.size && magic.contentEquals(BACKUP_MAGIC)
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Derives an AES-256 key from a password using PBKDF2-HMAC-SHA256.
     * Clears the PBEKeySpec and encoded key bytes after use.
     */
    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256)
        try {
            val secret = factory.generateSecret(spec)
            val keyBytes = secret.encoded
            try {
                return SecretKeySpec(keyBytes, "AES")
            } finally {
                keyBytes.fill(0)
            }
        } finally {
            spec.clearPassword()
        }
    }

    companion object {
        /** Magic bytes identifying a Grapevine backup file */
        private val BACKUP_MAGIC = "GVBK".toByteArray(Charsets.UTF_8)
        /** Current backup format version */
        private const val BACKUP_VERSION = 1
        /** Salt size for PBKDF2 key derivation (128 bits) */
        private const val SALT_SIZE = 16
        /** IV size for AES-GCM (96 bits - standard GCM nonce size) */
        private const val IV_SIZE = 12
        /** GCM authentication tag size (128 bits) */
        private const val TAG_SIZE = 16
        /** PBKDF2 iteration count - balance between security and performance */
        private const val PBKDF2_ITERATIONS = 100_000
        /** Ed25519 private key size (seed + public key = 64 bytes) */
        private const val PRIVATE_KEY_SIZE = 64
        /** Ed25519 public key size (32 bytes) */
        private const val PUBLIC_KEY_SIZE = 32
    }
}

/**
 * Data class for serializing backup content.
 * Contains the private key and identity metadata for backup/restore operations.
 */
@Serializable
data class BackupData(
    val version: Int,
    @Serializable(with = ByteArraySerializer::class)
    val privateKey: ByteArray,
    @Serializable(with = ByteArraySerializer::class)
    val publicKey: ByteArray,
    val displayName: String? = null,
    val avatarHash: String? = null,
    val bio: String? = null,
    val createdAt: Long
) {
    /**
     * Converts backup data to an Identity object.
     */
    fun toIdentity(): Identity {
        return Identity(
            publicKey = publicKey,
            displayName = displayName,
            avatarHash = avatarHash,
            bio = bio,
            createdAt = createdAt
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BackupData

        if (version != other.version) return false
        if (!privateKey.contentEquals(other.privateKey)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (displayName != other.displayName) return false
        if (avatarHash != other.avatarHash) return false
        if (bio != other.bio) return false
        if (createdAt != other.createdAt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + (avatarHash?.hashCode() ?: 0)
        result = 31 * result + (bio?.hashCode() ?: 0)
        result = 31 * result + createdAt.hashCode()
        return result
    }
}

/**
 * Exception thrown when backup operations fail.
 */
class IdentityBackupException(message: String, cause: Throwable? = null) : Exception(message, cause)
