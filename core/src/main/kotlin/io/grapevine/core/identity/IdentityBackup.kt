package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import io.grapevine.core.serialization.ByteArraySerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.io.File
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
 */
class IdentityBackup(
    private val cryptoProvider: CryptoProvider = CryptoProvider()
) {
    private val logger = LoggerFactory.getLogger(IdentityBackup::class.java)
    private val json = Json { prettyPrint = true }

    /**
     * Exports an identity to an encrypted backup file.
     *
     * @param privateKey The private key to backup (64 bytes)
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
        require(privateKey.size == 64) { "Private key must be 64 bytes" }

        logger.info("Creating identity backup")

        try {
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
            val plaintext = jsonData.toByteArray(Charsets.UTF_8)

            // Generate salt and IV
            val salt = ByteArray(SALT_SIZE)
            val iv = ByteArray(IV_SIZE)
            SecureRandom().nextBytes(salt)
            SecureRandom().nextBytes(iv)

            // Derive key from password
            val key = deriveKey(password, salt)

            // Encrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, iv))
            val ciphertext = cipher.doFinal(plaintext)

            // Write backup file: magic + version + salt + iv + ciphertext
            outputFile.parentFile?.mkdirs()
            outputFile.outputStream().use { out ->
                out.write(BACKUP_MAGIC)
                out.write(byteArrayOf(BACKUP_VERSION.toByte()))
                out.write(salt)
                out.write(iv)
                out.write(ciphertext)
            }

            logger.info("Identity backup created: ${outputFile.absolutePath}")
        } catch (e: Exception) {
            logger.error("Failed to create identity backup", e)
            throw IdentityBackupException("Failed to create backup: ${e.message}", e)
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

        logger.info("Importing identity backup: ${backupFile.absolutePath}")

        try {
            val data = backupFile.readBytes()

            // Verify magic bytes
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
            val key = deriveKey(password, salt)

            // Decrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, iv))
            val plaintext = try {
                cipher.doFinal(ciphertext)
            } catch (e: Exception) {
                throw IdentityBackupException("Invalid password or corrupted backup")
            }

            // Parse JSON
            val jsonData = plaintext.toString(Charsets.UTF_8)
            val backupData = json.decodeFromString<BackupData>(jsonData)

            // Validate
            if (backupData.privateKey.size != 64) {
                throw IdentityBackupException("Invalid backup: bad private key size")
            }
            if (backupData.publicKey.size != 32) {
                throw IdentityBackupException("Invalid backup: bad public key size")
            }

            logger.info("Identity backup imported successfully")
            return backupData
        } catch (e: IdentityBackupException) {
            throw e
        } catch (e: Exception) {
            logger.error("Failed to import identity backup", e)
            throw IdentityBackupException("Failed to import backup: ${e.message}", e)
        }
    }

    /**
     * Validates a backup file without fully decrypting it.
     *
     * @param backupFile The backup file to validate
     * @return true if the file appears to be a valid Grapevine backup
     */
    fun isValidBackupFile(backupFile: File): Boolean {
        if (!backupFile.exists()) return false
        if (backupFile.length() < BACKUP_MAGIC.size + 1 + SALT_SIZE + IV_SIZE + TAG_SIZE) return false

        return try {
            val magic = ByteArray(BACKUP_MAGIC.size)
            backupFile.inputStream().use { it.read(magic) }
            magic.contentEquals(BACKUP_MAGIC)
        } catch (e: Exception) {
            false
        }
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val secret = factory.generateSecret(spec)
        return SecretKeySpec(secret.encoded, "AES")
    }

    companion object {
        private val BACKUP_MAGIC = "GVBK".toByteArray(Charsets.UTF_8) // Grapevine Backup
        private const val BACKUP_VERSION = 1
        private const val SALT_SIZE = 16
        private const val IV_SIZE = 12
        private const val TAG_SIZE = 16
        private const val PBKDF2_ITERATIONS = 100_000
    }
}

/**
 * Data class for serializing backup content.
 */
@Serializable
data class BackupData(
    val version: Int,
    @Serializable(with = io.grapevine.core.serialization.ByteArraySerializer::class)
    val privateKey: ByteArray,
    @Serializable(with = io.grapevine.core.serialization.ByteArraySerializer::class)
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
