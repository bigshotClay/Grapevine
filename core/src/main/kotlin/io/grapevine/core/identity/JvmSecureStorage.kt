package io.grapevine.core.identity

import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * JVM implementation of SecureStorage using a PKCS12 KeyStore.
 *
 * This implementation stores encryption keys in a PKCS12 keystore file and
 * encrypted data in separate files within the storage directory. Each stored
 * entry uses AES-256-GCM encryption with a unique per-entry key.
 *
 * ## Storage Structure
 * - `grapevine.keystore` - PKCS12 keystore containing AES encryption keys
 * - `entries/<key-hash>.enc` - Encrypted data files (IV + ciphertext)
 *
 * ## Security Considerations
 * **WARNING**: The keystore password is derived from machine-specific system properties
 * (OS name, username, home directory). These values are NOT secrets - an attacker with
 * filesystem access and knowledge of the machine/user info can reproduce the password.
 *
 * For production deployments requiring stronger protection, consider:
 * - Integrating with OS-native credential managers (Windows Credential Manager,
 *   macOS Keychain, Linux Secret Service)
 * - Requiring a user-supplied passphrase
 * - Using platform-specific KeyStore types (Windows-MY, KeychainStore)
 *
 * ## Thread Safety
 * This class is thread-safe. All keystore and file operations are synchronized.
 *
 * ## File Permissions
 * On POSIX systems, restrictive permissions (owner read/write only) are set on
 * the storage directory and all created files.
 */
class JvmSecureStorage(
    storageDir: String = getDefaultStorageDir()
) : SecureStorage {
    private val logger = LoggerFactory.getLogger(JvmSecureStorage::class.java)
    private val storagePath: Path = Path.of(storageDir)
    private val keystorePath: Path = storagePath.resolve("grapevine.keystore")
    private val entriesDir: Path = storagePath.resolve("entries")
    private val keystorePassword = getOrCreateKeystorePassword()
    private val keystore: KeyStore
    private val lock = ReentrantReadWriteLock()
    private val secureRandom = SecureRandom()

    init {
        createDirectoryWithPermissions(storagePath)
        createDirectoryWithPermissions(entriesDir)

        keystore = KeyStore.getInstance("PKCS12")
        if (Files.exists(keystorePath)) {
            Files.newInputStream(keystorePath).use { stream ->
                keystore.load(stream, keystorePassword)
            }
        } else {
            keystore.load(null, keystorePassword)
            saveKeystore()
        }
    }

    override fun store(key: String, value: ByteArray): Boolean {
        return lock.write {
            try {
                val keyAlias = sanitizeAlias(key)
                val encryptionKey = getOrCreateEncryptionKey(keyAlias)

                val cipher = Cipher.getInstance(AES_GCM_ALGORITHM)
                val iv = ByteArray(GCM_IV_LENGTH)
                secureRandom.nextBytes(iv)
                cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
                val encryptedData = cipher.doFinal(value)

                val combined = iv + encryptedData
                val entryFile = entriesDir.resolve("$keyAlias.enc")
                writeFileAtomically(entryFile, combined)

                logger.debug("Stored secret for key: {}", key)
                true
            } catch (e: Exception) {
                logger.error("Failed to store secret for key: {}", key, e)
                false
            }
        }
    }

    override fun retrieve(key: String): ByteArray? {
        return lock.read {
            try {
                val keyAlias = sanitizeAlias(key)
                val encryptionKey = getEncryptionKey(keyAlias) ?: return@read null

                val entryFile = entriesDir.resolve("$keyAlias.enc")
                if (!Files.exists(entryFile)) return@read null

                val combined = Files.readAllBytes(entryFile)
                if (combined.size < GCM_IV_LENGTH) {
                    logger.warn("Encrypted data for key {} is too short", key)
                    return@read null
                }

                val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
                val encryptedData = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

                val cipher = Cipher.getInstance(AES_GCM_ALGORITHM)
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
                cipher.doFinal(encryptedData)
            } catch (e: Exception) {
                logger.error("Failed to retrieve secret for key: {}", key, e)
                null
            }
        }
    }

    override fun delete(key: String): Boolean {
        return lock.write {
            try {
                val keyAlias = sanitizeAlias(key)
                var deleted = false

                val keyStoreAlias = "${keyAlias}_key"
                if (keystore.containsAlias(keyStoreAlias)) {
                    keystore.deleteEntry(keyStoreAlias)
                    saveKeystore()
                    deleted = true
                }

                val entryFile = entriesDir.resolve("$keyAlias.enc")
                if (Files.exists(entryFile)) {
                    Files.delete(entryFile)
                    deleted = true
                }

                if (deleted) {
                    logger.debug("Deleted secret for key: {}", key)
                }
                deleted
            } catch (e: Exception) {
                logger.error("Failed to delete secret for key: {}", key, e)
                false
            }
        }
    }

    override fun exists(key: String): Boolean {
        return lock.read {
            val keyAlias = sanitizeAlias(key)
            val entryFile = entriesDir.resolve("$keyAlias.enc")
            Files.exists(entryFile)
        }
    }

    private fun getOrCreateEncryptionKey(keyAlias: String): SecretKey {
        val alias = "${keyAlias}_key"
        return if (keystore.containsAlias(alias)) {
            val entry = keystore.getEntry(
                alias,
                KeyStore.PasswordProtection(keystorePassword)
            ) as KeyStore.SecretKeyEntry
            entry.secretKey
        } else {
            val keyGen = KeyGenerator.getInstance("AES")
            try {
                keyGen.init(AES_KEY_SIZE_BITS, secureRandom)
            } catch (e: Exception) {
                logger.warn("256-bit AES not available, falling back to 128-bit")
                keyGen.init(AES_FALLBACK_KEY_SIZE_BITS, secureRandom)
            }
            val newKey = keyGen.generateKey()
            keystore.setEntry(
                alias,
                KeyStore.SecretKeyEntry(newKey),
                KeyStore.PasswordProtection(keystorePassword)
            )
            saveKeystore()
            newKey
        }
    }

    private fun getEncryptionKey(keyAlias: String): SecretKey? {
        val alias = "${keyAlias}_key"
        return if (keystore.containsAlias(alias)) {
            val entry = keystore.getEntry(
                alias,
                KeyStore.PasswordProtection(keystorePassword)
            ) as? KeyStore.SecretKeyEntry
            entry?.secretKey
        } else {
            null
        }
    }

    private fun saveKeystore() {
        val tempFile = storagePath.resolve("grapevine.keystore.tmp")
        try {
            Files.newOutputStream(
                tempFile,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING
            ).use { stream ->
                keystore.store(stream, keystorePassword)
            }
            setRestrictivePermissions(tempFile)
            Files.move(tempFile, keystorePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: Exception) {
            try {
                Files.deleteIfExists(tempFile)
            } catch (deleteEx: Exception) {
                logger.warn("Failed to delete temp keystore file", deleteEx)
            }
            throw e
        }
    }

    private fun writeFileAtomically(targetPath: Path, data: ByteArray) {
        val tempFile = targetPath.resolveSibling("${targetPath.fileName}.tmp")
        try {
            Files.write(
                tempFile,
                data,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING
            )
            setRestrictivePermissions(tempFile)
            Files.move(tempFile, targetPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: Exception) {
            try {
                Files.deleteIfExists(tempFile)
            } catch (deleteEx: Exception) {
                logger.warn("Failed to delete temp file", deleteEx)
            }
            throw e
        }
    }

    private fun createDirectoryWithPermissions(path: Path) {
        if (!Files.exists(path)) {
            Files.createDirectories(path)
            setRestrictivePermissions(path)
        }
    }

    private fun setRestrictivePermissions(path: Path) {
        try {
            if (isPosixFileSystem(path)) {
                val permissions = PosixFilePermissions.fromString("rw-------")
                Files.setPosixFilePermissions(path, permissions)
            }
        } catch (e: Exception) {
            logger.debug("Could not set restrictive permissions on {}: {}", path, e.message)
        }
    }

    private fun isPosixFileSystem(path: Path): Boolean {
        return try {
            path.fileSystem.supportedFileAttributeViews().contains("posix")
        } catch (e: Exception) {
            false
        }
    }

    private fun sanitizeAlias(key: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(key.toByteArray(Charsets.UTF_8))
        return hash.toHexString()
    }

    private fun getOrCreateKeystorePassword(): CharArray {
        val machineId = deriveMachineIdentifier()
        return machineId.toCharArray()
    }

    private fun deriveMachineIdentifier(): String {
        val osName = System.getProperty("os.name", "unknown")
        val userName = System.getProperty("user.name", "unknown")
        val userHome = System.getProperty("user.home", "unknown")

        val input = "$osName:$userName:$userHome:grapevine-keystore-v1"
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.toHexString()
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val AES_GCM_ALGORITHM = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val AES_KEY_SIZE_BITS = 256
        private const val AES_FALLBACK_KEY_SIZE_BITS = 128

        private fun getDefaultStorageDir(): String {
            val userHome = System.getProperty("user.home")
            return when {
                System.getProperty("os.name").lowercase().contains("win") -> {
                    val appData = System.getenv("APPDATA") ?: "$userHome/AppData/Roaming"
                    "$appData/Grapevine"
                }
                System.getProperty("os.name").lowercase().contains("mac") -> {
                    "$userHome/Library/Application Support/Grapevine"
                }
                else -> {
                    val dataHome = System.getenv("XDG_DATA_HOME") ?: "$userHome/.local/share"
                    "$dataHome/grapevine"
                }
            }
        }
    }
}
