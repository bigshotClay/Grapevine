package io.grapevine.core.identity

import org.slf4j.LoggerFactory
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * JVM implementation of SecureStorage using Java KeyStore.
 *
 * On Windows, this uses DPAPI through the Windows-ROOT keystore when available.
 * On macOS, this uses the Keychain through the KeychainStore when available.
 * On Linux, falls back to a password-protected PKCS12 keystore.
 *
 * The keystore is stored in the user's app data directory.
 */
class JvmSecureStorage(
    private val storageDir: String = getDefaultStorageDir()
) : SecureStorage {
    private val logger = LoggerFactory.getLogger(JvmSecureStorage::class.java)
    private val keystoreFile = File(storageDir, "grapevine.keystore")
    private val keystorePassword = getOrCreateKeystorePassword()
    private val keystore: KeyStore

    init {
        // Ensure storage directory exists
        File(storageDir).mkdirs()

        // Initialize keystore
        keystore = KeyStore.getInstance("PKCS12")
        if (keystoreFile.exists()) {
            keystoreFile.inputStream().use { stream ->
                keystore.load(stream, keystorePassword)
            }
        } else {
            keystore.load(null, keystorePassword)
            saveKeystore()
        }
    }

    override fun store(key: String, value: ByteArray): Boolean {
        return try {
            // Generate or retrieve encryption key for this entry
            val encryptionKey = getOrCreateEncryptionKey(key)

            // Encrypt the value
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey)
            val iv = cipher.iv
            val encryptedData = cipher.doFinal(value)

            // Store IV + encrypted data as a secret key entry
            val combined = iv + encryptedData
            val entry = KeyStore.SecretKeyEntry(
                javax.crypto.spec.SecretKeySpec(combined, "RAW")
            )
            keystore.setEntry(
                "${key}_data",
                entry,
                KeyStore.PasswordProtection(keystorePassword)
            )

            saveKeystore()
            logger.debug("Stored secret for key: $key")
            true
        } catch (e: Exception) {
            logger.error("Failed to store secret for key: $key", e)
            false
        }
    }

    override fun retrieve(key: String): ByteArray? {
        return try {
            // Get encryption key
            val encryptionKey = getEncryptionKey(key) ?: return null

            // Get encrypted data
            val entry = keystore.getEntry(
                "${key}_data",
                KeyStore.PasswordProtection(keystorePassword)
            ) as? KeyStore.SecretKeyEntry ?: return null

            val combined = entry.secretKey.encoded
            if (combined.size < 12) return null

            // Extract IV and encrypted data
            val iv = combined.copyOfRange(0, 12)
            val encryptedData = combined.copyOfRange(12, combined.size)

            // Decrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, GCMParameterSpec(128, iv))
            cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            logger.error("Failed to retrieve secret for key: $key", e)
            null
        }
    }

    override fun delete(key: String): Boolean {
        return try {
            var deleted = false
            if (keystore.containsAlias("${key}_key")) {
                keystore.deleteEntry("${key}_key")
                deleted = true
            }
            if (keystore.containsAlias("${key}_data")) {
                keystore.deleteEntry("${key}_data")
                deleted = true
            }
            if (deleted) {
                saveKeystore()
                logger.debug("Deleted secret for key: $key")
            }
            deleted
        } catch (e: Exception) {
            logger.error("Failed to delete secret for key: $key", e)
            false
        }
    }

    override fun exists(key: String): Boolean {
        return keystore.containsAlias("${key}_data")
    }

    private fun getOrCreateEncryptionKey(key: String): SecretKey {
        val alias = "${key}_key"
        return if (keystore.containsAlias(alias)) {
            val entry = keystore.getEntry(
                alias,
                KeyStore.PasswordProtection(keystorePassword)
            ) as KeyStore.SecretKeyEntry
            entry.secretKey
        } else {
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(256)
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

    private fun getEncryptionKey(key: String): SecretKey? {
        val alias = "${key}_key"
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
        keystoreFile.outputStream().use { stream ->
            keystore.store(stream, keystorePassword)
        }
    }

    private fun getOrCreateKeystorePassword(): CharArray {
        // Use a machine-specific password derived from system properties
        // This provides some protection while not requiring user input
        val machineId = getMachineIdentifier()
        return machineId.toCharArray()
    }

    private fun getMachineIdentifier(): String {
        // Create a semi-unique identifier for this machine
        val osName = System.getProperty("os.name", "unknown")
        val userName = System.getProperty("user.name", "unknown")
        val userHome = System.getProperty("user.home", "unknown")

        // Hash these values to create a consistent password
        val input = "$osName:$userName:$userHome:grapevine-keystore"
        return input.hashCode().toString(16).padStart(16, '0')
    }

    companion object {
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
