package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class IdentityBackupTest {
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var identityBackup: IdentityBackup

    @TempDir
    lateinit var tempDir: Path

    @BeforeEach
    fun setUp() {
        cryptoProvider = CryptoProvider()
        identityBackup = IdentityBackup()
    }

    @Test
    fun `export and import backup successfully`() {
        // Generate a key pair
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(
            publicKey = publicKey,
            displayName = "Test User",
            bio = "This is a test bio",
            createdAt = 1234567890L
        )

        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()
        val password = "testPassword123"

        // Export
        identityBackup.exportBackup(privateKey, identity, password, backupFile)
        assertTrue(backupFile.exists())

        // Import
        val imported = identityBackup.importBackup(backupFile, password)

        assertArrayEquals(privateKey, imported.privateKey)
        assertArrayEquals(publicKey, imported.publicKey)
        assertEquals("Test User", imported.displayName)
        assertEquals("This is a test bio", imported.bio)
        assertEquals(1234567890L, imported.createdAt)
    }

    @Test
    fun `import fails with wrong password`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()

        identityBackup.exportBackup(privateKey, identity, "correctPassword", backupFile)

        assertThrows<IdentityBackupException> {
            identityBackup.importBackup(backupFile, "wrongPassword")
        }
    }

    @Test
    fun `import fails with corrupted file`() {
        val backupFile = tempDir.resolve("corrupted.gvbk").toFile()
        backupFile.writeText("This is not a valid backup file")

        assertThrows<IdentityBackupException> {
            identityBackup.importBackup(backupFile, "anyPassword")
        }
    }

    @Test
    fun `import fails with non-existent file`() {
        val backupFile = tempDir.resolve("nonexistent.gvbk").toFile()

        assertThrows<IllegalArgumentException> {
            identityBackup.importBackup(backupFile, "anyPassword")
        }
    }

    @Test
    fun `export fails with empty password`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()

        assertThrows<IllegalArgumentException> {
            identityBackup.exportBackup(privateKey, identity, "", backupFile)
        }
    }

    @Test
    fun `isValidBackupFile returns true for valid backup`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()

        identityBackup.exportBackup(privateKey, identity, "password", backupFile)

        assertTrue(identityBackup.isValidBackupFile(backupFile))
    }

    @Test
    fun `isValidBackupFile returns false for invalid file`() {
        val invalidFile = tempDir.resolve("invalid.gvbk").toFile()
        invalidFile.writeText("not a backup")

        assertFalse(identityBackup.isValidBackupFile(invalidFile))
    }

    @Test
    fun `isValidBackupFile returns false for non-existent file`() {
        val nonExistent = tempDir.resolve("nonexistent.gvbk").toFile()
        assertFalse(identityBackup.isValidBackupFile(nonExistent))
    }

    @Test
    fun `backup preserves identity metadata`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes
        val validAvatarHash = "a".repeat(64) // Valid 64-char hex string

        val identity = Identity(
            publicKey = publicKey,
            displayName = "Alice",
            avatarHash = validAvatarHash,
            bio = "Hello, I'm Alice!",
            createdAt = 9876543210L
        )

        val backupFile = tempDir.resolve("metadata-backup.gvbk").toFile()
        identityBackup.exportBackup(privateKey, identity, "password", backupFile)

        val imported = identityBackup.importBackup(backupFile, "password")
        val restoredIdentity = imported.toIdentity()

        assertEquals(identity.displayName, restoredIdentity.displayName)
        assertEquals(identity.avatarHash, restoredIdentity.avatarHash)
        assertEquals(identity.bio, restoredIdentity.bio)
        assertEquals(identity.createdAt, restoredIdentity.createdAt)
        assertArrayEquals(identity.publicKey, restoredIdentity.publicKey)
    }

    @Test
    fun `backup creates parent directories if needed`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("nested/dir/backup.gvbk").toFile()

        identityBackup.exportBackup(privateKey, identity, "password", backupFile)

        assertTrue(backupFile.exists())
        assertTrue(backupFile.parentFile.exists())
    }

    // ==================== Edge Case Tests ====================

    @Test
    fun `isValidBackupFile returns false for truncated file - only magic bytes`() {
        val truncatedFile = tempDir.resolve("truncated.gvbk").toFile()
        truncatedFile.writeBytes("GVBK".toByteArray()) // Only magic, no version/salt/iv

        assertFalse(identityBackup.isValidBackupFile(truncatedFile))
    }

    @Test
    fun `isValidBackupFile returns false for file with wrong magic bytes`() {
        val wrongMagicFile = tempDir.resolve("wrong-magic.gvbk").toFile()
        // Write wrong magic + enough bytes to pass size check
        wrongMagicFile.writeBytes("FAKE".toByteArray() + ByteArray(50))

        assertFalse(identityBackup.isValidBackupFile(wrongMagicFile))
    }

    @Test
    fun `import fails for truncated file`() {
        val truncatedFile = tempDir.resolve("truncated.gvbk").toFile()
        // Write valid magic + version but truncated content
        truncatedFile.writeBytes("GVBK".toByteArray() + byteArrayOf(1) + ByteArray(10))

        val exception = assertThrows<IdentityBackupException> {
            identityBackup.importBackup(truncatedFile, "password")
        }
        assertTrue(
            exception.message?.contains("too small") == true,
            "Expected message to contain 'too small', got: ${exception.message}"
        )
    }

    @Test
    fun `import fails for wrong version`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()

        // Create valid backup first
        identityBackup.exportBackup(privateKey, identity, "password", backupFile)

        // Modify version byte (5th byte, after "GVBK")
        val data = backupFile.readBytes()
        assertTrue(data.size > 4, "Backup file unexpectedly small: ${data.size} bytes")
        data[4] = 99.toByte() // Invalid version
        backupFile.writeBytes(data)

        val exception = assertThrows<IdentityBackupException> {
            identityBackup.importBackup(backupFile, "password")
        }
        assertTrue(
            exception.message?.contains("Unsupported backup version") == true,
            "Expected message to contain 'Unsupported backup version', got: ${exception.message}"
        )
    }

    @Test
    fun `import fails for tampered ciphertext`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()

        identityBackup.exportBackup(privateKey, identity, "password", backupFile)

        // Tamper with ciphertext (flip multiple bytes to ensure detection)
        // Header: 4 (magic) + 1 (version) + 16 (salt) + 12 (iv) = 33 bytes
        // Everything after offset 33 is ciphertext + GCM auth tag
        val data = backupFile.readBytes()
        val headerSize = 33 // magic + version + salt + iv
        assertTrue(
            data.size > headerSize + 16, // At least header + GCM tag size
            "Backup file unexpectedly small: ${data.size} bytes, expected > ${headerSize + 16}"
        )

        // Flip multiple bytes in the ciphertext/auth tag area for robust detection
        for (offset in listOf(data.size - 1, data.size - 5, data.size - 10)) {
            if (offset >= headerSize) {
                data[offset] = (data[offset].toInt() xor 0xFF).toByte()
            }
        }
        backupFile.writeBytes(data)

        val exception = assertThrows<IdentityBackupException> {
            identityBackup.importBackup(backupFile, "password")
        }
        assertTrue(
            exception.message?.contains("Invalid password") == true ||
                exception.message?.contains("corrupted") == true,
            "Expected message to indicate invalid password or corruption, got: ${exception.message}"
        )
    }

    @Test
    fun `isValidBackupFile returns false for empty file`() {
        val emptyFile = tempDir.resolve("empty.gvbk").toFile()
        emptyFile.createNewFile()

        assertFalse(identityBackup.isValidBackupFile(emptyFile))
    }

    @Test
    fun `export fails with invalid private key size`() {
        val publicKey = ByteArray(32) { it.toByte() }
        val invalidPrivateKey = ByteArray(32) { it.toByte() } // Should be 64 bytes

        val identity = Identity(publicKey = publicKey)
        val backupFile = tempDir.resolve("test-backup.gvbk").toFile()

        assertThrows<IllegalArgumentException> {
            identityBackup.exportBackup(invalidPrivateKey, identity, "password", backupFile)
        }
    }

    @Test
    fun `backup round trip preserves equality`() {
        val keyPair = cryptoProvider.generateSigningKeyPair()
        val privateKey = keyPair.secretKey.asBytes
        val publicKey = keyPair.publicKey.asBytes
        val validAvatarHash = "b".repeat(64)

        val identity = Identity(
            publicKey = publicKey,
            displayName = "Bob",
            avatarHash = validAvatarHash,
            bio = "Test bio with unicode: 你好世界 🎉",
            createdAt = 1234567890L
        )

        val backupFile = tempDir.resolve("roundtrip.gvbk").toFile()
        val password = "securePassword123!"

        // Export
        identityBackup.exportBackup(privateKey, identity, password, backupFile)

        // Import
        val imported = identityBackup.importBackup(backupFile, password)

        // Verify
        assertArrayEquals(privateKey, imported.privateKey)
        assertEquals(identity, imported.toIdentity())
    }

    @Test
    fun `import with empty password fails`() {
        val backupFile = tempDir.resolve("test.gvbk").toFile()
        backupFile.writeText("dummy")

        assertThrows<IllegalArgumentException> {
            identityBackup.importBackup(backupFile, "")
        }
    }
}
