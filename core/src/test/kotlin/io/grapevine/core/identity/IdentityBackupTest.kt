package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.AfterEach
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
        identityBackup = IdentityBackup(cryptoProvider)
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

        val identity = Identity(
            publicKey = publicKey,
            displayName = "Alice",
            avatarHash = "abc123hash",
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
}
