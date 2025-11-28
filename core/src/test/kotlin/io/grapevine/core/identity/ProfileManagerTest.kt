package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class ProfileManagerTest {
    private lateinit var secureStorage: InMemorySecureStorage
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var identityManager: IdentityManager
    private lateinit var profileManager: ProfileManager

    // Valid SHA-256 hex hashes for testing
    private val validHash1 = "a".repeat(64)
    private val validHash2 = "b".repeat(64)
    private val validHash3 = "c".repeat(64)

    @BeforeEach
    fun setUp() {
        secureStorage = InMemorySecureStorage()
        cryptoProvider = CryptoProvider()
        identityManager = IdentityManager(secureStorage, cryptoProvider)
        identityManager.initialize()
        profileManager = ProfileManager(identityManager, cryptoProvider)
    }

    @AfterEach
    fun tearDown() {
        identityManager.clearCache()
    }

    @Test
    fun `getProfile returns empty profile initially`() {
        val profile = profileManager.getProfile()

        assertNotNull(profile.publicKey)
        assertNull(profile.displayName)
        assertNull(profile.avatarHash)
        assertNull(profile.bio)
    }

    @Test
    fun `setDisplayName updates display name`() {
        profileManager.setDisplayName("Alice")

        val profile = profileManager.getProfile()
        assertEquals("Alice", profile.displayName)
    }

    @Test
    fun `setDisplayName trims whitespace`() {
        profileManager.setDisplayName("  Alice  ")

        val profile = profileManager.getProfile()
        assertEquals("Alice", profile.displayName)
    }

    @Test
    fun `setDisplayName clears with null`() {
        profileManager.setDisplayName("Alice")
        profileManager.setDisplayName(null)

        val profile = profileManager.getProfile()
        assertNull(profile.displayName)
    }

    @Test
    fun `setDisplayName clears with empty string`() {
        profileManager.setDisplayName("Alice")
        profileManager.setDisplayName("  ")

        val profile = profileManager.getProfile()
        assertNull(profile.displayName)
    }

    @Test
    fun `setDisplayName rejects name exceeding max length`() {
        val longName = "a".repeat(Identity.MAX_DISPLAY_NAME_LENGTH + 1)

        assertThrows<IllegalArgumentException> {
            profileManager.setDisplayName(longName)
        }
    }

    @Test
    fun `setDisplayName accepts name at max length`() {
        val maxName = "a".repeat(Identity.MAX_DISPLAY_NAME_LENGTH)

        profileManager.setDisplayName(maxName)

        assertEquals(maxName, profileManager.getProfile().displayName)
    }

    @Test
    fun `setAvatar computes hash and stores it`() {
        val imageData = "fake image data".toByteArray()

        val hash = profileManager.setAvatar(imageData)

        assertNotNull(hash)
        assertEquals(64, hash.length) // SHA-256 hex string
        assertEquals(hash, profileManager.getProfile().avatarHash)
    }

    @Test
    fun `setAvatarHash sets valid hash directly`() {
        profileManager.setAvatarHash(validHash1)

        assertEquals(validHash1, profileManager.getProfile().avatarHash)
    }

    @Test
    fun `setAvatarHash normalizes uppercase to lowercase`() {
        val upperHash = "A".repeat(64)

        profileManager.setAvatarHash(upperHash)

        assertEquals(validHash1, profileManager.getProfile().avatarHash)
    }

    @Test
    fun `setAvatarHash rejects invalid hash format`() {
        assertThrows<IllegalArgumentException> {
            profileManager.setAvatarHash("invalid-hash")
        }
    }

    @Test
    fun `setAvatarHash rejects hash with wrong length`() {
        assertThrows<IllegalArgumentException> {
            profileManager.setAvatarHash("abc123") // Too short
        }
    }

    @Test
    fun `setAvatarHash clears with null`() {
        profileManager.setAvatarHash(validHash1)
        profileManager.setAvatarHash(null)

        assertNull(profileManager.getProfile().avatarHash)
    }

    @Test
    fun `setAvatarHash clears with empty string`() {
        profileManager.setAvatarHash(validHash1)
        profileManager.setAvatarHash("")

        assertNull(profileManager.getProfile().avatarHash)
    }

    @Test
    fun `clearAvatar removes avatar hash`() {
        profileManager.setAvatarHash(validHash1)
        profileManager.clearAvatar()

        assertNull(profileManager.getProfile().avatarHash)
    }

    @Test
    fun `setBio updates bio`() {
        profileManager.setBio("Hello, I'm Alice!")

        assertEquals("Hello, I'm Alice!", profileManager.getProfile().bio)
    }

    @Test
    fun `setBio trims whitespace`() {
        profileManager.setBio("  Hello  ")

        assertEquals("Hello", profileManager.getProfile().bio)
    }

    @Test
    fun `setBio clears with null`() {
        profileManager.setBio("Hello")
        profileManager.setBio(null)

        assertNull(profileManager.getProfile().bio)
    }

    @Test
    fun `setBio rejects bio exceeding max length`() {
        val longBio = "a".repeat(Identity.MAX_BIO_LENGTH + 1)

        assertThrows<IllegalArgumentException> {
            profileManager.setBio(longBio)
        }
    }

    @Test
    fun `setBio accepts bio at max length`() {
        val maxBio = "a".repeat(Identity.MAX_BIO_LENGTH)

        profileManager.setBio(maxBio)

        assertEquals(maxBio, profileManager.getProfile().bio)
    }

    @Test
    fun `updateProfile updates multiple fields at once`() {
        profileManager.updateProfile(
            displayName = "Alice",
            avatarHash = validHash1,
            bio = "Hello!"
        )

        val profile = profileManager.getProfile()
        assertEquals("Alice", profile.displayName)
        assertEquals(validHash1, profile.avatarHash)
        assertEquals("Hello!", profile.bio)
    }

    @Test
    fun `updateProfile clears fields with empty strings`() {
        profileManager.setDisplayName("Alice")
        profileManager.setBio("Hello")
        profileManager.setAvatarHash(validHash1)

        profileManager.updateProfile(
            displayName = "",
            avatarHash = "",
            bio = ""
        )

        val profile = profileManager.getProfile()
        assertNull(profile.displayName)
        assertNull(profile.avatarHash)
        assertNull(profile.bio)
    }

    @Test
    fun `updateProfile rejects invalid avatar hash`() {
        assertThrows<IllegalArgumentException> {
            profileManager.updateProfile(avatarHash = "invalid")
        }
    }

    @Test
    fun `updateProfile validates all fields before applying changes`() {
        profileManager.setDisplayName("Original")

        // Should fail on avatar hash validation without changing displayName
        assertThrows<IllegalArgumentException> {
            profileManager.updateProfile(displayName = "New", avatarHash = "invalid")
        }

        // Original value should be preserved
        assertEquals("Original", profileManager.getProfile().displayName)
    }

    @Test
    fun `updateProfile preserves fields when null is passed`() {
        profileManager.setDisplayName("Alice")
        profileManager.setBio("Hello")

        profileManager.updateProfile(displayName = null, bio = null)

        val profile = profileManager.getProfile()
        assertEquals("Alice", profile.displayName)
        assertEquals("Hello", profile.bio)
    }

    @Test
    fun `createIdentityWithProfile creates identity with profile fields`() {
        val validHash = "a".repeat(64) // Valid SHA-256 hex hash
        profileManager.setDisplayName("Alice")
        profileManager.setAvatarHash(validHash)
        profileManager.setBio("Hello!")

        val identity = profileManager.createIdentityWithProfile()

        assertEquals("Alice", identity.displayName)
        assertEquals(validHash, identity.avatarHash)
        assertEquals("Hello!", identity.bio)
        assertArrayEquals(identityManager.getPublicKey(), identity.publicKey)
    }

    @Test
    fun `loadFromIdentity loads profile data`() {
        val validHash = "b".repeat(64) // Valid SHA-256 hex hash
        val publicKey = identityManager.getPublicKey()
        val identity = Identity(
            publicKey = publicKey,
            displayName = "Bob",
            avatarHash = validHash,
            bio = "I'm Bob"
        )

        profileManager.loadFromIdentity(identity)

        val profile = profileManager.getProfile()
        assertEquals("Bob", profile.displayName)
        assertEquals(validHash, profile.avatarHash)
        assertEquals("I'm Bob", profile.bio)
    }

    @Test
    fun `profile listener is notified on display name change`() {
        var notifiedProfile: Profile? = null
        profileManager.addProfileListener(object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {
                notifiedProfile = profile
            }
        })

        profileManager.setDisplayName("Alice")

        assertNotNull(notifiedProfile)
        assertEquals("Alice", notifiedProfile?.displayName)
    }

    @Test
    fun `profile listener is notified on avatar change`() {
        var notificationCount = 0
        profileManager.addProfileListener(object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {
                notificationCount++
            }
        })

        profileManager.setAvatarHash(validHash1)
        profileManager.setAvatarHash(validHash2)

        assertEquals(2, notificationCount)
    }

    @Test
    fun `profile listener is not notified when value unchanged`() {
        var notificationCount = 0
        profileManager.addProfileListener(object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {
                notificationCount++
            }
        })

        profileManager.setDisplayName("Alice")
        profileManager.setDisplayName("Alice") // Same value

        assertEquals(1, notificationCount)
    }

    @Test
    fun `removeProfileListener stops notifications`() {
        var notificationCount = 0
        val listener = object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {
                notificationCount++
            }
        }
        profileManager.addProfileListener(listener)

        profileManager.setDisplayName("Alice")
        profileManager.removeProfileListener(listener)
        profileManager.setDisplayName("Bob")

        assertEquals(1, notificationCount)
    }

    @Test
    fun `Profile shortId matches public key`() {
        val profile = profileManager.getProfile()
        val identity = identityManager.getIdentity()

        assertEquals(identity.shortId, profile.shortId)
    }

    @Test
    fun `Profile equals and hashCode work correctly`() {
        val publicKey = ByteArray(32)
        val profile1 = Profile(publicKey, "Alice", validHash1, "bio")
        val profile2 = Profile(publicKey.copyOf(), "Alice", validHash1, "bio")
        val profile3 = Profile(publicKey, "Bob", validHash1, "bio")

        assertEquals(profile1, profile2)
        assertEquals(profile1.hashCode(), profile2.hashCode())
        assertNotEquals(profile1, profile3)
    }

    // ==================== ByteArray Immutability Tests ====================

    @Test
    fun `getProfile returns defensive copy of public key`() {
        val profile1 = profileManager.getProfile()
        val profile2 = profileManager.getProfile()

        // Modify the first profile's public key
        profile1.publicKey[0] = 0xFF.toByte()

        // Second profile should be unaffected
        assertFalse(profile1.publicKey.contentEquals(profile2.publicKey))
    }

    @Test
    fun `setAvatar is not affected by caller modifying input array`() {
        val imageData = "original image data".toByteArray()
        val hash = profileManager.setAvatar(imageData)

        // Modify the original array
        imageData.fill(0)

        // Hash should be unchanged
        assertEquals(hash, profileManager.getProfile().avatarHash)
    }

    // ==================== Listener Edge Cases ====================

    @Test
    fun `listener throwing exception does not stop other listeners`() {
        val notificationCount = AtomicInteger(0)

        profileManager.addProfileListener(object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {
                throw RuntimeException("Intentional test exception")
            }
        })
        profileManager.addProfileListener(object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {
                notificationCount.incrementAndGet()
            }
        })

        profileManager.setDisplayName("Alice")

        assertEquals(1, notificationCount.get())
    }

    @Test
    fun `removeProfileListener returns true when listener exists`() {
        val listener = object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {}
        }
        profileManager.addProfileListener(listener)

        assertTrue(profileManager.removeProfileListener(listener))
    }

    @Test
    fun `removeProfileListener returns false when listener not found`() {
        val listener = object : ProfileManager.ProfileUpdateListener {
            override fun onProfileUpdated(profile: Profile) {}
        }

        assertFalse(profileManager.removeProfileListener(listener))
    }

    // ==================== Profile toString Tests ====================

    @Test
    fun `Profile toString does not leak full public key`() {
        val profile = profileManager.getProfile()
        val toString = profile.toString()

        // Should contain shortId, not full key bytes
        assertTrue(toString.contains("shortId="))
        assertFalse(toString.contains("[B@")) // ByteArray toString pattern
    }

    @Test
    fun `Profile toString truncates long bio`() {
        profileManager.setBio("This is a very long bio that should be truncated in the toString output to prevent log spam")
        val profile = profileManager.getProfile()
        val toString = profile.toString()

        assertTrue(toString.contains("..."))
        assertTrue(toString.length < 200) // Reasonable length
    }

    @Test
    fun `Profile toString truncates avatar hash`() {
        profileManager.setAvatarHash(validHash1)
        val profile = profileManager.getProfile()
        val toString = profile.toString()

        // Should show only first 8 chars + "..."
        assertTrue(toString.contains("avatarHash=aaaaaaaa..."))
        assertFalse(toString.contains(validHash1)) // Full hash should not appear
    }

    // ==================== Concurrency Tests ====================

    @Test
    fun `concurrent updates do not cause data corruption`() {
        val executor = Executors.newFixedThreadPool(10)
        val iterations = 100
        val barrier = CyclicBarrier(10)
        val latch = CountDownLatch(10)

        repeat(10) { threadIndex ->
            executor.submit {
                try {
                    barrier.await() // Ensure all threads start together
                    repeat(iterations) { i ->
                        profileManager.setDisplayName("Thread$threadIndex-$i")
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS))
        executor.shutdown()

        // Profile should have a valid value (not corrupted)
        val profile = profileManager.getProfile()
        assertNotNull(profile.displayName)
        assertTrue(profile.displayName!!.startsWith("Thread"))
    }

    @Test
    fun `concurrent listener add and remove does not cause ConcurrentModificationException`() {
        val executor = Executors.newFixedThreadPool(5)
        val iterations = 100
        val latch = CountDownLatch(5)
        val exceptionCount = AtomicInteger(0)

        // 2 threads add/remove listeners
        repeat(2) {
            executor.submit {
                try {
                    repeat(iterations) {
                        val listener = object : ProfileManager.ProfileUpdateListener {
                            override fun onProfileUpdated(profile: Profile) {}
                        }
                        profileManager.addProfileListener(listener)
                        profileManager.removeProfileListener(listener)
                    }
                } catch (e: Exception) {
                    exceptionCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        // 3 threads update profile (which notifies listeners)
        repeat(3) { threadIndex ->
            executor.submit {
                try {
                    repeat(iterations) { i ->
                        profileManager.setDisplayName("Thread$threadIndex-$i")
                    }
                } catch (e: Exception) {
                    exceptionCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS))
        executor.shutdown()

        assertEquals(0, exceptionCount.get())
    }

    // ==================== Validation Edge Cases ====================

    @Test
    fun `setDisplayName validates trimmed length not original length`() {
        // Name with leading/trailing spaces that exceeds max when untrimmed
        // but is valid when trimmed
        val spacePadded = " " + "a".repeat(Identity.MAX_DISPLAY_NAME_LENGTH) + " "

        // This should succeed because we validate the trimmed length
        profileManager.setDisplayName(spacePadded)

        assertEquals("a".repeat(Identity.MAX_DISPLAY_NAME_LENGTH), profileManager.getProfile().displayName)
    }

    @Test
    fun `setBio validates trimmed length not original length`() {
        // Bio with leading/trailing spaces that exceeds max when untrimmed
        val spacePadded = " " + "a".repeat(Identity.MAX_BIO_LENGTH) + " "

        // This should succeed because we validate the trimmed length
        profileManager.setBio(spacePadded)

        assertEquals("a".repeat(Identity.MAX_BIO_LENGTH), profileManager.getProfile().bio)
    }

    @Test
    fun `setDisplayName counts unicode codepoints not chars`() {
        // Emoji is typically 1 codepoint but multiple chars
        val emojiName = "\uD83D\uDE00".repeat(Identity.MAX_DISPLAY_NAME_LENGTH) // 😀

        // Should succeed - each emoji is 1 codepoint
        profileManager.setDisplayName(emojiName)

        assertEquals(emojiName, profileManager.getProfile().displayName)
    }

    @Test
    fun `setDisplayName rejects name exceeding max codepoints`() {
        val emojiName = "\uD83D\uDE00".repeat(Identity.MAX_DISPLAY_NAME_LENGTH + 1)

        assertThrows<IllegalArgumentException> {
            profileManager.setDisplayName(emojiName)
        }
    }
}
