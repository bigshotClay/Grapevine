package io.grapevine.core.identity

import io.grapevine.core.crypto.CryptoProvider
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ProfileManagerTest {
    private lateinit var secureStorage: InMemorySecureStorage
    private lateinit var cryptoProvider: CryptoProvider
    private lateinit var identityManager: IdentityManager
    private lateinit var profileManager: ProfileManager

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
    fun `setAvatarHash sets hash directly`() {
        val hash = "abc123def456"

        profileManager.setAvatarHash(hash)

        assertEquals(hash, profileManager.getProfile().avatarHash)
    }

    @Test
    fun `clearAvatar removes avatar hash`() {
        profileManager.setAvatarHash("somehash")
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
            avatarHash = "hash123",
            bio = "Hello!"
        )

        val profile = profileManager.getProfile()
        assertEquals("Alice", profile.displayName)
        assertEquals("hash123", profile.avatarHash)
        assertEquals("Hello!", profile.bio)
    }

    @Test
    fun `updateProfile clears fields with empty strings`() {
        profileManager.setDisplayName("Alice")
        profileManager.setBio("Hello")
        profileManager.setAvatarHash("hash")

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
        profileManager.setDisplayName("Alice")
        profileManager.setAvatarHash("hash123")
        profileManager.setBio("Hello!")

        val identity = profileManager.createIdentityWithProfile()

        assertEquals("Alice", identity.displayName)
        assertEquals("hash123", identity.avatarHash)
        assertEquals("Hello!", identity.bio)
        assertArrayEquals(identityManager.getPublicKey(), identity.publicKey)
    }

    @Test
    fun `loadFromIdentity loads profile data`() {
        val publicKey = identityManager.getPublicKey()
        val identity = Identity(
            publicKey = publicKey,
            displayName = "Bob",
            avatarHash = "bobhash",
            bio = "I'm Bob"
        )

        profileManager.loadFromIdentity(identity)

        val profile = profileManager.getProfile()
        assertEquals("Bob", profile.displayName)
        assertEquals("bobhash", profile.avatarHash)
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

        profileManager.setAvatarHash("hash1")
        profileManager.setAvatarHash("hash2")

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
        val profile1 = Profile(publicKey, "Alice", "hash", "bio")
        val profile2 = Profile(publicKey.copyOf(), "Alice", "hash", "bio")
        val profile3 = Profile(publicKey, "Bob", "hash", "bio")

        assertEquals(profile1, profile2)
        assertEquals(profile1.hashCode(), profile2.hashCode())
        assertNotEquals(profile1, profile3)
    }
}
