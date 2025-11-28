package io.grapevine.storage

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DatabaseManagerTest {
    private lateinit var dbManager: DatabaseManager

    @BeforeEach
    fun setUp() {
        dbManager = DatabaseManager()
    }

    @AfterEach
    fun tearDown() {
        dbManager.close()
    }

    @Test
    fun `openInMemory creates database successfully`() {
        val db = dbManager.openInMemory()
        assertNotNull(db)
    }

    @Test
    fun `identity operations work correctly`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Insert an identity
        db.identityQueries.insert(
            id = "test-id-123",
            public_key = "test-public-key".toByteArray(),
            display_name = "Test User",
            avatar_hash = null,
            is_local = 1L,
            is_genesis = 0L,
            created_at = now,
            updated_at = now
        )

        // Retrieve by ID
        val identity = db.identityQueries.getById("test-id-123").executeAsOneOrNull()
        assertNotNull(identity)
        assertEquals("test-id-123", identity?.id)
        assertEquals("Test User", identity?.display_name)
        assertEquals(1L, identity?.is_local)

        // Retrieve local identity
        val localIdentity = db.identityQueries.getLocal().executeAsOneOrNull()
        assertNotNull(localIdentity)
        assertEquals("test-id-123", localIdentity?.id)
    }

    @Test
    fun `follow relationship operations work correctly`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Create two identities
        db.identityQueries.insert("user-1", "key1".toByteArray(), "User 1", null, 1L, 0L, now, now)
        db.identityQueries.insert("user-2", "key2".toByteArray(), "User 2", null, 0L, 0L, now, now)

        // Create follow relationship
        db.followRelationshipQueries.insert(
            id = "follow-1",
            follower_id = "user-1",
            following_id = "user-2",
            status = "active",
            created_at = now,
            updated_at = now
        )

        // Check follower count
        val followerCount = db.followRelationshipQueries.getFollowerCount("user-2").executeAsOne()
        assertEquals(1L, followerCount)

        // Check following count
        val followingCount = db.followRelationshipQueries.getFollowingCount("user-1").executeAsOne()
        assertEquals(1L, followingCount)
    }

    @Test
    fun `user preferences work correctly`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Set a preference
        db.userPreferenceQueries.set("theme", "dark", now)

        // Get the preference
        val value = db.userPreferenceQueries.getValue("theme").executeAsOneOrNull()
        assertEquals("dark", value)

        // Update the preference
        db.userPreferenceQueries.set("theme", "light", now + 1000)

        val updatedValue = db.userPreferenceQueries.getValue("theme").executeAsOneOrNull()
        assertEquals("light", updatedValue)
    }

    @Test
    fun `content metadata and chunks work correctly`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()
        val contentHash = "sha256-abcdef123456"

        // Insert content metadata
        db.contentMetadataQueries.insert(
            content_hash = contentHash,
            content_type = "image",
            file_size = 1024,
            chunk_count = 2,
            chunks_available = 0,
            is_complete = 0L,
            original_filename = "test.jpg",
            mime_type = "image/jpeg",
            width = 800,
            height = 600,
            duration_ms = null,
            created_at = now,
            updated_at = now
        )

        // Insert chunks
        db.contentChunkQueries.insert(
            id = "chunk-1",
            content_hash = contentHash,
            chunk_index = 0,
            chunk_hash = "chunk-hash-1",
            chunk_data = "chunk data 1".toByteArray(),
            created_at = now
        )
        db.contentChunkQueries.insert(
            id = "chunk-2",
            content_hash = contentHash,
            chunk_index = 1,
            chunk_hash = "chunk-hash-2",
            chunk_data = "chunk data 2".toByteArray(),
            created_at = now
        )

        // Verify chunk count
        val chunkCount = db.contentChunkQueries.getChunkCount(contentHash).executeAsOne()
        assertEquals(2L, chunkCount)

        // Update availability
        db.contentMetadataQueries.updateAvailability(
            chunks_available = 2,
            is_complete = 1L,
            updated_at = now + 1000,
            content_hash = contentHash
        )

        // Verify completion
        val metadata = db.contentMetadataQueries.getByHash(contentHash).executeAsOneOrNull()
        assertNotNull(metadata)
        assertEquals(1L, metadata?.is_complete)
        assertEquals(2L, metadata?.chunks_available)
    }

    // ==================== Genesis Identity Tests ====================

    @Test
    fun `hasGenesis returns false when no genesis exists`() {
        val db = dbManager.openInMemory()

        val hasGenesis = db.identityQueries.hasGenesis().executeAsOne()
        assertFalse(hasGenesis)
    }

    @Test
    fun `hasGenesis returns true after setGenesis`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Create an identity
        db.identityQueries.insert(
            id = "genesis-user",
            public_key = "genesis-public-key".toByteArray(),
            display_name = "Genesis User",
            avatar_hash = null,
            is_local = 1L,
            is_genesis = 0L,
            created_at = now,
            updated_at = now
        )

        // Mark as genesis
        db.identityQueries.setGenesis(now, "genesis-user")

        val hasGenesis = db.identityQueries.hasGenesis().executeAsOne()
        assertTrue(hasGenesis)
    }

    @Test
    fun `getGenesis returns the genesis identity`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Create a genesis identity
        db.identityQueries.insert(
            id = "genesis-user",
            public_key = "genesis-public-key".toByteArray(),
            display_name = "Genesis User",
            avatar_hash = null,
            is_local = 1L,
            is_genesis = 1L,
            created_at = now,
            updated_at = now
        )

        val genesis = db.identityQueries.getGenesis().executeAsOneOrNull()
        assertNotNull(genesis)
        assertEquals("genesis-user", genesis?.id)
        assertEquals("Genesis User", genesis?.display_name)
        assertEquals(1L, genesis?.is_genesis)
    }

    @Test
    fun `clearAllGenesis clears existing genesis flags`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Create two identities, both marked as genesis (simulating bad state)
        db.identityQueries.insert(
            id = "user-1",
            public_key = "key1".toByteArray(),
            display_name = "User 1",
            avatar_hash = null,
            is_local = 1L,
            is_genesis = 1L,
            created_at = now,
            updated_at = now
        )
        db.identityQueries.insert(
            id = "user-2",
            public_key = "key2".toByteArray(),
            display_name = "User 2",
            avatar_hash = null,
            is_local = 0L,
            is_genesis = 1L,
            created_at = now,
            updated_at = now
        )

        // Clear all genesis flags
        db.identityQueries.clearAllGenesis(now + 1000)

        // Verify no genesis exists
        val hasGenesis = db.identityQueries.hasGenesis().executeAsOne()
        assertFalse(hasGenesis)

        // Verify both identities have is_genesis = 0
        val user1 = db.identityQueries.getById("user-1").executeAsOneOrNull()
        val user2 = db.identityQueries.getById("user-2").executeAsOneOrNull()
        assertEquals(0L, user1?.is_genesis)
        assertEquals(0L, user2?.is_genesis)
    }

    @Test
    fun `setGenesis after clearAllGenesis ensures single genesis`() {
        val db = dbManager.openInMemory()
        val now = System.currentTimeMillis()

        // Create two identities
        db.identityQueries.insert(
            id = "user-1",
            public_key = "key1".toByteArray(),
            display_name = "User 1",
            avatar_hash = null,
            is_local = 1L,
            is_genesis = 1L, // Start as genesis
            created_at = now,
            updated_at = now
        )
        db.identityQueries.insert(
            id = "user-2",
            public_key = "key2".toByteArray(),
            display_name = "User 2",
            avatar_hash = null,
            is_local = 0L,
            is_genesis = 0L,
            created_at = now,
            updated_at = now
        )

        // Clear all genesis and set user-2 as new genesis
        val updateTime = now + 1000
        db.identityQueries.clearAllGenesis(updateTime)
        db.identityQueries.setGenesis(updateTime, "user-2")

        // Verify only user-2 is genesis
        val user1 = db.identityQueries.getById("user-1").executeAsOneOrNull()
        val user2 = db.identityQueries.getById("user-2").executeAsOneOrNull()
        assertEquals(0L, user1?.is_genesis)
        assertEquals(1L, user2?.is_genesis)

        // Verify getGenesis returns user-2
        val genesis = db.identityQueries.getGenesis().executeAsOneOrNull()
        assertEquals("user-2", genesis?.id)
    }
}
