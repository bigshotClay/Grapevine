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
        db.identityQueries.insert("user-1", "key1".toByteArray(), "User 1", null, 1L, now, now)
        db.identityQueries.insert("user-2", "key2".toByteArray(), "User 2", null, 0L, now, now)

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
}
