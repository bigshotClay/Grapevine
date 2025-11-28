package io.grapevine.core.identity

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Base64

/**
 * Tests for [IdentitySerializer] focusing on:
 * - Round-trip serialization idempotency
 * - Forward/backward compatibility
 * - Defensive copying behavior
 * - Error handling
 */
@OptIn(ExperimentalSerializationApi::class)
class IdentitySerializerTest {

    private val validAvatarHash = "a".repeat(64)
    private val json = Json { ignoreUnknownKeys = false } // Strict JSON for testing
    private val lenientJson = Json { ignoreUnknownKeys = true }

    private fun createTestPublicKey(): ByteArray = ByteArray(32) { it.toByte() }

    private fun encodePublicKey(key: ByteArray): String =
        Base64.getEncoder().encodeToString(key)

    @Nested
    inner class RoundTripTests {

        @Test
        fun `round-trip produces identical bytes - basic identity`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(
                publicKey = publicKey,
                displayName = "Alice",
                avatarHash = validAvatarHash,
                bio = "Hello world",
                createdAt = 1234567890L
            )

            val json1 = json.encodeToString(Identity.serializer(), identity)
            val restored = json.decodeFromString(Identity.serializer(), json1)
            val json2 = json.encodeToString(Identity.serializer(), restored)

            assertEquals(json1, json2, "Serialization should be idempotent")
        }

        @Test
        fun `round-trip with all null optional fields`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(
                publicKey = publicKey,
                createdAt = 12345L
            )

            val json1 = json.encodeToString(Identity.serializer(), identity)
            val restored = json.decodeFromString(Identity.serializer(), json1)
            val json2 = json.encodeToString(Identity.serializer(), restored)

            assertEquals(json1, json2)
            assertNull(restored.displayName)
            assertNull(restored.avatarHash)
            assertNull(restored.bio)
        }

        @Test
        fun `round-trip preserves emoji in displayName`() {
            val publicKey = createTestPublicKey()
            val emojiName = "Alice 😀🎉"
            val identity = Identity(
                publicKey = publicKey,
                displayName = emojiName,
                createdAt = 12345L
            )

            val json1 = json.encodeToString(Identity.serializer(), identity)
            val restored = json.decodeFromString(Identity.serializer(), json1)

            assertEquals(emojiName, restored.displayName)
        }

        @Test
        fun `round-trip preserves createdAt value`() {
            val publicKey = createTestPublicKey()
            val timestamp = 9876543210L
            val identity = Identity(
                publicKey = publicKey,
                createdAt = timestamp
            )

            val serialized = json.encodeToString(Identity.serializer(), identity)
            val restored = json.decodeFromString(Identity.serializer(), serialized)

            assertEquals(timestamp, restored.createdAt)
        }

        @Test
        fun `round-trip normalizes non-canonical input and stabilizes`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)
            val upperHash = "ABCDEF0123456789".repeat(4)
            val nfdName = "cafe\u0301" // NFD form

            // Start with non-canonical JSON (simulating external source)
            val nonCanonicalJson = """{"publicKey":"$publicKeyBase64","displayName":"$nfdName","avatarHash":"$upperHash","bio":"  spaced  ","createdAt":12345}"""

            val restored1 = json.decodeFromString(Identity.serializer(), nonCanonicalJson)
            val json1 = json.encodeToString(Identity.serializer(), restored1)

            val restored2 = json.decodeFromString(Identity.serializer(), json1)
            val json2 = json.encodeToString(Identity.serializer(), restored2)

            // After one normalization pass, subsequent round-trips are stable
            assertEquals(json1, json2, "Should stabilize after first normalization")
            assertEquals("café", restored2.displayName)
            assertEquals(upperHash.lowercase(), restored2.avatarHash)
            assertEquals("spaced", restored2.bio)
        }
    }

    @Nested
    inner class ForwardCompatibilityTests {

        // Note: Forward compatibility with JSON requires ignoreUnknownKeys = true in Json configuration.
        // The serializer's else branch handles formats that can return unknown indices, but JSON
        // needs the configuration option to skip unknown keys before the serializer is invoked.

        @Test
        fun `ignores unknown fields when Json is configured with ignoreUnknownKeys`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            // JSON with extra fields that might be added in future versions
            val futureJson = """{"publicKey":"$publicKeyBase64","displayName":"Alice","avatarHash":null,"bio":null,"createdAt":12345,"newField":"value","anotherNewField":42}"""

            // Should not throw when using lenientJson (ignoreUnknownKeys = true)
            val restored = lenientJson.decodeFromString(Identity.serializer(), futureJson)

            assertEquals("Alice", restored.displayName)
            assertEquals(12345L, restored.createdAt)
        }

        @Test
        fun `ignores unknown nested objects when Json is configured with ignoreUnknownKeys`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            val futureJson = """{"publicKey":"$publicKeyBase64","displayName":"Alice","avatarHash":null,"bio":null,"createdAt":12345,"metadata":{"version":2,"flags":["a","b"]}}"""

            val restored = lenientJson.decodeFromString(Identity.serializer(), futureJson)

            assertEquals("Alice", restored.displayName)
        }

        @Test
        fun `strict Json rejects unknown fields by default`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            val futureJson = """{"publicKey":"$publicKeyBase64","displayName":"Alice","avatarHash":null,"bio":null,"createdAt":12345,"unknownField":"value"}"""

            // Strict json should reject unknown keys
            assertThrows<SerializationException> {
                json.decodeFromString(Identity.serializer(), futureJson)
            }
        }
    }

    @Nested
    inner class BackwardCompatibilityTests {

        @Test
        fun `createdAt defaults to 0 when missing`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            // Older format without createdAt (simulating legacy data)
            // Note: Since our serializer uses a loop with defaults, missing fields get default values
            val legacyJson = """{"publicKey":"$publicKeyBase64","displayName":"Alice","avatarHash":null,"bio":null}"""

            val restored = json.decodeFromString(Identity.serializer(), legacyJson)

            assertEquals(0L, restored.createdAt, "Missing createdAt should default to 0")
        }

        @Test
        fun `handles missing optional string fields`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            val minimalJson = """{"publicKey":"$publicKeyBase64"}"""

            val restored = json.decodeFromString(Identity.serializer(), minimalJson)

            assertNull(restored.displayName)
            assertNull(restored.avatarHash)
            assertNull(restored.bio)
            assertEquals(0L, restored.createdAt)
        }
    }

    @Nested
    inner class DefensiveCopyTests {

        @Test
        fun `deserialized publicKey is independent from any internal buffer`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(
                publicKey = publicKey,
                createdAt = 12345L
            )

            val serialized = json.encodeToString(Identity.serializer(), identity)
            val restored = json.decodeFromString(Identity.serializer(), serialized)

            // Get publicKey and mutate it
            val retrievedKey = restored.publicKey
            retrievedKey[0] = 0xFF.toByte()

            // Identity should be unchanged
            assertEquals(0.toByte(), restored.publicKey[0])
        }

        @Test
        fun `multiple deserializations produce independent instances`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(
                publicKey = publicKey,
                displayName = "Test",
                createdAt = 12345L
            )

            val serialized = json.encodeToString(Identity.serializer(), identity)

            val restored1 = json.decodeFromString(Identity.serializer(), serialized)
            val restored2 = json.decodeFromString(Identity.serializer(), serialized)

            // Should be equal
            assertEquals(restored1, restored2)

            // But publicKey arrays should be independent
            val key1 = restored1.publicKey
            val key2 = restored2.publicKey
            key1[0] = 0xFF.toByte()

            // restored2 should be unchanged
            assertEquals(0.toByte(), restored2.publicKey[0])
        }
    }

    @Nested
    inner class ErrorHandlingTests {

        @Test
        fun `throws SerializationException when publicKey is missing`() {
            val incompleteJson = """{"displayName":"Alice","avatarHash":null,"bio":null,"createdAt":12345}"""

            val exception = assertThrows<SerializationException> {
                json.decodeFromString(Identity.serializer(), incompleteJson)
            }

            assertTrue(exception.message?.contains("publicKey") == true)
        }

        @Test
        fun `throws on invalid publicKey base64`() {
            val invalidJson = """{"publicKey":"not-valid-base64!!!","displayName":"Alice","avatarHash":null,"bio":null,"createdAt":12345}"""

            assertThrows<IllegalArgumentException> {
                json.decodeFromString(Identity.serializer(), invalidJson)
            }
        }

        @Test
        fun `throws on publicKey with wrong length`() {
            val shortKey = ByteArray(16)
            val shortKeyBase64 = encodePublicKey(shortKey)

            val invalidJson = """{"publicKey":"$shortKeyBase64","displayName":"Alice","avatarHash":null,"bio":null,"createdAt":12345}"""

            assertThrows<IllegalArgumentException> {
                json.decodeFromString(Identity.serializer(), invalidJson)
            }
        }

        @Test
        fun `validation errors from Identity constructor propagate`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            // Display name with control character
            val invalidJson = """{"publicKey":"$publicKeyBase64","displayName":"Test\u0000Name","avatarHash":null,"bio":null,"createdAt":12345}"""

            assertThrows<IllegalArgumentException> {
                json.decodeFromString(Identity.serializer(), invalidJson)
            }
        }
    }

    @Nested
    inner class DescriptorTests {

        @Test
        fun `descriptor has correct element count`() {
            assertEquals(5, IdentitySerializer.descriptor.elementsCount)
        }

        @Test
        fun `descriptor has correct element names`() {
            val descriptor = IdentitySerializer.descriptor
            assertEquals("publicKey", descriptor.getElementName(0))
            assertEquals("displayName", descriptor.getElementName(1))
            assertEquals("avatarHash", descriptor.getElementName(2))
            assertEquals("bio", descriptor.getElementName(3))
            assertEquals("createdAt", descriptor.getElementName(4))
        }

        @Test
        fun `serialized JSON uses correct field names`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(
                publicKey = publicKey,
                displayName = "Alice",
                avatarHash = validAvatarHash,
                bio = "Hello",
                createdAt = 12345L
            )

            val jsonElement = json.encodeToJsonElement(Identity.serializer(), identity)
            val jsonObject = jsonElement.jsonObject

            assertTrue(jsonObject.containsKey("publicKey"))
            assertTrue(jsonObject.containsKey("displayName"))
            assertTrue(jsonObject.containsKey("avatarHash"))
            assertTrue(jsonObject.containsKey("bio"))
            assertTrue(jsonObject.containsKey("createdAt"))
        }
    }

    @Nested
    inner class CreatedAtSemanticsTests {

        @Test
        fun `createdAt of 0 indicates deserialized data with missing timestamp`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            // Legacy data without createdAt
            val legacyJson = """{"publicKey":"$publicKeyBase64","displayName":"Alice","avatarHash":null,"bio":null}"""

            val restored = json.decodeFromString(Identity.serializer(), legacyJson)

            assertEquals(0L, restored.createdAt)
        }

        @Test
        fun `new Identity instances have non-zero createdAt`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(publicKey = publicKey)

            assertTrue(identity.createdAt > 0, "New instances should have current timestamp")
        }

        @Test
        fun `explicit createdAt of 0 is preserved through serialization`() {
            val publicKey = createTestPublicKey()
            val identity = Identity(
                publicKey = publicKey,
                createdAt = 0L // Explicit zero
            )

            val serialized = json.encodeToString(Identity.serializer(), identity)
            val restored = json.decodeFromString(Identity.serializer(), serialized)

            assertEquals(0L, restored.createdAt)
        }
    }

    @Nested
    inner class NormalizationDelegationTests {

        @Test
        fun `deserialization delegates normalization to Identity factory`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            // All these should be normalized by Identity's factory
            val jsonWithNonCanonical = """{"publicKey":"$publicKeyBase64","displayName":"  Alice  ","avatarHash":"AABBCCDD${"EE".repeat(28)}","bio":"cafe\u0301","createdAt":12345}"""

            val restored = json.decodeFromString(Identity.serializer(), jsonWithNonCanonical)

            assertEquals("Alice", restored.displayName) // Trimmed
            assertEquals("aabbccdd" + "ee".repeat(28), restored.avatarHash) // Lowercased
            assertEquals("café", restored.bio) // NFC normalized
        }

        @Test
        fun `blank displayName becomes null after deserialization`() {
            val publicKey = createTestPublicKey()
            val publicKeyBase64 = encodePublicKey(publicKey)

            val jsonWithBlank = """{"publicKey":"$publicKeyBase64","displayName":"   ","avatarHash":null,"bio":null,"createdAt":12345}"""

            val restored = json.decodeFromString(Identity.serializer(), jsonWithBlank)

            assertNull(restored.displayName, "Blank displayName should become null")
        }
    }
}
