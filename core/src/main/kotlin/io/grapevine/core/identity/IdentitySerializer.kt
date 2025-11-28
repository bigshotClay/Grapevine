package io.grapevine.core.identity

import io.grapevine.core.serialization.ByteArraySerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.*

/**
 * Custom serializer for [Identity] that ensures canonical values are always serialized
 * and deserialized data is normalized.
 *
 * This serializer:
 * - Reads/writes the normalized [displayName], [avatarHash], and [bio] properties
 * - Normalizes any non-canonical input data during deserialization
 * - Ensures serialize -> deserialize -> serialize produces identical output (idempotent)
 *
 * ## Forward compatibility
 * For JSON deserialization with unknown fields (from newer versions), configure the Json
 * instance with `ignoreUnknownKeys = true`. The serializer handles unknown indices gracefully
 * for formats that support them, but JSON requires this configuration.
 *
 * ## createdAt semantics
 * The [createdAt] field defaults to 0 when missing from serialized data. This is valid
 * because [createdAt] represents the local load/creation time (not a persisted timestamp),
 * and 0 indicates "unknown" for deserialized data. The [Identity] factory method uses
 * [System.currentTimeMillis] for new instances, so 0 only occurs for deserialized data.
 */
@OptIn(ExperimentalSerializationApi::class)
object IdentitySerializer : KSerializer<Identity> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Identity") {
        element("publicKey", ByteArraySerializer.descriptor)
        element<String?>("displayName")
        element<String?>("avatarHash")
        element<String?>("bio")
        element<Long>("createdAt")
    }

    override fun serialize(encoder: Encoder, value: Identity) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, ByteArraySerializer, value.publicKey)
            encodeNullableSerializableElement(descriptor, 1, String.serializer(), value.displayName)
            encodeNullableSerializableElement(descriptor, 2, String.serializer(), value.avatarHash)
            encodeNullableSerializableElement(descriptor, 3, String.serializer(), value.bio)
            encodeLongElement(descriptor, 4, value.createdAt)
        }
    }

    override fun deserialize(decoder: Decoder): Identity {
        return decoder.decodeStructure(descriptor) {
            var publicKey: ByteArray? = null
            var displayName: String? = null
            var avatarHash: String? = null
            var bio: String? = null
            var createdAt: Long = 0

            while (true) {
                when (val index = decodeElementIndex(descriptor)) {
                    0 -> publicKey = decodeSerializableElement(descriptor, 0, ByteArraySerializer)
                    1 -> displayName = decodeNullableSerializableElement(descriptor, 1, String.serializer())
                    2 -> avatarHash = decodeNullableSerializableElement(descriptor, 2, String.serializer())
                    3 -> bio = decodeNullableSerializableElement(descriptor, 3, String.serializer())
                    4 -> createdAt = decodeLongElement(descriptor, 4)
                    CompositeDecoder.DECODE_DONE -> break
                    // Ignore unknown fields for forward compatibility with newer versions
                    else -> continue
                }
            }

            if (publicKey == null) {
                throw SerializationException("Required field 'publicKey' is missing")
            }

            // Use invoke factory which normalizes all values and makes a defensive copy of publicKey
            Identity(
                publicKey = publicKey,
                displayName = displayName,
                avatarHash = avatarHash,
                bio = bio,
                createdAt = createdAt
            )
        }
    }
}
