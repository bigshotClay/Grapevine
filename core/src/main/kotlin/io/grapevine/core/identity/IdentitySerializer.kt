package io.grapevine.core.identity

import io.grapevine.core.serialization.ByteArraySerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
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
 */
@OptIn(ExperimentalSerializationApi::class)
object IdentitySerializer : KSerializer<Identity> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Identity") {
        element<String>("publicKey")
        element<String?>("displayName")
        element<String?>("avatarHash")
        element<String?>("bio")
        element<Long>("createdAt")
    }

    override fun serialize(encoder: Encoder, value: Identity) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, ByteArraySerializer, value.publicKey)
            encodeNullableSerializableElement(descriptor, 1, kotlinx.serialization.serializer<String>(), value.displayName)
            encodeNullableSerializableElement(descriptor, 2, kotlinx.serialization.serializer<String>(), value.avatarHash)
            encodeNullableSerializableElement(descriptor, 3, kotlinx.serialization.serializer<String>(), value.bio)
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
                    1 -> displayName = decodeNullableSerializableElement(descriptor, 1, kotlinx.serialization.serializer<String>())
                    2 -> avatarHash = decodeNullableSerializableElement(descriptor, 2, kotlinx.serialization.serializer<String>())
                    3 -> bio = decodeNullableSerializableElement(descriptor, 3, kotlinx.serialization.serializer<String>())
                    4 -> createdAt = decodeLongElement(descriptor, 4)
                    CompositeDecoder.DECODE_DONE -> break
                    else -> error("Unexpected index: $index")
                }
            }

            requireNotNull(publicKey) { "publicKey is required" }

            // Use invoke factory which normalizes all values
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
