package io.grapevine.core.genesis

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * In-memory implementation of [GenesisStorage] for testing purposes.
 *
 * This implementation stores genesis information in memory and is not persistent.
 * For production use, use a persistent implementation backed by database or preferences.
 *
 * ## Thread Safety
 * This implementation is thread-safe using read-write locks.
 */
class InMemoryGenesisStorage : GenesisStorage {
    private val lock = ReentrantReadWriteLock()
    private var genesisInfo: GenesisInfo? = null

    override fun hasGenesis(): Boolean = lock.read {
        genesisInfo != null
    }

    override fun getGenesisInfo(): GenesisInfo? = lock.read {
        genesisInfo?.let {
            // Return defensive copy
            GenesisInfo(
                publicKey = it.publicKey.copyOf(),
                displayName = it.displayName,
                createdAt = it.createdAt
            )
        }
    }

    override fun setGenesis(genesisInfo: GenesisInfo) = lock.write {
        if (this.genesisInfo != null) {
            throw GenesisException("Genesis already exists")
        }
        // Store defensive copy
        this.genesisInfo = GenesisInfo(
            publicKey = genesisInfo.publicKey.copyOf(),
            displayName = genesisInfo.displayName,
            createdAt = genesisInfo.createdAt
        )
    }

    override fun clearGenesis() = lock.write {
        genesisInfo = null
    }
}
