package io.grapevine.network

import nl.tudelft.ipv8.IPv8
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.attestation.trustchain.BlockListener
import nl.tudelft.ipv8.attestation.trustchain.BlockSigner
import nl.tudelft.ipv8.attestation.trustchain.TrustChainBlock
import nl.tudelft.ipv8.attestation.trustchain.TrustChainCommunity
import nl.tudelft.ipv8.attestation.trustchain.TrustChainSettings
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainStore
import nl.tudelft.ipv8.attestation.trustchain.validation.TransactionValidator
import nl.tudelft.ipv8.attestation.trustchain.validation.ValidationResult
import org.slf4j.LoggerFactory

/**
 * Block types used in Grapevine.
 */
object BlockTypes {
    const val INVITE = "grapevine_invite"
    const val POST = "grapevine_post"
    const val FOLLOW = "grapevine_follow"
    const val UNFOLLOW = "grapevine_unfollow"
    const val PROFILE_UPDATE = "grapevine_profile"
}

/**
 * Manages TrustChain operations for Grapevine.
 * Handles block creation, validation, and signing.
 */
class TrustChainManager(
    private val ipv8: IPv8
) {
    private val logger = LoggerFactory.getLogger(TrustChainManager::class.java)
    private val blockListeners = mutableListOf<GrapevineBlockListener>()

    private val trustChain: TrustChainCommunity?
        get() = ipv8.getOverlay()

    init {
        setupValidators()
        setupBlockSigners()
        setupBlockListeners()
    }

    /**
     * Creates a proposal block for a post.
     *
     * @param contentHash The hash of the content
     * @param contentType The type of content (text, image, video)
     * @param metadata Additional metadata for the post
     * @return The created block, or null if creation failed
     */
    fun createPostBlock(
        contentHash: String,
        contentType: String,
        metadata: Map<String, Any?> = emptyMap()
    ): TrustChainBlock? {
        val community = trustChain ?: return null

        val transaction = mapOf(
            "content_hash" to contentHash,
            "content_type" to contentType,
            "timestamp" to System.currentTimeMillis()
        ) + metadata

        return community.createProposalBlock(
            BlockTypes.POST,
            transaction,
            community.myPeer.publicKey.keyToBin()
        )
    }

    /**
     * Creates an invite block to invite a new user to the network.
     *
     * @param inviteePublicKey The public key of the person being invited
     * @param message Optional invitation message
     * @return The created block, or null if creation failed
     */
    fun createInviteBlock(
        inviteePublicKey: ByteArray,
        message: String? = null
    ): TrustChainBlock? {
        val community = trustChain ?: return null

        val transaction = mutableMapOf<String, Any?>(
            "invitee_key" to inviteePublicKey,
            "timestamp" to System.currentTimeMillis()
        )
        if (message != null) {
            transaction["message"] = message
        }

        return community.createProposalBlock(
            BlockTypes.INVITE,
            transaction,
            inviteePublicKey
        )
    }

    /**
     * Creates a follow block to follow another user.
     *
     * @param targetPublicKey The public key of the user to follow
     * @return The created block, or null if creation failed
     */
    fun createFollowBlock(targetPublicKey: ByteArray): TrustChainBlock? {
        val community = trustChain ?: return null

        val transaction = mapOf(
            "target_key" to targetPublicKey,
            "timestamp" to System.currentTimeMillis()
        )

        return community.createProposalBlock(
            BlockTypes.FOLLOW,
            transaction,
            community.myPeer.publicKey.keyToBin()
        )
    }

    /**
     * Creates an unfollow block to stop following another user.
     *
     * @param targetPublicKey The public key of the user to unfollow
     * @return The created block, or null if creation failed
     */
    fun createUnfollowBlock(targetPublicKey: ByteArray): TrustChainBlock? {
        val community = trustChain ?: return null

        val transaction = mapOf(
            "target_key" to targetPublicKey,
            "timestamp" to System.currentTimeMillis()
        )

        return community.createProposalBlock(
            BlockTypes.UNFOLLOW,
            transaction,
            community.myPeer.publicKey.keyToBin()
        )
    }

    /**
     * Creates a profile update block.
     *
     * @param displayName The user's display name
     * @param avatarHash Hash of the avatar image (optional)
     * @param bio User bio (optional)
     * @return The created block, or null if creation failed
     */
    fun createProfileUpdateBlock(
        displayName: String,
        avatarHash: String? = null,
        bio: String? = null
    ): TrustChainBlock? {
        val community = trustChain ?: return null

        val transaction = mutableMapOf<String, Any?>(
            "display_name" to displayName,
            "timestamp" to System.currentTimeMillis()
        )
        avatarHash?.let { transaction["avatar_hash"] = it }
        bio?.let { transaction["bio"] = it }

        return community.createProposalBlock(
            BlockTypes.PROFILE_UPDATE,
            transaction,
            community.myPeer.publicKey.keyToBin()
        )
    }

    /**
     * Gets all blocks of a specific type from the local chain.
     */
    fun getBlocksByType(blockType: String): List<TrustChainBlock> {
        val community = trustChain ?: return emptyList()
        return community.database.getBlocksWithType(blockType)
    }

    /**
     * Gets all blocks for a specific public key.
     */
    fun getBlocksForPublicKey(publicKey: ByteArray): List<TrustChainBlock> {
        val community = trustChain ?: return emptyList()
        return community.database.getMutualBlocks(publicKey, limit = 1000)
    }

    /**
     * Gets the latest block for the current user.
     */
    fun getLatestBlock(): TrustChainBlock? {
        val community = trustChain ?: return null
        return community.database.getLatest(community.myPeer.publicKey.keyToBin())
    }

    /**
     * Crawls the chain of a specific peer to retrieve their blocks.
     */
    suspend fun crawlPeerChain(peer: Peer) {
        val community = trustChain ?: return
        logger.info("Crawling chain for peer: ${peer.mid}")
        community.crawlChain(peer)
    }

    /**
     * Adds a listener for Grapevine blocks.
     */
    fun addBlockListener(listener: GrapevineBlockListener) {
        blockListeners.add(listener)
    }

    /**
     * Removes a block listener.
     */
    fun removeBlockListener(listener: GrapevineBlockListener) {
        blockListeners.remove(listener)
    }

    private fun setupValidators() {
        val community = trustChain ?: return

        // Validate post blocks
        community.registerTransactionValidator(BlockTypes.POST, object : TransactionValidator {
            override fun validate(block: TrustChainBlock, database: TrustChainStore): ValidationResult {
                val hasContentHash = block.transaction["content_hash"] != null
                val hasContentType = block.transaction["content_type"] != null
                return if (hasContentHash && hasContentType || block.isAgreement) {
                    ValidationResult.Valid
                } else {
                    ValidationResult.Invalid(listOf("Missing required fields: content_hash, content_type"))
                }
            }
        })

        // Validate invite blocks
        community.registerTransactionValidator(BlockTypes.INVITE, object : TransactionValidator {
            override fun validate(block: TrustChainBlock, database: TrustChainStore): ValidationResult {
                val hasInviteeKey = block.transaction["invitee_key"] != null
                return if (hasInviteeKey || block.isAgreement) {
                    ValidationResult.Valid
                } else {
                    ValidationResult.Invalid(listOf("Missing required field: invitee_key"))
                }
            }
        })

        // Validate follow blocks
        community.registerTransactionValidator(BlockTypes.FOLLOW, object : TransactionValidator {
            override fun validate(block: TrustChainBlock, database: TrustChainStore): ValidationResult {
                val hasTargetKey = block.transaction["target_key"] != null
                return if (hasTargetKey || block.isAgreement) {
                    ValidationResult.Valid
                } else {
                    ValidationResult.Invalid(listOf("Missing required field: target_key"))
                }
            }
        })

        // Validate unfollow blocks
        community.registerTransactionValidator(BlockTypes.UNFOLLOW, object : TransactionValidator {
            override fun validate(block: TrustChainBlock, database: TrustChainStore): ValidationResult {
                val hasTargetKey = block.transaction["target_key"] != null
                return if (hasTargetKey || block.isAgreement) {
                    ValidationResult.Valid
                } else {
                    ValidationResult.Invalid(listOf("Missing required field: target_key"))
                }
            }
        })

        // Validate profile update blocks
        community.registerTransactionValidator(BlockTypes.PROFILE_UPDATE, object : TransactionValidator {
            override fun validate(block: TrustChainBlock, database: TrustChainStore): ValidationResult {
                val hasDisplayName = block.transaction["display_name"] != null
                return if (hasDisplayName || block.isAgreement) {
                    ValidationResult.Valid
                } else {
                    ValidationResult.Invalid(listOf("Missing required field: display_name"))
                }
            }
        })
    }

    private fun setupBlockSigners() {
        val community = trustChain ?: return

        // Auto-sign invite blocks (the invitee accepts by signing)
        community.registerBlockSigner(BlockTypes.INVITE, object : BlockSigner {
            override fun onSignatureRequest(block: TrustChainBlock) {
                logger.info("Received invite block signature request: ${block.blockId}")
                // Auto-sign invite blocks to accept invitation
                community.createAgreementBlock(block, mapOf<Any?, Any?>())
                blockListeners.forEach { it.onInviteReceived(block) }
            }
        })
    }

    private fun setupBlockListeners() {
        val community = trustChain ?: return

        community.addListener(BlockTypes.POST, object : BlockListener {
            override fun onBlockReceived(block: TrustChainBlock) {
                logger.debug("Received post block: ${block.blockId}")
                blockListeners.forEach { it.onPostReceived(block) }
            }
        })

        community.addListener(BlockTypes.INVITE, object : BlockListener {
            override fun onBlockReceived(block: TrustChainBlock) {
                logger.debug("Received invite block: ${block.blockId}")
            }
        })

        community.addListener(BlockTypes.FOLLOW, object : BlockListener {
            override fun onBlockReceived(block: TrustChainBlock) {
                logger.debug("Received follow block: ${block.blockId}")
                blockListeners.forEach { it.onFollowReceived(block) }
            }
        })

        community.addListener(BlockTypes.UNFOLLOW, object : BlockListener {
            override fun onBlockReceived(block: TrustChainBlock) {
                logger.debug("Received unfollow block: ${block.blockId}")
                blockListeners.forEach { it.onUnfollowReceived(block) }
            }
        })

        community.addListener(BlockTypes.PROFILE_UPDATE, object : BlockListener {
            override fun onBlockReceived(block: TrustChainBlock) {
                logger.debug("Received profile update block: ${block.blockId}")
                blockListeners.forEach { it.onProfileUpdateReceived(block) }
            }
        })
    }

    /**
     * Listener interface for Grapevine-specific blocks.
     */
    interface GrapevineBlockListener {
        fun onPostReceived(block: TrustChainBlock) {}
        fun onInviteReceived(block: TrustChainBlock) {}
        fun onFollowReceived(block: TrustChainBlock) {}
        fun onUnfollowReceived(block: TrustChainBlock) {}
        fun onProfileUpdateReceived(block: TrustChainBlock) {}
    }

    companion object {
        /**
         * Creates default TrustChain settings.
         */
        fun createDefaultSettings(): TrustChainSettings {
            return TrustChainSettings()
        }
    }
}
