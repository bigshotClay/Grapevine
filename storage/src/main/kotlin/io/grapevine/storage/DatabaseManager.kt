package io.grapevine.storage

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import io.grapevine.storage.db.GrapevineDatabase
import java.io.File

/**
 * Manages the SQLite database connection and schema.
 *
 * Handles database creation and migrations for existing databases.
 */
class DatabaseManager(
    private val databasePath: String = getDefaultDatabasePath()
) {
    private var driver: JdbcSqliteDriver? = null
    private var database: GrapevineDatabase? = null

    /**
     * Opens or creates the database, applying any pending migrations.
     */
    fun open(): GrapevineDatabase {
        if (database != null) {
            return database!!
        }

        // Ensure parent directory exists
        File(databasePath).parentFile?.mkdirs()

        val url = "jdbc:sqlite:$databasePath"
        driver = JdbcSqliteDriver(url)

        // Create schema or migrate existing database
        migrateIfNeeded(driver!!)

        database = GrapevineDatabase(driver!!)
        return database!!
    }

    /**
     * Creates the schema or migrates from an existing version.
     */
    private fun migrateIfNeeded(driver: JdbcSqliteDriver) {
        val currentVersion = getSchemaVersion(driver)
        val targetVersion = GrapevineDatabase.Schema.version

        when {
            currentVersion == 0L -> {
                // New database - create fresh schema
                GrapevineDatabase.Schema.create(driver)
            }
            currentVersion < targetVersion -> {
                // Existing database - apply migrations
                GrapevineDatabase.Schema.migrate(driver, currentVersion, targetVersion)
            }
            // currentVersion >= targetVersion: already up to date
        }
    }

    /**
     * Gets the current schema version from the database.
     * Returns 0 if this is a new database.
     */
    private fun getSchemaVersion(driver: JdbcSqliteDriver): Long {
        return try {
            driver.execute(null, "SELECT 1 FROM identity LIMIT 1", 0, null)
            // Table exists, check for is_genesis column to determine version
            try {
                driver.execute(null, "SELECT is_genesis FROM identity LIMIT 1", 0, null)
                GrapevineDatabase.Schema.version // Current version has is_genesis
            } catch (e: Exception) {
                1L // Version 1 (before is_genesis was added)
            }
        } catch (e: Exception) {
            0L // New database
        }
    }

    /**
     * Creates an in-memory database for testing.
     */
    fun openInMemory(): GrapevineDatabase {
        driver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY)
        GrapevineDatabase.Schema.create(driver!!)
        database = GrapevineDatabase(driver!!)
        return database!!
    }

    /**
     * Gets the current database instance, opening it if necessary.
     */
    fun getDatabase(): GrapevineDatabase {
        return database ?: open()
    }

    /**
     * Closes the database connection.
     */
    fun close() {
        driver?.close()
        driver = null
        database = null
    }

    companion object {
        private fun getDefaultDatabasePath(): String {
            val userHome = System.getProperty("user.home")
            val appDataDir = when {
                System.getProperty("os.name").lowercase().contains("win") -> {
                    System.getenv("APPDATA") ?: "$userHome/AppData/Roaming"
                }
                System.getProperty("os.name").lowercase().contains("mac") -> {
                    "$userHome/Library/Application Support"
                }
                else -> {
                    System.getenv("XDG_DATA_HOME") ?: "$userHome/.local/share"
                }
            }
            return "$appDataDir/Grapevine/grapevine.db"
        }
    }
}
