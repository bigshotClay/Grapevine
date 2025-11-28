package io.grapevine.storage

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import io.grapevine.storage.db.GrapevineDatabase
import java.io.File

/**
 * Manages the SQLite database connection and schema.
 */
class DatabaseManager(
    private val databasePath: String = getDefaultDatabasePath()
) {
    private var driver: JdbcSqliteDriver? = null
    private var database: GrapevineDatabase? = null

    /**
     * Opens or creates the database.
     */
    fun open(): GrapevineDatabase {
        if (database != null) {
            return database!!
        }

        // Ensure parent directory exists
        File(databasePath).parentFile?.mkdirs()

        val url = "jdbc:sqlite:$databasePath"
        driver = JdbcSqliteDriver(url)

        // Create schema if database is new
        GrapevineDatabase.Schema.create(driver!!)

        database = GrapevineDatabase(driver!!)
        return database!!
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
