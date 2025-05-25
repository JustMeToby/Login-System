<?php
// src/Database/Database.php
namespace LoginSystem\Database;

use PDO;
use PDOException;

/**
 * Class Database
 * Handles database connections.
 * @package LoginSystem\Database
 */
class Database {
    private static $pdo = null;

    /**
     * Gets a PDO database connection.
     *
     * Initializes the connection if it hasn't been already.
     * Uses DB_PATH and USER_TABLE_NAME constants from config.php.
     *
     * @return PDO|null The PDO connection object or null on failure.
     */
    public static function getConnection(): ?PDO {
        if (self::$pdo === null) {
            if (!defined('DB_PATH')) {
                // This should ideally be logged or handled more gracefully
                error_log("DB_PATH is not defined. Check config/config.php.");
                return null;
            }

            $dbPath = ROOT_PATH . DB_PATH; // ROOT_PATH should be defined in bootstrap.php

            try {
                self::$pdo = new PDO('sqlite:' . $dbPath);
                self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                self::$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

                // Check if the users table exists, if not, try to create it using schema.sql
                if (defined('USER_TABLE_NAME')) {
                    $stmt = self::$pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='" . USER_TABLE_NAME . "'");
                    if ($stmt->fetch() === false) {
                        // Table doesn't exist, try to create it
                        if (file_exists(ROOT_PATH . 'config/schema.sql')) {
                            $schema = file_get_contents(ROOT_PATH . 'config/schema.sql');
                            // Remove comments from schema SQL to avoid issues with some PDO drivers
                            $schema = preg_replace('%--[^
]*%', '', $schema); // Remove -- comments
                            $schema = preg_replace('%\/\*(?:(?!\*\/)[\s\S])*\*\/%', '', $schema); // Remove /* */ comments
                            $schema = trim($schema);
                            if(!empty($schema)){
                                try {
                                    self::$pdo->exec($schema);
                                } catch (PDOException $e) {
                                    error_log("Failed to create table from schema.sql: " . $e->getMessage());
                                    // Potentially re-throw or handle as critical error
                                    return null;
                                }
                            }
                        } else {
                            error_log("USER_TABLE_NAME '" . USER_TABLE_NAME . "' does not exist and config/schema.sql was not found.");
                            // This is a critical setup error.
                        }
                    }
                }

            } catch (PDOException $e) {
                // Log the error, don't expose details to the user in production
                error_log("Database connection failed: " . $e->getMessage());
                self::$pdo = null; // Ensure pdo is null if connection failed
                // Depending on the application's needs, you might throw an exception here
                // or return null and let the caller handle it.
            }
        }
        return self::$pdo;
    }
}
?>
