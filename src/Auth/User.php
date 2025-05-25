<?php
// src/Auth/User.php
namespace LoginSystem\Auth;

use PDO;
use LoginSystem\Database\Database; // Assuming Database class is in this namespace

/**
 * Class User
 * Handles user authentication, registration, and profile management.
 * @package LoginSystem\Auth
 */
class User {
    private ?PDO $pdo;
    private ?\LoginSystem\Logging\AuditLoggerService $auditLogger = null;

    /**
     * User constructor.
     * @param PDO $pdo The database connection object.
     * @param \LoginSystem\Logging\AuditLoggerService|null $auditLogger Optional audit logger service.
     */
    public function __construct(PDO $pdo, ?\LoginSystem\Logging\AuditLoggerService $auditLogger = null) {
        $this->pdo = $pdo;
        $this->auditLogger = $auditLogger;
        if ($this->pdo === null) {
            // This should not happen if Database::getConnection handles errors properly
            error_log("User class instantiated with null PDO object.");
            // Optionally throw an exception
            // throw new \Exception("Database connection is not available.");
        }
    }

    /**
     * Creates a new user in the database.
     *
     * @param string $username The username.
     * @param string $email The email address.
     * @param string $password The plain text password.
     * @return bool|int User ID on success, false on failure.
     */
    public function create(string $username, string $email, string $password) {
        if ($this->pdo === null) return false;

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        if (!$passwordHash) {
            error_log("Password hashing failed.");
            return false;
        }

        try {
            $stmt = $this->pdo->prepare("INSERT INTO " . USER_TABLE_NAME . " (username, email, password_hash, created_at, updated_at) VALUES (:username, :email, :password_hash, datetime('now'), datetime('now'))");
            $stmt->execute([
                ':username' => $username,
                ':email' => $email,
                ':password_hash' => $passwordHash
            ]);
            $userId = $this->pdo->lastInsertId();
            if ($userId && $this->auditLogger) {
                $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_REGISTERED, (int)$userId, ['username' => $username, 'email' => $email]);
            }
            return $userId;
        } catch (\PDOException $e) {
            // Log error, check for specific codes like unique constraint violation (23000)
            error_log("User creation failed: " . $e->getMessage());
            if ($e->getCode() == 23000 || $e->getCode() == '23000') { // SQLite error code for unique constraint
                // Could be username or email, specific check might be needed if desired
                // For now, just return false or a specific error indicator
            }
            return false;
        }
    }

    /**
     * Finds a user by their username or email.
     *
     * @param string $loginIdentifier Username or email.
     * @return array|false User data as an associative array, or false if not found.
     */
    public function findByLogin(string $loginIdentifier) {
        if ($this->pdo === null) return false;
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM " . USER_TABLE_NAME . " WHERE username = :login OR email = :login LIMIT 1");
            $stmt->execute([':login' => $loginIdentifier]);
            return $stmt->fetch();
        } catch (\PDOException $e) {
            error_log("Find by login failed: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Finds a user by their ID.
     *
     * @param int $userId The ID of the user.
     * @return array|false User data as an associative array, or false if not found.
     */
    public function findById(int $userId) {
        if ($this->pdo === null) return false;
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM " . USER_TABLE_NAME . " WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $userId]);
            return $stmt->fetch();
        } catch (\PDOException $e) {
            error_log("Find by ID failed: " . $e->getMessage());
            return false;
        }
    }


    /**
     * Verifies a user's password.
     *
     * @param array $user User data array (must include 'password_hash').
     * @param string $password The plain text password to verify.
     * @return bool True if the password matches, false otherwise.
     */
    public function verifyPassword(array $user, string $password): bool {
        if (empty($user['password_hash'])) {
            return false;
        }
        return password_verify($password, $user['password_hash']);
    }

    /**
     * Updates a user's password.
     *
     * @param int $userId The ID of the user to update.
     * @param string $newPassword The new plain text password.
     * @return bool True on success, false on failure.
     */
    public function updatePassword(int $userId, string $newPassword): bool {
        if ($this->pdo === null) return false;
        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        if (!$newPasswordHash) {
            error_log("Password hashing failed during update.");
            return false;
        }

        try {
            $stmt = $this->pdo->prepare("UPDATE " . USER_TABLE_NAME . " SET password_hash = :password_hash, updated_at = datetime('now') WHERE id = :id");
            return $stmt->execute([
                ':password_hash' => $newPasswordHash,
                ':id' => $userId
            ]);
        } catch (\PDOException $e) {
            error_log("Update password failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Sets a password reset token for a user.
     *
     * @param string $email The email of the user.
     * @param string $token The reset token.
     * @param string $expiry The expiry timestamp (Y-m-d H:i:s format).
     * @return bool True on success, false on failure.
     */
    public function setResetToken(string $email, string $token, string $expiry): bool {
        if ($this->pdo === null) return false;
        try {
            $stmt = $this->pdo->prepare("UPDATE " . USER_TABLE_NAME . " SET reset_token = :token, reset_token_expiry = :expiry, updated_at = datetime('now') WHERE email = :email");
            $result = $stmt->execute([
                ':token' => $token,
                ':expiry' => $expiry,
                ':email' => $email
            ]);
            return $result && $stmt->rowCount() > 0;
        } catch (\PDOException $e) {
            error_log("Set reset token failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Finds a user by a valid (non-expired) password reset token.
     *
     * @param string $token The reset token.
     * @return array|false User data array, or false if token not found or expired.
     */
    public function findUserByResetToken(string $token) {
        if ($this->pdo === null) return false;
        try {
            $stmt = $this->pdo->prepare("SELECT * FROM " . USER_TABLE_NAME . " WHERE reset_token = :token AND reset_token_expiry > datetime('now') LIMIT 1");
            $stmt->execute([':token' => $token]);
            return $stmt->fetch();
        } catch (\PDOException $e) {
            error_log("Find user by reset token failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Clears a user's password reset token and expiry.
     *
     * @param int $userId The ID of the user.
     * @return bool True on success, false on failure.
     */
    public function clearResetToken(int $userId): bool {
        if ($this->pdo === null) return false;
        try {
            $stmt = $this->pdo->prepare("UPDATE " . USER_TABLE_NAME . " SET reset_token = NULL, reset_token_expiry = NULL, updated_at = datetime('now') WHERE id = :id");
            return $stmt->execute([':id' => $userId]);
        } catch (\PDOException $e) {
            error_log("Clear reset token failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Creates the default admin account if it doesn't already exist.
     * Uses ADMIN_USERNAME and ADMIN_PASSWORD from config.php.
     *
     * @return bool True if admin account exists or was created, false on error.
     */
    public function createAdminAccountIfNotExists(): bool {
        if ($this->pdo === null) return false;
        if (!defined('ADMIN_USERNAME') || !defined('ADMIN_PASSWORD')) {
            error_log("Admin username or password not defined in config.");
            return false;
        }

        $adminUsername = ADMIN_USERNAME;
        $adminUser = $this->findByLogin($adminUsername);

        if ($adminUser) {
            return true; // Admin already exists
        }

        // Admin does not exist, try to create
        // Assuming admin uses username as email for simplicity, or you might need ADMIN_EMAIL in config
        $adminEmail = $adminUsername . '@localhost.local'; // Placeholder email
        
        $createdId = $this->create($adminUsername, $adminEmail, ADMIN_PASSWORD);

        if ($createdId) {
            // Optionally log admin creation
            error_log("Default admin account '" . $adminUsername . "' created successfully.");
            return true;
        } else {
            error_log("Failed to create default admin account '" . $adminUsername . "'. Check logs for details (e.g., unique constraint on email if placeholder is reused).");
            return false;
        }
    }
}
?>
