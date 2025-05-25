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
            $params = [
                ':username' => $username,
                ':email' => $email,
                ':password_hash' => $passwordHash
            ];

            if (defined('EMAIL_VERIFICATION_ENABLED') && EMAIL_VERIFICATION_ENABLED === true) {
                $verificationToken = bin2hex(random_bytes(32));
                $tokenExpiryTime = date('Y-m-d H:i:s', time() + (defined('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS') ? EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS : 86400));
                
                $sql = "INSERT INTO " . USER_TABLE_NAME . " (username, email, password_hash, verification_token, verification_token_expiry, is_verified, created_at, updated_at) 
                        VALUES (:username, :email, :password_hash, :verification_token, :verification_token_expiry, 0, datetime('now', 'localtime'), datetime('now', 'localtime'))";
                $params[':verification_token'] = $verificationToken;
                $params[':verification_token_expiry'] = $tokenExpiryTime;
                // is_verified defaults to 0 per schema, but explicitly setting it is also fine.
            } else {
                $sql = "INSERT INTO " . USER_TABLE_NAME . " (username, email, password_hash, is_verified, created_at, updated_at) 
                        VALUES (:username, :email, :password_hash, 1, datetime('now', 'localtime'), datetime('now', 'localtime'))";
                // No token needed, is_verified is set to 1
            }
            
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            $userId = $this->pdo->lastInsertId();

            if ($userId && $this->auditLogger) {
                $details = ['username' => $username, 'email' => $email, 'verification_enabled' => (defined('EMAIL_VERIFICATION_ENABLED') && EMAIL_VERIFICATION_ENABLED === true)];
                if (isset($verificationToken)) {
                    $details['verification_token_set'] = true; // Or even log the token if policy allows (not recommended for production logs)
                }
                $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_REGISTERED, (int)$userId, $details);
            }
            return $userId;
        } catch (\PDOException $e) {
            error_log("User creation failed: " . $e->getMessage());
            // Check for specific codes like unique constraint violation
            if ($e->getCode() == 23000 || $e->getCode() == '23000') { 
                // Handle unique constraint violation (username or email already exists)
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
        if ($this->pdo === null) {
            if ($this->auditLogger) {
                $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_FAILED, $userId, ['reason' => 'Database connection not available.']);
            }
            return false;
        }
        
        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        if (!$newPasswordHash) {
            error_log("Password hashing failed during update.");
            if ($this->auditLogger) {
                $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_FAILED, $userId, ['reason' => 'Password hashing failed.']);
            }
            return false;
        }

        try {
            $stmt = $this->pdo->prepare("UPDATE " . USER_TABLE_NAME . " SET password_hash = :password_hash, updated_at = datetime('now') WHERE id = :id");
            $success = $stmt->execute([
                ':password_hash' => $newPasswordHash,
                ':id' => $userId
            ]);

            if ($success) {
                if ($this->auditLogger) {
                    $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_SUCCESS, $userId);
                }
                return true;
            } else {
                if ($this->auditLogger) {
                    $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_FAILED, $userId, ['reason' => 'Database execute failed.']);
                }
                return false;
            }
        } catch (\PDOException $e) {
            error_log("Update password failed: " . $e->getMessage());
            if ($this->auditLogger) {
                $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_FAILED, $userId, ['reason' => 'Database exception: ' . $e->getMessage()]);
            }
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

    /**
     * Finds a user by a valid (non-expired) email verification token.
     *
     * @param string $token The verification token.
     * @return array|null User data array, or null if token not found or expired.
     */
    public function findUserByVerificationToken(string $token): ?array {
        if ($this->pdo === null) return null;
        try {
            $stmt = $this->pdo->prepare(
                "SELECT * FROM " . USER_TABLE_NAME . " 
                 WHERE verification_token = :token 
                 AND verification_token_expiry > datetime('now', 'localtime') 
                 LIMIT 1"
            );
            $stmt->execute([':token' => $token]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            return $user ?: null;
        } catch (\PDOException $e) {
            error_log("Find user by verification token failed: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Marks a user's email address as verified.
     *
     * @param int $userId The ID of the user to verify.
     * @return bool True on success, false on failure.
     */
    public function verifyEmailAddress(int $userId): bool {
        if ($this->pdo === null) return false;
        try {
            $stmt = $this->pdo->prepare(
                "UPDATE " . USER_TABLE_NAME . " 
                 SET is_verified = 1, verification_token = NULL, verification_token_expiry = NULL, updated_at = datetime('now', 'localtime') 
                 WHERE id = :id AND is_verified = 0"
            );
            $stmt->execute([':id' => $userId]);
            
            $success = $stmt->rowCount() > 0;

            if ($success && $this->auditLogger) {
                $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_SUCCESS, $userId);
            }
            return $success;
        } catch (\PDOException $e) {
            error_log("Verify email address failed: " . $e->getMessage());
            return false;
        }
    }


    // --- Placeholders for Email Change Feature ---

    /**
     * Hypothetical method to request an email change (e.g., sends verification to new email).
     * @param int $userId
     * @param string $newEmail
     * @return bool
     */
    public function requestEmailChange(int $userId, string $newEmail): bool {
        // $currentUser = $this->findById($userId);
        // $oldEmail = $currentUser['email'] ?? 'unknown';
        // ... logic to generate a token, store it with new email and user ID ...
        // ... logic to send verification email to $newEmail ...
        
        // if ($this->auditLogger) {
        //     $this->auditLogger->log(
        //         \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_CHANGE_REQUESTED,
        //         $userId,
        //         ['old_email' => $oldEmail, 'new_email' => $newEmail]
        //     );
        // }
        return true; // Placeholder
    }

    /**
     * Hypothetical method to confirm an email change using a token.
     * @param int $userId
     * @param string $token
     * @return bool
     */
    public function confirmEmailChange(int $userId, string $token): bool {
        // ... logic to validate token and find associated new email ...
        // $newEmail = '...'; // Retrieved based on token
        // $oldEmail = '...'; // Retrieved from user record before update

        // if (/* token is valid and email updated successfully */) {
        //     // ... actual email update in database ...
        //     if ($this->auditLogger) {
        //         $this->auditLogger->log(
        //             \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_CHANGE_SUCCESS,
        //             $userId,
        //             ['old_email' => $oldEmail, 'new_email' => $newEmail]
        //         );
        //     }
        //     return true;
        // } else {
        //     if ($this->auditLogger) {
        //         $this->auditLogger->log(
        //             \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_CHANGE_FAILED,
        //             $userId,
        //             ['email_attempted' => $newEmail, 'reason' => 'Invalid token or other error.']
        //         );
        //     }
        //     return false;
        // }
        return true; // Placeholder
    }

    // --- Placeholders for Admin Actions ---

    /**
     * Hypothetical method for an admin to deactivate a user account.
     * This assumes an admin check has already happened before calling this.
     * @param int $adminUserId The ID of the admin performing the action.
     * @param int $targetUserId The ID of the user to deactivate.
     * @return bool
     */
    public function adminDeactivateUser(int $adminUserId, int $targetUserId): bool {
        // ... logic to deactivate user $targetUserId ...
        // $success = ... ; 
        
        // if ($this->auditLogger) {
        //     $this->auditLogger->log(
        //         \LoginSystem\Logging\AuditLoggerService::EVENT_ADMIN_ACTION,
        //         $adminUserId,
        //         [
        //             'action' => 'deactivate_user',
        //             'target_user_id' => $targetUserId,
        //             'success' => $success // example detail
        //         ]
        //     );
        // }
        return true; // Placeholder
    }
    
    /**
     * Hypothetical method for an admin to change a user's role.
     * This assumes an admin check has already happened before calling this.
     * @param int $adminUserId The ID of the admin performing the action.
     * @param int $targetUserId The ID of the user whose role is being changed.
     * @param string $newRole The new role to assign.
     * @return bool
     */
    public function adminChangeUserRole(int $adminUserId, int $targetUserId, string $newRole): bool {
        // ... logic to change role for user $targetUserId ...
        // $success = ... ;

        // if ($this->auditLogger) {
        //     $this->auditLogger->log(
        //         \LoginSystem\Logging\AuditLoggerService::EVENT_ADMIN_ACTION,
        //         $adminUserId,
        //         [
        //             'action' => 'change_user_role',
        //             'target_user_id' => $targetUserId,
        //             'new_role' => $newRole,
        //             'success' => $success // example detail
        //         ]
        //     );
        // }
        return true; // Placeholder
    }
}
?>
