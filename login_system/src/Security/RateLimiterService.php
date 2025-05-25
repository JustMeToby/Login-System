<?php
// src/Security/RateLimiterService.php
namespace LoginSystem\Security;

use PDO;
use LoginSystem\Logging\AuditLoggerService; // Corrected import

class RateLimiterService {
    private PDO $pdo;
    private ?AuditLoggerService $auditLogger = null; // Corrected type hint

    public function __construct(PDO $pdo, ?AuditLoggerService $auditLogger = null) {
        $this->pdo = $pdo;
        $this->auditLogger = $auditLogger;
    }

    /**
     * Checks if an IP address is allowed to make further login attempts.
     *
     * @param string $ipAddress The IP address to check.
     * @return bool True if attempts are allowed, false if locked out.
     */
    public function checkIpLoginAttempts(string $ipAddress): bool {
        $sql = "SELECT attempts_count, last_attempt_at FROM login_attempts WHERE ip_address = :ip_address";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':ip_address' => $ipAddress]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();

        if ($record) {
            $lastAttemptTime = (int)$record['last_attempt_at'];
            $attemptsCount = (int)$record['attempts_count'];

            // Check for active lockout
            if ($attemptsCount >= MAX_IP_LOGIN_ATTEMPTS && ($currentTime - $lastAttemptTime) < IP_LOCKOUT_SECONDS) {
                return false; // Locked out
            }

            // Check if lockout has expired
            if ($attemptsCount >= MAX_IP_LOGIN_ATTEMPTS && ($currentTime - $lastAttemptTime) >= IP_LOCKOUT_SECONDS) {
                $this->clearIpLoginAttempts($ipAddress); // Lockout expired, clear and allow
                return true;
            }

            // Check if attempts are stale (older than ATTEMPT_COUNT_VALIDITY_SECONDS)
            if (($currentTime - $lastAttemptTime) > ATTEMPT_COUNT_VALIDITY_SECONDS) {
                $this->clearIpLoginAttempts($ipAddress); // Stale attempts, clear and allow
                return true;
            }
        }
        return true; // No record or conditions not met for lockout/staleness
    }

    /**
     * Records a login attempt for an IP address.
     *
     * @param string $ipAddress The IP address making the attempt.
     */
    public function recordIpLoginAttempt(string $ipAddress): void {
        $sqlSelect = "SELECT attempts_count, last_attempt_at FROM login_attempts WHERE ip_address = :ip_address";
        $stmtSelect = $this->pdo->prepare($sqlSelect);
        $stmtSelect->execute([':ip_address' => $ipAddress]);
        $record = $stmtSelect->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();
        $newAttemptsCount = 1;

        if ($record) {
            $lastAttemptTime = (int)$record['last_attempt_at'];
            $currentAttemptsCount = (int)$record['attempts_count'];

            // If last attempt is within validity window, increment count. Otherwise, it's a fresh first attempt.
            if (($currentTime - $lastAttemptTime) <= ATTEMPT_COUNT_VALIDITY_SECONDS) {
                // Check if current attempt count would be for an already expired lockout, then reset
                if ($currentAttemptsCount >= MAX_IP_LOGIN_ATTEMPTS && ($currentTime - $lastAttemptTime) >= IP_LOCKOUT_SECONDS) {
                    $newAttemptsCount = 1; // Lockout expired, this is a new first attempt
                } else {
                    $newAttemptsCount = $currentAttemptsCount + 1;
                }
            } else {
                 // Stale attempts, so reset to 1
                $newAttemptsCount = 1;
            }
        }

        $sqlUpsert = "INSERT INTO login_attempts (ip_address, last_attempt_at, attempts_count)
                      VALUES (:ip_address, :last_attempt_at, :attempts_count)
                      ON CONFLICT(ip_address) DO UPDATE SET
                      last_attempt_at = :last_attempt_at, attempts_count = :attempts_count";
        $stmtUpsert = $this->pdo->prepare($sqlUpsert);
        $stmtUpsert->execute([
            ':ip_address' => $ipAddress,
            ':last_attempt_at' => $currentTime,
            ':attempts_count' => $newAttemptsCount
        ]);

        if ($this->auditLogger && $newAttemptsCount === MAX_IP_LOGIN_ATTEMPTS) {
            $this->auditLogger->log(
                AuditLoggerService::EVENT_ACCOUNT_LOCKED_IP, // Corrected Event Name
                null, // userId is null for IP based events
                ['ip_address' => $ipAddress, 'attempts' => $newAttemptsCount]
            );
        }
    }

    /**
     * Clears all login attempts for a given IP address.
     *
     * @param string $ipAddress The IP address to clear.
     */
    public function clearIpLoginAttempts(string $ipAddress): void {
        $sql = "DELETE FROM login_attempts WHERE ip_address = :ip_address";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':ip_address' => $ipAddress]);
    }

    /**
     * Checks if a user account is allowed to make further login attempts.
     *
     * @param int $userId The ID of the user to check.
     * @return bool True if attempts are allowed, false if locked out.
     */
    public function checkUserLoginAttempts(int $userId): bool {
        $sql = "SELECT attempts_count, last_attempt_at FROM user_specific_attempts 
                WHERE user_id = :user_id AND attempt_type = 'login'";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':user_id' => $userId]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();

        if ($record) {
            $lastAttemptTime = (int)$record['last_attempt_at'];
            $attemptsCount = (int)$record['attempts_count'];

            // Check for active lockout
            if ($attemptsCount >= MAX_USER_LOGIN_ATTEMPTS && ($currentTime - $lastAttemptTime) < USER_LOCKOUT_SECONDS) {
                return false; // Locked out
            }

            // Check if lockout has expired
            if ($attemptsCount >= MAX_USER_LOGIN_ATTEMPTS && ($currentTime - $lastAttemptTime) >= USER_LOCKOUT_SECONDS) {
                $this->clearUserLoginAttempts($userId); // Lockout expired, clear and allow
                return true;
            }

            // Check if attempts are stale
            if (($currentTime - $lastAttemptTime) > ATTEMPT_COUNT_VALIDITY_SECONDS) {
                $this->clearUserLoginAttempts($userId); // Stale attempts, clear and allow
                return true;
            }
        }
        return true; // No record or conditions not met for lockout/staleness
    }

    /**
     * Records a login attempt for a user account.
     *
     * @param int $userId The ID of the user making the attempt.
     */
    public function recordUserLoginAttempt(int $userId): void {
        $sqlSelect = "SELECT attempts_count, last_attempt_at FROM user_specific_attempts 
                      WHERE user_id = :user_id AND attempt_type = 'login'";
        $stmtSelect = $this->pdo->prepare($sqlSelect);
        $stmtSelect->execute([':user_id' => $userId]);
        $record = $stmtSelect->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();
        $newAttemptsCount = 1;
        $attemptType = 'login';

        if ($record) {
            $lastAttemptTime = (int)$record['last_attempt_at'];
            $currentAttemptsCount = (int)$record['attempts_count'];

            if (($currentTime - $lastAttemptTime) <= ATTEMPT_COUNT_VALIDITY_SECONDS) {
                 // Check if current attempt count would be for an already expired lockout, then reset
                if ($currentAttemptsCount >= MAX_USER_LOGIN_ATTEMPTS && ($currentTime - $lastAttemptTime) >= USER_LOCKOUT_SECONDS) {
                    $newAttemptsCount = 1; // Lockout expired, this is a new first attempt
                } else {
                    $newAttemptsCount = $currentAttemptsCount + 1;
                }
            } else {
                // Stale attempts, so reset to 1
                $newAttemptsCount = 1;
            }
        }

        $sqlUpsert = "INSERT INTO user_specific_attempts (user_id, attempt_type, last_attempt_at, attempts_count)
                      VALUES (:user_id, :attempt_type, :last_attempt_at, :attempts_count)
                      ON CONFLICT(user_id, attempt_type) DO UPDATE SET
                      last_attempt_at = :last_attempt_at, attempts_count = :attempts_count";
        $stmtUpsert = $this->pdo->prepare($sqlUpsert);
        $stmtUpsert->execute([
            ':user_id' => $userId,
            ':attempt_type' => $attemptType,
            ':last_attempt_at' => $currentTime,
            ':attempts_count' => $newAttemptsCount
        ]);

        if ($this->auditLogger && $newAttemptsCount === MAX_USER_LOGIN_ATTEMPTS) {
            $this->auditLogger->log(
                AuditLoggerService::EVENT_ACCOUNT_LOCKED_USER, // Corrected Event Name
                $userId,
                ['user_id' => $userId, 'attempts' => $newAttemptsCount]
            );
        }
    }

    /**
     * Clears all login attempts for a given user account.
     *
     * @param int $userId The ID of the user to clear.
     */
    public function clearUserLoginAttempts(int $userId): void {
        $sql = "DELETE FROM user_specific_attempts WHERE user_id = :user_id AND attempt_type = 'login'";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':user_id' => $userId]);
    }

    // Constants for password reset IP tracking
    private const string ATTEMPT_TYPE_PASSWORD_RESET_IP = 'password_reset_ip';
    private const int USER_ID_FOR_IP_ACTIONS = 0; // Using user_id 0 for IP-specific actions not tied to a real user

    /**
     * Checks if an IP address is allowed to make further password reset requests.
     *
     * @param string $ipAddress The IP address to check.
     * @return bool True if requests are allowed, false if locked out.
     */
    public function checkPasswordResetIpAttempts(string $ipAddress): bool {
        $sql = "SELECT attempts_count, last_attempt_at FROM user_specific_attempts 
                WHERE user_id = :user_id AND attempt_type = :attempt_type";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':user_id' => self::USER_ID_FOR_IP_ACTIONS,
            ':attempt_type' => self::ATTEMPT_TYPE_PASSWORD_RESET_IP
        ]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();

        if ($record) {
            $lastAttemptTime = (int)$record['last_attempt_at'];
            $attemptsCount = (int)$record['attempts_count'];

            // Check for active lockout
            if ($attemptsCount >= MAX_RESET_PASSWORD_ATTEMPTS_PER_IP && ($currentTime - $lastAttemptTime) < RESET_PASSWORD_IP_LOCKOUT_SECONDS) {
                return false; // Locked out
            }

            // Check if lockout has expired
            if ($attemptsCount >= MAX_RESET_PASSWORD_ATTEMPTS_PER_IP && ($currentTime - $lastAttemptTime) >= RESET_PASSWORD_IP_LOCKOUT_SECONDS) {
                $this->clearPasswordResetIpAttempts($ipAddress); // Lockout expired, clear and allow
                return true;
            }

            // Check if attempts are stale (using general ATTEMPT_COUNT_VALIDITY_SECONDS for now)
            // Consider if a different validity window is needed for password resets
            if (($currentTime - $lastAttemptTime) > ATTEMPT_COUNT_VALIDITY_SECONDS) {
                $this->clearPasswordResetIpAttempts($ipAddress); // Stale attempts, clear and allow
                return true;
            }
        }
        return true; // No record or conditions not met for lockout/staleness
    }

    /**
     * Records a password reset request attempt for an IP address.
     *
     * @param string $ipAddress The IP address making the attempt.
     */
    public function recordPasswordResetIpAttempt(string $ipAddress): void {
        $sqlSelect = "SELECT attempts_count, last_attempt_at FROM user_specific_attempts 
                      WHERE user_id = :user_id AND attempt_type = :attempt_type";
        $stmtSelect = $this->pdo->prepare($sqlSelect);
        $stmtSelect->execute([
            ':user_id' => self::USER_ID_FOR_IP_ACTIONS,
            ':attempt_type' => self::ATTEMPT_TYPE_PASSWORD_RESET_IP
        ]);
        $record = $stmtSelect->fetch(PDO::FETCH_ASSOC);

        $currentTime = time();
        $newAttemptsCount = 1;

        if ($record) {
            $lastAttemptTime = (int)$record['last_attempt_at'];
            $currentAttemptsCount = (int)$record['attempts_count'];

            // If last attempt is within validity window, increment. Otherwise, it's a fresh first attempt.
            if (($currentTime - $lastAttemptTime) <= ATTEMPT_COUNT_VALIDITY_SECONDS) {
                // Check if current attempt count would be for an already expired lockout, then reset
                if ($currentAttemptsCount >= MAX_RESET_PASSWORD_ATTEMPTS_PER_IP && ($currentTime - $lastAttemptTime) >= RESET_PASSWORD_IP_LOCKOUT_SECONDS) {
                    $newAttemptsCount = 1; // Lockout expired, this is a new first attempt
                } else {
                    $newAttemptsCount = $currentAttemptsCount + 1;
                }
            } else {
                // Stale attempts, so reset to 1
                $newAttemptsCount = 1;
            }
        }

        $sqlUpsert = "INSERT INTO user_specific_attempts (user_id, attempt_type, last_attempt_at, attempts_count)
                      VALUES (:user_id, :attempt_type, :last_attempt_at, :attempts_count)
                      ON CONFLICT(user_id, attempt_type) DO UPDATE SET
                      last_attempt_at = :last_attempt_at, attempts_count = :attempts_count";
        $stmtUpsert = $this->pdo->prepare($sqlUpsert);
        $stmtUpsert->execute([
            ':user_id' => self::USER_ID_FOR_IP_ACTIONS,
            ':attempt_type' => self::ATTEMPT_TYPE_PASSWORD_RESET_IP,
            ':last_attempt_at' => $currentTime,
            ':attempts_count' => $newAttemptsCount
        ]);

        if ($this->auditLogger && $newAttemptsCount === MAX_RESET_PASSWORD_ATTEMPTS_PER_IP) {
            $this->auditLogger->log(
                AuditLoggerService::EVENT_PASSWORD_RESET_IP_LOCKOUT,
                null, // No specific user for this IP-based event
                ['ip_address' => $ipAddress, 'attempts' => $newAttemptsCount]
            );
        }
    }

    /**
     * Clears all password reset attempts for a given IP address.
     *
     * @param string $ipAddress The IP address to clear.
     */
    public function clearPasswordResetIpAttempts(string $ipAddress): void {
        $sql = "DELETE FROM user_specific_attempts 
                WHERE user_id = :user_id AND attempt_type = :attempt_type";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':user_id' => self::USER_ID_FOR_IP_ACTIONS,
            ':attempt_type' => self::ATTEMPT_TYPE_PASSWORD_RESET_IP
        ]);
    }
}

?>
