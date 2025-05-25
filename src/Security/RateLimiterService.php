<?php
// src/Security/RateLimiterService.php
namespace LoginSystem\Security;

use PDO;

class RateLimiterService {
    private PDO $pdo;
    private ?\LoginSystem\Logging\AuditLoggerService $auditLogger = null;

    // Constants for attempt types - can be expanded
    const TYPE_IP_LOGIN = 'ip_login';
    const TYPE_USER_LOGIN = 'user_login';
    const TYPE_IP_RESET_REQUEST = 'ip_reset_request';
    // Add more types as needed, e.g., TYPE_USER_EMAIL_VERIFICATION_REQUEST

    public function __construct(PDO $pdo, ?\LoginSystem\Logging\AuditLoggerService $auditLogger = null) {
        $this->pdo = $pdo;
        $this->auditLogger = $auditLogger;
    }

    /**
     * Checks if a given identifier (IP or user ID) is currently blocked for a specific attempt type.
     * It also clears expired attempts before checking.
     *
     * @param string $identifier The IP address or user ID.
     * @param string $attemptType The type of attempt (e.g., self::TYPE_IP_LOGIN).
     * @return bool True if blocked, false otherwise.
     */
    public function isBlocked(string $identifier, string $attemptType): bool {
        $this->clearExpiredAttempts($identifier, $attemptType);

        $configMaxAttempts = 0;
        $configLockoutSeconds = 0;
        $configAttemptValiditySeconds = ATTEMPT_COUNT_VALIDITY_SECONDS; // General validity for counting attempts

        switch ($attemptType) {
            case self::TYPE_IP_LOGIN:
                $configMaxAttempts = MAX_IP_LOGIN_ATTEMPTS;
                $configLockoutSeconds = IP_LOCKOUT_SECONDS;
                $table = 'login_attempts';
                $field = 'ip_address';
                break;
            case self::TYPE_USER_LOGIN:
                $configMaxAttempts = MAX_USER_LOGIN_ATTEMPTS;
                $configLockoutSeconds = USER_LOCKOUT_SECONDS;
                $table = 'user_specific_attempts';
                $field = 'user_id'; // Assuming identifier is user_id for this type
                break;
            case self::TYPE_IP_RESET_REQUEST:
                $configMaxAttempts = MAX_RESET_PASSWORD_ATTEMPTS_PER_IP;
                $configLockoutSeconds = RESET_PASSWORD_IP_LOCKOUT_SECONDS;
                $table = 'login_attempts'; // Or a dedicated table if IP reset attempts are tracked differently
                $field = 'ip_address';
                 // Reset password attempts might have a longer validity or just rely on lockout
                $configAttemptValiditySeconds = $configLockoutSeconds; // Example: attempts count for the duration of lockout
                break;
            default:
                return false; // Unknown attempt type
        }

        $sql = "SELECT attempts_count, last_attempt_at FROM {$table} WHERE {$field} = :identifier";
        if ($table === 'user_specific_attempts') {
            $sql .= " AND attempt_type = :attempt_type_condition";
        }
        
        $stmt = $this->pdo->prepare($sql);
        $params = [':identifier' => $identifier];
        if ($table === 'user_specific_attempts') {
            $params[':attempt_type_condition'] = $attemptType;
        }
        $stmt->execute($params);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            // Check if currently within a lockout period from a previous max attempt breach
            if ($row['attempts_count'] >= $configMaxAttempts && (time() - $row['last_attempt_at']) < $configLockoutSeconds) {
                return true; // Still in lockout from exceeding max attempts
            }
            // Check if non-locked out attempts are still high but recent enough to count
            // This logic might be complex if we distinguish between "counting window" and "lockout window" strictly.
            // For simplicity here: if attempts are high, and the last one was recent enough to trigger a new lockout, consider it blocked.
            // The clearExpiredAttempts should handle attempts older than ATTEMPT_COUNT_VALIDITY_SECONDS if not locked out.
            if ($row['attempts_count'] >= $configMaxAttempts) {
                 // If max attempts reached, they are blocked until lockout period from last attempt passes
                 return (time() - $row['last_attempt_at']) < $configLockoutSeconds;
            }
        }
        return false;
    }

    /**
     * Records an attempt for a given identifier and type.
     *
     * @param string $identifier The IP address or user ID.
     * @param string $attemptType The type of attempt.
     */
    public function recordAttempt(string $identifier, string $attemptType): void {
        $this->clearExpiredAttempts($identifier, $attemptType); // Clean up before recording new one

        $table = '';
        $field = '';
        $currentTime = time();

        switch ($attemptType) {
            case self::TYPE_IP_LOGIN:
                $table = 'login_attempts';
                $field = 'ip_address';
                break;
            case self::TYPE_USER_LOGIN:
                $table = 'user_specific_attempts';
                $field = 'user_id';
                break;
            case self::TYPE_IP_RESET_REQUEST:
                $table = 'login_attempts'; // Or dedicated table
                $field = 'ip_address';
                break;
            default:
                return; // Unknown attempt type
        }

        $sqlSelect = "SELECT attempts_count, last_attempt_at FROM {$table} WHERE {$field} = :identifier";
        if ($table === 'user_specific_attempts') {
            $sqlSelect .= " AND attempt_type = :attempt_type_condition";
        }

        $stmtSelect = $this->pdo->prepare($sqlSelect);
        $paramsSelect = [':identifier' => $identifier];
        if ($table === 'user_specific_attempts') {
            $paramsSelect[':attempt_type_condition'] = $attemptType;
        }
        $stmtSelect->execute($paramsSelect);
        $row = $stmtSelect->fetch(PDO::FETCH_ASSOC);

        $newAttemptsCount = 1;
        if ($row) {
            // If last attempt was outside ATTEMPT_COUNT_VALIDITY_SECONDS, reset count, unless it's a lockout scenario
            // This logic is simplified: clearExpiredAttempts handles older, non-locking attempts.
            // Here, we just increment.
            $newAttemptsCount = $row['attempts_count'] + 1;
        }

        $paramsUpsert = [
            ':identifier' => $identifier,
            ':last_attempt_at' => $currentTime,
            ':attempts_count' => $newAttemptsCount
        ];

        if ($table === 'user_specific_attempts') {
            $sqlUpsert = "INSERT INTO user_specific_attempts (user_id, attempt_type, last_attempt_at, attempts_count)
                          VALUES (:identifier, :attempt_type_upsert, :last_attempt_at, :attempts_count)
                          ON CONFLICT(user_id, attempt_type) DO UPDATE SET
                          last_attempt_at = :last_attempt_at, attempts_count = :attempts_count";
            $paramsUpsert[':attempt_type_upsert'] = $attemptType;
        } else { // login_attempts (IP based)
             $sqlUpsert = "INSERT INTO login_attempts (ip_address, last_attempt_at, attempts_count)
                          VALUES (:identifier, :last_attempt_at, :attempts_count)
                          ON CONFLICT(ip_address) DO UPDATE SET
                          last_attempt_at = :last_attempt_at, attempts_count = :attempts_count";
        }
        
        $stmtUpsert = $this->pdo->prepare($sqlUpsert);
        $stmtUpsert->execute($paramsUpsert);

        // Log event if this attempt causes a lockout
        $currentConfigMaxAttempts = 0;
        switch ($attemptType) {
            case self::TYPE_IP_LOGIN: $currentConfigMaxAttempts = MAX_IP_LOGIN_ATTEMPTS; break;
            case self::TYPE_USER_LOGIN: $currentConfigMaxAttempts = MAX_USER_LOGIN_ATTEMPTS; break;
            case self::TYPE_IP_RESET_REQUEST: $currentConfigMaxAttempts = MAX_RESET_PASSWORD_ATTEMPTS_PER_IP; break;
        }

        if ($this->auditLogger && $currentConfigMaxAttempts > 0 && $newAttemptsCount === $currentConfigMaxAttempts) {
            $logEventType = null;
            $logDetails = ['identifier' => $identifier, 'type' => $attemptType, 'count' => $newAttemptsCount];
            $userIdToLog = null;

            if ($attemptType === self::TYPE_IP_LOGIN) {
                $logEventType = \LoginSystem\Logging\AuditLoggerService::EVENT_ACCOUNT_LOCKED_IP;
                // For IP lock, $identifier is the IP, $userIdToLog remains null unless we can associate it
            } elseif ($attemptType === self::TYPE_USER_LOGIN) {
                $logEventType = \LoginSystem\Logging\AuditLoggerService::EVENT_ACCOUNT_LOCKED_USER;
                $userIdToLog = (int)$identifier; // Assuming $identifier is user_id for this type
                $logDetails['user_id'] = $userIdToLog;
            } elseif ($attemptType === self::TYPE_IP_RESET_REQUEST) {
                $logEventType = \LoginSystem\Logging\AuditLoggerService::EVENT_IP_LOCKED_RESET;
                // For IP reset lock, $identifier is the IP
            }
            
            if ($logEventType) {
                $this->auditLogger->log($logEventType, $userIdToLog, $logDetails);
            }
        }
    }

    /**
     * Clears attempts for a given identifier and type. Typically called on successful action.
     *
     * @param string $identifier The IP address or user ID.
     * @param string $attemptType The type of attempt.
     */
    public function clearAttempts(string $identifier, string $attemptType): void {
        $table = '';
        $field = '';
        switch ($attemptType) {
            case self::TYPE_IP_LOGIN:
                $table = 'login_attempts';
                $field = 'ip_address';
                break;
            case self::TYPE_USER_LOGIN:
                $table = 'user_specific_attempts';
                $field = 'user_id';
                break;
            case self::TYPE_IP_RESET_REQUEST:
                // Typically, reset request attempts might not be cleared immediately on one success,
                // but rather expire or get cleared if a global lockout for that IP is lifted.
                // For now, let's make it clearable.
                $table = 'login_attempts'; // Or dedicated table
                $field = 'ip_address';
                break;
            default:
                return; // Unknown attempt type
        }

        $sql = "DELETE FROM {$table} WHERE {$field} = :identifier";
        if ($table === 'user_specific_attempts') {
            $sql .= " AND attempt_type = :attempt_type_condition";
        }
        
        $stmt = $this->pdo->prepare($sql);
        $params = [':identifier' => $identifier];
        if ($table === 'user_specific_attempts') {
            $params[':attempt_type_condition'] = $attemptType;
        }
        $stmt->execute($params);
    }

    /**
     * Clears attempts that are older than the defined validity window,
     * UNLESS they are part of an active lockout.
     *
     * @param string $identifier
     * @param string $attemptType
     */
    private function clearExpiredAttempts(string $identifier, string $attemptType): void {
        $table = '';
        $field = '';
        $configMaxAttempts = 0;
        $configLockoutSeconds = 0;
        $configAttemptValiditySeconds = ATTEMPT_COUNT_VALIDITY_SECONDS;

        switch ($attemptType) {
            case self::TYPE_IP_LOGIN:
                $table = 'login_attempts';
                $field = 'ip_address';
                $configMaxAttempts = MAX_IP_LOGIN_ATTEMPTS;
                $configLockoutSeconds = IP_LOCKOUT_SECONDS;
                break;
            case self::TYPE_USER_LOGIN:
                $table = 'user_specific_attempts';
                $field = 'user_id';
                $configMaxAttempts = MAX_USER_LOGIN_ATTEMPTS;
                $configLockoutSeconds = USER_LOCKOUT_SECONDS;
                break;
            case self::TYPE_IP_RESET_REQUEST:
                $table = 'login_attempts';
                $field = 'ip_address';
                $configMaxAttempts = MAX_RESET_PASSWORD_ATTEMPTS_PER_IP;
                $configLockoutSeconds = RESET_PASSWORD_IP_LOCKOUT_SECONDS;
                $configAttemptValiditySeconds = $configLockoutSeconds; // Attempts count for lockout duration
                break;
            default:
                return;
        }

        $sql = "DELETE FROM {$table} WHERE {$field} = :identifier 
                AND (
                    -- Condition 1: attempts are below max AND older than counting validity window
                    (attempts_count < :max_attempts AND (CAST(strftime('%s', 'now') AS INTEGER) - last_attempt_at) > :attempt_validity_seconds)
                    OR
                    -- Condition 2: attempts reached max (locked out) BUT lockout period has passed
                    (attempts_count >= :max_attempts AND (CAST(strftime('%s', 'now') AS INTEGER) - last_attempt_at) > :lockout_seconds)
                )";
        
        $params = [
            ':identifier' => $identifier,
            ':max_attempts' => $configMaxAttempts,
            ':attempt_validity_seconds' => $configAttemptValiditySeconds,
            ':lockout_seconds' => $configLockoutSeconds
        ];

        if ($table === 'user_specific_attempts') {
            $sql .= " AND attempt_type = :attempt_type_condition";
            $params[':attempt_type_condition'] = $attemptType;
        }
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
    }
}

?>
