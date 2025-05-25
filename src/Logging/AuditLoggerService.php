<?php
// src/Logging/AuditLoggerService.php
namespace LoginSystem\Logging;

use PDO;

class AuditLoggerService {
    private PDO $pdo;
    private bool $logEnabled;

    // Define constants for common event types
    // User Account Events
    const EVENT_USER_REGISTERED = 'USER_REGISTERED';
    const EVENT_USER_LOGIN_SUCCESS = 'USER_LOGIN_SUCCESS';
    const EVENT_USER_LOGIN_FAILURE = 'USER_LOGIN_FAILURE';
    const EVENT_USER_LOGOUT = 'USER_LOGOUT';
    const EVENT_EMAIL_VERIFIED = 'EMAIL_VERIFIED';
    const EVENT_VERIFICATION_EMAIL_SENT = 'VERIFICATION_EMAIL_SENT'; // Or RESENT
    
    // Password Management Events
    const EVENT_PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED';
    const EVENT_PASSWORD_RESET_SUCCESS = 'PASSWORD_RESET_SUCCESS';
    const EVENT_PASSWORD_CHANGE_SUCCESS = 'PASSWORD_CHANGE_SUCCESS'; // For user changing their own password
    
    // Account Lockout Events (from Rate Limiter)
    const EVENT_ACCOUNT_LOCKED_USER = 'ACCOUNT_LOCKED_USER'; // User-specific lockout
    const EVENT_ACCOUNT_LOCKED_IP = 'ACCOUNT_LOCKED_IP';   // IP-specific lockout for login
    const EVENT_IP_LOCKED_RESET = 'IP_LOCKED_RESET';       // IP-specific lockout for password reset

    // Admin/System Events (Placeholders for future use if an admin panel is built)
    // const EVENT_ADMIN_USER_DEACTIVATED = 'ADMIN_USER_DEACTIVATED';
    // const EVENT_ADMIN_CONFIG_CHANGED = 'ADMIN_CONFIG_CHANGED';


    public function __construct(PDO $pdo, bool $logEnabled = true) {
        $this->pdo = $pdo;
        $this->logEnabled = $logEnabled && defined('AUDIT_LOG_ENABLED') && AUDIT_LOG_ENABLED;
    }

    /**
     * Logs an event to the audit trail.
     *
     * @param string $eventType One of the EVENT_* constants.
     * @param int|null $userId The ID of the user associated with the event, if applicable.
     * @param array|null $detailsArray Additional details about the event (e.g., attempted username for failed login). Will be JSON encoded.
     * @return bool True on success, false on failure or if logging is disabled.
     */
    public function log(string $eventType, ?int $userId = null, ?array $detailsArray = null): bool {
        if (!$this->logEnabled) {
            return false;
        }

        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'; // Get client IP
        $detailsJson = $detailsArray ? json_encode($detailsArray) : null;

        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO audit_log (user_id, ip_address, event_type, details, timestamp) 
                 VALUES (:user_id, :ip_address, :event_type, :details, datetime('now', 'localtime'))"
            );
            
            $stmt->execute([
                ':user_id' => $userId,
                ':ip_address' => $ipAddress,
                ':event_type' => $eventType,
                ':details' => $detailsJson
            ]);
            return true;
        } catch (\PDOException $e) {
            // Handle logging error - e.g., log to a file or system log
            error_log("AuditLoggerService Error: Failed to log event. PDOException: " . $e->getMessage());
            return false;
        }
    }
}
?>
