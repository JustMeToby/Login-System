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
    const EVENT_USER_LOGIN_FAILURE = 'USER_LOGIN_FAILURE'; // Generic bad password/username
    const EVENT_LOGIN_FAILED_IP_LOCKOUT = 'LOGIN_FAILED_IP_LOCKOUT';
    const EVENT_LOGIN_FAILED_USER_LOCKOUT = 'LOGIN_FAILED_USER_LOCKOUT';
    const EVENT_LOGIN_FAILED_UNKNOWN_USER = 'LOGIN_FAILED_UNKNOWN_USER';
    const EVENT_LOGIN_FAILED_EMAIL_NOT_VERIFIED = 'LOGIN_FAILED_EMAIL_NOT_VERIFIED';
    const EVENT_USER_LOGOUT = 'USER_LOGOUT';

    // Email Verification Events
    const EVENT_EMAIL_VERIFICATION_REQUESTED = 'EMAIL_VERIFICATION_REQUESTED';
    const EVENT_EMAIL_VERIFICATION_SENT = 'EVENT_EMAIL_VERIFICATION_SENT'; // User was sent the verification email
    const EVENT_EMAIL_SEND_FAILED = 'EVENT_EMAIL_SEND_FAILED'; // Attempt to send an email failed
    const EVENT_EMAIL_VERIFICATION_SUCCESS = 'EMAIL_VERIFICATION_SUCCESS';
    const EVENT_EMAIL_ALREADY_VERIFIED = 'EVENT_EMAIL_ALREADY_VERIFIED'; // User attempted to verify an already verified email
    const EVENT_EMAIL_VERIFICATION_FAILED = 'EVENT_EMAIL_VERIFICATION_FAILED'; // Generic failure, details should specify reason (e.g. no token, user method false)
    const EVENT_EMAIL_VERIFICATION_FAILED_INVALID_TOKEN = 'EMAIL_VERIFICATION_FAILED_INVALID_TOKEN'; // Specific: token was invalid or expired
    const EVENT_EMAIL_VERIFICATION_FAILED_UNEXPECTED = 'EVENT_EMAIL_VERIFICATION_FAILED_UNEXPECTED'; // Specific: unexpected error during verification
    
    // Password Management Events
    const EVENT_PASSWORD_CHANGE_SUCCESS = 'PASSWORD_CHANGE_SUCCESS';
    const EVENT_PASSWORD_CHANGE_FAILED = 'PASSWORD_CHANGE_FAILED';
    const EVENT_PASSWORD_RESET_REQUEST_SUCCESS = 'PASSWORD_RESET_REQUEST_SUCCESS'; // Existing: EVENT_PASSWORD_RESET_REQUESTED might map here
    const EVENT_PASSWORD_RESET_REQUEST_FAILED_USER_NOT_FOUND = 'PASSWORD_RESET_REQUEST_FAILED_USER_NOT_FOUND';
    const EVENT_PASSWORD_RESET_REQUEST_FAILED_IP_LOCKOUT = 'PASSWORD_RESET_REQUEST_FAILED_IP_LOCKOUT';
    const EVENT_PASSWORD_RESET_SUCCESS = 'PASSWORD_RESET_SUCCESS'; // User successfully resets password via link
    const EVENT_PASSWORD_RESET_FAILED_INVALID_TOKEN = 'PASSWORD_RESET_FAILED_INVALID_TOKEN';
    
    // Account Lockout Events (triggered by RateLimiterService)
    const EVENT_ACCOUNT_LOCKED_USER = 'ACCOUNT_LOCKED_USER'; 
    const EVENT_ACCOUNT_LOCKED_IP = 'ACCOUNT_LOCKED_IP';   
    const EVENT_PASSWORD_RESET_IP_LOCKOUT = 'PASSWORD_RESET_IP_LOCKOUT'; // Was EVENT_IP_LOCKED_RESET

    // Session Management Events
    const EVENT_SESSION_EXPIRED_IDLE = 'SESSION_EXPIRED_IDLE';
    const EVENT_SESSION_EXPIRED_ABSOLUTE = 'SESSION_EXPIRED_ABSOLUTE';
    const EVENT_SESSION_REMEMBER_ME_CREATED = 'SESSION_REMEMBER_ME_CREATED';
    const EVENT_SESSION_REMEMBER_ME_TOKEN_USED = 'SESSION_REMEMBER_ME_TOKEN_USED';
    const EVENT_SESSION_REMEMBER_ME_TOKEN_INVALID = 'SESSION_REMEMBER_ME_TOKEN_INVALID';
    const EVENT_SESSION_REMEMBER_ME_TOKEN_RENEWED = 'SESSION_REMEMBER_ME_TOKEN_RENEWED'; // May be used if token is refreshed without full validation, or as alias
    const EVENT_SESSION_REVOKED_BY_USER = 'SESSION_REVOKED_BY_USER'; // User revokes a specific session
    const EVENT_SESSION_ALL_OTHERS_REVOKED_BY_USER = 'SESSION_ALL_OTHERS_REVOKED_BY_USER'; // User revokes all sessions except current "remember me"
    const EVENT_SESSION_ALL_REVOKED_BY_USER = 'SESSION_ALL_REVOKED_BY_USER'; // User revokes ALL sessions (e.g. via profile, or system on theft)

    // Admin/System Events
    const EVENT_ADMIN_ACTION = 'ADMIN_ACTION'; // Generic, details will specify
    // const EVENT_ADMIN_USER_DEACTIVATED = 'ADMIN_USER_DEACTIVATED';
    // const EVENT_ADMIN_CONFIG_CHANGED = 'ADMIN_CONFIG_CHANGED';

    // To map old constants if needed during transition, but new ones are defined above.
    // const EVENT_EMAIL_VERIFIED = self::EVENT_EMAIL_VERIFICATION_SUCCESS; // Example mapping
    // const EVENT_VERIFICATION_EMAIL_SENT = self::EVENT_EMAIL_VERIFICATION_REQUESTED; // Example mapping
    // const EVENT_PASSWORD_RESET_REQUESTED = self::EVENT_PASSWORD_RESET_REQUEST_SUCCESS; // Example mapping for request processing
    // const EVENT_IP_LOCKED_RESET = self::EVENT_PASSWORD_RESET_IP_LOCKOUT; // Example mapping


    public function __construct(PDO $pdo, bool $logEnabled = true) {
        $this->pdo = $pdo;
        $this->logEnabled = $logEnabled && defined('AUDIT_LOG_ENABLED') && AUDIT_LOG_ENABLED;
    }

    /**
     * Logs an event to the audit trail.
     *
     * @param string $eventType One of the EVENT_* constants.
     * @param int|null $userId The ID of the user associated with the event, if applicable.
     * @param string|null $ipAddress The IP address associated with the event. Auto-detected if null.
     * @param array|null $details Additional details about the event. Will be JSON encoded.
     * @return bool True on success, false on failure or if logging is disabled.
     */
    public function log(string $eventType, ?int $userId = null, ?string $ipAddress = null, ?array $details = null): bool {
        if (!$this->logEnabled) {
            return false;
        }

        $finalIpAddress = $ipAddress ?? ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN');
        $detailsJson = $details ? json_encode($details) : null;

        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO audit_log (user_id, ip_address, event_type, details, timestamp) 
                 VALUES (:user_id, :ip_address, :event_type, :details, datetime('now', 'localtime'))"
            );
            
            $stmt->execute([
                ':user_id' => $userId,
                ':ip_address' => $finalIpAddress,
                ':event_type' => $eventType,
                ':details' => $detailsJson
            ]);
            return true;
        } catch (\PDOException $e) {
            // Handle logging error - e.g., log to a file or system log
            // In a more complex system, this might throw an exception or use a dedicated logger interface.
            error_log("AuditLoggerService Error: Failed to log event. EventType: {$eventType}, UserID: {$userId}, IP: {$finalIpAddress}. PDOException: " . $e->getMessage());
            return false;
        }
    }
}
?>
