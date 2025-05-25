<?php
// src/Security/PersistentSessionManager.php
namespace LoginSystem\Security;

use PDO;
use LoginSystem\Logging\AuditLoggerService;
use LoginSystem\Auth\User; // Required to fetch user data

class PersistentSessionManager {
    private PDO $pdo;
    private AuditLoggerService $auditLogger;
    private User $userService; // To fetch user details like username

    public function __construct(PDO $pdo, AuditLoggerService $auditLogger, User $userService) {
        $this->pdo = $pdo;
        $this->auditLogger = $auditLogger;
        $this->userService = $userService;
    }

    public function generateToken(): string {
        return bin2hex(random_bytes(32));
    }

    public function hashToken(string $token): string {
        return hash('sha256', $token);
    }

    public function createPersistentSession(int $userId): void {
        $seriesId = $this->generateToken();
        $token = $this->generateToken();

        $hashedSeries = $this->hashToken($seriesId);
        $hashedToken = $this->hashToken($token);

        $expiryTime = time() + (REMEMBER_ME_DURATION_DAYS * 24 * 60 * 60);
        $expiresAtFormatted = date('Y-m-d H:i:s', $expiryTime);
        $currentTimeFormatted = date('Y-m-d H:i:s');
        
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO persistent_sessions (user_id, series_hash, token_hash, expires_at, last_used_at, created_at, user_agent, ip_address) 
                 VALUES (:user_id, :series_hash, :token_hash, :expires_at, :last_used_at, :created_at, :user_agent, :ip_address)"
            );
            $stmt->execute([
                ':user_id' => $userId,
                ':series_hash' => $hashedSeries,
                ':token_hash' => $hashedToken,
                ':expires_at' => $expiresAtFormatted,
                ':last_used_at' => $currentTimeFormatted,
                ':created_at' => $currentTimeFormatted,
                ':user_agent' => $userAgent,
                ':ip_address' => $ipAddress
            ]);

            setcookie(REMEMBER_ME_COOKIE_NAME_SERIES, $seriesId, $expiryTime, '/', '', isset($_SERVER['HTTPS']), true);
            setcookie(REMEMBER_ME_COOKIE_NAME_TOKEN, $token, $expiryTime, '/', '', isset($_SERVER['HTTPS']), true);

            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_REMEMBER_ME_CREATED,
                $userId,
                null, // IP handled by logger
                ['series_id_hash' => $hashedSeries, 'user_agent' => $userAgent]
            );
        } catch (\PDOException $e) {
            error_log("Error creating persistent session: " . $e->getMessage());
            // Potentially log this specific error with audit logger if appropriate
        }
    }

    public function validatePersistentSession(): ?array {
        $seriesIdFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES] ?? null;
        $tokenFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_TOKEN] ?? null;

        if (!$seriesIdFromCookie || !$tokenFromCookie) {
            return null;
        }

        $hashedSeriesFromCookie = $this->hashToken($seriesIdFromCookie);

        $stmt = $this->pdo->prepare("SELECT * FROM persistent_sessions WHERE series_hash = :series_hash");
        $stmt->execute([':series_hash' => $hashedSeriesFromCookie]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$session) {
            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_REMEMBER_ME_TOKEN_INVALID,
                null,
                null,
                ['reason' => 'Series not found', 'series_id_attempted_hash' => $hashedSeriesFromCookie]
            );
            $this->clearPersistentSessionCookies(); // Clear potentially compromised cookies
            return null;
        }

        if (strtotime($session['expires_at']) < time()) {
            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_REMEMBER_ME_TOKEN_INVALID,
                $session['user_id'],
                null,
                ['reason' => 'Session expired', 'series_id_hash' => $hashedSeriesFromCookie]
            );
            $this->clearPersistentSessionBySeriesHash($hashedSeriesFromCookie); // Clean up expired DB record and cookies
            return null;
        }
        
        $hashedTokenFromCookie = $this->hashToken($tokenFromCookie);

        if (hash_equals($session['token_hash'], $hashedTokenFromCookie)) {
            // Successful validation
            $userData = $this->userService->findById($session['user_id']);
            if (!$userData) { // Should not happen if DB is consistent
                $this->auditLogger->log(
                    AuditLoggerService::EVENT_SESSION_REMEMBER_ME_TOKEN_INVALID,
                    $session['user_id'],
                    null,
                    ['reason' => 'User not found for valid session', 'series_id_hash' => $hashedSeriesFromCookie]
                );
                $this->clearPersistentSessionBySeriesHash($hashedSeriesFromCookie);
                return null;
            }

            $newToken = $this->generateToken();
            $newHashedToken = $this->hashToken($newToken);
            $newLastUsedAt = date('Y-m-d H:i:s');

            $updateStmt = $this->pdo->prepare(
                "UPDATE persistent_sessions SET token_hash = :token_hash, last_used_at = :last_used_at 
                 WHERE id = :id"
            );
            $updateStmt->execute([
                ':token_hash' => $newHashedToken,
                ':last_used_at' => $newLastUsedAt,
                ':id' => $session['id']
            ]);

            setcookie(REMEMBER_ME_COOKIE_NAME_TOKEN, $newToken, strtotime($session['expires_at']), '/', '', isset($_SERVER['HTTPS']), true);
            // Series cookie remains the same

            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_REMEMBER_ME_TOKEN_USED,
                $session['user_id'],
                null,
                ['series_id_hash' => $hashedSeriesFromCookie]
            );
            
            return ['id' => $session['user_id'], 'username' => $userData['username']];

        } else {
            // Token mismatch - potential theft
            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_REMEMBER_ME_TOKEN_INVALID,
                $session['user_id'],
                null,
                ['reason' => 'Token mismatch - possible theft', 'series_id_hash' => $hashedSeriesFromCookie]
            );
            $this->clearAllUserPersistentSessions($session['user_id']); // Clear all for this user
            // clearPersistentSessionCookies() is called by clearAllUserPersistentSessions if it clears the current one,
            // but we call it explicitly to be sure the current invalid ones are gone.
            $this->clearPersistentSessionCookies();
            return null;
        }
    }

    public function clearPersistentSessionCookies(): void {
        $pastTime = time() - 3600;
        setcookie(REMEMBER_ME_COOKIE_NAME_SERIES, '', $pastTime, '/', '', isset($_SERVER['HTTPS']), true);
        setcookie(REMEMBER_ME_COOKIE_NAME_TOKEN, '', $pastTime, '/', '', isset($_SERVER['HTTPS']), true);
    }

    /**
     * Clears a persistent session from DB by its series hash and also clears cookies.
     * @param string $seriesHash The hashed series ID.
     */
    private function clearPersistentSessionBySeriesHash(string $seriesHash): void {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM persistent_sessions WHERE series_hash = :series_hash");
            $stmt->execute([':series_hash' => $seriesHash]);
        } catch (\PDOException $e) {
            error_log("Error clearing persistent session by series hash: " . $e->getMessage());
        }
        $this->clearPersistentSessionCookies();
    }
    
    // Public version if needed, taking raw series ID from cookie
    public function clearPersistentSessionBySeriesCookie(string $seriesIdFromCookie): void {
        $hashedSeries = $this->hashToken($seriesIdFromCookie);
        $this->clearPersistentSessionBySeriesHash($hashedSeries);
    }


    public function clearAllUserPersistentSessions(int $userId): void {
        try {
            // Check if one of the sessions being deleted matches current cookies
            // This is a bit complex as we only have series_hash in DB.
            // Simpler to just clear cookies if any user sessions are deleted.
            $seriesIdFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES] ?? null;
            $tokenFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_TOKEN] ?? null;
            $shouldClearCookies = false;

            if ($seriesIdFromCookie && $tokenFromCookie) {
                $stmtCheck = $this->pdo->prepare("SELECT COUNT(*) FROM persistent_sessions WHERE user_id = :user_id AND series_hash = :series_hash");
                $stmtCheck->execute([':user_id' => $userId, ':series_hash' => $this->hashToken($seriesIdFromCookie)]);
                if ($stmtCheck->fetchColumn() > 0) {
                    $shouldClearCookies = true;
                }
            }
            
            $stmt = $this->pdo->prepare("DELETE FROM persistent_sessions WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $userId]);

            if ($shouldClearCookies) {
                $this->clearPersistentSessionCookies();
            }

            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_ALL_REVOKED_BY_USER, // Or a more specific event like ALL_PERSISTENT_SESSIONS_REVOKED
                $userId,
                null,
                ['trigger' => 'theft_detection_or_user_request'] // Adjust trigger as needed
            );
        } catch (\PDOException $e) {
            error_log("Error clearing all persistent sessions for user: " . $e->getMessage());
        }
    }

    /**
     * Fetches all active persistent sessions for a given user.
     *
     * @param int $userId The ID of the user.
     * @return array An array of active session data.
     */
    public function getUserActiveSessions(int $userId): array {
        try {
            $stmt = $this->pdo->prepare(
                "SELECT id, created_at, last_used_at, ip_address, user_agent, series_hash 
                 FROM persistent_sessions 
                 WHERE user_id = :user_id AND expires_at > datetime('now', 'localtime') 
                 ORDER BY last_used_at DESC"
            );
            $stmt->execute([':user_id' => $userId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (\PDOException $e) {
            error_log("Error fetching user active sessions: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Revokes a specific persistent session by its ID, ensuring it belongs to the user.
     *
     * @param int $sessionId The ID of the session record to revoke.
     * @param int $userId The ID of the user attempting to revoke the session.
     * @return bool True on successful deletion, false otherwise.
     */
    public function revokeSessionById(int $sessionId, int $userId): bool {
        try {
            // First, get the series_hash of the session to be deleted
            $stmtFetch = $this->pdo->prepare("SELECT series_hash FROM persistent_sessions WHERE id = :session_id AND user_id = :user_id");
            $stmtFetch->execute([':session_id' => $sessionId, ':user_id' => $userId]);
            $sessionToDelete = $stmtFetch->fetch(PDO::FETCH_ASSOC);

            if (!$sessionToDelete) {
                return false; // Session not found or doesn't belong to user
            }
            
            $stmtDelete = $this->pdo->prepare("DELETE FROM persistent_sessions WHERE id = :session_id AND user_id = :user_id");
            $stmtDelete->execute([':session_id' => $sessionId, ':user_id' => $userId]);
            
            $success = $stmtDelete->rowCount() > 0;

            if ($success) {
                $this->auditLogger->log(
                    AuditLoggerService::EVENT_SESSION_REVOKED_BY_USER,
                    $userId,
                    null,
                    ['revoked_session_id' => $sessionId]
                );

                // Check if the revoked session was the current "Remember Me" session
                $currentSeriesIdFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES] ?? null;
                if ($currentSeriesIdFromCookie && hash_equals($sessionToDelete['series_hash'], $this->hashToken($currentSeriesIdFromCookie))) {
                    $this->clearPersistentSessionCookies();
                }
            }
            return $success;
        } catch (\PDOException $e) {
            error_log("Error revoking session by ID: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Revokes all persistent sessions for a user, optionally keeping the current one.
     *
     * @param int $userId The ID of the user.
     * @param string|null $currentSeriesIdFromCookie The raw series ID from the current cookie, to be kept.
     */
    public function revokeAllOtherSessions(int $userId, ?string $currentSeriesIdFromCookie = null): void {
        $params = [':user_id' => $userId];
        $sql = "DELETE FROM persistent_sessions WHERE user_id = :user_id";

        $keptSeriesHash = null;
        if ($currentSeriesIdFromCookie !== null) {
            $keptSeriesHash = $this->hashToken($currentSeriesIdFromCookie);
            $sql .= " AND series_hash != :kept_series_hash";
            $params[':kept_series_hash'] = $keptSeriesHash;
        }

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            
            $this->auditLogger->log(
                AuditLoggerService::EVENT_SESSION_ALL_OTHERS_REVOKED_BY_USER,
                $userId,
                null,
                ['kept_series_hash' => $keptSeriesHash] // Log the hash of the kept series if any
            );
        } catch (\PDOException $e) {
            error_log("Error revoking all other sessions: " . $e->getMessage());
        }
    }
}
?>
