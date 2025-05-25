<?php
/**
 * Handles the business logic for active_sessions.php.
 * This includes processing session revocation requests (POST) and
 * fetching active sessions for the current user (GET).
 *
 * Expected to be included by active_sessions.php.
 * Relies on services from bootstrap.php ($authController, $pdo, $auditLogger, $user, $security).
 */

use LoginSystem\Security\PersistentSessionManager;
use LoginSystem\Logging\AuditLoggerService;

// Ensure services are available (they are global from bootstrap.php)
global $authController, $pdo, $auditLogger, $user, $security;

if (!$authController || !$pdo || !$auditLogger || !$user || !$security) {
    // This check is important, but active_sessions.php should also ensure bootstrap is loaded.
    // If included by active_sessions.php after bootstrap, this might be redundant but safe.
    if (function_exists('error_log')) { // Check if error_log is available
        error_log("Critical services are not available in handle_active_sessions.php. Check bootstrap.php inclusion order.");
    }
    // Avoid die() here if this is just an include; let the main page handle fatal errors.
    // Consider throwing an exception or returning a status. For now, rely on main page's checks.
    return; // Stop execution of this script if services are missing.
}

// User must be logged in; this should be enforced by the calling script (active_sessions.php)
$currentUserId = $authController->getLoggedInUserId();
if (!$currentUserId) {
    // This script should not be reached if user is not logged in.
    // Redirect handled by active_sessions.php's requireLogin().
    return;
}

$persistentSessionManager = new PersistentSessionManager($pdo, $auditLogger, $user);

// Handle POST requests for session revocation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $authController->getAndSetFlashMessage('errors', ['Security token validation failed. Please try again.'], true);
    } else {
        if (isset($_POST['revoke_session_id'])) {
            $sessionIdToRevoke = (int)$_POST['revoke_session_id'];
            if ($persistentSessionManager->revokeSessionById($sessionIdToRevoke, $currentUserId)) {
                $authController->getAndSetFlashMessage('success', 'Session revoked successfully.');
            } else {
                $authController->getAndSetFlashMessage('errors', ['Failed to revoke session. It might have already been revoked or does not belong to you.'], true);
            }
        } elseif (isset($_POST['revoke_all_other_sessions'])) {
            // Get current series ID from cookie to avoid revoking the current "Remember Me" session
            $currentSeriesIdFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES] ?? null;
            $persistentSessionManager->revokeAllOtherSessions($currentUserId, $currentSeriesIdFromCookie);
            $authController->getAndSetFlashMessage('success', 'All other active sessions revoked successfully.');
        }
    }
    // Redirect to the same page to show messages and prevent re-submission
    $authController->redirect(PAGE_ACTIVE_SESSIONS);
    exit; // Ensure no further script execution after redirect
}

// Fetch active sessions for display (for GET requests, or after POST redirect)
$sessions = $persistentSessionManager->getUserActiveSessions($currentUserId);

// Determine the series hash of the current session from the cookie, if present
$currentSeriesHashFromCookie = null;
if (isset($_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES])) {
    // Use the same hashing method as PersistentSessionManager to compare
    $currentSeriesHashFromCookie = $persistentSessionManager->hashToken($_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES]);
}

// Note: CSRF token generation for the forms (on GET request)
// will be handled by the main active_sessions.php script after this include.
?>
