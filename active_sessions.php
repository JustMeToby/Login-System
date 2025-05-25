<?php
// active_sessions.php
require_once 'src/bootstrap.php';

use LoginSystem\Security\PersistentSessionManager;
use LoginSystem\Logging\AuditLoggerService;

// Ensure services are available (they are global from bootstrap.php)
global $authController, $pdo, $auditLogger, $user, $security;

if (!$authController || !$pdo || !$auditLogger || !$user || !$security) {
    die("Critical services are not available. Check bootstrap.php.");
}

$authController->requireLogin(); // User must be logged in

$currentUserId = $authController->getLoggedInUserId();
if (!$currentUserId) {
    // Should not happen if requireLogin() works
    $authController->redirect(PAGE_SIGNIN);
}

$persistentSessionManager = new PersistentSessionManager($pdo, $auditLogger, $user);

// Handle CSRF and revocation actions
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
            $currentSeriesIdFromCookie = $_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES] ?? null;
            $persistentSessionManager->revokeAllOtherSessions($currentUserId, $currentSeriesIdFromCookie);
            $authController->getAndSetFlashMessage('success', 'All other active sessions revoked successfully.');
        }
    }
    // Redirect to the same page to show messages and prevent re-submission
    $authController->redirect(PAGE_ACTIVE_SESSIONS);
}


// Fetch active sessions for display
$sessions = $persistentSessionManager->getUserActiveSessions($currentUserId);
$currentSeriesHashFromCookie = null;
if (isset($_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES])) {
    $currentSeriesHashFromCookie = $persistentSessionManager->hashToken($_COOKIE[REMEMBER_ME_COOKIE_NAME_SERIES]);
}

// Generate CSRF token for forms if not already done by POST handling (which redirects)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $security->generateCsrfToken();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Active Sessions</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container mt-5">
        <h2 class="mb-4">Manage Your Active "Remember Me" Sessions</h2>

        <?php display_flash_messages('errors', 'danger'); ?>
        <?php display_flash_messages('success', 'success'); ?>

        <?php if (empty($sessions)): ?>
            <p>You have no active "Remember Me" sessions.</p>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="thead-dark">
                        <tr>
                            <th>Created At</th>
                            <th>Last Used</th>
                            <th>IP Address</th>
                            <th>Device/Browser</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($sessions as $session): ?>
                            <tr>
                                <td><?php echo $security->escapeHTML(date('Y-m-d H:i:s', strtotime($session['created_at']))); ?></td>
                                <td><?php echo $security->escapeHTML(date('Y-m-d H:i:s', strtotime($session['last_used_at']))); ?></td>
                                <td><?php echo $security->escapeHTML($session['ip_address']); ?></td>
                                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?php echo $security->escapeHTML($session['user_agent']); ?>">
                                    <?php echo $security->escapeHTML($session['user_agent']); ?>
                                </td>
                                <td>
                                    <?php if ($currentSeriesHashFromCookie && hash_equals($session['series_hash'], $currentSeriesHashFromCookie)): ?>
                                        <span class="badge badge-success">Current Session</span>
                                    <?php else: ?>
                                        <span class="badge badge-secondary">Active</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <form method="POST" action="<?php echo $authController->buildUrl(PAGE_ACTIVE_SESSIONS); ?>" style="display:inline;">
                                        <?php echo $security->getCsrfInput(); ?>
                                        <input type="hidden" name="revoke_session_id" value="<?php echo $security->escapeHTML($session['id']); ?>">
                                        <button type="submit" class="btn btn-danger btn-sm" 
                                            <?php if ($currentSeriesHashFromCookie && hash_equals($session['series_hash'], $currentSeriesHashFromCookie)): ?>
                                                disabled title="Cannot revoke the current session directly here. Sign out to revoke."
                                            <?php endif; ?>
                                        >Revoke</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <hr class="my-4">

        <form method="POST" action="<?php echo $authController->buildUrl(PAGE_ACTIVE_SESSIONS); ?>" onsubmit="return confirm('Are you sure you want to revoke all other active sessions?');">
            <?php echo $security->getCsrfInput(); ?>
            <button type="submit" name="revoke_all_other_sessions" class="btn btn-warning">Revoke All Other Sessions</button>
        </form>
        
        <p class="mt-3"><a href="<?php echo $authController->buildUrl(PAGE_DASHBOARD); ?>">Back to Dashboard</a></p>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
