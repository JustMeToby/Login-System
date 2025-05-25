<?php
// active_sessions.php
require_once 'login_system/src/bootstrap.php'; // Updated path

// Ensure services are available (they are global from bootstrap.php)
// The bootstrap.php should handle critical service initialization.
// Specific checks for each service can be removed if bootstrap is reliable.
global $authController, $security; // $pdo, $auditLogger, $user are used by the include

if (!$authController || !$security) {
    // A basic check for essential services used directly on this page.
    // The include handle_active_sessions.php has its own checks for services it uses.
    if (function_exists('error_log')) {
        error_log("Critical services (AuthController or Security) not available in active_sessions.php.");
    }
    die("Essential services are not available. Please check system configuration.");
}

$authController->requireLogin(); // User must be logged in

// $currentUserId is obtained and used within the included handler.

// Include the handler for POST logic and data fetching.
// This script will define $sessions and $currentSeriesHashFromCookie.
// It uses $authController, $pdo, $auditLogger, $user, $security from bootstrap.
require_once 'login_system/includes/handle_active_sessions.php';

// Generate CSRF token for forms for GET requests.
// This should be done after the include, which handles POST (and redirects)
// and after data fetching, so the token is fresh for the displayed forms.
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $security->generateCsrfToken(); // $security object is from bootstrap.php
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Active Sessions - <?php echo $security->escapeHTML(defined('SITE_NAME') ? SITE_NAME : 'Login System'); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="login_system/css/style.css"> <!-- Updated path -->
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
                    <thead class="table-dark">
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
                                        <span class="badge text-bg-success">Current Session</span>
                                    <?php else: ?>
                                        <span class="badge text-bg-secondary">Active</span>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
