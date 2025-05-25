<?php
/**
 * Prepares data needed for the dashboard page.
 * Specifically, it gets and prepares the username for display.
 *
 * Expected to be included by dashboard.php after bootstrap.php.
 * Relies on $authController and $security services from bootstrap.php.
 * Defines $usernameDisplay for use in the dashboard HTML.
 */

// Ensure services are available (they are global from bootstrap.php)
// No need for explicit global keyword here if they are accessed directly as globals.
if (!isset($authController) || !isset($security)) {
    if (function_exists('error_log')) {
        error_log("Critical services (AuthController or Security) not available in prepare_dashboard.php.");
    }
    // Avoid die() in an include. Let the main page handle fatal errors or display a generic message.
    // For now, if services are missing, $usernameDisplay might not be set, leading to PHP notices.
    // A more robust solution might be to throw an exception or ensure services always exist.
    $usernameDisplay = 'User (Error)'; // Fallback display
    return; 
}

// Get username for display
// $authController->requireLogin() should have been called by the parent script (dashboard.php)
// before including this file, so user should be logged in.
$username = $authController->getLoggedInUsername();
$usernameDisplay = $username ? $security->escapeHTML($username) : 'User';

?>
