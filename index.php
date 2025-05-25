<?php
require_once 'login_system/src/bootstrap.php'; // Defines $authController and SESSION_USER_ID_KEY

// No need to explicitly start session here, bootstrap.php handles it.

// This script acts as the main entry point after bootstrap.
// It checks if the user is logged in and redirects to the appropriate page.
if (isset($_SESSION[SESSION_USER_ID_KEY])) {
    // User is logged in, redirect to dashboard
    $authController->redirect(PAGE_DASHBOARD);
} else {
    // User is not logged in, redirect to sign-in page
    $authController->redirect(PAGE_SIGNIN);
}
// No further output or HTML is needed here as redirect() handles exit.
?>
