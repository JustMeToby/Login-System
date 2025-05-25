<?php
/**
 * Handles user logout.
 *
 * This script includes the bootstrap to access the AuthController,
 * then calls the logout method which destroys the session and redirects
 * the user to the sign-in page.
 */
require_once 'login_system/src/bootstrap.php'; // Defines $authController

// Perform logout
$authController->logout(); // This method handles session destruction and redirects to signin.php
// No further output or HTML is needed here as logout() handles the redirect and exit.
?>
