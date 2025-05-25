<?php
/**
 * Handles user sign-in form submission, validation, rate limiting, and session management.
 * This script is included by signin.php and relies on variables/services
 * initialized by bootstrap.php (e.g., $authController, $user, $security, $rateLimiter, $auditLogger, $pdo).
 */

// This script assumes $clientIp has been defined in the calling script (signin.php)
// and that bootstrap.php has been included, providing access to necessary services.

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login_identifier = trim($_POST['login_identifier'] ?? ''); // Get identifier for logging early
    $password = $_POST['password'] ?? ''; // Get password for logging early if needed

    // ** Check IP Rate Limit First **
    if (!$rateLimiter->checkIpLoginAttempts($clientIp)) {
        // IP is locked out
        $auditLogger->log(
            \LoginSystem\Logging\AuditLoggerService::EVENT_LOGIN_FAILED_IP_LOCKOUT,
            null,
            ['ip_address' => $clientIp, 'username_attempted' => $login_identifier]
        );
        $authController->getAndSetFlashMessage('errors', ["Too many login attempts from your IP address. Please try again later."], true);
        $authController->redirect(PAGE_SIGNIN); // redirect() handles exit
    }

    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
        // Even for CSRF fail, we count it against the IP as an attempt to probe the system
        $rateLimiter->recordIpLoginAttempt($clientIp);
        $auditLogger->log(
            \LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_FAILURE, // Generic failure for CSRF
            null,
            ['ip_address' => $clientIp, 'username_attempted' => $login_identifier, 'reason' => 'CSRF token validation failed']
        );
        $authController->getAndSetFlashMessage('errors', $errors, true);
        $authController->redirect(PAGE_SIGNIN);
    }
    // Optional: unset($_SESSION[CSRF_TOKEN_NAME]); // If you want one-time CSRF for login

    $login_identifier_value = $security->escapeHTML($login_identifier); // Used to repopulate form

    if (empty($login_identifier)) {
        $errors[] = 'Username or Email is required.';
    }
    if (empty($password)) {
        $errors[] = 'Password is required.';
    }

    if (!empty($errors)) { // Input validation failed (e.g., empty fields)
        // Record IP attempt for validation failure as well
        $rateLimiter->recordIpLoginAttempt($clientIp);
        $auditLogger->log(
            \LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_FAILURE, // Generic failure
            null,
            ['ip_address' => $clientIp, 'username_attempted' => $login_identifier, 'reason' => 'Empty username or password fields.']
        );
        $authController->getAndSetFlashMessage('errors', $errors, true);
        $authController->redirect(PAGE_SIGNIN);
    }

    // At this point, input fields are non-empty, and CSRF was valid. IP is not initially locked out.
    $userData = $user->findByLogin($login_identifier);

    if ($userData) {
        // User found, now check user-specific rate limit before checking password
        if (!$rateLimiter->checkUserLoginAttempts($userData['id'])) {
            // User account is locked out
            $rateLimiter->recordIpLoginAttempt($clientIp); // Still record this IP attempt leading to discovering a locked user
            $auditLogger->log(
                \LoginSystem\Logging\AuditLoggerService::EVENT_LOGIN_FAILED_USER_LOCKOUT,
                $userData['id'],
                ['ip_address' => $clientIp, 'username' => $userData['username']]
            );
            $authController->getAndSetFlashMessage('errors', ["This account has been temporarily locked due to too many failed login attempts. Please try again later."], true);
            $authController->redirect(PAGE_SIGNIN);
        }

        // Check if email verification is required and if user is verified
        if (defined('EMAIL_VERIFICATION_ENABLED') && EMAIL_VERIFICATION_ENABLED === true) {
            if (!isset($userData['is_verified']) || (int)$userData['is_verified'] === 0) {
                // Email not verified
                $auditLogger->log(
                    \LoginSystem\Logging\AuditLoggerService::EVENT_LOGIN_FAILED_EMAIL_NOT_VERIFIED,
                    $userData['id'],
                    ['ip_address' => $clientIp, 'username' => $userData['username']]
                );
                // Record failed login attempt for IP and User
                $rateLimiter->recordIpLoginAttempt($clientIp);
                $rateLimiter->recordUserLoginAttempt($userData['id']);
                
                $authController->getAndSetFlashMessage('errors', ["Your email address is not verified. Please check your email for the verification link."], true);
                $authController->redirect(PAGE_SIGNIN);
            }
        }

        // If email is verified (or verification is not enabled), proceed to password check
        if ($user->verifyPassword($userData, $password)) {
            // Successful Login
            $rateLimiter->clearIpLoginAttempts($clientIp);
            $rateLimiter->clearUserLoginAttempts($userData['id']);
            
            $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_SUCCESS, $userData['id'], ['ip_address' => $clientIp]);
            $authController->login($userData['id'], $userData['username']);

            // Handle "Remember Me"
            if (isset($_POST['remember_me']) && $_POST['remember_me'] === '1') {
                // Ensure PersistentSessionManager is available or initialized
                // Assuming $pdo, $auditLogger, and $user are available globally from bootstrap.php
                if (isset($pdo) && isset($auditLogger) && isset($user)) {
                     // The User service is needed by PersistentSessionManager as per its constructor.
                    $persistentSessionManager = new \LoginSystem\Security\PersistentSessionManager($pdo, $auditLogger, $user);
                    $persistentSessionManager->createPersistentSession($userData['id']);
                } else {
                    // Log an error if dependencies are not available
                    error_log("PersistentSessionManager dependencies not available in signin.php's included handle_signin.php");
                }
            }

            $authController->redirect(PAGE_DASHBOARD);
        } else {
            // Invalid password
            $rateLimiter->recordIpLoginAttempt($clientIp);
            $rateLimiter->recordUserLoginAttempt($userData['id']);
            $auditLogger->log(
                \LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_FAILURE, // This constant is for bad password specifically when user is known
                $userData['id'],
                ['ip_address' => $clientIp, 'username_attempted' => $login_identifier, 'reason' => 'Invalid password']
            );
            $authController->getAndSetFlashMessage('errors', ['Invalid credentials. Please try again.'], true);
            $authController->redirect(PAGE_SIGNIN);
        }
    } else {
        // User not found
        $rateLimiter->recordIpLoginAttempt($clientIp);
        $auditLogger->log(
            \LoginSystem\Logging\AuditLoggerService::EVENT_LOGIN_FAILED_UNKNOWN_USER,
            null,
            ['ip_address' => $clientIp, 'username_attempted' => $login_identifier]
        );
        $authController->getAndSetFlashMessage('errors', ['Invalid credentials. Please try again.'], true);
        $authController->redirect(PAGE_SIGNIN);
    }
}
?>
