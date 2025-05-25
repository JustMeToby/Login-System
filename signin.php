<?php
/**
 * Handles user sign-in with rate limiting.
 *
 * This script displays the sign-in form, processes form submissions,
 * validates user credentials, implements IP and user-based rate limiting,
 * and manages session/login state using services from bootstrap.php.
 */
require_once 'src/bootstrap.php'; // Defines $authController, $user, $security, $rateLimiter

// A more robust IP getter could be moved to a utility function later
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown'; // Fallback for CLI or misconfigured server

$authController->requireGuest();

$errors = []; 
$login_identifier_value = ''; // To repopulate form field

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ** Check IP Rate Limit First **
    if ($rateLimiter->isBlocked($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN)) {
        $authController->getAndSetFlashMessage('errors', ["Too many login attempts from your IP address. Please try again later."], true);
        $authController->redirect(PAGE_SIGNIN); // redirect() handles exit
    }

    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
        $rateLimiter->recordAttempt($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN);
        $authController->getAndSetFlashMessage('errors', $errors, true);
        $authController->redirect(PAGE_SIGNIN);
    }
    // Optional: unset($_SESSION[CSRF_TOKEN_NAME]); // If you want one-time CSRF for login

    $login_identifier = trim($_POST['login_identifier'] ?? '');
    $password = $_POST['password'] ?? '';
    $login_identifier_value = $security->escapeHTML($login_identifier);

    if (empty($login_identifier)) {
        $errors[] = 'Username or Email is required.';
    }
    if (empty($password)) {
        $errors[] = 'Password is required.';
    }

    if (!empty($errors)) { // Input validation failed (e.g., empty fields)
        $rateLimiter->recordAttempt($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN);
        $authController->getAndSetFlashMessage('errors', $errors, true);
        $authController->redirect(PAGE_SIGNIN);
    }

    // At this point, input fields are non-empty, and CSRF was valid.
    $userData = $user->findByLogin($login_identifier);

    if ($userData) {
        // User found, now check user-specific rate limit before checking password
        if ($rateLimiter->isBlocked((string)$userData['id'], \LoginSystem\Security\RateLimiterService::TYPE_USER_LOGIN)) {
            $authController->getAndSetFlashMessage('errors', ["This account has been temporarily locked due to too many failed login attempts. Please try again later."], true);
            $rateLimiter->recordAttempt($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN); // Record the IP attempt too
            $authController->redirect(PAGE_SIGNIN);
        }

        if ($user->verifyPassword($userData, $password)) {
            // Successful Login
            $rateLimiter->clearAttempts($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN);
            $rateLimiter->clearAttempts((string)$userData['id'], \LoginSystem\Security\RateLimiterService::TYPE_USER_LOGIN);
            
            $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_SUCCESS, $userData['id']);
            $authController->login($userData['id'], $userData['username']);
            $authController->redirect(PAGE_DASHBOARD);
        } else {
            // Invalid password
            $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_FAILURE, $userData['id'], ['username_attempt' => $login_identifier, 'reason' => 'Invalid password']);
            $authController->getAndSetFlashMessage('errors', ['Invalid credentials. Please try again.'], true);
            $rateLimiter->recordAttempt($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN);
            $rateLimiter->recordAttempt((string)$userData['id'], \LoginSystem\Security\RateLimiterService::TYPE_USER_LOGIN);
            $authController->redirect(PAGE_SIGNIN);
        }
    } else {
        // User not found
        $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGIN_FAILURE, null, ['username_attempt' => $login_identifier, 'reason' => 'User not found']);
        $authController->getAndSetFlashMessage('errors', ['Invalid credentials. Please try again.'], true);
        $rateLimiter->recordAttempt($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_LOGIN);
        $authController->redirect(PAGE_SIGNIN);
    }

} else { // GET request
    // Generate CSRF token for the form if it's not already set (idempotent)
    $security->generateCsrfToken();
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - <?php echo $security->escapeHTML(defined('SITE_NAME') ? SITE_NAME : 'Login System'); ?></title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container">
            <h2 class="text-center mb-4">Sign In</h2>

            <?php display_flash_messages('errors', 'danger'); ?>
            <?php display_flash_messages('success', 'success'); // For messages like 'logged out successfully' ?>

            <form id="signinForm" method="POST" action="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>" novalidate>
                <?php echo $security->getCsrfInput(); ?>

                <div class="form-group">
                    <label for="login_identifier">Username or Email</label>
                    <input type="text" class="form-control" id="login_identifier" name="login_identifier" required value="<?php echo $login_identifier_value; ?>">
                    <div class="invalid-feedback">Username or Email is required.</div>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                    <div class="invalid-feedback">Password is required.</div>
                </div>
                <div class="form-group">
                    <a href="<?php echo $authController->buildUrl(PAGE_FORGOT_PASSWORD); ?>">Forgot Password?</a>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Sign In</button>
            </form>
            <p class="text-center mt-3">
                Don't have an account? <a href="<?php echo $authController->buildUrl(PAGE_SIGNUP); ?>">Sign Up</a>
            </p>
        </div>
    </div>
    <script>
        // Standard Bootstrap validation script
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var form = document.getElementById('signinForm');
                if (!form) return;

                form.addEventListener('submit', function(event) {
                    if (form.checkValidity() === false) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                }, false);
            }, false);
        })();
    </script>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
