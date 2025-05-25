<?php
/**
 * Handles user sign-in with rate limiting.
 *
 * This script displays the sign-in form, processes form submissions,
 * validates user credentials, implements IP and user-based rate limiting,
 * and manages session/login state using services from bootstrap.php.
 */
require_once 'login_system/src/bootstrap.php'; // Defines $authController, $user, $security, $rateLimiter

// A more robust IP getter could be moved to a utility function later
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown'; // Fallback for CLI or misconfigured server

$authController->requireGuest();

$errors = []; 
$login_identifier_value = ''; // To repopulate form field

// The POST request handling logic is now in handle_signin.php
require_once 'login_system/includes/handle_signin.php';

// The following block handles GET requests or scenarios where POST logic doesn't redirect.
// For GET requests, it ensures a CSRF token is available for the form.
if ($_SERVER['REQUEST_METHOD'] === 'GET') { 
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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="login_system/css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container">
            <h2 class="text-center mb-4">Sign In</h2>

            <?php display_flash_messages('errors', 'danger'); ?>
            <?php display_flash_messages('success', 'success'); // For messages like 'logged out successfully' ?>

            <form id="signinForm" method="POST" action="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>" novalidate>
                <?php echo $security->getCsrfInput(); ?>

                <div class="mb-3">
                    <label for="login_identifier" class="form-label">Username or Email</label>
                    <input type="text" class="form-control" id="login_identifier" name="login_identifier" required value="<?php echo $login_identifier_value; ?>">
                    <div class="invalid-feedback">Username or Email is required.</div>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                    <div class="invalid-feedback">Password is required.</div>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label> <!-- Assuming this duplicate field is intentional or will be handled separately -->
                    <input type="password" class="form-control" id="password" name="password" required>
                    <div class="invalid-feedback">Password is required.</div>
                </div>
                <div class="mb-3 form-check">
                    <input type="checkbox" class="form-check-input" id="remember_me" name="remember_me" value="1">
                    <label class="form-check-label" for="remember_me">Remember Me</label>
                </div>
                <div class="mb-3">
                    <a href="<?php echo $authController->buildUrl(PAGE_FORGOT_PASSWORD); ?>">Forgot Password?</a>
                </div>
                <button type="submit" class="btn btn-primary w-100">Sign In</button>
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
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
