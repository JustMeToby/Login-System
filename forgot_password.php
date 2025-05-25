<?php
/**
 * Handles the "Forgot Password" process with IP-based rate limiting.
 *
 * This script displays a form for users to enter their email address.
 * On submission, it checks for rate limits, validates input, generates a
 * password reset token (if the email exists), stores it, and (for demonstration)
 * displays a reset link. In a production environment, this link would be emailed.
 */
require_once 'src/bootstrap.php'; // $authController, $user, $security, $rateLimiter

// A more robust IP getter could be moved to a utility function later
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown'; // Fallback for CLI or misconfigured server

$authController->requireGuest(); // User should not be logged in

// $errors = []; // Not strictly used for logic if redirecting on each error, but good for structure. Flash messages are used.
$form_email_value = ''; // To repopulate form field on non-redirecting errors (not current flow)

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ** Check IP Rate Limit First **
    if ($rateLimiter->isBlocked($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_RESET_REQUEST)) {
        $authController->getAndSetFlashMessage('errors', ["Too many password reset requests from your IP address. Please try again later."], true);
        $authController->redirect(PAGE_FORGOT_PASSWORD); // redirect() handles exit
    }

    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $authController->getAndSetFlashMessage('errors', ['Security token validation failed. Please try submitting the form again.'], true);
        // Note: A failed CSRF might not count towards specific reset request limits,
        // but could be logged or handled by a more general IP-based suspicious activity limiter.
        // For this specific task, we are focusing on TYPE_IP_RESET_REQUEST after CSRF passes.
        $authController->redirect(PAGE_FORGOT_PASSWORD);
    }

    // ** Record the reset attempt from this IP after CSRF passes **
    // This ensures that even if the email is invalid or other issues occur, the attempt from this IP is noted.
    $rateLimiter->recordAttempt($clientIp, \LoginSystem\Security\RateLimiterService::TYPE_IP_RESET_REQUEST);

    $email = trim($_POST['email'] ?? '');
    $form_email_value = $security->escapeHTML($email); // For re-populating form if needed (though we redirect)

    $current_errors = []; // Use a temporary array for current request errors
    if (empty($email)) {
        $current_errors[] = 'Email is required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $current_errors[] = 'Invalid email format.';
    }

    if (!empty($current_errors)) {
        $authController->getAndSetFlashMessage('errors', $current_errors, true);
        $authController->redirect(PAGE_FORGOT_PASSWORD); // Redirect back to the form
    }

    // At this point, CSRF is valid, email format is valid, and attempt is recorded.
    // Proceed with token generation logic.
    $userData = $user->findByLogin($email); // findByLogin can find by email

    if ($userData) {
        $token = bin2hex(random_bytes(32));
        // Using EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS as per instruction for now.
        // A dedicated PASSWORD_RESET_TOKEN_LIFESPAN_SECONDS would be better.
        $expiryDateTime = date('Y-m-d H:i:s', time() + (defined('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS') ? EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS : 86400));

        if ($user->setResetToken($userData['email'], $token, $expiryDateTime)) {
            $resetLink = $authController->buildUrl(PAGE_RESET_PASSWORD, 'token=' . $token);
            $successMsg = "If an account with that email exists, a password reset link has been generated.";
            // buildUrl already escapes the URL for HTML attribute context.
            // Displaying the link text itself should also be escaped if it's constructed from parts that could be malicious,
            // but here $resetLink is fully formed and escaped by buildUrl.
            $infoMsg = "Password Reset Link (for demonstration only, would be emailed in production): <a href='" . $resetLink . "'>" . $security->escapeHTML($resetLink) . "</a>";
            
            $authController->getAndSetFlashMessage('success', $successMsg);
            $authController->getAndSetFlashMessage('info', $infoMsg);
            // Audit log for request
            if ($auditLogger) { // $auditLogger is globally available
                $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUESTED, $userData['id'], ['email' => $userData['email']]);
            }
        } else {
            // This indicates a server-side issue with setting the token.
            $authController->getAndSetFlashMessage('errors', ['Could not generate reset token due to a system error. Please try again later.'], true);
        }
    } else {
        // Generic message to avoid disclosing whether an email is registered or not.
        // This is the same message as if successful token generation to prevent email enumeration.
        $authController->getAndSetFlashMessage('success', "If an account with that email exists, a password reset link has been generated.");
    }
    
    // Redirect to the same page to show flash messages and clear POST data
    $authController->redirect(PAGE_FORGOT_PASSWORD);

} else { // GET request
    // Generate CSRF token for the form
    $security->generateCsrfToken();
}

// Retrieve flash messages for display (these are cleared from session by getAndSetFlashMessage)
$successMessageHTML = $authController->getAndSetFlashMessage('success');
$infoMessageHTML = $authController->getAndSetFlashMessage('info');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - <?php echo $security->escapeHTML(defined('SITE_NAME') ? SITE_NAME : 'Login System'); ?></title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container">
            <h2 class="text-center mb-4">Forgot Password</h2>

            <?php display_flash_messages('errors', 'danger'); // Display any error flash messages ?>
            
            <?php if ($successMessageHTML): ?>
                <div class="alert alert-success">
                    <p class="mb-0"><?php echo $security->escapeHTML($successMessageHTML); // Success message is plain text ?></p>
                </div>
            <?php endif; ?>

            <?php if ($infoMessageHTML): ?>
                <div class="alert alert-info">
                    <?php /* Info message contains HTML (the link), generated by buildUrl which escapes for href. Displaying the link text itself is also escaped. */ ?>
                    <p class="mb-0"><?php echo $infoMessageHTML; ?></p>
                </div>
            <?php endif; ?>

            <?php if (!$successMessageHTML && !$infoMessageHTML): // Only show form if no success/info message is being displayed ?>
            <form id="forgotPasswordForm" method="POST" action="<?php echo $authController->buildUrl(PAGE_FORGOT_PASSWORD); ?>" novalidate>
                <?php echo $security->getCsrfInput(); ?>
                <div class="form-group">
                    <label for="email">Enter your email address</label>
                    <input type="email" class="form-control" id="email" name="email" required value="<?php echo $form_email_value; // Repopulate on server-side validation error without redirect (not current flow) ?>">
                    <div class="invalid-feedback">Please enter a valid email.</div>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Send Reset Link</button>
            </form>
            <?php endif; ?>
            <p class="text-center mt-3">
                Remembered your password? <a href="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>">Sign In</a>
            </p>
        </div>
    </div>

    <script>
        // Standard Bootstrap validation script
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var form = document.getElementById('forgotPasswordForm');
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
