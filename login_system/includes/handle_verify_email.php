<?php
/**
 * Handles the email verification logic based on a token from the URL.
 *
 * Expected to be included by verify_email.php.
 * Relies on services from bootstrap.php ($user, $authController, $auditLogger).
 * It will define $errors (array) and $successMessage (string) for verify_email.php to use.
 */

// Ensure services are available (they are global from bootstrap.php)
// No need for explicit global keyword here if they are accessed directly as globals.
if (!isset($user) || !isset($authController) || !isset($auditLogger)) {
    if (function_exists('error_log')) {
        error_log("Critical services (User, AuthController, or AuditLogger) not available in handle_verify_email.php.");
    }
    // Set a generic error if services are missing.
    // $errors should be initialized in the calling script (verify_email.php).
    if (isset($errors) && is_array($errors)) {
        $errors[] = "A system error occurred. Please try again later or contact support.";
    }
    return; // Stop execution of this script.
}

// Initialize $errors and $successMessage if not already done by calling script (though it's better if they are)
if (!isset($errors) || !is_array($errors)) {
    $errors = [];
}
if (!isset($successMessage)) {
    $successMessage = '';
}

$token = $_GET['token'] ?? null;

if (empty($token)) {
    $errors[] = "No verification token provided.";
    if ($auditLogger) {
        $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED, null, ['reason' => 'No token in URL']);
    }
} else {
    // Token is present, proceed with validation and verification.
    $userData = $user->findUserByVerificationToken($token);

    if ($userData) {
        if ((int)$userData['is_verified'] === 1) {
            // User is already verified
            $successMessage = "This email address has already been verified. You can <a href='" . $authController->buildUrl(PAGE_SIGNIN) . "'>sign in</a>.";
            if ($auditLogger) {
                $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_ALREADY_VERIFIED, (int)$userData['id'], ['token_used' => $token]);
            }
        } else {
            // Token is valid, user found, and not yet verified. Proceed to verify.
            if ($user->verifyEmailAddress((int)$userData['id'])) {
                $successMessage = "Your email address has been successfully verified! You can now <a href='" . $authController->buildUrl(PAGE_SIGNIN) . "'>sign in</a>.";
                // EVENT_EMAIL_VERIFICATION_SUCCESS is logged by User::verifyEmailAddress
            } else {
                $errors[] = "An error occurred while verifying your email address. Please try again or contact support.";
                // User::verifyEmailAddress should log specific DB errors.
                if ($auditLogger) {
                    $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED, (int)$userData['id'], ['reason' => 'User::verifyEmailAddress returned false', 'token_used' => $token]);
                }
            }
        }
    } else {
        // Token is invalid, expired, or no user found for this token
        $errors[] = "Invalid or expired verification link. Please request a new one if needed or contact support.";
        if ($auditLogger) {
            $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED_INVALID_TOKEN, null, ['reason' => 'Invalid/expired token', 'token_attempted' => $token]);
        }
    }
}
?>
