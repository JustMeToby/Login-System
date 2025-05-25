<?php
/**
 * Handles the "Forgot Password" form submission, including rate limiting,
 * input validation, token generation, and user notification (via flash messages).
 * This script is included by forgot_password.php and relies on variables/services
 * initialized by bootstrap.php (e.g., $authController, $user, $security, $rateLimiter, $auditLogger)
 * and $clientIp defined in the calling script.
 * It also expects $form_email_value to be initialized in the calling script.
 */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? ''); // Get email early for logging
    // It's good practice to ensure $form_email_value is updated here for consistency,
    // even if the primary use case involves redirects clearing the form.
    $form_email_value = $security->escapeHTML($email);

    // ** Check IP Rate Limit First **
    if (!$rateLimiter->checkPasswordResetIpAttempts($clientIp)) {
        if ($auditLogger) {
            $auditLogger->log(
                \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUEST_FAILED_IP_LOCKOUT,
                null,
                ['ip_address' => $clientIp, 'email_attempted' => $email]
            );
        }
        $authController->getAndSetFlashMessage('errors', ["Too many password reset requests from this IP address. Please try again later."], true);
        $authController->redirect(PAGE_FORGOT_PASSWORD); // redirect() handles exit
    }

    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $rateLimiter->recordPasswordResetIpAttempt($clientIp);
        if ($auditLogger) {
            $auditLogger->log(
                \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUEST_FAILED_IP_LOCKOUT, // Consider a specific CSRF failure event if available
                null,
                ['ip_address' => $clientIp, 'email_attempted' => $email, 'reason' => 'CSRF token validation failed']
            );
        }
        $authController->getAndSetFlashMessage('errors', ['Security token validation failed. Please try submitting the form again.'], true);
        $authController->redirect(PAGE_FORGOT_PASSWORD);
    }

    // ** Record the reset attempt from this IP after CSRF passes and IP not initially locked **
    $rateLimiter->recordPasswordResetIpAttempt($clientIp);

    $current_errors = []; 
    if (empty($email)) {
        $current_errors[] = 'Email is required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $current_errors[] = 'Invalid email format.';
    }

    if (!empty($current_errors)) {
        if ($auditLogger) {
             $auditLogger->log(
                \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUEST_FAILED_USER_NOT_FOUND, // Or validation error
                null,
                ['ip_address' => $clientIp, 'email_attempted' => $email, 'reason' => implode(', ', $current_errors)]
            );
        }
        $authController->getAndSetFlashMessage('errors', $current_errors, true);
        $authController->redirect(PAGE_FORGOT_PASSWORD); 
    }

    $userData = $user->findByLogin($email); 

    if ($userData) {
        $token = bin2hex(random_bytes(32));
        $expirySeconds = defined('PASSWORD_RESET_TOKEN_LIFESPAN_SECONDS') ? PASSWORD_RESET_TOKEN_LIFESPAN_SECONDS : (defined('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS') ? EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS : 86400);
        $expiryDateTime = date('Y-m-d H:i:s', time() + $expirySeconds);

        if ($user->setResetToken($userData['email'], $token, $expiryDateTime)) {
            $resetLink = $authController->buildUrl(PAGE_RESET_PASSWORD, 'token=' . $token);
            $successMsg = "If an account with that email exists, a password reset link has been generated.";
            // The info message contains HTML, so it should be handled carefully when displayed.
            // $authController->buildUrl and $security->escapeHTML ensure parts of it are safe.
            $infoMsg = "Password Reset Link (for demonstration only, would be emailed in production): <a href='" . $resetLink . "'>" . $security->escapeHTML($resetLink) . "</a>";
            
            $authController->getAndSetFlashMessage('success', $successMsg);
            $authController->getAndSetFlashMessage('info', $infoMsg); // This sets the HTML directly into flash.
            if ($auditLogger) {
                $auditLogger->log(
                    \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUEST_SUCCESS,
                    $userData['id'],
                    ['ip_address' => $clientIp, 'email' => $userData['email']]
                );
            }
        } else {
            if ($auditLogger) {
                $auditLogger->log(
                    \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUEST_FAILED_USER_NOT_FOUND, // Or system error
                    $userData['id'],
                    ['ip_address' => $clientIp, 'email' => $userData['email'], 'reason' => 'Failed to set reset token in database.']
                );
            }
            $authController->getAndSetFlashMessage('errors', ['Could not generate reset token due to a system error. Please try again later.'], true);
        }
    } else {
        if ($auditLogger) {
            $auditLogger->log(
                \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_REQUEST_FAILED_USER_NOT_FOUND,
                null,
                ['ip_address' => $clientIp, 'email_attempted' => $email, 'reason' => 'Email not found in system.']
            );
        }
        $authController->getAndSetFlashMessage('success', "If an account with that email exists, a password reset link has been generated.");
    }
    
    $authController->redirect(PAGE_FORGOT_PASSWORD);
}
?>
