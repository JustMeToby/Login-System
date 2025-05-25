<?php
/**
 * Handles the logic for resetting a user's password.
 * This includes validating the reset token (from GET), and if valid,
 * processing the password reset form submission (POST).
 *
 * Expected to be included by reset_password.php.
 * Relies on services from bootstrap.php ($user, $security, $authController, $auditLogger).
 * Expects $token (from $_GET), $show_form, $user_id_for_reset to be initialized
 * in reset_password.php and modifies $show_form and $user_id_for_reset based on token validation.
 */

// Ensure $token is available from the parent script (reset_password.php)
if (!isset($token)) {
    // This case should ideally not be reached if reset_password.php defines $token.
    $authController->getAndSetFlashMessage('errors', ['Password reset token is missing.'], true);
    $authController->redirect(PAGE_FORGOT_PASSWORD);
    exit; // Stop further script execution
}

$errors = []; // Local errors for this request processing, will be put into flash for redirects.

if (empty($token)) {
    $authController->getAndSetFlashMessage('errors', ['Invalid or missing reset token.'], true);
    $authController->redirect(PAGE_FORGOT_PASSWORD); 
    exit;
}

// Validate token and check expiry
$userData = $user->findUserByResetToken($token);

if ($userData) {
    $show_form = true; // Signal to reset_password.php to display the form
    $user_id_for_reset = $userData['id']; // Make user ID available to reset_password.php if needed

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $security->generateCsrfToken(); // Generate CSRF token when form is about to be shown
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && $show_form) { // Ensure form was meant to be shown
        if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
            $errors[] = 'Security token validation failed. Please try submitting the form again.';
        } else {
            $posted_url_token = $_POST['url_token'] ?? '';
            if ($posted_url_token !== $token) {
                $errors[] = 'Password reset token mismatch. Please try the reset process again from the link in your email.';
                $show_form = false; // Critical: Don't show form if tokens mismatch
                if ($auditLogger) {
                    $log_user_id = $user_id_for_reset ?: null; // Use resolved ID if available
                    $auditLogger->log(
                        \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_FAILED_INVALID_TOKEN,
                        $log_user_id,
                        ['reason' => 'Form token mismatch with URL token.', 'url_token' => $token, 'form_token' => $posted_url_token]
                    );
                }
            } else {
                // CSRF and URL token are valid, proceed with password processing
                $password = $_POST['password'] ?? '';
                $confirm_password = $_POST['confirm_password'] ?? '';
                $policyErrors = [];

                if (empty($password)) {
                    $errors[] = 'New password is required.';
                } elseif ($password !== $confirm_password) {
                    $errors[] = 'Passwords do not match.';
                } else {
                    $passwordPolicyService = new \LoginSystem\Security\PasswordPolicyService();
                    $policyErrors = $passwordPolicyService->validatePassword($password);
                    if (!empty($policyErrors)) {
                        $errors = array_merge($errors, $policyErrors);
                    }
                }

                if (empty($errors) && $user_id_for_reset) {
                    if ($user->updatePassword($user_id_for_reset, $password)) {
                        if ($auditLogger) {
                            $auditLogger->log(
                                \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_SUCCESS,
                                $user_id_for_reset,
                                ['email' => $userData['email']] 
                            );
                        }
                        $user->clearResetToken($user_id_for_reset);
                        $signInUrl = $authController->buildUrl(PAGE_SIGNIN);
                        $authController->getAndSetFlashMessage('success', "Your password has been successfully reset! You can now <a href='{$signInUrl}'>sign in</a>.");
                        $show_form = false; // Form should not be shown after successful reset
                        $authController->redirect(PAGE_SIGNIN);
                        exit;
                    } else {
                        // User::updatePassword logs its own failures.
                        // Add a generic error if not already covered by policy.
                        if (empty($errors)) { // Avoid double message if policy error already listed
                           // $errors[] = 'An error occurred while resetting your password. Please try again.';
                           // Error is logged by User model, flash message will be set if redirect occurs below
                        }
                    }
                } elseif (!empty($policyErrors) && $user_id_for_reset) {
                    if ($auditLogger) {
                        $auditLogger->log(
                            \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_FAILED,
                            $user_id_for_reset,
                            ['reason' => 'Password policy violation during reset.', 'policy_errors' => $policyErrors, 'token_used' => $token]
                        );
                    }
                }
            } // end token mismatch check
        } // end CSRF check

        // If any errors occurred during POST processing, set flash and redirect back to form
        if (!empty($errors)) {
            $authController->getAndSetFlashMessage('errors', $errors, true);
            $authController->redirect(PAGE_RESET_PASSWORD, 'token=' . urlencode($token));
            exit;
        }
    } // end POST request check
} else { // Token is invalid or expired
    $show_form = false; // Ensure form is not shown
    $authController->getAndSetFlashMessage('errors', ['Invalid or expired password reset token. Please request a new one.'], true);
    // No redirect from here, reset_password.php will display this message.
    if ($auditLogger) {
        $auditLogger->log(
            \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_FAILED_INVALID_TOKEN,
            null,
            ['token_attempted' => $token]
        );
    }
}
?>
