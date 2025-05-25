<?php
/**
 * Handles the password reset process using a token.
 *
 * This script validates the token provided in the URL, displays a form
 * for entering a new password, and processes the password update.
 * It relies on services from bootstrap.php for token validation,
 * password updates, and user feedback.
 */
require_once 'src/bootstrap.php'; // Defines $authController, $user, $security

$authController->requireGuest(); // User should not be logged in

$errors = [];
$token = $_GET['token'] ?? '';
$show_form = false;
$user_id_for_reset = null; // Store user_id if token is valid

if (empty($token)) {
    $authController->getAndSetFlashMessage('errors', ['Invalid or missing reset token.'], true);
    $authController->redirect(PAGE_FORGOT_PASSWORD); // Redirect if no token
}

// Validate token and check expiry
$userData = $user->findUserByResetToken($token);

if ($userData) {
    $show_form = true;
    $user_id_for_reset = $userData['id'];
    // Generate CSRF token only when the form is about to be shown
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $security->generateCsrfToken();
    }
} else {
    $authController->getAndSetFlashMessage('errors', ['Invalid or expired password reset token. Please request a new one.'], true);
    // Do not redirect immediately from here if we want to show this message on reset_password.php itself
    // $authController->redirect('forgot_password.php');
    if ($auditLogger) {
        $auditLogger->log(
            \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_FAILED_INVALID_TOKEN,
            null,
            ['token_attempted' => $token]
        );
    }
}


if ($show_form && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
    } else {
        // Re-verify URL token from POST to ensure it wasn't tampered with
        $posted_url_token = $_POST['url_token'] ?? '';
        if ($posted_url_token !== $token) {
            $errors[] = 'Password reset token mismatch. Please try the reset process again from the link in your email.';
            $show_form = false; // Don't show form if tokens don't match
            if ($auditLogger && $user_id_for_reset) { // user_id_for_reset might be known if initial token was valid but form token differs
                 $auditLogger->log(
                    \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_FAILED_INVALID_TOKEN,
                    $user_id_for_reset,
                    ['reason' => 'Form token mismatch with URL token.', 'url_token' => $token, 'form_token' => $posted_url_token]
                );
            } elseif ($auditLogger) {
                 $auditLogger->log(
                    \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_FAILED_INVALID_TOKEN,
                    null,
                    ['reason' => 'Form token mismatch with URL token (user ID not resolved).', 'url_token' => $token, 'form_token' => $posted_url_token]
                );
            }
        } else {
            $password = $_POST['password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';
            
            $policyErrors = []; // For specific policy errors

            if (empty($password)) {
                $errors[] = 'New password is required.';
            } elseif ($password !== $confirm_password) {
                $errors[] = 'Passwords do not match.';
            } else {
                // Passwords are not empty and match, now check policy
                $passwordPolicyService = new \LoginSystem\Security\PasswordPolicyService();
                $policyErrors = $passwordPolicyService->validatePassword($password);
                if (!empty($policyErrors)) {
                    $errors = array_merge($errors, $policyErrors);
                }
            }

            if (empty($errors) && $user_id_for_reset) {
                // $user->updatePassword will log EVENT_PASSWORD_CHANGE_SUCCESS or EVENT_PASSWORD_CHANGE_FAILED (on DB error)
                if ($user->updatePassword($user_id_for_reset, $password)) {
                    if ($auditLogger && $userData) { // $userData has user info from valid token
                        $auditLogger->log(
                            \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_SUCCESS,
                            $user_id_for_reset,
                            ['email' => $userData['email']] 
                        );
                    }
                    $user->clearResetToken($user_id_for_reset); 
                    $signInUrl = $authController->buildUrl(PAGE_SIGNIN); 
                    $authController->getAndSetFlashMessage('success', "Your password has been successfully reset! You can now <a href='{$signInUrl}'>sign in</a>.");
                    $show_form = false; 
                    $authController->redirect(PAGE_SIGNIN);
                } else {
                    // User::updatePassword logs its own failures if they are due to DB or hashing.
                    // If updatePassword returns false for other reasons not logged by itself, add a generic error.
                    // However, the current updatePassword logs all its failure paths.
                    // If we reach here, it means updatePassword itself failed and logged it.
                    // We might want to still add a generic error for the user.
                    if (empty($errors)) { // Avoid duplicating errors if policy check already added some.
                         // $errors[] = 'An error occurred while resetting your password. Please try again.';
                         // User::updatePassword already logs EVENT_PASSWORD_CHANGE_FAILED.
                    }
                }
            } elseif (!empty($policyErrors) && $user_id_for_reset) { 
                // This condition specifically handles logging for policy violations that prevented updatePassword call.
                if ($auditLogger) {
                    $auditLogger->log(
                        \LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_CHANGE_FAILED,
                        $user_id_for_reset,
                        ['reason' => 'Password policy violation during reset.', 'policy_errors' => $policyErrors, 'token_used' => $token]
                    );
                }
            }
        }
    }
    // This will catch errors from CSRF, token mismatch, or password validation (including policy)
    if(!empty($errors)){ 
        $authController->getAndSetFlashMessage('errors', $errors, true);
        $authController->redirect(PAGE_RESET_PASSWORD, 'token=' . urlencode($token));
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container">
            <h2 class="text-center mb-4">Reset Your Password</h2>

            <?php display_flash_messages('errors', 'danger'); ?>
            <?php display_flash_messages('success', 'success'); // For success message after redirect from POST ?>

            <?php if ($show_form && !$authController->getAndSetFlashMessage('success')): // Only show form if token was valid and no success message is pending display ?>
            <form id="resetPasswordForm" method="POST" action="<?php echo $authController->buildUrl(PAGE_RESET_PASSWORD, 'token=' . $security->escapeHTML($token)); ?>" novalidate>
                <?php echo $security->getCsrfInput(); ?>
                <input type="hidden" name="url_token" value="<?php echo $security->escapeHTML($token); ?>">

                <div class="form-group">
                    <label for="password">New Password</label>
                    <input type="password" class="form-control" id="password" name="password" required minlength="8">
                    <div class="invalid-feedback">Password must be at least 8 characters.</div>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                    <div class="invalid-feedback">Please confirm your new password.</div>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Reset Password</button>
            </form>
            <?php elseif (!$show_form && empty($authController->getAndSetFlashMessage('success'))): // If form not shown due to bad token AND no success message is up ?>
                 <p class="text-center">If your token is invalid or expired, you can <a href="<?php echo $authController->buildUrl(PAGE_FORGOT_PASSWORD); ?>">request a new reset link</a>.</p>
            <?php endif; ?>
             <p class="text-center mt-3">
                <a href="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>">Back to Sign In</a>
            </p>
        </div>
    </div>

    <script>
        // Standard Bootstrap validation + password match
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var form = document.getElementById('resetPasswordForm');
                if (!form) return;

                form.addEventListener('submit', function(event) {
                    if (form.checkValidity() === false) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');

                    var password = document.getElementById('password');
                    var confirmPassword = document.getElementById('confirm_password');
                    if (password.value !== confirmPassword.value) {
                        confirmPassword.setCustomValidity("Passwords do not match.");
                        var feedback = confirmPassword.parentElement.querySelector('.invalid-feedback');
                        if(feedback) feedback.textContent = "Passwords do not match.";
                        event.preventDefault();
                        event.stopPropagation();
                    } else {
                        confirmPassword.setCustomValidity("");
                    }
                }, false);
                
                var passwordInput = document.getElementById('password');
                var confirmPasswordInput = document.getElementById('confirm_password');
                if(passwordInput && confirmPasswordInput) {
                    function validatePasswordMatch() {
                        if (passwordInput.value !== confirmPasswordInput.value) {
                            confirmPasswordInput.setCustomValidity("Passwords do not match.");
                        } else {
                            confirmPasswordInput.setCustomValidity("");
                        }
                    }
                    confirmPasswordInput.addEventListener('input', validatePasswordMatch);
                    passwordInput.addEventListener('input', function() {
                        validatePasswordMatch();
                        if(confirmPasswordInput.value !== ""){
                             confirmPasswordInput.reportValidity();
                        }
                    });
                }
            }, false);
        })();
    </script>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
