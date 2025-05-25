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
        } else {
            $password = $_POST['password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';

            if (empty($password)) {
                $errors[] = 'New password is required.';
            } elseif (strlen($password) < 8) {
                $errors[] = 'Password must be at least 8 characters long.';
            }
            if ($password !== $confirm_password) {
                $errors[] = 'Passwords do not match.';
            }

            if (empty($errors) && $user_id_for_reset) {
                if ($user->updatePassword($user_id_for_reset, $password)) {
                    if ($auditLogger) { // $auditLogger is globally available
                        $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_PASSWORD_RESET_SUCCESS, $user_id_for_reset);
                    }
                    $user->clearResetToken($user_id_for_reset); // Clear token after successful reset
                    // Note: The link in the flash message was already updated to use buildUrl(PAGE_SIGNIN) in a previous subtask (Turn 37).
                    // We'll ensure that structure is maintained.
                    $signInUrl = $authController->buildUrl(PAGE_SIGNIN); // Rebuild for clarity if needed, or use existing.
                    $authController->getAndSetFlashMessage('success', "Your password has been successfully reset! You can now <a href='{$signInUrl}'>sign in</a>.");
                    $show_form = false; // Hide form on success
                    // Redirect to signin page after successful password reset
                    $authController->redirect(PAGE_SIGNIN);

                } else {
                    $errors[] = 'An error occurred while resetting your password. Please try again.';
                    // Error is logged by User class
                }
            }
        }
    }
    if(!empty($errors)){
        $authController->getAndSetFlashMessage('errors', $errors, true);
        // Redirect back to the reset_password page with the token to show errors
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
