<?php
/**
 * Handles new user registration.
 *
 * This script displays the registration form, processes submissions,
 * validates input, creates new user accounts, and manages user feedback
 * using services from bootstrap.php.
 */
require_once 'login_system/src/bootstrap.php'; // Defines $authController, $user, $security

// Ensure user is a guest (not logged in), redirect to dashboard if logged in
$authController->requireGuest();

$errors = [];
$form_values = [
    'username' => '',
    'email' => ''
];

// The POST request handling logic is now in handle_signup.php
// It will use and potentially modify $errors and $form_values.
// It will also use $security, $user, $authController, $auditLogger.
require_once 'login_system/includes/handle_signup.php';

// For GET requests, ensure CSRF token is generated.
// Also, retrieve any success flash message that might have been set by handle_signup.php
// (e.g., if registration was successful and redirected to signin, then user navigates back to signup).
// Error flash messages are typically displayed on redirect back to signup page from handle_signup.php.
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $security->generateCsrfToken();
}

// Fetch success messages to display above the form (if any)
// Note: Error messages are displayed via display_flash_messages() using sessions,
// typically after a redirect from handle_signup.php if errors occurred.
$successMessageHTML = $authController->getAndSetFlashMessage('success');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - <?php echo $security->escapeHTML(defined('SITE_NAME') ? SITE_NAME : 'Login System'); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="login_system/css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container">
            <h2 class="text-center mb-4">Create Account</h2>

            <?php 
            // Display error flash messages that might have been set by handle_signup.php on redirect
            display_flash_messages('errors', 'danger'); 
            ?>

            <?php if ($successMessageHTML): ?>
                <div class="alert alert-success">
                    <?php 
                        // Success messages (e.g. from previous direct navigation after successful registration)
                        // are expected to be safe or already escaped.
                        echo $successMessageHTML; 
                    ?>
                </div>
            <?php endif; ?>

            <?php 
            // Conditionally display the form. If a success message is present (e.g. from a previous non-redirected success,
            // or if user navigates back to signup after a successful registration and redirect to signin),
            // it might be desirable to hide the form. The current logic will show the success message AND the form
            // if $successMessageHTML is set AND we don't explicitly hide the form.
            // The original logic was: `else: // Hide form on success (success message is shown above)`
            // If we want to hide the form when $successMessageHTML is present:
            if (!$successMessageHTML): 
            ?>
            <form id="signupForm" method="POST" action="<?php echo $authController->buildUrl(PAGE_SIGNUP); ?>" novalidate>
                <?php echo $security->getCsrfInput(); ?>
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required value="<?php echo $form_values['username']; ?>">
                    <div class="invalid-feedback">Username is required.</div>
                </div>
                <div class="mb-3">
                    <label for="email" class="form-label">Email address</label>
                    <input type="email" class="form-control" id="email" name="email" required value="<?php echo $form_values['email']; ?>">
                    <div class="invalid-feedback">Please enter a valid email.</div>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required minlength="8">
                    <div class="invalid-feedback">Password must be at least 8 characters.</div>
                </div>
                <div class="mb-3">
                    <label for="confirm_password" class="form-label">Confirm Password</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                    <div class="invalid-feedback">Please confirm your password.</div>
                </div>
                <button type="submit" class="btn btn-primary w-100">Sign Up</button>
            </form>
            <p class="text-center mt-3">
                Already have an account? <a href="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>">Sign In</a>
            </p>
            </form> <?php /* Closing form tag for the if (!$successMessageHTML) condition */ ?>
            <?php endif; // End of if (!$successMessageHTML) ?>
        </div>
    </div>

    <script>
        // Standard Bootstrap validation script + password match
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var form = document.getElementById('signupForm');
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
                        // Ensure the feedback div exists and update its text
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
                        // If confirm has content, trigger its validation display
                        if(confirmPasswordInput.value !== ""){
                             confirmPasswordInput.reportValidity();
                        }
                    });
                }
            }, false);
        })();
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
