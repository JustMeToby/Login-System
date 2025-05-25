<?php
/**
 * Handles new user registration.
 *
 * This script displays the registration form, processes submissions,
 * validates input, creates new user accounts, and manages user feedback
 * using services from bootstrap.php.
 */
require_once 'src/bootstrap.php'; // Defines $authController, $user, $security

// Ensure user is a guest (not logged in), redirect to dashboard if logged in
$authController->requireGuest();

$errors = [];
$form_values = [
    'username' => '',
    'email' => ''
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$security->verifyCsrfToken($_POST[CSRF_TOKEN_NAME] ?? '')) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        $form_values['username'] = $security->escapeHTML($username);
        $form_values['email'] = $security->escapeHTML($email);

        // Basic validation
        if (empty($username)) {
            $errors[] = 'Username is required.';
        }
        if (empty($email)) {
            $errors[] = 'Email is required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email format.';
        }
        if (empty($password)) {
            $errors[] = 'Password is required.';
        } elseif (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters long.';
        }
        if (empty($password)) { // This check for empty password is fine
            $errors[] = 'Password is required.';
        } elseif ($password !== $confirm_password) { // Check match before policy
            $errors[] = 'Passwords do not match.';
        } else {
            // Passwords match, now check policy
            // Note: The individual check for min length (strlen($password) < 8) is now covered by the policy service.
            // We can remove it if PASSWORD_POLICY_MIN_LENGTH is always set and >= 8, or keep it as a preliminary client-side hint.
            // For this integration, we'll rely on the policy service for password content validation.
            // The old: elseif (strlen($password) < 8) { $errors[] = 'Password must be at least 8 characters long.'; } can be removed
            // if the policy service handles min length effectively.
            
            $passwordPolicyService = new \LoginSystem\Security\PasswordPolicyService();
            $policyErrors = $passwordPolicyService->validatePassword($password);
            if (!empty($policyErrors)) {
                $errors = array_merge($errors, $policyErrors);
            }
        }

        // Proceed to check username/email existence only if other validations (including password policy) passed
        if (empty($errors)) {
            if ($user->findByLogin($username)) {
                $errors[] = 'Username already taken. Please choose another.';
            }
            // Check email existence only if username was not already taken (and other errors are still empty)
            if (empty($errors) && $user->findByLogin($email)) {
                $errors[] = 'Email already registered. Please use another or <a href="signin.php">sign in</a>.';
            }
        }

        if (empty($errors)) {
            // All checks passed, including password policy and unique username/email
            // All checks passed, including password policy and unique username/email
            $userId = $user->create($username, $email, $password); // User::create already logs EVENT_USER_REGISTERED
            if ($userId) {
                if (defined('EMAIL_VERIFICATION_ENABLED') && EMAIL_VERIFICATION_ENABLED === true) {
                    // Log the request for verification email (already done in previous turn, this is a good place)
                    if ($auditLogger) {
                        $auditLogger->log(
                            \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_REQUESTED,
                            (int)$userId,
                            ['email' => $email] // Logged with user ID and email
                        );
                    }

                    // Fetch the user data to get the token
                    $newUserData = $user->findById((int)$userId);
                    if ($newUserData && !empty($newUserData['verification_token'])) {
                        $verificationLink = $authController->buildUrl(PAGE_VERIFY_EMAIL, 'token=' . urlencode($newUserData['verification_token']));
                        
                        // Ensure $email, $username, $userId, $verificationLink, $authController, $security, and $auditLogger 
                        // are available and correctly populated in this scope.
                        // $email and $username are from form POST data. $userId is from $user->create().

                        $emailSent = \LoginSystem\Utils\EmailService::sendVerificationEmail($email, $username, $verificationLink);

                        if ($emailSent) {
                            $successMessage = "Registration successful! A verification link has been sent to your email address (" . $security->escapeHTML($email) . "). Please click the link to activate your account.";
                            $authController->getAndSetFlashMessage('success', $successMessage);
                            if ($auditLogger) {
                                $auditLogger->log(
                                    \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_SENT, 
                                    (int)$userId,
                                    ['email' => $email]
                                );
                            }
                        } else {
                            $errorMessage = "Registration successful, but we encountered an issue sending your verification email. Please contact support if you don't receive it shortly.";
                            $authController->getAndSetFlashMessage('errors', [$errorMessage], true); // true to append
                            if ($auditLogger) {
                                $auditLogger->log(
                                    \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_SEND_FAILED,
                                    (int)$userId,
                                    ['email' => $email, 'type' => 'verification', 'reason' => 'EmailService::sendVerificationEmail returned false']
                                );
                            }
                        }
                        // The existing redirect, like $authController->redirect(PAGE_SIGNIN);, will handle showing the flash message.
                    } else {
                        // This case should ideally not happen if User::create works as expected
                        error_log("Failed to retrieve verification token for new user ID: {$userId}");
                        $authController->getAndSetFlashMessage('errors', ['Registration was successful, but there was an issue sending the verification email. Please contact support.'], true);
                    }
                } else {
                    // Email verification not enabled
                    $signInUrl = $authController->buildUrl(PAGE_SIGNIN);
                    $authController->getAndSetFlashMessage('success', "Registration successful! You can now <a href='{$signInUrl}'>sign in</a>.");
                }
                // Redirect to signin page to show the message (or signup page itself if preferred)
                $authController->redirect(PAGE_SIGNIN); 
            } else {
                // User creation failed (e.g. DB error not caught by earlier checks)
                $errors[] = 'An error occurred during registration. Please try again. If the problem persists, contact support.';
                // Detailed error is logged by User class
            }
        }
    }
    if (!empty($errors)) {
        $authController->getAndSetFlashMessage('errors', $errors, true);
        $authController->redirect(PAGE_SIGNUP); // Redirect to show flash errors
    }

} else {
    // Generate CSRF token for GET request
    $security->generateCsrfToken();
}

$successMessageHTML = $authController->getAndSetFlashMessage('success');

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container">
            <h2 class="text-center mb-4">Create Account</h2>

            <?php display_flash_messages('errors', 'danger'); ?>

            <?php if ($successMessageHTML): ?>
                <div class="alert alert-success">
                    <?php 
                        // Message from User::create can contain HTML, so not escaping here
                        // Ensure any HTML set in flash messages is safe or appropriately escaped there.
                        // For this specific success message, we allow the link.
                        echo $successMessageHTML; 
                    ?>
                </div>
            <?php else: // Hide form on success (success message is shown above) ?>
            <form id="signupForm" method="POST" action="<?php echo $authController->buildUrl(PAGE_SIGNUP); ?>" novalidate>
                <?php echo $security->getCsrfInput(); ?>
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required value="<?php echo $form_values['username']; ?>">
                    <div class="invalid-feedback">Username is required.</div>
                </div>
                <div class="form-group">
                    <label for="email">Email address</label>
                    <input type="email" class="form-control" id="email" name="email" required value="<?php echo $form_values['email']; ?>">
                    <div class="invalid-feedback">Please enter a valid email.</div>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required minlength="8">
                    <div class="invalid-feedback">Password must be at least 8 characters.</div>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                    <div class="invalid-feedback">Please confirm your password.</div>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Sign Up</button>
            </form>
            <p class="text-center mt-3">
                Already have an account? <a href="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>">Sign In</a>
            </p>
            <?php endif; ?>
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
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
