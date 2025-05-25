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
        if ($password !== $confirm_password) {
            $errors[] = 'Passwords do not match.';
        }

        // Check if username or email already exists
        if (empty($errors)) {
            if ($user->findByLogin($username)) {
                $errors[] = 'Username already taken. Please choose another.';
            }
            if ($user->findByLogin($email)) {
                $errors[] = 'Email already registered. Please use another or <a href="signin.php">sign in</a>.';
            }
        }

        if (empty($errors)) {
            $userId = $user->create($username, $email, $password);
            if ($userId) {
                $signInUrl = $authController->buildUrl(PAGE_SIGNIN);
                $authController->getAndSetFlashMessage('success', "Signup successful! You can now <a href='{$signInUrl}'>sign in</a>.");
                $authController->redirect(PAGE_SIGNUP); // Redirect to show success and clear form
            } else {
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
