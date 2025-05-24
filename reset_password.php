<?php
session_start();

// HTTP Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com; style-src 'self' https://stackpath.bootstrapcdn.com 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://stackpath.bootstrapcdn.com;");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"); // Uncomment if site is HTTPS only

$db_path = 'db/users.sqlite';
$pdo = new PDO('sqlite:' . $db_path);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$errors = [];
$success_message = '';
$token = $_GET['token'] ?? '';
$show_form = false;
$user_id = null;

if (empty($token)) {
    $errors[] = 'Invalid or missing reset token.';
} else {
    try {
        $stmt = $pdo->prepare("SELECT id, reset_token_expiry FROM users WHERE reset_token = :token");
        $stmt->execute([':token' => $token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $expiry_time = strtotime($user['reset_token_expiry']);
            if (time() > $expiry_time) {
                $errors[] = 'Password reset token has expired.';
            } else {
                $show_form = true;
                $user_id = $user['id']; // Store user_id for update
                // Generate CSRF token only when the form is about to be shown
                if ($_SERVER['REQUEST_METHOD'] === 'GET') {
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                }
            }
        } else {
            $errors[] = 'Invalid password reset token.';
        }
    } catch (PDOException $e) {
        $errors[] = 'Error validating token. Please try again.';
        // Log $e->getMessage()
    }
}

if ($show_form && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
    } else {
        unset($_SESSION['csrf_token']); // Invalidate token after use

        // Re-verify URL token from POST to ensure it wasn't tampered with if passed in form
        $posted_url_token = $_POST['url_token'] ?? ''; // The token from URL, now submitted in form
        if($posted_url_token !== $token){ // $token is from $_GET initially
            $errors[] = 'Password reset token mismatch. Please try the reset process again.';
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

        if (empty($errors) && $user_id) { // Ensure user_id was fetched
            try {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);
                $update_stmt = $pdo->prepare("UPDATE users SET password_hash = :password_hash, reset_token = NULL, reset_token_expiry = NULL WHERE id = :id");
                $update_stmt->execute([
                    ':password_hash' => $password_hash,
                    ':id' => $user_id
                ]);
                $success_message = 'Your password has been successfully reset! You can now <a href="signin.php">sign in</a>.';
                $show_form = false; // Hide form on success
            } catch (PDOException $e) {
                $errors[] = 'An error occurred while resetting your password. Please try again.';
                // Log $e->getMessage()
            }
        }
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
        <div class="auth-container"> <!-- Changed class here -->
            <h2 class="text-center mb-4">Reset Your Password</h2>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <p class="mb-0"><?php echo htmlspecialchars($error); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if ($success_message): ?>
                <div class="alert alert-success">
                    <p class="mb-0"><?php echo $success_message; // Contains HTML link ?></p>
                </div>
            <?php endif; ?>

            <?php if ($show_form): ?>
            <form id="resetPasswordForm" method="POST" action="reset_password.php?token=<?php echo htmlspecialchars($token); ?>" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>">
                <input type="hidden" name="url_token" value="<?php echo htmlspecialchars($token); ?>"> <!-- Pass the URL token -->
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
            <?php elseif (empty($success_message) && !empty($token)): // if no success and token was present but form not shown (e.g. token error) ?>
                <p class="text-center"><a href="forgot_password.php">Request a new reset link</a></p>
            <?php endif; ?>
             <p class="text-center mt-3">
                <a href="signin.php">Back to Sign In</a>
            </p>
        </div>
    </div>

    <script>
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
                        confirmPassword.parentElement.querySelector('.invalid-feedback').textContent = "Passwords do not match.";
                        event.preventDefault();
                        event.stopPropagation();
                    } else {
                        confirmPassword.setCustomValidity("");
                    }
                }, false);

                var passwordInput = document.getElementById('password');
                var confirmPasswordInput = document.getElementById('confirm_password');
                if(passwordInput && confirmPasswordInput) {
                    confirmPasswordInput.addEventListener('input', function() {
                        if (passwordInput.value !== confirmPasswordInput.value) {
                            confirmPasswordInput.setCustomValidity("Passwords do not match.");
                        } else {
                            confirmPasswordInput.setCustomValidity("");
                        }
                    });
                    passwordInput.addEventListener('input', function() {
                        if (passwordInput.value !== confirmPasswordInput.value && confirmPasswordInput.value !== "") {
                            confirmPasswordInput.setCustomValidity("Passwords do not match.");
                        } else {
                            confirmPasswordInput.setCustomValidity("");
                        }
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
