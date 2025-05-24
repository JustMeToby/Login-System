<?php
session_start();

// HTTP Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com; style-src 'self' https://stackpath.bootstrapcdn.com 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://stackpath.bootstrapcdn.com;");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"); // Uncomment if site is HTTPS only

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$db_path = 'db/users.sqlite';
$pdo = new PDO('sqlite:' . $db_path);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$errors = [];
$success_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
    } else {
        // CSRF token is valid, proceed with form processing
        unset($_SESSION['csrf_token']); // Invalidate token after use

        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

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
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username OR email = :email");
        $stmt->execute([':username' => $username, ':email' => $email]);
        if ($stmt->fetchColumn() > 0) {
            $stmt_check_username = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
            $stmt_check_username->execute([':username' => $username]);
            if ($stmt_check_username->fetchColumn() > 0) {
                $errors[] = 'Username already taken. Please choose another.';
            }

            $stmt_check_email = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = :email");
            $stmt_check_email->execute([':email' => $email]);
            if ($stmt_check_email->fetchColumn() > 0) {
                $errors[] = 'Email already registered. Please use another or login.';
            }
        }
    }

    if (empty($errors)) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        try {
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)");
            $stmt->execute([
                ':username' => $username,
                ':email' => $email,
                ':password_hash' => $password_hash
            ]);
            $success_message = 'Signup successful! You can now <a href="signin.php">sign in</a>.';
        } catch (PDOException $e) {
            // Catch potential unique constraint violation if checks somehow failed (race condition, etc.)
            if ($e->getCode() == 23000) { // SQLSTATE[23000]: Integrity constraint violation
                 $errors[] = 'Username or email already exists.';
            } else {
                 $errors[] = 'An error occurred during registration. Please try again.';
                 // Log $e->getMessage() for debugging in a real application
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
    <title>Sign Up</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container"> <!-- Changed class here -->
            <h2 class="text-center mb-4">Create Account</h2>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <p class="mb-0"><?php echo htmlspecialchars($error); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if ($success_message): ?>
                <div class="alert alert-success">
                    <p class="mb-0"><?php echo $success_message; // Already contains HTML link, so not escaping ?></p>
                </div>
            <?php else: // Hide form on success ?>
            <form id="signupForm" method="POST" action="signup.php" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
                    <div class="invalid-feedback">Username is required.</div>
                </div>
                <div class="form-group">
                    <label for="email">Email address</label>
                    <input type="email" class="form-control" id="email" name="email" required value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
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
                Already have an account? <a href="signin.php">Sign In</a>
            </p>
            <?php endif; ?>
        </div>
    </div>

    <script>
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

                    // Custom validation for password match
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

                // Real-time password match feedback (optional but good UX)
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
                     passwordInput.addEventListener('input', function() { // if user changes original pass after typing confirm
                        if (passwordInput.value !== confirmPasswordInput.value && confirmPasswordInput.value !== "") {
                            confirmPasswordInput.setCustomValidity("Passwords do not match.");
                        } else {
                            confirmPasswordInput.setCustomValidity("");
                        }
                        // Trigger validation display on confirm field
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
