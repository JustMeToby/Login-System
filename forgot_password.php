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
$info_message = ''; // For displaying the reset link

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
    } else {
        unset($_SESSION['csrf_token']); // Invalidate token after use

        $email = trim($_POST['email'] ?? '');

        if (empty($email)) {
        $errors[] = 'Email is required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Invalid email format.';
    }

    if (empty($errors)) {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $token = bin2hex(random_bytes(32));
                $expiry_time = date('Y-m-d H:i:s', time() + 3600); // Token valid for 1 hour

                $update_stmt = $pdo->prepare("UPDATE users SET reset_token = :token, reset_token_expiry = :expiry WHERE email = :email");
                $update_stmt->execute([
                    ':token' => $token,
                    ':expiry' => $expiry_time,
                    ':email' => $email
                ]);

                // Simulate email sending
                $reset_link = "reset_password.php?token=" . $token;
                $success_message = "If an account with that email exists, a password reset link has been generated.";
                // For demonstration, we'll display the link. In production, this would be emailed.
                $info_message = "Password Reset Link (for demonstration): <a href='" . htmlspecialchars($reset_link) . "'>" . htmlspecialchars($reset_link) . "</a>";

            } else {
                // Generic message to avoid disclosing whether an email is registered
                $success_message = "If an account with that email exists, a password reset link has been generated.";
            }
        } catch (PDOException $e) {
            $errors[] = 'An error occurred. Please try again later.';
            // Log $e->getMessage() for debugging
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container"> <!-- Changed class here -->
            <h2 class="text-center mb-4">Forgot Password</h2>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <p class="mb-0"><?php echo htmlspecialchars($error); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if ($success_message): ?>
                <div class="alert alert-success">
                    <p class="mb-0"><?php echo htmlspecialchars($success_message); ?></p>
                </div>
            <?php endif; ?>

            <?php if ($info_message): ?>
                <div class="alert alert-info">
                    <p class="mb-0"><?php echo $info_message; // Contains HTML, so not double escaping ?></p>
                </div>
            <?php endif; ?>

            <?php if (empty($success_message) && empty($info_message)): // Hide form if messages are shown ?>
            <form id="forgotPasswordForm" method="POST" action="forgot_password.php" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>">
                <div class="form-group">
                    <label for="email">Enter your email address</label>
                    <input type="email" class="form-control" id="email" name="email" required value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
                    <div class="invalid-feedback">Please enter a valid email.</div>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Send Reset Link</button>
            </form>
            <?php endif; ?>
            <p class="text-center mt-3">
                Remembered your password? <a href="signin.php">Sign In</a>
            </p>
        </div>
    </div>

    <script>
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var form = document.getElementById('forgotPasswordForm');
                if (!form) return;

                form.addEventListener('submit', function(event) {
                    if (form.checkValidity() === false) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                }, false);
            }, false);
        })();
    </script>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
