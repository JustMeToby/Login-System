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

// If user is already logged in, redirect to dashboard
if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Security token validation failed. Please try submitting the form again.';
    } else {
        unset($_SESSION['csrf_token']); // Invalidate token after use

        $login_identifier = trim($_POST['login_identifier'] ?? ''); // Can be username or email
        $password = $_POST['password'] ?? '';

        if (empty($login_identifier)) {

    $login_identifier = trim($_POST['login_identifier'] ?? ''); // Can be username or email
    $password = $_POST['password'] ?? '';

    if (empty($login_identifier)) {

        $errors[] = 'Username or Email is required.';
    }
    if (empty($password)) {
        $errors[] = 'Password is required.';
    }

    if (empty($errors)) {
        try {
            $stmt = $pdo->prepare("SELECT id, username, password_hash FROM users WHERE username = :login OR email = :login");
            $stmt->execute([':login' => $login_identifier]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password_hash'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                header('Location: dashboard.php');
                exit;
            } else {
                $errors[] = 'Invalid credentials. Please try again.';
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
    <title>Sign In</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-container"> <!-- Changed class here -->
            <h2 class="text-center mb-4">Sign In</h2>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <p class="mb-0"><?php echo htmlspecialchars($error); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <form id="signinForm" method="POST" action="signin.php" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'] ?? ''); ?>">

                <div class="form-group">
                    <label for="login_identifier">Username or Email</label>
                    <input type="text" class="form-control" id="login_identifier" name="login_identifier" required value="<?php echo htmlspecialchars($_POST['login_identifier'] ?? ''); ?>">
                    <div class="invalid-feedback">Username or Email is required.</div>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                    <div class="invalid-feedback">Password is required.</div>
                </div>
                <div class="form-group">
                    <a href="forgot_password.php">Forgot Password?</a>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Sign In</button>
            </form>
            <p class="text-center mt-3">
                Don't have an account? <a href="signup.php">Sign Up</a>
            </p>
        </div>
    </div>

    <script>
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var form = document.getElementById('signinForm');
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
