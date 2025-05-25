<?php
require_once 'src/bootstrap.php'; // For $user, $authController, $auditLogger, $security

// Ensure user is a guest (not logged in) to prevent session confusion.
// If a user is already logged in, they don't need to verify an email via a link like this typically.
// However, a logged-in user *could* be verifying a *new* email address for their account in a different flow,
// but for initial signup verification, they are expected to be logged out.
// If $authController->requireGuest() is too strict (e.g. redirects to dashboard),
// we can just proceed, but it's cleaner if they are not logged in.
// For now, let's not enforce requireGuest() as the token itself is the primary authorizer.

$token = $_GET['token'] ?? null;
$errors = [];
$successMessage = '';

if (empty($token)) {
    $errors[] = "No verification token provided.";
    if ($auditLogger) {
        $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED, null, ['reason' => 'No token in URL']);
    }
} else {
    // Validate token format briefly (e.g. expected length if known, or alphanumeric)
    // For now, we rely on findUserByVerificationToken's behavior with the token.
    // $security->sanitize($token) or ensure it's handled safely by DB query.
    // User::findUserByVerificationToken should use prepared statements, making it safe.

    $userData = $user->findUserByVerificationToken($token);

    if ($userData) {
        if ($userData['is_verified'] == 1) {
            // User is already verified
            $successMessage = "This email address has already been verified. You can <a href='" . $authController->buildUrl(PAGE_SIGNIN) . "'>sign in</a>.";
            // Optionally log this event as an info/notice
            if ($auditLogger) {
                $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_ALREADY_VERIFIED, (int)$userData['id'], ['token_used' => $token]);
            }
        } else {
            // Token is valid, user found, and not yet verified. Proceed to verify.
            if ($user->verifyEmailAddress((int)$userData['id'])) {
                $successMessage = "Your email address has been successfully verified! You can now <a href='" . $authController->buildUrl(PAGE_SIGNIN) . "'>sign in</a>.";
                // AuditLoggerService::EVENT_EMAIL_VERIFICATION_SUCCESS is logged by User::verifyEmailAddress
            } else {
                $errors[] = "An error occurred while verifying your email address. Please try again or contact support.";
                // This case implies findUserByVerificationToken found a user, but User::verifyEmailAddress failed (e.g., DB error during UPDATE).
                // User::verifyEmailAddress should log specific DB errors.
                if ($auditLogger) {
                    $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED, (int)$userData['id'], ['reason' => 'User::verifyEmailAddress returned false', 'token_used' => $token]);
                }
            }
        }
    } else {
        // Token is invalid, expired, or no user found for this token
        $errors[] = "Invalid or expired verification link. Please request a new one if needed or contact support.";
        if ($auditLogger) {
            // We don't have a user ID if token is invalid.
            // For invalid/expired token, we can use the more specific constant if desired,
            // or the general one with details. Let's use the specific one here.
            $auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED_INVALID_TOKEN, null, ['reason' => 'Invalid/expired token', 'token_attempted' => $token]);
        }
    }
}

// Set flash messages for display on a more structured page (e.g., signin page)
// Or display them directly here. For simplicity, let's display here.

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css"> <!-- Assuming your style.css is relevant -->
</head>
<body>
    <div class="container">
        <div class="auth-container mt-5"> <!-- Using similar styling to other auth pages -->
            <h2 class="text-center mb-4">Email Verification Status</h2>

            <?php if (!empty($successMessage)): ?>
                <div class="alert alert-success" role="alert">
                    <?php echo $successMessage; // Contains HTML link, ensure it's safe ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger" role="alert">
                    <?php foreach ($errors as $error): ?>
                        <p><?php echo htmlspecialchars($error); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if (empty($successMessage) && empty($errors)): ?>
                <!-- This case should ideally not be reached if token is always processed -->
                <div class="alert alert-info" role="alert">
                    Processing your verification request...
                </div>
            <?php endif; ?>
            
            <p class="text-center mt-3">
                Return to <a href="<?php echo $authController->buildUrl(PAGE_INDEX); ?>">Homepage</a>
                <?php if (empty($userData) || $userData['is_verified'] == 0) : ?>
                 | Go to <a href="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>">Sign In</a>
                <?php endif; ?>
            </p>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
