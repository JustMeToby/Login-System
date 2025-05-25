<?php
// verify_email.php
require_once 'src/bootstrap.php';

use LoginSystem\Logging\AuditLoggerService;

// Ensure services are available (they are global from bootstrap.php)
global $user, $authController, $auditLogger, $security;

if (!$user || !$authController || !$auditLogger || !$security) {
    // In a real app, you might have a more robust error page here
    die("Critical services are not available. Please check bootstrap.php and ensure all services are initialized.");
}

// User should ideally be a guest to verify email, but if they are logged in and click a link,
// it shouldn't prevent verification. No specific requireGuest() or requireLogin() here.

$token = $_GET['token'] ?? null;

if (empty($token)) {
    // Display an immediate error message if no token is provided.
    // This part is shown if bootstrap.php or this script itself has an issue before redirection.
    // Normally, flash messages + redirect are preferred.
    $authController->getAndSetFlashMessage('errors', ['Invalid or missing verification token.']);
    $authController->redirect(PAGE_SIGNUP); // Or PAGE_INDEX, depending on desired flow
    exit; // Ensure script stops after redirect
}

$userData = $user->findUserByVerificationToken($token);

if ($userData === null) {
    // Token is invalid, expired, or already used (findUserByVerificationToken returns null)
    if ($auditLogger) {
        $auditLogger->log(
            AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED_INVALID_TOKEN,
            null, // User ID is unknown if token is invalid
            ['token_attempted' => $token]
        );
    }
    $authController->getAndSetFlashMessage('errors', ['The verification link is invalid, expired, or has already been used. Please try registering again or contact support.']);
    $authController->redirect(PAGE_SIGNUP); // Redirect to signup or a generic error page
    exit;
}

// Token is valid, user data found
$userIdToVerify = $userData['id'];
$verificationSuccess = $user->verifyEmailAddress($userIdToVerify);

if ($verificationSuccess) {
    // User::verifyEmailAddress logs EVENT_EMAIL_VERIFICATION_SUCCESS
    $authController->getAndSetFlashMessage('success', ['Your email address has been successfully verified! You can now log in.']);
    $authController->redirect(PAGE_SIGNIN);
    exit;
} else {
    // Verification failed, possibly already verified or a DB issue
    if ($auditLogger) {
        $auditLogger->log(
            AuditLoggerService::EVENT_EMAIL_VERIFICATION_FAILED_UNEXPECTED,
            $userIdToVerify,
            ['token_used' => $token, 'reason' => 'Verification attempt failed, possibly already verified or DB issue.']
        );
    }
    $authController->getAndSetFlashMessage('info', ['This account may already be verified, or an unexpected issue occurred. Please try logging in.']);
    $authController->redirect(PAGE_SIGNIN);
    exit;
}

// Fallback HTML structure (should ideally not be reached if redirects work)
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container mt-5">
        <h2 class="mb-4 text-center">Email Verification</h2>
        <?php
        // Display flash messages if any were set and no redirect occurred
        display_flash_messages('errors', 'danger');
        display_flash_messages('success', 'success');
        display_flash_messages('info', 'info');
        ?>
        <p class="text-center">
            <a href="<?php echo $authController->buildUrl(PAGE_INDEX); ?>">Go to Homepage</a>
        </p>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
