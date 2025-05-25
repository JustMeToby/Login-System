<?php
require_once 'login_system/src/bootstrap.php'; // Updated path. For $user, $authController, $auditLogger, $security

// The original comment about requireGuest() is noted. For this page, not enforcing it strictly.
// Token processing is the primary authorization mechanism.

// Initialize variables that the included handler will set.
$errors = [];
$successMessage = '';
// $userData will not be directly available here anymore, logic moved to handler.

// Include the handler script. It will:
// 1. Get $_GET['token'].
// 2. Validate token and attempt verification.
// 3. Set $errors (array) or $successMessage (string).
// It uses $user, $authController, $auditLogger from bootstrap.
require_once 'login_system/includes/handle_verify_email.php';

// $security is available from bootstrap if needed for HTML escaping, though
// $successMessage may contain HTML (links) and $errors are escaped with htmlspecialchars below.
global $security; // Ensure $security is in scope if SITE_NAME needs it, or pass it if used by buildUrl indirectly.

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - <?php echo isset($security) ? $security->escapeHTML(defined('SITE_NAME') ? SITE_NAME : 'Login System') : (defined('SITE_NAME') ? SITE_NAME : 'Login System'); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="login_system/css/style.css"> <!-- Updated path -->
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
                <?php // This case might occur if handle_verify_email.php returns early without setting messages (e.g. service failure) ?>
                <div class="alert alert-warning" role="alert">
                    Could not process verification request. Please ensure you have a valid link or contact support.
                </div>
            <?php endif; ?>
            
            <p class="text-center mt-3">
                Return to <a href="<?php echo $authController->buildUrl(PAGE_INDEX); ?>">Homepage</a>
                <?php // Display "Sign In" link if there's no success message (as success messages already contain a sign-in link)
                      // or if there are errors (user might want to sign in to try other options).
                if (empty($successMessage)): ?>
                 | Go to <a href="<?php echo $authController->buildUrl(PAGE_SIGNIN); ?>">Sign In</a>
                <?php endif; ?>
            </p>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
