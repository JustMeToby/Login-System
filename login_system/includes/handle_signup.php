<?php
/**
 * Handles new user registration form submission, validation, and user creation.
 * This script is included by signup.php and relies on variables/services
 * initialized by bootstrap.php (e.g., $authController, $user, $security, $auditLogger).
 * It also expects $errors and $form_values to be initialized in the calling script.
 */

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
        } elseif ($password !== $confirm_password) { // Check match before policy
            $errors[] = 'Passwords do not match.';
        } else {
            // Passwords match, now check policy
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
            $userId = $user->create($username, $email, $password); // User::create already logs EVENT_USER_REGISTERED
            if ($userId) {
                if (defined('EMAIL_VERIFICATION_ENABLED') && EMAIL_VERIFICATION_ENABLED === true) {
                    if ($auditLogger) {
                        $auditLogger->log(
                            \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_VERIFICATION_REQUESTED,
                            (int)$userId,
                            ['email' => $email]
                        );
                    }

                    $newUserData = $user->findById((int)$userId);
                    if ($newUserData && !empty($newUserData['verification_token'])) {
                        $verificationLink = $authController->buildUrl(PAGE_VERIFY_EMAIL, 'token=' . urlencode($newUserData['verification_token']));
                        
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
                            $authController->getAndSetFlashMessage('errors', [$errorMessage], true);
                            if ($auditLogger) {
                                $auditLogger->log(
                                    \LoginSystem\Logging\AuditLoggerService::EVENT_EMAIL_SEND_FAILED,
                                    (int)$userId,
                                    ['email' => $email, 'type' => 'verification', 'reason' => 'EmailService::sendVerificationEmail returned false']
                                );
                            }
                        }
                    } else {
                        error_log("Failed to retrieve verification token for new user ID: {$userId} in handle_signup.php");
                        $authController->getAndSetFlashMessage('errors', ['Registration was successful, but there was an issue sending the verification email. Please contact support.'], true);
                    }
                } else {
                    // Email verification not enabled
                    $signInUrl = $authController->buildUrl(PAGE_SIGNIN);
                    $authController->getAndSetFlashMessage('success', "Registration successful! You can now <a href='{$signInUrl}'>sign in</a>.");
                }
                $authController->redirect(PAGE_SIGNIN); 
            } else {
                // User creation failed
                $errors[] = 'An error occurred during registration. Please try again. If the problem persists, contact support.';
            }
        }
    } // end CSRF check
    
    // If there were any errors (CSRF, validation, creation failure), set flash message and redirect back to signup.
    if (!empty($errors)) {
        $authController->getAndSetFlashMessage('errors', $errors, true); // true to append if other messages exist
        $authController->redirect(PAGE_SIGNUP); 
    }
}
?>
