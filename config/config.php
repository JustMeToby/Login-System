<?php
// config/config.php

// **Database Configuration**
// Path to the SQLite database file. Relative to the project root.
define('DB_PATH', 'db/users.sqlite'); // Default, assuming 'db' folder is in the root

// Name of the users table
define('USER_TABLE_NAME', 'users');

// **Site Configuration**
// Base URL of your application (e.g., http://localhost/yourproject)
// Important: No trailing slash
define('BASE_URL', ''); // Needs to be configured by the user

// ** Page Paths Configuration **
// Define the filenames/paths for key pages.
// These are relative to the BASE_URL.
// Example: if signin page is at htdocs/myapp/auth/login.php and BASE_URL is /myapp,
// then PAGE_SIGNIN could be 'auth/login.php'.
// If files are in the root of where BASE_URL points, then just filenames are needed.
define('PAGE_INDEX', 'index.php');
define('PAGE_SIGNIN', 'signin.php');
define('PAGE_SIGNUP', 'signup.php');
define('PAGE_DASHBOARD', 'dashboard.php');
define('PAGE_LOGOUT', 'logout.php');
define('PAGE_FORGOT_PASSWORD', 'forgot_password.php');
define('PAGE_RESET_PASSWORD', 'reset_password.php'); // Used to build the reset link
define('PAGE_VERIFY_EMAIL', 'verify_email.php'); // Page to handle email verification

// **Admin Account Configuration**
// Default administrator account details
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD', 'admin'); // This will be hashed by the User class

// **Security Configuration**
// Name for the CSRF token in forms and session
define('CSRF_TOKEN_NAME', 'csrf_token');

// **Session Configuration**
// Key names for session variables
define('SESSION_USER_ID_KEY', 'user_id');
define('SESSION_USERNAME_KEY', 'username');
define('SESSION_FLASH_MESSAGES_KEY', 'flash_messages');

// **Application Namespace**
// PSR-4 Namespace prefix for the application's classes (used by the autoloader)
// No leading or trailing backslashes
define('APP_NAMESPACE_PREFIX', 'LoginSystem');

// === NEW CONFIGURATIONS START ===

// **Rate Limiting Configuration**
define('MAX_IP_LOGIN_ATTEMPTS', 5); // Max login attempts per IP before lockout
define('IP_LOCKOUT_SECONDS', 300); // Lockout duration for IP in seconds (5 minutes)
define('MAX_USER_LOGIN_ATTEMPTS', 3); // Max login attempts per user account before lockout
define('USER_LOCKOUT_SECONDS', 900); // Lockout duration for user account in seconds (15 minutes)
define('MAX_RESET_PASSWORD_ATTEMPTS_PER_IP', 3); // Max password reset requests per IP in a time window
define('RESET_PASSWORD_IP_LOCKOUT_SECONDS', 3600); // Lockout duration for IP for password resets (1 hour)
define('ATTEMPT_COUNT_VALIDITY_SECONDS', 900); // Time window (e.g. 15 mins) for which attempts are counted towards lockout for IP/User login. Reset attempts might use longer windows or just the lockout.

// **Session Management Configuration**
define('SESSION_IDLE_TIMEOUT_SECONDS', 1800); // Inactivity time before session expires (30 minutes)
define('SESSION_ABSOLUTE_TIMEOUT_SECONDS', 86400); // Absolute time before session expires, regardless of activity (24 hours)
define('REMEMBER_ME_COOKIE_NAME_SERIES', 'loginsystem_series');
define('REMEMBER_ME_COOKIE_NAME_TOKEN', 'loginsystem_token');
define('REMEMBER_ME_DURATION_DAYS', 30); // How long "Remember Me" should last

// **Password Policy Configuration**
define('PASSWORD_POLICY_MIN_LENGTH', 8);
define('PASSWORD_POLICY_REQUIRE_UPPERCASE', true);
define('PASSWORD_POLICY_REQUIRE_LOWERCASE', true);
define('PASSWORD_POLICY_REQUIRE_NUMBER', true);
define('PASSWORD_POLICY_REQUIRE_SPECIAL', true); // e.g., !@#$%^&*()
// define('PASSWORD_POLICY_PREVENT_REUSE_COUNT', 0); // Number of past passwords to check against (0 = disabled, advanced feature, deferred)

// **Audit Logging Configuration**
define('AUDIT_LOG_ENABLED', true); // Master switch for audit logging

// **Email Verification Configuration**
define('EMAIL_VERIFICATION_ENABLED', true); // Master switch for email verification at signup
define('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS', 86400); // Lifespan of email verification token (24 hours)

// === NEW CONFIGURATIONS END ===

// **Error Reporting**
// For development:
// error_reporting(E_ALL);
// ini_set('display_errors', 1);
// For production:
// error_reporting(0);
// ini_set('display_errors', 0);
// Consider a more robust logging solution for production.

// **Important Note for Users:**
// Please configure BASE_URL. If your application is in a subdirectory (e.g., http://localhost/my_login_system),
// BASE_URL should be '/my_login_system'. If it's at the root (e.g., http://localhost),
// BASE_URL can be an empty string or '/'.
// For local development without a virtual host, if your project is in htdocs/myapp,
// and you access it via http://localhost/myapp/, then BASE_URL should be '/myapp'.
?>
