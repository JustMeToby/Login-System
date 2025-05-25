<?php
// config/config.php

// **Database Configuration**
// Path to the SQLite database file. Relative to the project root.
if (!defined('DB_PATH')) {
    define('DB_PATH', 'db/users.sqlite'); // Default, assuming 'db' folder is in the root
}

// Name of the users table
if (!defined('USER_TABLE_NAME')) {
    define('USER_TABLE_NAME', 'users');
}

// **Site Configuration**
// Base URL of your application (e.g., http://localhost/yourproject)
// Important: No trailing slash
if (!defined('BASE_URL')) {
    define('BASE_URL', ''); // Needs to be configured by the user
}

// ** Page Paths Configuration **
// Define the filenames/paths for key pages.
// These are relative to the BASE_URL.
// Example: if signin page is at htdocs/myapp/auth/login.php and BASE_URL is /myapp,
// then PAGE_SIGNIN could be 'auth/login.php'.
// If files are in the root of where BASE_URL points, then just filenames are needed.
if (!defined('PAGE_INDEX')) { define('PAGE_INDEX', 'index.php'); }
if (!defined('PAGE_SIGNIN')) { define('PAGE_SIGNIN', 'signin.php'); }
if (!defined('PAGE_SIGNUP')) { define('PAGE_SIGNUP', 'signup.php'); }
if (!defined('PAGE_DASHBOARD')) { define('PAGE_DASHBOARD', 'dashboard.php'); }
if (!defined('PAGE_LOGOUT')) { define('PAGE_LOGOUT', 'logout.php'); }
if (!defined('PAGE_FORGOT_PASSWORD')) { define('PAGE_FORGOT_PASSWORD', 'forgot_password.php'); }
if (!defined('PAGE_RESET_PASSWORD')) { define('PAGE_RESET_PASSWORD', 'reset_password.php'); }
if (!defined('PAGE_VERIFY_EMAIL')) { define('PAGE_VERIFY_EMAIL', 'verify_email.php'); }

// **Admin Account Configuration**
// Default administrator account details
if (!defined('ADMIN_USERNAME')) { define('ADMIN_USERNAME', 'admin'); }
if (!defined('ADMIN_PASSWORD')) { define('ADMIN_PASSWORD', 'admin'); } // This will be hashed by the User class

// **Security Configuration**
// Name for the CSRF token in forms and session
if (!defined('CSRF_TOKEN_NAME')) { define('CSRF_TOKEN_NAME', 'csrf_token'); }

// **Session Configuration**
// Key names for session variables
if (!defined('SESSION_USER_ID_KEY')) { define('SESSION_USER_ID_KEY', 'user_id'); }
if (!defined('SESSION_USERNAME_KEY')) { define('SESSION_USERNAME_KEY', 'username'); }
if (!defined('SESSION_FLASH_MESSAGES_KEY')) { define('SESSION_FLASH_MESSAGES_KEY', 'flash_messages'); }

// **Application Namespace**
// PSR-4 Namespace prefix for the application's classes (used by the autoloader)
// No leading or trailing backslashes
if (!defined('APP_NAMESPACE_PREFIX')) { define('APP_NAMESPACE_PREFIX', 'LoginSystem'); }

// === NEW CONFIGURATIONS START ===

// **Rate Limiting Configuration**
if (!defined('MAX_IP_LOGIN_ATTEMPTS')) { define('MAX_IP_LOGIN_ATTEMPTS', 5); }
if (!defined('IP_LOCKOUT_SECONDS')) { define('IP_LOCKOUT_SECONDS', 300); }
if (!defined('MAX_USER_LOGIN_ATTEMPTS')) { define('MAX_USER_LOGIN_ATTEMPTS', 3); }
if (!defined('USER_LOCKOUT_SECONDS')) { define('USER_LOCKOUT_SECONDS', 900); }
if (!defined('MAX_RESET_PASSWORD_ATTEMPTS_PER_IP')) { define('MAX_RESET_PASSWORD_ATTEMPTS_PER_IP', 3); }
if (!defined('RESET_PASSWORD_IP_LOCKOUT_SECONDS')) { define('RESET_PASSWORD_IP_LOCKOUT_SECONDS', 3600); }
if (!defined('ATTEMPT_COUNT_VALIDITY_SECONDS')) { define('ATTEMPT_COUNT_VALIDITY_SECONDS', 900); }

// **Session Management Configuration**
if (!defined('SESSION_IDLE_TIMEOUT_SECONDS')) { define('SESSION_IDLE_TIMEOUT_SECONDS', 1800); }
if (!defined('SESSION_ABSOLUTE_TIMEOUT_SECONDS')) { define('SESSION_ABSOLUTE_TIMEOUT_SECONDS', 86400); }
if (!defined('REMEMBER_ME_COOKIE_NAME_SERIES')) { define('REMEMBER_ME_COOKIE_NAME_SERIES', 'loginsystem_series'); }
if (!defined('REMEMBER_ME_COOKIE_NAME_TOKEN')) { define('REMEMBER_ME_COOKIE_NAME_TOKEN', 'loginsystem_token'); }
if (!defined('REMEMBER_ME_DURATION_DAYS')) { define('REMEMBER_ME_DURATION_DAYS', 30); }

// **Password Policy Configuration**
if (!defined('PASSWORD_POLICY_MIN_LENGTH')) { define('PASSWORD_POLICY_MIN_LENGTH', 8); }
if (!defined('PASSWORD_POLICY_REQUIRE_UPPERCASE')) { define('PASSWORD_POLICY_REQUIRE_UPPERCASE', true); }
if (!defined('PASSWORD_POLICY_REQUIRE_LOWERCASE')) { define('PASSWORD_POLICY_REQUIRE_LOWERCASE', true); }
if (!defined('PASSWORD_POLICY_REQUIRE_NUMBER')) { define('PASSWORD_POLICY_REQUIRE_NUMBER', true); }
if (!defined('PASSWORD_POLICY_REQUIRE_SPECIAL')) { define('PASSWORD_POLICY_REQUIRE_SPECIAL', true); }

// **Audit Logging Configuration**
if (!defined('AUDIT_LOG_ENABLED')) { define('AUDIT_LOG_ENABLED', true); }

// **Email Verification Configuration**
if (!defined('EMAIL_VERIFICATION_ENABLED')) { define('EMAIL_VERIFICATION_ENABLED', true); }
if (!defined('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS')) { define('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS', 86400); }

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
