<?php
// src/bootstrap.php

// --- Basic Setup ---
// Define ROOT_PATH if not already defined (e.g., by a front controller)
// dirname(__DIR__) will give the 'src' directory's parent, which is the project root.
if (!defined('ROOT_PATH')) {
    define('ROOT_PATH', dirname(__DIR__) . '/');
}

// Start the session if not already started.
if (session_status() == PHP_SESSION_NONE) {
    // Set session cookie parameters for security if desired
    // session_set_cookie_params([
    //     'lifetime' => 3600, // or your desired session lifetime
    //     'path' => '/', // or your base path if in a subdirectory
    //     'domain' => '', // your domain
    //     'secure' => isset($_SERVER['HTTPS']), // Send only over HTTPS
    //     'httponly' => true, // Prevent JavaScript access to session cookie
    //     'samesite' => 'Lax' // Or 'Strict'
    // ]);
    session_start();
}

// --- Load Configuration ---
// All constants should be available after this.
if (file_exists(ROOT_PATH . 'config/config.php')) {
    require_once ROOT_PATH . 'config/config.php';
} else {
    // Critical error: Config file is missing.
    // You might want to display a user-friendly error page or log and die.
    error_log("FATAL ERROR: config/config.php not found at " . ROOT_PATH . 'config/config.php');
    die("<h1>Configuration Error</h1><p>The system configuration file is missing. Please check the installation.</p>");
}

// --- Custom PSR-4 Autoloader ---
// Implements a simple autoloader for the APP_NAMESPACE_PREFIX.
spl_autoload_register(function ($class) {
    // Check if the class uses the application's namespace prefix
    if (strpos($class, APP_NAMESPACE_PREFIX . '\\') === 0) {
        // Remove the prefix
        $relativeClass = substr($class, strlen(APP_NAMESPACE_PREFIX . '\\'));
        // Replace namespace separators with directory separators
        $file = ROOT_PATH . 'src/' . str_replace('\\', '/', $relativeClass) . '.php';

        if (file_exists($file)) {
            require_once $file;
        } else {
            error_log("Autoloader: File for class " . $class . " not found at " . $file);
        }
    }
});

// --- Global Error Handling & Security Headers (Early Setup) ---
// Instantiate Security utility first as it handles headers and CSRF.
$security = new \LoginSystem\Utils\Security();
$security->sendHeaders(); // Send security headers as early as possible.

// Set up error display based on config (example, more robust needed for prod)
if (defined('ERROR_REPORTING_LEVEL') && defined('DISPLAY_ERRORS')) {
    error_reporting(ERROR_REPORTING_LEVEL);
    ini_set('display_errors', DISPLAY_ERRORS);
} else { // Default to development friendly settings if not defined
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}


// --- Initialize Core Services ---
// Database Connection
// The Database class getConnection method also attempts to create tables from schema.sql if they don't exist.
$pdo = \LoginSystem\Database\Database::getConnection();

if ($pdo === null) {
    // Critical error: Database connection failed or table creation failed.
    // This should be logged by the Database class itself.
    // Display a user-friendly error page or log and die.
    // Ensure BASE_URL is defined before trying to use it in a message.
    $baseUrlForError = defined('BASE_URL') ? BASE_URL : '';
    die("<h1>Database Error</h1><p>A critical error occurred with the database. Please check system logs. If you are the administrator, ensure the database path in config/config.php is correct and the directory is writable. Also verify config/schema.sql.</p><p><a href='" . htmlspecialchars($baseUrlForError) . "/'>Go to homepage</a></p>");
}

// User Service
$user = new \LoginSystem\Auth\User($pdo, $auditLogger);

// Auth Controller
// Ensure BASE_URL is defined before passing it to AuthController.
if (!defined('BASE_URL')) {
    error_log("FATAL ERROR: BASE_URL is not defined in config/config.php.");
    die("<h1>Configuration Error</h1><p>BASE_URL is not defined. Please check config/config.php.</p>");
}
$authController = new \LoginSystem\Auth\AuthController($user, $security, BASE_URL, $auditLogger);

// Rate Limiter Service
$rateLimiter = new \LoginSystem\Security\RateLimiterService($pdo, $auditLogger);

// Audit Logger Service
// The service itself checks defined('AUDIT_LOG_ENABLED') && AUDIT_LOG_ENABLED
$auditLogger = new \LoginSystem\Logging\AuditLoggerService($pdo);


// --- Initial Application Logic ---
// Attempt to create the admin account if it doesn't exist.
// This is done after all core services are initialized.
if (!$user->createAdminAccountIfNotExists()) {
    // Log this, but don't necessarily die, as it might fail due to
    // legitimate reasons (e.g., DB permissions after initial connect but before table write).
    // The application might still be usable for existing users.
    error_log("Notice: Could not create or verify the default admin account. This might be due to database permissions or other issues logged by the User class.");
}

// --- Make services available globally ---
// These variables will be accessible by the procedural PHP files that include this bootstrap.
// Alternatives could be a service locator or dependency injection container for larger apps.
global $pdo, $security, $user, $authController, $rateLimiter, $auditLogger;

// --- Flash Message Convenience ---
/**
 * Displays flash messages stored in the session for a given key.
 *
 * @param string $key The key for the flash messages (e.g., 'errors', 'success').
 * @param string $alertType The Bootstrap alert class type (e.g., 'danger', 'success', 'info').
 * @return void
 */
function display_flash_messages(string $key, string $alertType = 'info') {
    global $authController; // Use the global $authController
    if ($authController) {
        $messages = $authController->getAndSetFlashMessage($key);
        if (!empty($messages)) {
            echo '<div class="alert alert-' . htmlspecialchars($alertType) . '">';
            if (is_array($messages)) {
                foreach ($messages as $message) {
                    // If a sub-array of messages was passed (e.g. from validation)
                    if (is_array($message)) {
                        foreach ($message as $subMsg) {
                             echo '<p class="mb-0">' . htmlspecialchars(strval($subMsg)) . '</p>';
                        }
                    } else {
                        echo '<p class="mb-0">' . htmlspecialchars(strval($message)) . '</p>';
                    }
                }
            } else {
                echo '<p class="mb-0">' . htmlspecialchars(strval($messages)) . '</p>';
            }
            echo '</div>';
        }
    }
}

?>
