<?php

// Indicate that we are in a testing environment
define('IN_TESTING', true);

// Define a base URL for tests if not already set (config.php might use it)
if (!defined('BASE_URL')) {
    define('BASE_URL', 'http://localhost');
}

// Define other environment-specific configurations or overrides before loading main config.
// For example, to use an in-memory SQLite database for tests:
// if (!defined('DB_CONNECTION_STRING')) {
//     define('DB_CONNECTION_STRING', 'sqlite::memory:');
// }
// if (!defined('DB_USERNAME')) {
//     define('DB_USERNAME', null);
// }
// if (!defined('DB_PASSWORD')) {
//     define('DB_PASSWORD', null);
// }

// Load the main application configuration.
// Suppress errors if it tries to set headers or other things that might fail in CLI.
// @ allows to suppress errors, but it's generally better if config.php is test-aware.
// However, for now, let's assume it's mostly about defining constants.
if (file_exists(dirname(__DIR__) . '/config/config.php')) {
    require_once dirname(__DIR__) . '/config/config.php';
} else {
    echo "config/config.php not found. Please ensure it exists.\n";
    exit(1);
}

// Load the main application bootstrap for autoloading and core services.
// The services initialized here ($pdo, $user, $authController, etc.) will be the
// "real" services. Tests will often mock these or their dependencies.
if (file_exists(dirname(__DIR__) . '/src/bootstrap.php')) {
    require_once dirname(__DIR__) . '/src/bootstrap.php';
} else {
    echo "src/bootstrap.php not found. Please ensure it exists.\n";
    exit(1);
}

// Autoload Composer dependencies if any (though the project aims to avoid them)
// if (file_exists(dirname(__DIR__) . '/vendor/autoload.php')) {
//     require_once dirname(__DIR__) . '/vendor/autoload.php';
// }

// Set a default timezone if not set, to avoid warnings
if (!ini_get('date.timezone') && !getenv('TZ')) {
    date_default_timezone_set('UTC');
}

echo "tests/bootstrap.php loaded successfully.\n";
// You can add any other test-specific setup here.
?>
