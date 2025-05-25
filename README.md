# PHP Login System (Modular & Configurable)

This project provides a secure, reusable PHP login system built with a focus on modern practices, modularity, and ease of integration into existing projects without external dependencies like Composer.

## Features

*   **User Registration:** Standard username, email, and password registration.
*   **User Login & Logout:** Secure session-based authentication for user sign-in and sign-out.
*   **Email Verification:**
    *   Upon registration, users are sent a verification email.
    *   The account remains inactive (or restricted) until the user clicks the verification link in the email.
    *   This helps ensure that the user has provided a valid and accessible email address.
    *   Verification links have a configurable lifespan (default is 24 hours, set via `EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS` in `login_system/config/config.php`).
*   **Password Hashing:** Passwords are securely hashed using `password_hash()` and verified with `password_verify()`.
*   **Password Reset:** Users can request a password reset link via email if they forget their password. The link is sent to their registered email address.
*   **Password Policies:** Enforced password complexity (e.g., minimum length, character types via `PasswordPolicyService`).
*   **CSRF Protection:** All forms are protected against Cross-Site Request Forgery attacks using tokens.
*   **Rate Limiting:** Login attempts and password reset requests are rate-limited to prevent abuse and brute-force attacks.
*   **Persistent Sessions ("Remember Me"):** Users can choose to be remembered on their device for an extended period, avoiding the need to log in repeatedly. (Uses `persistent_sessions` table).
*   **Security Headers:** Common security headers (e.g., Content Security Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) are implemented to enhance protection against common web vulnerabilities.
*   **Admin Account:** Automatic creation of a default administrator account on first setup.
*   **Audit Logging:** Key user actions (e.g., registration, login, password reset, email verification) and significant security events are logged for monitoring and review.
*   **Highly Configurable:** Core settings (database, site URL, page paths, security parameters, email settings) are managed via `login_system/config/config.php`.
*   **Modular Design:** Backend logic is organized into classes (e.g., `Database`, `Security`, `User`, `AuthController`, `EmailService`) within the `LoginSystem` namespace, located in `login_system/src/`. Page-specific PHP logic is often in `login_system/includes/`.
*   **Custom Autoloader:** A simple PSR-4 compliant autoloader is provided in `login_system/src/bootstrap.php`, eliminating the need for Composer for this standalone system.
*   **Easy Integration:** Designed to be relatively easy to integrate into existing PHP projects.

## Directory Structure

The system uses the following directory structure:

```
.
├── login_system/           # Core system files
│   ├── config/             # Configuration files
│   │   ├── config.php      # Main configuration (DB, site URL, page paths, admin)
│   │   └── schema.sql      # SQL schema for database tables
│   ├── css/                # CSS stylesheets
│   │   └── style.css
│   ├── db/                 # SQLite database directory (default location)
│   │   └── users.sqlite    # SQLite database file
│   ├── includes/           # PHP include files for page-specific logic (e.g., form handling)
│   │   ├── handle_signin.php
│   │   └── ...
│   ├── src/                # Core PHP classes (backend logic)
│   │   ├── Auth/           # Authentication related classes
│   │   │   ├── AuthController.php
│   │   │   └── User.php
│   │   ├── Database/
│   │   │   └── Database.php
│   │   ├── Logging/
│   │   │   └── AuditLoggerService.php
│   │   ├── Security/       # Security feature classes
│   │   │   ├── PasswordPolicyService.php
│   │   │   ├── PersistentSessionManager.php
│   │   │   └── RateLimiterService.php
│   │   ├── Utils/          # Utility classes
│   │   │   ├── EmailService.php
│   │   │   └── Security.php
│   │   └── bootstrap.php   # Initializes the application, autoloads classes, sets up services
│   └── tests/              # PHPUnit tests
│       ├── Auth/
│       └── ...
├── active_sessions.php     # Page to manage active "Remember Me" sessions
├── dashboard.php           # Default user dashboard page
├── forgot_password.php     # Default forgot password page
├── index.php               # Default entry point (redirects based on login state)
├── logout.php              # Default logout script
├── reset_password.php      # Default reset password page
├── signin.php              # Default sign-in page
├── signup.php              # Default sign-up page
├── verify_email.php        # Page to handle email verification links
├── phpunit.xml             # PHPUnit configuration file
└── README.md               # This file
```

## System Requirements

*   PHP 7.4 or higher (recommended 8.0+)
*   PDO extension enabled (for SQLite or other database interaction)
*   SQLite3 extension enabled (if using default SQLite database)
    *   If using another database (e.g., MySQL), you'll need to adjust the DSN in `login_system/config/config.php` and potentially the SQL in `login_system/config/schema.sql` and `login_system/src/Database/Database.php`.
    *   A functional mail server or mail service configured for PHP's `mail()` function is required for email sending features (email verification, password reset).

## Installation & Setup

1.  **Download/Clone:**
    *   Place all files and folders, maintaining the directory structure, into your project. The main application logic resides in the `login_system/` directory, while user-facing pages like `signin.php` are in the root.

2.  **Configure `login_system/config/config.php`:** This is the most critical step.
    *   Open `login_system/config/config.php` and carefully review and update all settings, especially:
        *   `DB_PATH`: For SQLite, ensure the path to the database file (e.g., `login_system/db/users.sqlite`) is correct and the `login_system/db/` directory is writable by your web server. For other databases, you might adapt this or use a full DSN.
        *   `DB_CONNECTION_STRING`, `DB_USERNAME`, `DB_PASSWORD`: For databases like MySQL/PostgreSQL (you'll need to modify `Database.php` to use these if not using SQLite).
        *   **`BASE_URL`**: Crucial for correct link generation. Set it to the base URL where the login system is accessible.
            *   Example: If project is at `http://localhost/`, `BASE_URL` can be `''` or `/`.
            *   Example: If project is at `http://localhost/myapp/`, `BASE_URL` should be `/myapp`.
            *   **Do not include a trailing slash.**
        *   **Page Path Constants (`PAGE_SIGNIN`, `PAGE_DASHBOARD`, etc.)**: Define filenames for key pages. These are typically in the project root and are relative to `BASE_URL`.
        *   `ADMIN_USERNAME`, `ADMIN_PASSWORD`: For the default admin account.
        *   `EMAIL_VERIFICATION_ENABLED`: Set to `true` to enable email verification.
        *   Review other security and feature-related constants.

3.  **Database Setup:**
    *   The system attempts to create all necessary tables automatically using `login_system/config/schema.sql` if they don't exist. This happens when `Database::getConnection()` is first called (typically in `login_system/src/bootstrap.php`).
    *   Ensure the database user has privileges to create tables, or create them manually by executing the SQL in `login_system/config/schema.sql` (adapt SQL for your specific database system if not SQLite).
    *   For SQLite, ensure the directory containing the database file (e.g., `login_system/db/`) is writable by the web server.

4.  **Permissions:**
    *   Ensure your web server has read access to all project files.
    *   Ensure your web server has write access to the `login_system/db/` directory (or your chosen database path) if using SQLite.

5.  **Accessing the System:**
    *   Navigate to the path defined by `PAGE_INDEX` (by default `index.php`) under your `BASE_URL` in your browser (e.g., `http://localhost/your_project_folder/` or `http://yourdomain.com/`). This will redirect you appropriately.

## Core Components (Backend Logic in `login_system/src/`)

*   **`login_system/src/bootstrap.php`**:
    *   The central file included by all user-facing PHP scripts.
    *   Handles session initialization, loading `login_system/config/config.php`, setting up the custom PSR-4 autoloader for classes in `login_system/src/`, instantiating core service classes, sending security headers, and creating the admin account if needed.
    *   Makes key service objects (`$pdo`, `$security`, `$user`, `$authController`, etc.) globally available for the root PHP files and included scripts in `login_system/includes/`.

*   **`login_system/src/Database/Database.php` (`LoginSystem\Database\Database`)**:
    *   Manages the database connection (PDO).
    *   Includes logic to automatically create the database schema from `login_system/config/schema.sql` if tables don't exist.

*   **`login_system/src/Utils/Security.php` (`LoginSystem\Utils\Security`)**:
    *   Provides security-related utility functions (CSRF, escaping, headers).
*   **`login_system/src/Utils/EmailService.php` (`LoginSystem\Utils\EmailService`)**:
    *   Handles sending emails (e.g., verification, password reset) using PHP's `mail()` function.
*   **`login_system/src/Auth/User.php` (`LoginSystem\Auth\User`)**:
    *   Manages user data, registration, verification, password operations, and interactions with the users table.
*   **`login_system/src/Auth/AuthController.php` (`LoginSystem\Auth\AuthController`)**:
    *   Manages the authentication flow, user state, and redirects.
    *   Uses the `PAGE_` constants from `config.php` to determine redirect paths.
    *   Provides a `buildUrl()` method to correctly construct URLs based on `BASE_URL` and page constants.
*   **Other services** in `login_system/src/Logging/` and `login_system/src/Security/` handle audit trails, rate limiting, persistent sessions, and password policies.

## Page Structure (Root Files & Includes)

The PHP files in the root directory (e.g., `signin.php`, `signup.php`) handle user interaction. Their locations and filenames are configurable via the `PAGE_` constants in `login_system/config/config.php`. These files:
1.  Include `login_system/src/bootstrap.php` to initialize the system.
2.  Often include a specific handler from `login_system/includes/` (e.g., `login_system/includes/handle_signin.php`) which contains the primary PHP logic for that page, such as form processing.
3.  Display HTML content, potentially using variables set by the included handler.
They can be customized to match your project's look and feel.

## Security Features Implemented

*   **Password Hashing:** Uses `password_hash()` and `password_verify()` for strong password storage.
*   **CSRF Protection:** Implemented on all state-changing forms.
*   **HTTP Security Headers:** Includes Content Security Policy (CSP), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.
*   **Session Management:** Secure session handling practices with idle and absolute timeouts.
*   **Input Validation & Sanitization:** Applied to user inputs.
*   **Prepared Statements:** Used for all database queries to prevent SQL injection.
*   **Rate Limiting:** For login and password reset attempts.
*   **Email Verification:** Confirms user email ownership.
*   **Audit Trails:** Logs important system and user events.
*   **Persistent Sessions ("Remember Me"):** Secure implementation with series and token identifiers.

## Customization

*   **Styling & HTML Structure:** Modify CSS (`login_system/css/style.css`) and the HTML in the root PHP files (e.g., `signin.php`, `signup.php`).
*   **Page Locations & Filenames:** Change `PAGE_` constants in `login_system/config/config.php`. The physical files are expected to remain in the root.
*   **Database:**
    *   Adapt `login_system/config/config.php` for your database path/DSN and credentials.
    *   Modify `login_system/config/schema.sql` if you need different table structures or are using a non-SQLite database (syntax adjustments may be needed).
    *   The `login_system/src/Database/Database.php` class may need minor adjustments for different SQL dialects if features beyond basic PDO are used.
*   **Email Sending:** The default `login_system/src/Utils/EmailService.php` uses PHP's `mail()`. For more robust email delivery, you might replace its implementation with a library like PHPMailer or SwiftMailer, or use an API-based email service.
*   **Password Policies:** Adjust parameters in `login_system/src/Security/PasswordPolicyService.php` or extend it.
*   **Logging:** The `login_system/src/Logging/AuditLoggerService.php` can be extended to log to different targets or change log formats.

## Troubleshooting

*   **"Configuration Error: BASE_URL is not defined" / "PAGE_SIGNIN is not defined"**: Ensure `login_system/config/config.php` is correctly set up and all constants are defined.
*   **"Database Error" / Table not found**: Check `DB_PATH` in `login_system/config/config.php`, writability of `login_system/db/` (if using SQLite), and the contents of `login_system/config/schema.sql`.
*   **Redirect issues / incorrect URLs / 404 errors**:
    *   Double-check `BASE_URL` in `login_system/config/config.php`.
    *   Verify your `PAGE_` constants in `login_system/config/config.php` correctly refer to the filenames in the project root.
    *   Ensure your web server's rewrite rules (if any) are compatible.
*   **Headers already sent**: Check for stray output (e.g. spaces, HTML before PHP blocks) in PHP files, especially `config.php` or `bootstrap.php`.
```
