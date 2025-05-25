# PHP Login System (Modular & Configurable)

This project provides a secure, reusable PHP login system built with a focus on modern practices, modularity, and ease of integration into existing projects without external dependencies like Composer.

## Features

*   **User Registration:** Standard username, email, and password registration.
*   **User Login & Logout:** Secure session-based authentication for user sign-in and sign-out.
*   **Email Verification:**
    *   Upon registration, users are sent a verification email.
    *   The account remains inactive (or restricted) until the user clicks the verification link in the email.
    *   This helps ensure that the user has provided a valid and accessible email address.
    *   Verification links have a configurable lifespan (default is 24 hours, set via `EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS` in `config.php`).
*   **Password Hashing:** Passwords are securely hashed using `password_hash()` and verified with `password_verify()`.
*   **Password Reset:** Users can request a password reset link via email if they forget their password. The link is sent to their registered email address.
*   **Password Policies:** Enforced password complexity (e.g., minimum length, character types via `PasswordPolicyService`).
*   **CSRF Protection:** All forms are protected against Cross-Site Request Forgery attacks using tokens.
*   **Rate Limiting:** Login attempts and password reset requests are rate-limited to prevent abuse and brute-force attacks.
*   **Persistent Sessions ("Remember Me"):** Users can choose to be remembered on their device for an extended period, avoiding the need to log in repeatedly. (Uses `persistent_sessions` table).
*   **Security Headers:** Common security headers (e.g., Content Security Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) are implemented to enhance protection against common web vulnerabilities.
*   **Admin Account:** Automatic creation of a default administrator account on first setup.
*   **Audit Logging:** Key user actions (e.g., registration, login, password reset, email verification) and significant security events are logged for monitoring and review.
*   **Highly Configurable:** Core settings (database, site URL, page paths, security parameters, email settings) are managed via `config/config.php`.
*   **Modular Design:** Backend logic is organized into classes (e.g., `Database`, `Security`, `User`, `AuthController`, `EmailService`) within the `LoginSystem` namespace.
*   **Custom Autoloader:** A simple PSR-4 compliant autoloader is provided in `src/bootstrap.php`, eliminating the need for Composer for this standalone system.
*   **Easy Integration:** Designed to be relatively easy to integrate into existing PHP projects.

## Directory Structure

The system uses the following directory structure:

```
.
├── config/                 # Configuration files
│   ├── config.php          # Main configuration (DB, site URL, page paths, admin)
│   └── schema.sql          # SQL schema for the users table
├── css/                    # CSS stylesheets
│   └── style.css
├── db/                     # SQLite database directory (default)
│   └── users.sqlite        # SQLite database file
├── src/                    # Core PHP classes (backend logic)
│   ├── Auth/               # Authentication related classes
│   │   ├── AuthController.php
│   │   └── User.php
│   ├── Database/
│   │   └── Database.php
│   ├── Utils/
│   │   ├── EmailService.php
│   │   └── Security.php
│   └── bootstrap.php       # Initializes the application, autoloads classes, sets up services
├── signin.php              # Default sign-in page (configurable via config.php)
├── signup.php              # Default sign-up page (configurable via config.php)
├── dashboard.php           # Default user dashboard page (configurable via config.php)
├── logout.php              # Default logout script (configurable via config.php)
├── forgot_password.php     # Default forgot password page (configurable via config.php)
├── reset_password.php      # Default reset password page (configurable via config.php)
├── verify_email.php        # Page to handle email verification links
├── index.php               # Default entry point (configurable via config.php)
└── README.md               # This file
```

## System Requirements

*   PHP 7.2 or higher (recommended 7.4+)
*   PDO extension enabled (for SQLite or other database interaction)
*   SQLite3 extension enabled (if using default SQLite database)
    *   If using another database (e.g., MySQL), you'll need to adjust the DSN in `config/config.php` and potentially the SQL in `config/schema.sql` and `Database.php`.
    *   A functional mail server or mail service configured for PHP's `mail()` function is required for email sending features (email verification, password reset).

## Installation & Setup

1.  **Download/Clone:**
    *   Place all files and folders, maintaining the directory structure, into your project (e.g., `/loginsystem` or a subdirectory).

2.  **Configure `config/config.php`:** This is the most critical step.
    *   Open `config/config.php` and carefully review and update all settings, especially:
        *   `DB_CONNECTION_STRING` (formerly `DB_PATH` for SQLite): Update the DSN for your database. For SQLite, ensure the path to the database file (e.g., `db/users.sqlite`) is correct and the `db/` directory is writable by your web server.
        *   `DB_USERNAME`, `DB_PASSWORD`: For databases like MySQL/PostgreSQL.
        *   **`BASE_URL`**: Crucial for correct link generation. Set it to the base URL where the login system is accessible.
            *   Example: If project is at `http://localhost/`, `BASE_URL` can be `''` or `/`.
            *   Example: If project is at `http://localhost/myapp/auth/`, `BASE_URL` should be `/myapp/auth`.
            *   **Do not include a trailing slash.**
        *   **Page Path Constants (`PAGE_SIGNIN`, `PAGE_DASHBOARD`, etc.)**: Define filenames or paths (relative to `BASE_URL`) for key pages. Adapt if you rename or move files like `signin.php`.
        *   `ADMIN_USERNAME`, `ADMIN_PASSWORD`: For the default admin account.
        *   `EMAIL_VERIFICATION_ENABLED`: Set to `true` to enable email verification.
        *   `EMAIL_FROM`: The "From" address for emails sent by the system.
        *   `EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS`, `PASSWORD_RESET_TOKEN_LIFESPAN_SECONDS`: Lifespan of tokens.
        *   Review other security and feature-related constants.

3.  **Database Setup:**
    *   The system attempts to create the users table and other necessary tables (like `login_attempts`, `persistent_sessions`, `password_resets`, `audit_logs`) automatically using `config/schema.sql` if they don't exist. This happens when `Database::getConnection()` is first called (typically in `src/bootstrap.php`).
    *   Ensure the database user has privileges to create tables, or create them manually by executing the SQL in `config/schema.sql` (adapt SQL for your specific database system if not SQLite).
    *   For SQLite, ensure the directory containing the database file (e.g., `db/`) is writable by the web server.

3.  **Database Setup:**
    *   The system will attempt to create the users table automatically using the `config/schema.sql` file if it doesn't exist when the `Database::getConnection()` method is first called (typically when `src/bootstrap.php` runs).
    *   Ensure the directory specified for `DB_PATH` (e.g., `db/`) is writable by your web server so the SQLite database file can be created.
    *   If you prefer to create the table manually or are using a different database system:
        1.  Access your database management tool (e.g., phpMyAdmin, SQLite browser).
        2.  Execute the SQL commands found in `config/schema.sql`. Adapt the SQL syntax if you are not using SQLite.

4.  **File Locations (If Changed):**
    *   If you changed any of the `PAGE_` constants in `config/config.php` (e.g., `PAGE_SIGNIN` to `'auth/login.php'`), ensure your actual PHP files (e.g., the refactored `signin.php`) are moved to these new locations if you haven't already. The system will redirect and build links to these configured paths.

5.  **Permissions:**
    *   Ensure your web server has read access to all project files.
    *   Ensure your web server has write access to the `db/` directory (or your chosen database path) if using SQLite.

6.  **Accessing the System:**
    *   Navigate to the path defined by `PAGE_INDEX` (by default `index.php`) under your `BASE_URL` in your browser (e.g., `http://localhost/your_login_system_folder/` or `http://yourdomain.com/auth/`). This will redirect you appropriately.

## Core Components (Backend Logic in `src/`)

*   **`src/bootstrap.php`**:
    *   The central file included by all user-facing PHP scripts.
    *   Handles session initialization, loading `config.php`, setting up the custom PSR-4 autoloader, instantiating core service classes, sending security headers, and creating the admin account if needed.
    *   Makes key service objects (`$pdo`, `$security`, `$user`, `$authController`) globally available for the root PHP files.

*   **`src/Database/Database.php` (`LoginSystem\Database\Database`)**:
    *   Manages the database connection (PDO).
    *   Includes logic to automatically create the database schema from `config/schema.sql` if the user table doesn't exist.

*   **`src/Utils/Security.php` (`LoginSystem\Utils\Security`)**:
    *   Provides security-related utility functions (CSRF, escaping, headers).
*   **`src/Utils/EmailService.php` (`LoginSystem\Utils\EmailService`)**:
    *   Handles sending emails (e.g., verification, password reset) using PHP's `mail()` function.
*   **`src/Auth/User.php` (`LoginSystem\Auth\User`)**:
    *   Manages user data, registration, verification, password operations, and interactions with the users table.
*   **`src/Auth/AuthController.php` (`LoginSystem\Auth\AuthController`)**:
    *   Manages the authentication flow, user state, and redirects.
    *   Uses the `PAGE_` constants from `config.php` to determine redirect paths.
    *   Provides a `buildUrl()` method to correctly construct URLs based on `BASE_URL` and page constants.

## Frontend Pages (Configurable Locations)

The PHP files that handle user interaction (e.g., `signin.php`, `signup.php`) are by default in the root directory. Their locations and filenames are configurable via the `PAGE_` constants in `config/config.php`. These files:
1.  Include `src/bootstrap.php`.
2.  Handle user input.
3.  Call methods from the service objects.
4.  Display HTML content.
They can be customized to match your project's look and feel. If you change their location in `config.php`, remember to move the physical files as well.

## Security Features Implemented

*   **Password Hashing:** Uses `password_hash()` and `password_verify()` for strong password storage.
*   **CSRF Protection:** Implemented on all state-changing forms.
*   **HTTP Security Headers:** Includes Content Security Policy (CSP), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.
*   **Session Management:** Secure session handling practices.
*   **Input Validation & Sanitization:** Applied to user inputs.
*   **Prepared Statements:** Used for all database queries to prevent SQL injection.
*   **Rate Limiting:** For login and password reset attempts.
*   **Email Verification:** Confirms user email ownership.
*   **Audit Trails:** Logs important system and user events.

## Customization

*   **Styling & HTML Structure:** Modify CSS (`css/style.css`) and the HTML in the root PHP files (e.g., `signin.php`, `signup.php`).
*   **Page Locations & Filenames:** Change `PAGE_` constants in `config/config.php` and move/rename the corresponding PHP files.
*   **Database:**
    *   Adapt `config/config.php` for your database DSN and credentials.
    *   Modify `config/schema.sql` if you need different table structures or are using a non-SQLite database (syntax adjustments may be needed).
    *   The `Database.php` class may need minor adjustments for different SQL dialects if features beyond basic PDO are used.
*   **Email Sending:** The default `EmailService.php` uses PHP's `mail()`. For more robust email delivery, you might replace its implementation with a library like PHPMailer or SwiftMailer, or use an API-based email service.
*   **Password Policies:** Adjust parameters in `PasswordPolicyService.php` or extend it.
*   **Logging:** The `AuditLoggerService.php` can be extended to log to different targets or change log formats.

## Troubleshooting

*   **"Configuration Error: BASE_URL is not defined" / "PAGE_SIGNIN is not defined"**: Ensure `config/config.php` is correctly set up and all constants are defined.
*   **"Database Error" / Table not found**: Check `DB_PATH`, directory writability, and `config/schema.sql`.
*   **Redirect issues / incorrect URLs / 404 errors**:
    *   Double-check `BASE_URL` in `config/config.php`.
    *   Verify your `PAGE_` constants in `config.php` match the actual locations and filenames of your pages.
    *   Ensure your web server's rewrite rules (if any) are compatible.
*   **Headers already sent**: Check for stray output before `header()` calls.
```
