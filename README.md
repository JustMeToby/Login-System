# PHP Login System (Modular & Configurable)

This project provides a secure, reusable PHP login system built with a focus on modern practices, modularity, and ease of integration into existing projects without external dependencies like Composer.

## Features

*   **User Authentication:** Secure sign-up, sign-in, and logout functionality.
*   **Password Management:** Secure password hashing (using `password_hash` and `password_verify`), password reset via email (simulated), and "forgot password" feature.
*   **CSRF Protection:** Cross-Site Request Forgery protection on all forms.
*   **Security Headers:** Common security headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) are implemented.
*   **Admin Account:** Automatic creation of a default administrator account.
*   **Highly Configurable:** Key settings, including page filenames/paths, are managed via a central configuration file.
*   **Modular Design:** Core logic is encapsulated in classes (Database, Security, User, AuthController).
*   **Custom Autoloader:** Uses a simple PSR-4 compliant autoloader for its classes, no Composer needed.
*   **Easy Integration:** Designed to be dropped into an existing project. Frontend pages (root PHP files) can be customized, and their locations can be configured.

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
│   │   └── Security.php
│   └── bootstrap.php       # Initializes the application, autoloads classes
├── signin.php              # Default sign-in page (configurable)
├── signup.php              # Default sign-up page (configurable)
├── dashboard.php           # Default user dashboard page (configurable)
├── logout.php              # Default logout script (configurable)
├── forgot_password.php     # Default forgot password page (configurable)
├── reset_password.php      # Default reset password page (configurable)
├── index.php               # Default entry point (configurable)
└── README.md               # This file
```

## System Requirements

*   PHP 7.2 or higher (recommended 7.4+)
*   PDO extension enabled (for SQLite or other database interaction)
*   SQLite3 extension enabled (if using default SQLite database)
    *   If using another database (e.g., MySQL), you'll need to adjust the DSN in `config/config.php` and potentially the SQL in `config/schema.sql`.

## Installation & Setup

1.  **Download/Clone:**
    *   Place all the files and folders (maintaining the structure) into your project directory (e.g., `/loginsystem` or directly into your project's auth-related folder).

2.  **Configure `config/config.php`:**
    *   Open `config/config.php` and carefully review and update the settings:
        *   `DB_PATH`: Path to your SQLite database file (e.g., `db/users.sqlite`). Ensure the `db/` directory is writable by your web server if SQLite is to create the file.
        *   `USER_TABLE_NAME`: Name of the users table (default is `users`).
        *   **`BASE_URL`**: This is crucial. Set it to the correct base URL of your application where this login system resides.
            *   If your project is at the web root (e.g., `http://localhost/`), `BASE_URL` can be an empty string `''` or `/`.
            *   If your project is in a subdirectory (e.g., `http://localhost/myproject/`), `BASE_URL` should be `/myproject`.
            *   **Do not include a trailing slash.**
        *   **Page Path Constants (`PAGE_SIGNIN`, `PAGE_DASHBOARD`, etc.)**:
            *   These constants define the filenames or paths (relative to `BASE_URL`) for key application pages.
            *   The defaults are standard filenames like `signin.php`. You can change these if your project uses different filenames or places these pages in subdirectories (e.g., `auth/login.php`).
            *   Example: If your sign-in page is `http://localhost/myapp/user/login.php` and `BASE_URL` is `/myapp`, then `PAGE_SIGNIN` should be `'user/login.php'`.
        *   `ADMIN_USERNAME` & `ADMIN_PASSWORD`: Credentials for the default admin account. The password will be hashed upon first run if the admin account doesn't exist.
        *   Other constants like `CSRF_TOKEN_NAME`, session keys, and `APP_NAMESPACE_PREFIX` can usually be left at their defaults.

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
    *   Provides security-related utility functions.

*   **`src/Auth/User.php` (`LoginSystem\Auth\User`)**:
    *   Handles all user-specific database operations.

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

*   **Password Hashing:** Uses `password_hash()` and `password_verify()`.
*   **CSRF Protection:** On all forms.
*   **HTTP Security Headers:** CSP, X-Content-Type-Options, etc.
*   **Session Management:** Secure session practices.
*   **Input Sanitization & Prepared Statements.**

## Customization

*   **Styling & HTML Structure:** Modify CSS and the root PHP files.
*   **Page Locations:** Change `PAGE_` constants in `config.php` and move the corresponding files.
*   **Database:** Adapt `config.php` (DSN, credentials - requiring `Database.php` modification) and `config/schema.sql`.
*   **Email Sending:** Integrate an email library in `forgot_password.php` for the reset link.

## Troubleshooting

*   **"Configuration Error: BASE_URL is not defined" / "PAGE_SIGNIN is not defined"**: Ensure `config/config.php` is correctly set up and all constants are defined.
*   **"Database Error" / Table not found**: Check `DB_PATH`, directory writability, and `config/schema.sql`.
*   **Redirect issues / incorrect URLs / 404 errors**:
    *   Double-check `BASE_URL` in `config/config.php`.
    *   Verify your `PAGE_` constants in `config.php` match the actual locations and filenames of your pages.
    *   Ensure your web server's rewrite rules (if any) are compatible.
*   **Headers already sent**: Check for stray output before `header()` calls.
```
