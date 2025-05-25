<?php
// src/Utils/Security.php
namespace LoginSystem\Utils;

/**
 * Class Security
 * Provides utility functions for security-related tasks.
 * @package LoginSystem\Utils
 */
class Security {

    /**
     * Sends common security headers.
     * Call this before any other output.
     * @return void
     */
    public function sendHeaders(): void {
        if (headers_sent()) {
            return; // Headers already sent
        }
        // Recommended: Content Security Policy - adjust as needed for your specific application
        // This is a restrictive policy, you might need to allow CDNs for CSS/JS etc.
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self';");
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        // header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"); // Uncomment if site is HTTPS only & you understand HSTS
    }

    /**
     * Generates a CSRF token, stores it in the session, and returns it.
     *
     * @return string The generated CSRF token.
     */
    public function generateCsrfToken(): string {
        if (session_status() == PHP_SESSION_NONE) {
            session_start(); // Ensure session is started
        }
        if (empty($_SESSION[CSRF_TOKEN_NAME])) {
            $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        }
        return $_SESSION[CSRF_TOKEN_NAME];
    }

    /**
     * Verifies the CSRF token from POST data against the one in the session.
     *
     * @param string|null $tokenValue The token value from the form. If null, checks $_POST.
     * @return bool True if the token is valid, false otherwise.
     */
    public function verifyCsrfToken(string $tokenValue = null): bool {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        $postedToken = $tokenValue ?? ($_POST[CSRF_TOKEN_NAME] ?? null);

        if (empty($postedToken) || !isset($_SESSION[CSRF_TOKEN_NAME])) {
            return false;
        }

        $result = hash_equals($_SESSION[CSRF_TOKEN_NAME], $postedToken);
        // It's good practice to unset the token after first use if the action is one-time,
        // but for general forms that might be re-submitted on validation error,
        // you might keep it until successful submission or session expiry.
        // For simplicity here, we'll keep it for the session duration unless explicitly regenerated.
        // To make it a one-time token for critical actions:
        // if ($result) { unset($_SESSION[CSRF_TOKEN_NAME]); }
        return $result;
    }

    /**
     * Returns an HTML hidden input field with the CSRF token.
     *
     * @return string HTML string for the CSRF token input field.
     */
    public function getCsrfInput(): string {
        $token = $this->generateCsrfToken(); // Ensure token exists
        return '<input type="hidden" name="' . CSRF_TOKEN_NAME . '" value="' . $this->escapeHTML($token) . '">';
    }

    /**
     * Escapes HTML special characters for output.
     *
     * @param mixed $data The data to escape. If it's an array, it will escape recursively.
     * @return mixed Escaped data.
     */
    public function escapeHTML($data) {
        if (is_array($data)) {
            return array_map([$this, 'escapeHTML'], $data);
        }
        if (is_string($data)) {
            return htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }
        // For other types (int, bool, null), htmlspecialchars would return an empty string or error,
        // so it's better to return them as is if they are not strings.
        return $data;
    }
}
?>
