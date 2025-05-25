<?php
// src/Auth/AuthController.php
namespace LoginSystem\Auth;

use LoginSystem\Utils\Security;

/**
 * Class AuthController
 * Manages user authentication flow, sessions, and redirects using configurable page paths.
 * @package LoginSystem\Auth
 */
class AuthController {
    private User $user;
    private Security $security;
    private string $baseUrl;
    private ?\LoginSystem\Logging\AuditLoggerService $auditLogger = null;

    /**
     * AuthController constructor.
     * @param User $user The User service object.
     * @param Security $security The Security service object.
     * @param string $baseUrl The base URL of the application.
     * @param \LoginSystem\Logging\AuditLoggerService|null $auditLogger Optional audit logger service.
     */
    public function __construct(User $user, Security $security, string $baseUrl, ?\LoginSystem\Logging\AuditLoggerService $auditLogger = null) {
        $this->user = $user;
        $this->security = $security;
        $this->baseUrl = rtrim($baseUrl, '/'); // Ensure no trailing slash
        $this->auditLogger = $auditLogger;
    }

    /**
     * Redirects to a given path (usually a page constant) relative to the base URL.
     * Appends optional query string.
     * Exits script after redirect.
     * @param string $pageConstantOrPath Path to redirect to (e.g., PAGE_SIGNIN or 'custom/path.php').
     * @param string $queryString Optional query string to append (e.g., 'logged_out=true').
     * @return void
     */
    public function redirect(string $pageConstantOrPath, string $queryString = ''): void {
        $path = defined($pageConstantOrPath) ? constant($pageConstantOrPath) : $pageConstantOrPath;
        $url = $this->baseUrl . '/' . ltrim($path, '/');
        if (!empty($queryString)) {
            $url .= '?' . $queryString;
        }

        if (headers_sent()) {
            // Fallback if headers already sent, though this should be avoided
            echo "<script>window.location.href = '" . $this->security->escapeHTML($url) . "';</script>";
            exit;
        }
        header('Location: ' . $url);
        exit;
    }

    /**
     * Ensures that a user is logged in. Redirects to sign-in page if not.
     * @return void
     */
    public function requireLogin(): void {
        if (session_status() == PHP_SESSION_NONE) session_start();
        if (!isset($_SESSION[SESSION_USER_ID_KEY])) {
            $this->getAndSetFlashMessage('errors', ['Please sign in to access this page.'], true);
            $this->redirect(PAGE_SIGNIN); // Use constant
        }
    }

    /**
     * Ensures that a user is a guest (not logged in). Redirects to dashboard if logged in.
     * @return void
     */
    public function requireGuest(): void {
        if (session_status() == PHP_SESSION_NONE) session_start();
        if (isset($_SESSION[SESSION_USER_ID_KEY])) {
            $this->redirect(PAGE_DASHBOARD); // Use constant
        }
    }

    /**
     * Logs in a user by setting session variables.
     *
     * @param int $userId The user's ID.
     * @param string $username The user's username.
     * @return void
     */
    public function login(int $userId, string $username): void {
        if (session_status() == PHP_SESSION_NONE) session_start();
        session_regenerate_id(true);
        $_SESSION[SESSION_USER_ID_KEY] = $userId;
        $_SESSION[SESSION_USERNAME_KEY] = $username;
    }

    /**
     * Logs out the current user by destroying the session.
     * Redirects to the sign-in page.
     * @return void
     */
    public function logout(): void {
        if (session_status() == PHP_SESSION_NONE) session_start();

        $userIdToLog = $this->getLoggedInUserId(); // Get user ID before session is destroyed
        if ($this->auditLogger && $userIdToLog) {
            $this->auditLogger->log(\LoginSystem\Logging\AuditLoggerService::EVENT_USER_LOGOUT, $userIdToLog);
        }

        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
        $this->redirect(PAGE_SIGNIN, 'logged_out=true'); // Use constant and pass query string
    }

    /**
     * Gets the currently logged-in username.
     * @return string|null
     */
    public function getLoggedInUsername(): ?string {
        if (session_status() == PHP_SESSION_NONE) session_start();
        return $_SESSION[SESSION_USERNAME_KEY] ?? null;
    }
    
    /**
     * Gets the currently logged-in user ID.
     * @return int|null
     */
    public function getLoggedInUserId(): ?int {
        if (session_status() == PHP_SESSION_NONE) session_start();
        return $_SESSION[SESSION_USER_ID_KEY] ?? null;
    }

    /**
     * Manages flash messages.
     * @param string $key
     * @param mixed $message
     * @param bool $isError (deprecated)
     * @return mixed|null
     */
    public function getAndSetFlashMessage(string $key, $message = null, bool $isError = false) {
        if (session_status() == PHP_SESSION_NONE) session_start();
        if (!defined('SESSION_FLASH_MESSAGES_KEY')) define('SESSION_FLASH_MESSAGES_KEY', 'flash_messages');

        if ($message !== null) {
            $_SESSION[SESSION_FLASH_MESSAGES_KEY][$key][] = $message;
        } else {
            $flashMessages = $_SESSION[SESSION_FLASH_MESSAGES_KEY][$key] ?? null;
            if ($flashMessages !== null) {
                unset($_SESSION[SESSION_FLASH_MESSAGES_KEY][$key]);
                if (is_array($flashMessages) && count($flashMessages) === 1 && isset($flashMessages[0]) && is_array($flashMessages[0])) {
                    return $flashMessages[0];
                }
                return $flashMessages;
            }
            return null;
        }
    }

    /**
     * Builds a full URL for a given page constant or path, including query string.
     * Useful for generating links in views or emails.
     *
     * @param string $pageConstantOrPath The page constant (e.g., PAGE_RESET_PASSWORD) or a relative path.
     * @param string $queryString Optional query string (e.g., 'token=xyz').
     * @return string The full URL.
     */
    public function buildUrl(string $pageConstantOrPath, string $queryString = ''): string {
        $path = defined($pageConstantOrPath) ? constant($pageConstantOrPath) : $pageConstantOrPath;
        $url = $this->baseUrl . '/' . ltrim($path, '/');
        if (!empty($queryString)) {
            $url .= '?' . $queryString;
        }
        return $this->security->escapeHTML($url); // Escape for safe display in HTML attributes
    }
}
?>
