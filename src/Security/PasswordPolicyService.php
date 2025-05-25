<?php
// src/Security/PasswordPolicyService.php
namespace LoginSystem\Security;

class PasswordPolicyService {

    /**
     * Constructor for PasswordPolicyService.
     * Currently no specific dependencies or configuration needed at construction time,
     * as policies are read from globally defined constants.
     */
    public function __construct() {
        // No specific initialization needed for now.
    }

    /**
     * Validates a password against defined policies.
     *
     * @param string $password The password to validate.
     * @return array An array of error messages. Empty if the password is valid.
     */
    public function validatePassword(string $password): array {
        $errors = [];

        // Check Minimum Length
        if (defined('PASSWORD_POLICY_MIN_LENGTH') && PASSWORD_POLICY_MIN_LENGTH > 0) {
            if (strlen($password) < PASSWORD_POLICY_MIN_LENGTH) {
                $errors[] = "Password must be at least " . PASSWORD_POLICY_MIN_LENGTH . " characters long.";
            }
        }

        // Check Uppercase Requirement
        if (defined('PASSWORD_POLICY_REQUIRE_UPPERCASE') && PASSWORD_POLICY_REQUIRE_UPPERCASE) {
            if (!preg_match('/[A-Z]/', $password)) {
                $errors[] = "Password must contain at least one uppercase letter.";
            }
        }

        // Check Lowercase Requirement
        if (defined('PASSWORD_POLICY_REQUIRE_LOWERCASE') && PASSWORD_POLICY_REQUIRE_LOWERCASE) {
            if (!preg_match('/[a-z]/', $password)) {
                $errors[] = "Password must contain at least one lowercase letter.";
            }
        }

        // Check Number Requirement
        if (defined('PASSWORD_POLICY_REQUIRE_NUMBER') && PASSWORD_POLICY_REQUIRE_NUMBER) {
            if (!preg_match('/[0-9]/', $password)) {
                $errors[] = "Password must contain at least one number.";
            }
        }

        // Check Special Character Requirement
        // The regex /[^A-Za-z0-9]/ checks for any character that is NOT a letter or number.
        if (defined('PASSWORD_POLICY_REQUIRE_SPECIAL') && PASSWORD_POLICY_REQUIRE_SPECIAL) {
            if (!preg_match('/[^A-Za-z0-9\s]/', $password)) { // Also excluding whitespace from being "special"
                $errors[] = "Password must contain at least one special character.";
            }
        }
        
        // Future Enhancement: Password Reuse Prevention
        // if (defined('PASSWORD_POLICY_PREVENT_REUSE_COUNT') && PASSWORD_POLICY_PREVENT_REUSE_COUNT > 0) {
        //     // This would require access to the user's password history.
        //     // $errors[] = "Password cannot be one of your last " . PASSWORD_POLICY_PREVENT_REUSE_COUNT . " passwords.";
        // }

        return $errors;
    }
}
?>
