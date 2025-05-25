<?php
namespace LoginSystem\Utils; // Double backslash for PHP namespace

class EmailService {
    public static function sendVerificationEmail(string $to, string $username, string $verificationLink): bool {
        $subject = "Verify Your Email Address";
        $escapedUsername = htmlspecialchars($username);
        $escapedVerificationLink = htmlspecialchars($verificationLink);

        $message = "<p>Hello {$escapedUsername},</p>";
        $message .= "<p>Thank you for registering. Please click the link below to verify your email address:</p>";
        $message .= "<p><a href='{$escapedVerificationLink}'>{$escapedVerificationLink}</a></p>";
        $message .= "<p>If you did not register, please ignore this email.</p>";

        $headers = "MIME-Version: 1.0" . "
";
        $headers .= "Content-type:text/html;charset=UTF-8" . "
";
        $headers .= "From: noreply@localhost" . "
";

        if (mail($to, $subject, $message, $headers)) {
            return true;
        } else {
            error_log("EmailService: Failed to send verification email to " . $to);
            return false;
        }
    }
}
?>
