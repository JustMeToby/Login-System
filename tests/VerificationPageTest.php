<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use LoginSystem\Auth\User;
use LoginSystem\Auth\AuthController;
use LoginSystem\Logging\AuditLoggerService;
use LoginSystem\Utils\Security; // Security class might be used by AuthController or the page

// Define page constants that verify_email.php or its dependencies might use
if (!defined('PAGE_SIGNIN')) {
    define('PAGE_SIGNIN', 'signin.php');
}
if (!defined('PAGE_INDEX')) {
    define('PAGE_INDEX', 'index.php');
}
// Add any other constants verify_email.php might require from config.php
// For example, if it uses specific audit event names defined as constants:
if (!defined('EVENT_EMAIL_VERIFICATION_FAILED')) { // Assuming this might be a constant
    define('EVENT_EMAIL_VERIFICATION_FAILED', 'EVENT_EMAIL_VERIFICATION_FAILED');
}
if (!defined('EVENT_EMAIL_ALREADY_VERIFIED')) { // Assuming this might be a constant
    define('EVENT_EMAIL_ALREADY_VERIFIED', 'EVENT_EMAIL_ALREADY_VERIFIED');
}


class VerificationPageTest extends TestCase
{
    private $userMock;
    private $authControllerMock;
    private $auditLoggerMock;
    private $securityMock; // If AuthController or page uses it directly

    private $originalGET;

    protected function setUp(): void
    {
        $this->userMock = $this->createMock(User::class);
        $this->authControllerMock = $this->createMock(AuthController::class);
        $this->auditLoggerMock = $this->createMock(AuditLoggerService::class);
        $this->securityMock = $this->createMock(Security::class); // If needed

        // Mock buildUrl to return a predictable URL
        $this->authControllerMock->method('buildUrl')->willReturnArgument(0); // Simple echo back

        // Backup $_GET
        $this->originalGET = $_GET;
    }

    protected function tearDown(): void
    {
        // Restore $_GET
        $_GET = $this->originalGET;
    }

    private function executeVerifyEmailScript(array $getParams)
    {
        // Set up global mocks that verify_email.php will use
        // These are typically initialized in src/bootstrap.php, so we're overriding them here
        // for the test's scope. This is a bit of a hack for testing legacy scripts.
        global $user, $authController, $auditLogger, $security;
        $user = $this->userMock;
        $authController = $this->authControllerMock;
        $auditLogger = $this->auditLoggerMock;
        $security = $this->securityMock; // If verify_email.php uses a global $security object

        $_GET = $getParams;

        ob_start();
        // Include the script to be tested.
        // Ensure the path is correct relative to this test file or PHPUnit's execution dir.
        // If phpunit.xml sets a bootstrap that defines a base path, use that.
        // Assuming verify_email.php is in the project root.
        include __DIR__ . '/../verify_email.php';
        return ob_get_clean();
    }

    public function testVerifyEmailPageWithValidToken()
    {
        $token = 'valid_token_fresh';
        $userId = 123;
        $userData = ['id' => $userId, 'is_verified' => 0, 'username' => 'testuser'];

        $this->userMock->expects($this->once())
            ->method('findUserByVerificationToken')
            ->with($token)
            ->willReturn($userData);

        $this->userMock->expects($this->once())
            ->method('verifyEmailAddress')
            ->with($userId)
            ->willReturn(true); // This mock implies EVENT_EMAIL_VERIFICATION_SUCCESS is logged by User class

        // Audit log for EVENT_EMAIL_VERIFICATION_SUCCESS is handled by User::verifyEmailAddress mock.
        // No direct log call expected from verify_email.php for this specific event if User class handles it.

        $output = $this->executeVerifyEmailScript(['token' => $token]);

        $this->assertStringContainsStringIgnoringCase("email address has been successfully verified", $output);
        $this->assertStringNotContainsStringIgnoringCase("error occurred", $output);
        $this->assertStringNotContainsStringIgnoringCase("invalid or expired", $output);
    }

    public function testVerifyEmailPageWithInvalidToken()
    {
        $token = 'invalid_or_expired_token';

        $this->userMock->expects($this->once())
            ->method('findUserByVerificationToken')
            ->with($token)
            ->willReturn(null); // Simulate token not found or expired

        $this->userMock->expects($this->never())->method('verifyEmailAddress'); // Should not be called

        $this->auditLoggerMock->expects($this->once())
            ->method('log')
            ->with(
                EVENT_EMAIL_VERIFICATION_FAILED, // Or the string literal if not defined as constant
                null, // No user ID available for an invalid token
                ['reason' => 'Invalid/expired token', 'token_attempted' => $token]
            );

        $output = $this->executeVerifyEmailScript(['token' => $token]);

        $this->assertStringContainsStringIgnoringCase("invalid or expired verification link", $output);
        $this->assertStringNotContainsStringIgnoringCase("successfully verified", $output);
    }
    
    public function testVerifyEmailPageWithNoToken()
    {
        $this->userMock->expects($this->never())->method('findUserByVerificationToken');
        $this->userMock->expects($this->never())->method('verifyEmailAddress');

        $this->auditLoggerMock->expects($this->once())
            ->method('log')
            ->with(
                EVENT_EMAIL_VERIFICATION_FAILED,
                null,
                ['reason' => 'No token in URL']
            );

        $output = $this->executeVerifyEmailScript([]); // No token in $_GET

        $this->assertStringContainsStringIgnoringCase("no verification token provided", $output);
    }


    public function testVerifyEmailPageWithAlreadyVerifiedToken()
    {
        $token = 'already_verified_token';
        $userId = 456;
        $userData = ['id' => $userId, 'is_verified' => 1, 'username' => 'verifieduser']; // is_verified is 1

        $this->userMock->expects($this->once())
            ->method('findUserByVerificationToken')
            ->with($token)
            ->willReturn($userData);

        $this->userMock->expects($this->never())->method('verifyEmailAddress'); // Should not attempt to verify again

        $this->auditLoggerMock->expects($this->once())
            ->method('log')
            ->with(
                EVENT_EMAIL_ALREADY_VERIFIED, // Or the string literal
                $userId,
                ['token_used' => $token]
            );

        $output = $this->executeVerifyEmailScript(['token' => $token]);

        $this->assertStringContainsStringIgnoringCase("email address has already been verified", $output);
        $this->assertStringNotContainsStringIgnoringCase("error occurred", $output);
    }
    
    public function testVerifyEmailPageUserFoundButVerificationFailsInUserClass()
    {
        $token = 'valid_token_db_fail';
        $userId = 789;
        $userData = ['id' => $userId, 'is_verified' => 0, 'username' => ' unluckyuser'];

        $this->userMock->expects($this->once())
            ->method('findUserByVerificationToken')
            ->with($token)
            ->willReturn($userData);

        $this->userMock->expects($this->once())
            ->method('verifyEmailAddress') // This time, User::verifyEmailAddress itself fails
            ->with($userId)
            ->willReturn(false);

        // Audit log for EVENT_EMAIL_VERIFICATION_FAILED due to User::verifyEmailAddress returning false
        // This log is expected from verify_email.php itself.
        $this->auditLoggerMock->expects($this->once())
            ->method('log')
            ->with(
                EVENT_EMAIL_VERIFICATION_FAILED,
                $userId,
                ['reason' => 'User::verifyEmailAddress returned false', 'token_used' => $token]
            );
        
        $output = $this->executeVerifyEmailScript(['token' => $token]);

        $this->assertStringContainsStringIgnoringCase("error occurred while verifying your email", $output);
        $this->assertStringNotContainsStringIgnoringCase("successfully verified", $output);
    }
}
?>
