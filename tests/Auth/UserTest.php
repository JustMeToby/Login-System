<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use LoginSystem\Auth\User;
use LoginSystem\Logging\AuditLoggerService;

// Define constants that might be used directly or indirectly by User class,
// or for setting up test conditions.
if (!defined('EMAIL_VERIFICATION_ENABLED')) {
    define('EMAIL_VERIFICATION_ENABLED', true); // Default for most tests in this suite
}
if (!defined('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS')) {
    define('EMAIL_VERIFICATION_TOKEN_LIFESPAN_SECONDS', 86400); // 24 hours
}
if (!defined('USER_TABLE_NAME')) {
    define('USER_TABLE_NAME', 'users');
}


class UserTest extends TestCase
{
    private $pdoMock;
    private $auditLoggerMock;
    private $user;
    private $stmtMock;

    protected function setUp(): void
    {
        // Create mocks for dependencies
        $this->pdoMock = $this->createMock(PDO::class);
        $this->auditLoggerMock = $this->createMock(AuditLoggerService::class);
        $this->stmtMock = $this->createMock(PDOStatement::class);

        // Instantiate the User class with mocked dependencies
        $this->user = new User($this->pdoMock, $this->auditLoggerMock);

        // Common expectation for prepare, can be overridden in specific tests
        $this->pdoMock->method('prepare')->willReturn($this->stmtMock);
    }

    public function testUserCreationWithEmailVerificationEnabled()
    {
        // Ensure EMAIL_VERIFICATION_ENABLED is true for this test context
        // This is more of a configuration check for the test setup.
        // If User::create behaves differently based on it, we ensure it's set.
        // User::create itself reads this constant.

        $username = 'testuser';
        $email = 'test@example.com';
        $password = 'password123';
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT); // We need to know what this will be

        // Mock User::hashPassword to control the hashed output or expect it
        // For simplicity, we'll assume password_hash is tested by PHP itself and
        // that User::hashPassword correctly calls it. We'll check the is_verified and token fields.

        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with($this->callback(function ($params) use ($username, $email) {
                $this->assertEquals($username, $params[':username']);
                $this->assertEquals($email, $params[':email']);
                $this->assertTrue(password_verify('password123', $params[':password']));
                $this->assertEquals(0, $params[':is_verified']); // Key assertion for this test
                $this->assertNotEmpty($params[':verification_token']);
                $this->assertIsInt($params[':verification_token_expiry']);
                $this->assertGreaterThan(time(), $params[':verification_token_expiry']);
                return true;
            }))
            ->willReturn(true);

        $this->pdoMock->expects($this->once())
            ->method('lastInsertId')
            ->willReturn('123'); // Mocked user ID

        // Expect audit log call
        $this->auditLoggerMock->expects($this->once())
            ->method('log')
            ->with(
                AuditLoggerService::EVENT_USER_REGISTERED,
                123, // Expected user ID from lastInsertId
                ['username' => $username, 'email' => $email]
            );

        $userId = $this->user->create($username, $email, $password);

        $this->assertEquals('123', $userId);

        // To "fetch the user from the (mocked) database" and assert is_verified and token:
        // The actual insertion details (is_verified, token) are checked in the execute callback.
        // If we wanted to test findById here, we'd set up another mock for it.
        // For this test, the assertions within the execute callback cover the state of the user upon creation.
    }

    public function testFindUserByValidVerificationToken()
    {
        $token = 'valid_token';
        $expectedUserData = [
            'id' => 1, 
            'username' => 'testuser', 
            'email' => 'test@example.com',
            'is_verified' => 0,
            'verification_token' => $token,
            'verification_token_expiry' => time() + 3600 // Expires in the future
        ];

        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with([':token' => $token])
            ->willReturn(true);
        $this->stmtMock->expects($this->once())
            ->method('fetch')
            ->with(PDO::FETCH_ASSOC)
            ->willReturn($expectedUserData);
        
        // SQL query in User::findUserByVerificationToken already checks expiry.
        // So, if a user is returned, the token was valid and not expired at DB level.
        $userData = $this->user->findUserByVerificationToken($token);
        $this->assertEquals($expectedUserData, $userData);
    }

    public function testFindUserByInvalidVerificationToken()
    {
        $token = 'invalid_token';
        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with([':token' => $token])
            ->willReturn(true);
        $this->stmtMock->expects($this->once())
            ->method('fetch')
            ->with(PDO::FETCH_ASSOC)
            ->willReturn(false); // Simulate token not found

        $userData = $this->user->findUserByVerificationToken($token);
        $this->assertNull($userData);
    }
    
    public function testFindUserByExpiredVerificationToken()
    {
        $token = 'expired_token';
        // The SQL query itself in User::findUserByVerificationToken includes:
        // "AND verification_token_expiry > strftime('%s', 'now')" for SQLite
        // or "AND verification_token_expiry > UNIX_TIMESTAMP()" for MySQL.
        // So, if the token is expired, the DB query (mocked by fetch) should return no user.
        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with([':token' => $token])
            ->willReturn(true);
        $this->stmtMock->expects($this->once())
            ->method('fetch')
            ->with(PDO::FETCH_ASSOC)
            ->willReturn(false); // Simulate token expired (DB query returns no row)

        $userData = $this->user->findUserByVerificationToken($token);
        $this->assertNull($userData);
    }

    public function testVerifyEmailAddressSuccess()
    {
        $userId = 123;
        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with([':id' => $userId])
            ->willReturn(true);
        $this->stmtMock->expects($this->once())
            ->method('rowCount')
            ->willReturn(1); // 1 row affected, meaning user was found and updated

        $this->auditLoggerMock->expects($this->once())
            ->method('log')
            ->with(
                AuditLoggerService::EVENT_EMAIL_VERIFICATION_SUCCESS,
                $userId,
                ['message' => 'Email verified successfully.']
            );
        
        $result = $this->user->verifyEmailAddress($userId);
        $this->assertTrue($result);
    }

    public function testVerifyEmailAddressFailureOnDBError()
    {
        $userId = 123;
        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with([':id' => $userId])
            ->willReturn(false); // Simulate DB error on execute
        // rowCount() won't be called if execute fails

        $this->auditLoggerMock->expects($this->never()) // Should not log success
            ->method('log');

        $result = $this->user->verifyEmailAddress($userId);
        $this->assertFalse($result);
    }

    public function testVerifyEmailAddressUserAlreadyVerifiedOrNotFound()
    {
        $userId = 123;
        $this->stmtMock->expects($this->once())
            ->method('execute')
            ->with([':id' => $userId])
            ->willReturn(true); // Execute is fine
        $this->stmtMock->expects($this->once())
            ->method('rowCount')
            ->willReturn(0); // 0 rows affected (user already verified or does not exist)

        $this->auditLoggerMock->expects($this->never()) // Should not log success
            ->method('log');
            
        $result = $this->user->verifyEmailAddress($userId);
        $this->assertFalse($result);
    }
}

?>
