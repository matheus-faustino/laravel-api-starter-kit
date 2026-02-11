<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth;

use App\Contracts\Auth\EmailVerificationServiceInterface;
use App\Contracts\Auth\TokenServiceInterface;
use App\Models\User;
use App\Services\Auth\AuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Tests\TestCase;

class AuthServiceTest extends TestCase
{
    use RefreshDatabase;

    private AuthService $authService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->authService = new AuthService(
            app(TokenServiceInterface::class),
            app(EmailVerificationServiceInterface::class)
        );
    }

    public function test_register_creates_user_with_correct_data(): void
    {
        $data = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'Password123!',
        ];

        $result = $this->authService->register($data);

        $this->assertArrayHasKey('user', $result);
        $this->assertArrayHasKey('token', $result);
        $this->assertInstanceOf(User::class, $result['user']);
        $this->assertIsString($result['token']);
        $this->assertNotEmpty($result['token']);
    }

    public function test_register_stores_user_in_database(): void
    {
        $data = [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'password' => 'Password123!',
        ];

        $this->authService->register($data);

        $this->assertDatabaseHas('users', [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
        ]);
    }

    public function test_register_hashes_password(): void
    {
        $data = [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'Password123!',
        ];

        $result = $this->authService->register($data);

        $user = User::find($result['user']->id);
        $this->assertTrue(Hash::check('Password123!', $user->password));
        $this->assertNotEquals('Password123!', $user->password);
    }

    public function test_login_with_valid_credentials_returns_user_and_token(): void
    {
        $user = User::factory()->create([
            'email' => 'login@example.com',
            'password' => 'Password123!',
        ]);

        $result = $this->authService->login([
            'email' => 'login@example.com',
            'password' => 'Password123!',
        ]);

        $this->assertArrayHasKey('user', $result);
        $this->assertArrayHasKey('token', $result);
        $this->assertEquals($user->id, $result['user']->id);
        $this->assertIsString($result['token']);
    }

    public function test_login_with_invalid_email_throws_exception(): void
    {
        User::factory()->create([
            'email' => 'valid@example.com',
            'password' => 'Password123!',
        ]);

        $this->expectException(ValidationException::class);

        $this->authService->login([
            'email' => 'invalid@example.com',
            'password' => 'Password123!',
        ]);
    }

    public function test_login_with_invalid_password_throws_exception_with_email_error(): void
    {
        User::factory()->create([
            'email' => 'user@example.com',
            'password' => 'Password123!',
        ]);

        try {
            $this->authService->login([
                'email' => 'user@example.com',
                'password' => 'WrongPassword!',
            ]);
            $this->fail('Expected ValidationException was not thrown');
        } catch (ValidationException $e) {
            $this->assertArrayHasKey('email', $e->errors());
        }
    }

    public function test_login_creates_new_token_each_time(): void
    {
        $user = User::factory()->create([
            'email' => 'multi@example.com',
            'password' => 'Password123!',
        ]);

        $result1 = $this->authService->login([
            'email' => 'multi@example.com',
            'password' => 'Password123!',
        ]);

        $result2 = $this->authService->login([
            'email' => 'multi@example.com',
            'password' => 'Password123!',
        ]);

        $this->assertNotEquals($result1['token'], $result2['token']);
        $this->assertCount(2, $user->fresh()->tokens);
    }
}
