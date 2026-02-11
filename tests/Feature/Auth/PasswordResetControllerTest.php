<?php

declare(strict_types=1);

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\RateLimiter;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class PasswordResetControllerTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        RateLimiter::clear('password-forgot');
    }

    // Send Reset Link Tests

    public function test_send_reset_link_for_existing_user(): void
    {
        User::factory()->create(['email' => 'user@example.com']);

        $response = $this->postJson('/api/password/forgot', [
            'email' => 'user@example.com',
        ]);

        $response->assertOk()
            ->assertJsonStructure(['message']);
    }

    public function test_send_reset_link_creates_token_in_database(): void
    {
        User::factory()->create(['email' => 'token@example.com']);

        $this->postJson('/api/password/forgot', [
            'email' => 'token@example.com',
        ]);

        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => 'token@example.com',
        ]);
    }

    public function test_send_reset_link_for_nonexistent_user_returns_error(): void
    {
        $response = $this->postJson('/api/password/forgot', [
            'email' => 'nonexistent@example.com',
        ]);

        $response->assertStatus(400)
            ->assertJsonStructure(['message']);
    }

    // Forgot Password Validation Tests

    #[DataProvider('forgotPasswordValidationDataProvider')]
    public function test_forgot_password_validation(array $data, array $expectedErrors): void
    {
        $response = $this->postJson('/api/password/forgot', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors($expectedErrors);
    }

    public static function forgotPasswordValidationDataProvider(): array
    {
        return [
            'missing email' => [
                'data' => [],
                'expectedErrors' => ['email'],
            ],
            'invalid email format' => [
                'data' => ['email' => 'invalid-email'],
                'expectedErrors' => ['email'],
            ],
            'empty email' => [
                'data' => ['email' => ''],
                'expectedErrors' => ['email'],
            ],
        ];
    }

    // Reset Password Tests

    public function test_reset_password_with_valid_token(): void
    {
        $user = User::factory()->create([
            'email' => 'reset@example.com',
            'password' => 'OldPassword123!',
        ]);

        $token = Password::createToken($user);

        $response = $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'reset@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $response->assertOk()
            ->assertJsonStructure(['message']);

        $user->refresh();
        $this->assertTrue(Hash::check('NewPassword456!', $user->password));
    }

    public function test_reset_password_revokes_all_tokens(): void
    {
        $user = User::factory()->create(['email' => 'tokens@example.com']);
        $user->createToken('token-1');
        $user->createToken('token-2');

        $this->assertCount(2, $user->tokens);

        $token = Password::createToken($user);

        $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'tokens@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $this->assertCount(0, $user->fresh()->tokens);
    }

    public function test_reset_password_with_invalid_token_returns_error(): void
    {
        User::factory()->create(['email' => 'invalid@example.com']);

        $response = $this->postJson('/api/password/reset', [
            'token' => 'invalid-token',
            'email' => 'invalid@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['email']);
    }

    public function test_reset_password_with_wrong_email_returns_error(): void
    {
        $user = User::factory()->create(['email' => 'correct@example.com']);
        $token = Password::createToken($user);

        $response = $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'wrong@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['email']);
    }

    public function test_reset_password_deletes_token_after_use(): void
    {
        $user = User::factory()->create(['email' => 'delete@example.com']);
        $token = Password::createToken($user);

        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => 'delete@example.com',
        ]);

        $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'delete@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);

        $this->assertDatabaseMissing('password_reset_tokens', [
            'email' => 'delete@example.com',
        ]);
    }

    // Reset Password Validation Tests

    #[DataProvider('resetPasswordValidationDataProvider')]
    public function test_reset_password_validation(array $data, array $expectedErrors): void
    {
        $response = $this->postJson('/api/password/reset', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors($expectedErrors);
    }

    public static function resetPasswordValidationDataProvider(): array
    {
        return [
            'missing all fields' => [
                'data' => [],
                'expectedErrors' => ['token', 'email', 'password'],
            ],
            'missing token' => [
                'data' => [
                    'email' => 'test@example.com',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['token'],
            ],
            'missing email' => [
                'data' => [
                    'token' => 'some-token',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['email'],
            ],
            'missing password' => [
                'data' => [
                    'token' => 'some-token',
                    'email' => 'test@example.com',
                ],
                'expectedErrors' => ['password'],
            ],
            'invalid email format' => [
                'data' => [
                    'token' => 'some-token',
                    'email' => 'invalid-email',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['email'],
            ],
            'password confirmation mismatch' => [
                'data' => [
                    'token' => 'some-token',
                    'email' => 'test@example.com',
                    'password' => 'Password123!',
                    'password_confirmation' => 'DifferentPassword123!',
                ],
                'expectedErrors' => ['password'],
            ],
            'password too short' => [
                'data' => [
                    'token' => 'some-token',
                    'email' => 'test@example.com',
                    'password' => 'short',
                    'password_confirmation' => 'short',
                ],
                'expectedErrors' => ['password'],
            ],
        ];
    }

    // Integration Tests

    public function test_full_password_reset_flow(): void
    {
        $user = User::factory()->create([
            'email' => 'flow@example.com',
            'password' => 'OldPassword123!',
        ]);

        $forgotResponse = $this->postJson('/api/password/forgot', [
            'email' => 'flow@example.com',
        ]);
        $forgotResponse->assertOk();

        $token = Password::createToken($user);

        $resetResponse = $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'flow@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);
        $resetResponse->assertOk();

        $loginResponse = $this->postJson('/api/auth/login', [
            'email' => 'flow@example.com',
            'password' => 'NewPassword456!',
        ]);
        $loginResponse->assertOk();

        $oldPasswordResponse = $this->postJson('/api/auth/login', [
            'email' => 'flow@example.com',
            'password' => 'OldPassword123!',
        ]);
        $oldPasswordResponse->assertUnprocessable();
    }

    public function test_reset_password_invalidates_existing_sessions(): void
    {
        $user = User::factory()->create(['email' => 'session@example.com']);
        $existingToken = $user->createToken('existing-session')->plainTextToken;

        $this->withHeader('Authorization', 'Bearer '.$existingToken)
            ->getJson('/api/auth/me')
            ->assertOk();

        $resetToken = Password::createToken($user);

        $resetResponse = $this->postJson('/api/password/reset', [
            'token' => $resetToken,
            'email' => 'session@example.com',
            'password' => 'NewPassword456!',
            'password_confirmation' => 'NewPassword456!',
        ]);
        $resetResponse->assertOk();

        $this->assertCount(0, $user->fresh()->tokens);
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $user->id,
        ]);

        $this->refreshApplication();

        $this->withHeader('Authorization', 'Bearer '.$existingToken)
            ->getJson('/api/auth/me')
            ->assertUnauthorized();
    }

    public function test_cannot_reuse_reset_token(): void
    {
        $user = User::factory()->create(['email' => 'reuse@example.com']);
        $token = Password::createToken($user);

        $firstReset = $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'reuse@example.com',
            'password' => 'FirstPassword123!',
            'password_confirmation' => 'FirstPassword123!',
        ]);
        $firstReset->assertOk();

        $secondReset = $this->postJson('/api/password/reset', [
            'token' => $token,
            'email' => 'reuse@example.com',
            'password' => 'SecondPassword456!',
            'password_confirmation' => 'SecondPassword456!',
        ]);
        $secondReset->assertUnprocessable();
    }
}
