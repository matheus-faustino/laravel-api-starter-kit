<?php

declare(strict_types=1);

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class AuthControllerTest extends TestCase
{
    use RefreshDatabase;

    // Register Tests

    public function test_register_creates_user_and_returns_token(): void
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ]);

        $response->assertCreated()
            ->assertJsonStructure([
                'user' => ['id', 'name', 'email', 'created_at', 'updated_at'],
                'token',
            ]);

        $this->assertDatabaseHas('users', [
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);
    }

    public function test_register_returns_correct_user_data(): void
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ]);

        $response->assertCreated()
            ->assertJsonPath('user.name', 'Jane Doe')
            ->assertJsonPath('user.email', 'jane@example.com');
    }

    public function test_register_creates_authentication_token(): void
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Token User',
            'email' => 'token@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ]);

        $token = $response->json('token');

        $this->assertNotEmpty($token);
        $this->assertStringContainsString('|', $token);

        $meResponse = $this->withHeader('Authorization', 'Bearer '.$token)
            ->getJson('/api/auth/me');

        $meResponse->assertOk()
            ->assertJsonPath('user.email', 'token@example.com');
    }

    // Register Validation Tests

    #[DataProvider('registerValidationDataProvider')]
    public function test_register_validation(array $data, array $expectedErrors): void
    {
        User::factory()->create(['email' => 'existing@example.com']);

        $response = $this->postJson('/api/auth/register', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors($expectedErrors);
    }

    public static function registerValidationDataProvider(): array
    {
        return [
            'missing all fields' => [
                'data' => [],
                'expectedErrors' => ['name', 'email', 'password'],
            ],
            'missing name' => [
                'data' => [
                    'email' => 'test@example.com',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['name'],
            ],
            'missing email' => [
                'data' => [
                    'name' => 'Test User',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['email'],
            ],
            'missing password' => [
                'data' => [
                    'name' => 'Test User',
                    'email' => 'test@example.com',
                ],
                'expectedErrors' => ['password'],
            ],
            'invalid email format' => [
                'data' => [
                    'name' => 'Test User',
                    'email' => 'invalid-email',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['email'],
            ],
            'email already taken' => [
                'data' => [
                    'name' => 'Test User',
                    'email' => 'existing@example.com',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['email'],
            ],
            'password too short' => [
                'data' => [
                    'name' => 'Test User',
                    'email' => 'test@example.com',
                    'password' => 'short',
                    'password_confirmation' => 'short',
                ],
                'expectedErrors' => ['password'],
            ],
            'password confirmation mismatch' => [
                'data' => [
                    'name' => 'Test User',
                    'email' => 'test@example.com',
                    'password' => 'Password123!',
                    'password_confirmation' => 'DifferentPassword123!',
                ],
                'expectedErrors' => ['password'],
            ],
            'name too long' => [
                'data' => [
                    'name' => str_repeat('a', 256),
                    'email' => 'test@example.com',
                    'password' => 'Password123!',
                    'password_confirmation' => 'Password123!',
                ],
                'expectedErrors' => ['name'],
            ],
        ];
    }

    // Login Tests

    public function test_login_with_valid_credentials_returns_user_and_token(): void
    {
        $user = User::factory()->create([
            'email' => 'login@example.com',
            'password' => 'Password123!',
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'login@example.com',
            'password' => 'Password123!',
        ]);

        $response->assertOk()
            ->assertJsonStructure([
                'user' => ['id', 'name', 'email', 'email_verified_at', 'created_at', 'updated_at'],
                'token',
            ])
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('user.email', 'login@example.com');
    }

    public function test_login_token_can_authenticate(): void
    {
        User::factory()->create([
            'email' => 'auth@example.com',
            'password' => 'Password123!',
        ]);

        $loginResponse = $this->postJson('/api/auth/login', [
            'email' => 'auth@example.com',
            'password' => 'Password123!',
        ]);

        $token = $loginResponse->json('token');

        $meResponse = $this->withHeader('Authorization', 'Bearer '.$token)
            ->getJson('/api/auth/me');

        $meResponse->assertOk()
            ->assertJsonPath('user.email', 'auth@example.com');
    }

    public function test_login_with_invalid_password_returns_error(): void
    {
        User::factory()->create([
            'email' => 'user@example.com',
            'password' => 'Password123!',
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'user@example.com',
            'password' => 'WrongPassword!',
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['email']);
    }

    public function test_login_with_nonexistent_email_returns_error(): void
    {
        $response = $this->postJson('/api/auth/login', [
            'email' => 'nonexistent@example.com',
            'password' => 'Password123!',
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['email']);
    }

    // Login Validation Tests

    #[DataProvider('loginValidationDataProvider')]
    public function test_login_validation(array $data, array $expectedErrors): void
    {
        $response = $this->postJson('/api/auth/login', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors($expectedErrors);
    }

    public static function loginValidationDataProvider(): array
    {
        return [
            'missing all fields' => [
                'data' => [],
                'expectedErrors' => ['email', 'password'],
            ],
            'missing email' => [
                'data' => ['password' => 'Password123!'],
                'expectedErrors' => ['email'],
            ],
            'missing password' => [
                'data' => ['email' => 'test@example.com'],
                'expectedErrors' => ['password'],
            ],
            'invalid email format' => [
                'data' => [
                    'email' => 'invalid-email',
                    'password' => 'Password123!',
                ],
                'expectedErrors' => ['email'],
            ],
        ];
    }

    // Logout Tests

    public function test_logout_revokes_token(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token')->plainTextToken;

        $logoutResponse = $this->withHeader('Authorization', 'Bearer '.$token)
            ->postJson('/api/auth/logout');

        $logoutResponse->assertOk()
            ->assertJsonStructure(['message']);

        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $user->id,
            'name' => 'test-token',
        ]);

        $this->refreshApplication();

        $meResponse = $this->withHeader('Authorization', 'Bearer '.$token)
            ->getJson('/api/auth/me');

        $meResponse->assertUnauthorized();
    }

    public function test_logout_requires_authentication(): void
    {
        $response = $this->postJson('/api/auth/logout');

        $response->assertUnauthorized();
    }

    public function test_logout_only_revokes_current_token(): void
    {
        $user = User::factory()->create();
        $token1 = $user->createToken('token-1')->plainTextToken;
        $token2 = $user->createToken('token-2')->plainTextToken;

        $this->withHeader('Authorization', 'Bearer '.$token1)
            ->postJson('/api/auth/logout')
            ->assertOk();

        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $user->id,
            'name' => 'token-1',
        ]);

        $this->assertDatabaseHas('personal_access_tokens', [
            'tokenable_id' => $user->id,
            'name' => 'token-2',
        ]);

        $this->assertCount(1, $user->fresh()->tokens);
    }

    // Me Endpoint Tests

    public function test_me_returns_authenticated_user(): void
    {
        $user = User::factory()->create([
            'name' => 'Test User',
            'email' => 'test@example.com',
        ]);

        $token = $user->createToken('test-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer '.$token)
            ->getJson('/api/auth/me');

        $response->assertOk()
            ->assertJsonStructure([
                'user' => ['id', 'name', 'email', 'email_verified_at', 'created_at', 'updated_at'],
            ])
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('user.name', 'Test User')
            ->assertJsonPath('user.email', 'test@example.com');
    }

    public function test_me_requires_authentication(): void
    {
        $response = $this->getJson('/api/auth/me');

        $response->assertUnauthorized();
    }

    public function test_me_with_invalid_token_returns_unauthorized(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->getJson('/api/auth/me');

        $response->assertUnauthorized();
    }

    public function test_me_does_not_expose_password(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer '.$token)
            ->getJson('/api/auth/me');

        $response->assertOk()
            ->assertJsonMissingPath('user.password');
    }
}
