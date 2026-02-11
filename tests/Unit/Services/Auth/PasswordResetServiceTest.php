<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth;

use App\Contracts\Auth\TokenServiceInterface;
use App\Models\User;
use App\Services\Auth\PasswordResetService;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Tests\TestCase;

class PasswordResetServiceTest extends TestCase
{
    use RefreshDatabase;

    private PasswordResetService $passwordResetService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->passwordResetService = new PasswordResetService(
            app(TokenServiceInterface::class)
        );
    }

    public function test_send_reset_link_returns_sent_status_for_existing_user(): void
    {
        $user = User::factory()->create([
            'email' => 'user@example.com',
        ]);

        $status = $this->passwordResetService->sendResetLink('user@example.com');

        $this->assertEquals(Password::RESET_LINK_SENT, $status);
    }

    public function test_send_reset_link_returns_invalid_user_for_nonexistent_email(): void
    {
        $status = $this->passwordResetService->sendResetLink('nonexistent@example.com');

        $this->assertEquals(Password::INVALID_USER, $status);
    }

    public function test_reset_updates_user_password(): void
    {
        $user = User::factory()->create([
            'email' => 'reset@example.com',
            'password' => 'OldPassword123!',
        ]);

        $token = Password::createToken($user);

        $this->passwordResetService->reset([
            'email' => 'reset@example.com',
            'password' => 'NewPassword456!',
            'token' => $token,
        ]);

        $user->refresh();
        $this->assertTrue(Hash::check('NewPassword456!', $user->password));
        $this->assertFalse(Hash::check('OldPassword123!', $user->password));
    }

    public function test_reset_dispatches_password_reset_event(): void
    {
        Event::fake([PasswordReset::class]);

        $user = User::factory()->create([
            'email' => 'event@example.com',
        ]);

        $token = Password::createToken($user);

        $this->passwordResetService->reset([
            'email' => 'event@example.com',
            'password' => 'NewPassword456!',
            'token' => $token,
        ]);

        Event::assertDispatched(PasswordReset::class, function ($event) use ($user) {
            return $event->user->id === $user->id;
        });
    }

    public function test_reset_throws_exception_for_invalid_token_with_email_error(): void
    {
        $user = User::factory()->create([
            'email' => 'invalid@example.com',
        ]);

        try {
            $this->passwordResetService->reset([
                'email' => 'invalid@example.com',
                'password' => 'NewPassword456!',
                'token' => 'invalid-token',
            ]);
            $this->fail('Expected ValidationException was not thrown');
        } catch (ValidationException $e) {
            $this->assertArrayHasKey('email', $e->errors());
        }
    }

    public function test_reset_throws_exception_for_nonexistent_user(): void
    {
        $this->expectException(ValidationException::class);

        $this->passwordResetService->reset([
            'email' => 'nonexistent@example.com',
            'password' => 'NewPassword456!',
            'token' => 'some-token',
        ]);
    }

    public function test_reset_updates_remember_token(): void
    {
        $user = User::factory()->create([
            'email' => 'remember@example.com',
        ]);

        $originalRememberToken = $user->remember_token;
        $token = Password::createToken($user);

        $this->passwordResetService->reset([
            'email' => 'remember@example.com',
            'password' => 'NewPassword456!',
            'token' => $token,
        ]);

        $this->assertNotEquals($originalRememberToken, $user->fresh()->remember_token);
    }


}
