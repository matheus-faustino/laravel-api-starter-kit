<?php

declare(strict_types=1);

namespace Tests\Feature\Auth;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\URL;
use Tests\TestCase;

class EmailVerificationControllerTest extends TestCase
{
    use RefreshDatabase;

    // Verify Email Tests

    public function test_verify_email_with_valid_link(): void
    {
        $user = User::factory()->unverified()->create();

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $response = $this->getJson($verificationUrl);

        $response->assertOk()
            ->assertJsonStructure(['message']);

        $this->assertNotNull($user->fresh()->email_verified_at);
    }

    public function test_verify_email_returns_success_for_already_verified_user(): void
    {
        $user = User::factory()->create();

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $response = $this->getJson($verificationUrl);

        $response->assertOk()
            ->assertJsonStructure(['message']);
    }

    public function test_verify_email_with_invalid_hash_returns_forbidden(): void
    {
        $user = User::factory()->unverified()->create();

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $user->id,
                'hash' => 'invalid-hash',
            ]
        );

        $response = $this->getJson($verificationUrl);

        $response->assertForbidden()
            ->assertJsonStructure(['message']);

        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_verify_email_with_expired_link_returns_forbidden(): void
    {
        $user = User::factory()->unverified()->create();

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->subMinutes(1),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $response = $this->getJson($verificationUrl);

        $response->assertForbidden();

        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_verify_email_with_invalid_signature_returns_forbidden(): void
    {
        $user = User::factory()->unverified()->create();

        $response = $this->getJson("/api/email/verify/{$user->id}/".sha1($user->email).'?signature=invalid');

        $response->assertForbidden();
    }

    public function test_verify_email_with_nonexistent_user_returns_not_found(): void
    {
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => 99999,
                'hash' => sha1('test@example.com'),
            ]
        );

        $response = $this->getJson($verificationUrl);

        $response->assertNotFound();
    }

    public function test_verify_email_with_different_user_hash_returns_forbidden(): void
    {
        $user = User::factory()->unverified()->create(['email' => 'user@example.com']);
        $otherUser = User::factory()->create(['email' => 'other@example.com']);

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $user->id,
                'hash' => sha1($otherUser->email),
            ]
        );

        $response = $this->getJson($verificationUrl);

        $response->assertForbidden();
        $this->assertNull($user->fresh()->email_verified_at);
    }

    // Resend Verification Email Tests

    public function test_resend_verification_email_for_unverified_user(): void
    {
        $user = User::factory()->unverified()->create();
        $token = $user->createToken('test-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer '.$token)
            ->postJson('/api/email/resend');

        $response->assertOk()
            ->assertJsonStructure(['message']);
    }

    public function test_resend_verification_email_for_verified_user_returns_already_verified(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer '.$token)
            ->postJson('/api/email/resend');

        $response->assertOk()
            ->assertJsonStructure(['message']);
    }

    public function test_resend_verification_email_requires_authentication(): void
    {
        $response = $this->postJson('/api/email/resend');

        $response->assertUnauthorized();
    }

    public function test_resend_verification_email_with_invalid_token(): void
    {
        $response = $this->withHeader('Authorization', 'Bearer invalid-token')
            ->postJson('/api/email/resend');

        $response->assertUnauthorized();
    }

    // Integration Tests

    public function test_full_email_verification_flow(): void
    {
        $registerResponse = $this->postJson('/api/auth/register', [
            'name' => 'New User',
            'email' => 'newuser@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ]);

        $registerResponse->assertCreated();
        $token = $registerResponse->json('token');

        $user = User::where('email', 'newuser@example.com')->first();
        $this->assertNull($user->email_verified_at);

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $verifyResponse = $this->getJson($verificationUrl);
        $verifyResponse->assertOk();

        $this->assertNotNull($user->fresh()->email_verified_at);
    }

    public function test_user_can_resend_then_verify(): void
    {
        $user = User::factory()->unverified()->create();
        $token = $user->createToken('test-token')->plainTextToken;

        $resendResponse = $this->withHeader('Authorization', 'Bearer '.$token)
            ->postJson('/api/email/resend');

        $resendResponse->assertOk();

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            [
                'id' => $user->id,
                'hash' => sha1($user->email),
            ]
        );

        $verifyResponse = $this->getJson($verificationUrl);
        $verifyResponse->assertOk();

        $this->assertNotNull($user->fresh()->email_verified_at);
    }
}
