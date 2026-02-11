<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth;

use App\Models\User;
use App\Services\Auth\TokenService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class TokenServiceTest extends TestCase
{
    use RefreshDatabase;

    private TokenService $tokenService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tokenService = new TokenService();
    }

    public function test_create_token_returns_string(): void
    {
        $user = User::factory()->create();

        $token = $this->tokenService->createToken($user);

        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function test_create_token_contains_pipe_separator(): void
    {
        $user = User::factory()->create();

        $token = $this->tokenService->createToken($user);

        $this->assertStringContainsString('|', $token);
    }

    public function test_create_token_stores_token_in_database(): void
    {
        $user = User::factory()->create();

        $this->tokenService->createToken($user);

        $this->assertDatabaseHas('personal_access_tokens', [
            'tokenable_id' => $user->id,
            'tokenable_type' => User::class,
            'name' => 'auth-token',
        ]);
    }

    public function test_create_token_with_custom_name(): void
    {
        $user = User::factory()->create();

        $this->tokenService->createToken($user, 'custom-token-name');

        $this->assertDatabaseHas('personal_access_tokens', [
            'tokenable_id' => $user->id,
            'name' => 'custom-token-name',
        ]);
    }

    public function test_create_multiple_tokens_for_same_user(): void
    {
        $user = User::factory()->create();

        $token1 = $this->tokenService->createToken($user, 'token-1');
        $token2 = $this->tokenService->createToken($user, 'token-2');

        $this->assertNotEquals($token1, $token2);
        $this->assertCount(2, $user->tokens);
    }

    public function test_revoke_current_token_deletes_token(): void
    {
        $user = User::factory()->create();
        $token = $user->createToken('test-token');
        $user->withAccessToken($token->accessToken);

        $this->tokenService->revokeCurrentToken($user);

        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $token->accessToken->id,
        ]);
    }

    public function test_revoke_current_token_keeps_other_tokens(): void
    {
        $user = User::factory()->create();
        $token1 = $user->createToken('token-1');
        $token2 = $user->createToken('token-2');
        $user->withAccessToken($token1->accessToken);

        $this->tokenService->revokeCurrentToken($user);

        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $token1->accessToken->id,
        ]);
        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $token2->accessToken->id,
        ]);
    }

    public function test_revoke_all_tokens_deletes_all_user_tokens(): void
    {
        $user = User::factory()->create();
        $user->createToken('token-1');
        $user->createToken('token-2');
        $user->createToken('token-3');

        $this->assertCount(3, $user->tokens);

        $this->tokenService->revokeAllTokens($user);

        $this->assertCount(0, $user->fresh()->tokens);
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $user->id,
        ]);
    }

    public function test_revoke_all_tokens_does_not_affect_other_users(): void
    {
        $user1 = User::factory()->create();
        $user2 = User::factory()->create();

        $user1->createToken('user1-token');
        $user2->createToken('user2-token');

        $this->tokenService->revokeAllTokens($user1);

        $this->assertCount(0, $user1->fresh()->tokens);
        $this->assertCount(1, $user2->fresh()->tokens);
    }

}
