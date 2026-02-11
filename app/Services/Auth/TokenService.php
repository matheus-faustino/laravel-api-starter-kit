<?php

declare(strict_types=1);

namespace App\Services\Auth;

use App\Contracts\Auth\TokenServiceInterface;
use App\Models\User;

/**
 * Authentication token management service.
 *
 * Implements access token creation and revocation
 * using Laravel Sanctum.
 *
 * @see TokenServiceInterface
 */
class TokenService implements TokenServiceInterface
{
    /**
     * {@inheritDoc}
     */
    public function createToken(User $user, string $name = 'auth-token'): string
    {
        return $user->createToken($name)->plainTextToken;
    }

    /**
     * {@inheritDoc}
     */
    public function revokeCurrentToken(User $user): void
    {
        $user->currentAccessToken()->delete();
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllTokens(User $user): void
    {
        $user->tokens()->delete();
    }
}
