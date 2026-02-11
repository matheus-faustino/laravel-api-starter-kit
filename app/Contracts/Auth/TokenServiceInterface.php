<?php

declare(strict_types=1);

namespace App\Contracts\Auth;

use App\Models\User;

/**
 * Token management service interface.
 *
 * Defines the contract for creating and revoking authentication tokens
 * using Laravel Sanctum.
 */
interface TokenServiceInterface
{
    /**
     * Create a new access token for the user.
     *
     * @param User   $user User for whom the token will be created
     * @param string $name Token identifier name
     *
     * @return string Plain text access token
     */
    public function createToken(User $user, string $name = 'auth-token'): string;

    /**
     * Revoke the user's current access token.
     *
     * Removes only the token being used in the current request.
     *
     * @param User $user User whose current token will be revoked
     */
    public function revokeCurrentToken(User $user): void;

    /**
     * Revoke all user's access tokens.
     *
     * Removes all tokens associated with the user,
     * forcing logout from all active sessions.
     *
     * @param User $user User whose tokens will be revoked
     */
    public function revokeAllTokens(User $user): void;
}
