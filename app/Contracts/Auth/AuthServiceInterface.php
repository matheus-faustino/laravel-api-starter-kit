<?php

declare(strict_types=1);

namespace App\Contracts\Auth;

use App\Models\User;

/**
 * Authentication service interface.
 *
 * Defines the contract for user authentication operations,
 * including registration, login, and logout.
 */
interface AuthServiceInterface
{
    /**
     * Register a new user in the system.
     *
     * Creates a new user account with the provided data,
     * sends a verification email, and generates an authentication token.
     *
     * @param array{name: string, email: string, password: string} $data User data for registration
     *
     * @return array{user: User, token: string} Created user and authentication token
     */
    public function register(array $data): array;

    /**
     * Authenticate an existing user.
     *
     * Validates the provided credentials and, if valid,
     * returns the authenticated user with a new token.
     *
     * @param array{email: string, password: string} $credentials Access credentials
     *
     * @return array{user: User, token: string} Authenticated user and access token
     *
     * @throws \Illuminate\Validation\ValidationException When credentials are invalid
     */
    public function login(array $credentials): array;

    /**
     * End the user's session.
     *
     * Revokes the user's current access token.
     *
     * @param User $user User to be logged out
     */
    public function logout(User $user): void;
}
