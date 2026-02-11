<?php

declare(strict_types=1);

namespace App\Contracts\Auth;

/**
 * Password reset service interface.
 *
 * Defines the contract for user password recovery
 * and reset operations.
 */
interface PasswordResetServiceInterface
{
    /**
     * Send a password reset link to the provided email.
     *
     * Generates a reset token and sends a notification
     * to the user's email with the recovery link.
     *
     * @param string $email Email of the user requesting the reset
     *
     * @return string Send status (Password::* constant)
     */
    public function sendResetLink(string $email): string;

    /**
     * Reset the user's password.
     *
     * Validates the reset token, updates the user's password,
     * revokes all existing access tokens, and dispatches the PasswordReset event.
     *
     * @param array{email: string, password: string, token: string} $data Reset data
     *
     * @throws \Illuminate\Validation\ValidationException When the token is invalid or expired
     */
    public function reset(array $data): void;
}
