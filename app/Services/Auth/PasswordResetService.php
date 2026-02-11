<?php

declare(strict_types=1);

namespace App\Services\Auth;

use App\Contracts\Auth\PasswordResetServiceInterface;
use App\Contracts\Auth\TokenServiceInterface;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

/**
 * Password reset service.
 *
 * Implements recovery link sending
 * and user password reset operations.
 *
 * @see PasswordResetServiceInterface
 */
class PasswordResetService implements PasswordResetServiceInterface
{
    /**
     * Create a new service instance.
     *
     * @param TokenServiceInterface $tokenService Token management service
     */
    public function __construct(
        private readonly TokenServiceInterface $tokenService
    ) {}

    /**
     * {@inheritDoc}
     */
    public function sendResetLink(string $email): string
    {
        return Password::sendResetLink(['email' => $email]);
    }

    /**
     * {@inheritDoc}
     */
    public function reset(array $data): void
    {
        $status = Password::reset(
            [
                'email' => $data['email'],
                'password' => $data['password'],
                'password_confirmation' => $data['password'],
                'token' => $data['token'],
            ],
            function (User $user, string $password): void {
                $user->forceFill([
                    'password' => $password,
                    'remember_token' => Str::random(60),
                ])->save();

                $this->tokenService->revokeAllTokens($user);

                event(new PasswordReset($user));
            }
        );

        if ($status !== Password::PASSWORD_RESET) {
            throw ValidationException::withMessages([
                'email' => [__($status)],
            ]);
        }
    }
}
