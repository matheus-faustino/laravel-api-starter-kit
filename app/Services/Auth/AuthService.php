<?php

declare(strict_types=1);

namespace App\Services\Auth;

use App\Contracts\Auth\AuthServiceInterface;
use App\Contracts\Auth\EmailVerificationServiceInterface;
use App\Contracts\Auth\TokenServiceInterface;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

/**
 * User authentication service.
 *
 * Implements registration, login, and logout operations,
 * coordinating token and email verification services.
 *
 * @see AuthServiceInterface
 */
class AuthService implements AuthServiceInterface
{
    /**
     * Create a new service instance.
     *
     * @param TokenServiceInterface             $tokenService             Token management service
     * @param EmailVerificationServiceInterface $emailVerificationService Email verification service
     */
    public function __construct(
        private readonly TokenServiceInterface $tokenService,
        private readonly EmailVerificationServiceInterface $emailVerificationService,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function register(array $data): array
    {
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => $data['password'],
        ]);

        $this->emailVerificationService->sendVerificationEmail($user);

        return [
            'user' => $user,
            'token' => $this->tokenService->createToken($user),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function login(array $credentials): array
    {
        $user = User::where('email', $credentials['email'])->first();

        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            throw ValidationException::withMessages([
                'email' => [__('messages.credentials_incorrect')],
            ]);
        }

        return [
            'user' => $user,
            'token' => $this->tokenService->createToken($user),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function logout(User $user): void
    {
        $this->tokenService->revokeCurrentToken($user);
    }
}
