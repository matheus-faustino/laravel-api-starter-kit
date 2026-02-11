<?php

declare(strict_types=1);

namespace App\Services\Auth;

use App\Contracts\Auth\EmailVerificationServiceInterface;
use App\Models\User;
use Illuminate\Auth\Events\Verified;

/**
 * Email verification service.
 *
 * Implements sending, resending, and confirming
 * user email verification operations.
 *
 * @see EmailVerificationServiceInterface
 */
class EmailVerificationService implements EmailVerificationServiceInterface
{
    /**
     * {@inheritDoc}
     */
    public function sendVerificationEmail(User $user): void
    {
        $user->sendEmailVerificationNotification();
    }

    /**
     * {@inheritDoc}
     */
    public function resend(User $user): bool
    {
        if ($user->hasVerifiedEmail()) {
            return false;
        }

        $this->sendVerificationEmail($user);

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function verify(User $user): bool
    {
        if ($user->hasVerifiedEmail()) {
            return false;
        }

        if ($user->markEmailAsVerified()) {
            event(new Verified($user));

            return true;
        }

        return false;
    }
}
