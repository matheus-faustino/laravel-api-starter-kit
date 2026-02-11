<?php

declare(strict_types=1);

namespace App\Contracts\Auth;

use App\Models\User;

/**
 * Email verification service interface.
 *
 * Defines the contract for user email verification operations,
 * including sending, resending, and confirming verification.
 */
interface EmailVerificationServiceInterface
{
    /**
     * Send the verification email to the user.
     *
     * Dispatches the email verification notification to the user's
     * registered email address.
     *
     * @param User $user User who will receive the verification email
     */
    public function sendVerificationEmail(User $user): void;

    /**
     * Resend the verification email to the user.
     *
     * Checks if the user has not yet verified their email and,
     * if not, sends a new verification email.
     *
     * @param User $user User who will receive the resend
     *
     * @return bool True if the email was resent, false if already verified
     */
    public function resend(User $user): bool;

    /**
     * Mark the user's email as verified.
     *
     * Confirms the email verification and dispatches the Verified event.
     *
     * @param User $user User whose email will be verified
     *
     * @return bool True if the email was verified, false if already verified
     */
    public function verify(User $user): bool;
}
