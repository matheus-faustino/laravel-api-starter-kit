<?php

declare(strict_types=1);

namespace App\Providers;

use App\Contracts\Auth\AuthServiceInterface;
use App\Contracts\Auth\EmailVerificationServiceInterface;
use App\Contracts\Auth\PasswordResetServiceInterface;
use App\Contracts\Auth\TokenServiceInterface;
use App\Services\Auth\AuthService;
use App\Services\Auth\EmailVerificationService;
use App\Services\Auth\PasswordResetService;
use App\Services\Auth\TokenService;
use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * @var array<class-string, class-string>
     */
    public array $bindings = [
        TokenServiceInterface::class => TokenService::class,
        EmailVerificationServiceInterface::class => EmailVerificationService::class,
        PasswordResetServiceInterface::class => PasswordResetService::class,
        AuthServiceInterface::class => AuthService::class,
    ];
}
