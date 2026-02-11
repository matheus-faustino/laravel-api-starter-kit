<?php

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\EmailVerificationController;
use App\Http\Controllers\Auth\PasswordResetController;
use Illuminate\Support\Facades\Route;

// Authentication Routes

Route::prefix('auth')->group(function () {
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);

    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::get('/me', [AuthController::class, 'me']);
    });
});

// Email Verification Routes

Route::prefix('email')->group(function () {
    Route::get('/verify/{id}/{hash}', [EmailVerificationController::class, 'verify'])
        ->middleware('signed')
        ->name('verification.verify');

    Route::post('/resend', [EmailVerificationController::class, 'resend'])
        ->middleware(['auth:sanctum', 'throttle:6,1'])
        ->name('verification.send');
});

// Password Reset Routes

Route::prefix('password')->middleware('throttle:6,1')->group(function () {
    Route::post('/forgot', [PasswordResetController::class, 'sendResetLink'])
        ->name('password.email');

    Route::post('/reset', [PasswordResetController::class, 'reset'])
        ->name('password.update');

    Route::get('/reset/{token}', fn() => response()->json(['token' => request()->route('token')]))
        ->name('password.reset');
});
