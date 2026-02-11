<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Contracts\Auth\PasswordResetServiceInterface;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\ForgotPasswordRequest;
use App\Http\Requests\Auth\ResetPasswordRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Password;
use OpenApi\Attributes as OA;

#[OA\Get(
    path: '/password/reset/{token}',
    summary: 'Get password reset token',
    description: 'Returns the password reset token from the URL. Used by email clients to extract the token before redirecting to the frontend application. Limited to 6 requests per minute.',
    operationId: 'getPasswordResetToken',
    tags: ['Password Reset'],
    parameters: [
        new OA\Parameter(
            name: 'token',
            in: 'path',
            required: true,
            description: 'Password reset token received by email',
            schema: new OA\Schema(type: 'string', example: 'abc123def456...')
        )
    ],
    responses: [
        new OA\Response(
            response: 200,
            description: 'Token retrieved successfully',
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'token', type: 'string', example: 'abc123def456...', description: 'Password reset token')
                ]
            )
        ),
        new OA\Response(
            response: 429,
            description: 'Too many requests - rate limit exceeded',
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: 'message', type: 'string', example: 'Too Many Attempts.')
                ]
            )
        )
    ]
)]
class PasswordResetController extends Controller
{
    public function __construct(
        private readonly PasswordResetServiceInterface $passwordResetService
    ) {}

    #[OA\Post(
        path: '/password/forgot',
        summary: 'Request password recovery',
        description: 'Sends an email with a link to reset the password. Limited to 6 requests per minute.',
        operationId: 'forgotPassword',
        tags: ['Password Reset'],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', format: 'email', example: 'john@example.com', description: 'Registered user\'s email')
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Password recovery link sent successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'We have emailed your password reset link.')
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: 'Error sending recovery link',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'We can\'t find a user with that email address.')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'The email field is required.'),
                        new OA\Property(
                            property: 'errors',
                            type: 'object',
                            example: ['email' => ['The email field is required.']]
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 429,
                description: 'Too many requests - rate limit exceeded',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Too Many Attempts.')
                    ]
                )
            )
        ]
    )]
    public function sendResetLink(ForgotPasswordRequest $request): JsonResponse
    {
        $status = $this->passwordResetService->sendResetLink(
            $request->validated('email')
        );

        if ($status !== Password::RESET_LINK_SENT) {
            return response()->json([
                'message' => __($status),
            ], 400);
        }

        return response()->json([
            'message' => __($status),
        ]);
    }

    #[OA\Post(
        path: '/password/reset',
        summary: 'Reset password',
        description: 'Resets the user\'s password using the token received by email. Limited to 6 requests per minute.',
        operationId: 'resetPassword',
        tags: ['Password Reset'],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['token', 'email', 'password', 'password_confirmation'],
                properties: [
                    new OA\Property(property: 'token', type: 'string', example: 'abc123def456...', description: 'Recovery token received by email'),
                    new OA\Property(property: 'email', type: 'string', format: 'email', example: 'john@example.com', description: 'User\'s email'),
                    new OA\Property(property: 'password', type: 'string', format: 'password', example: 'NewPassword123!', description: 'New password (minimum 8 characters)'),
                    new OA\Property(property: 'password_confirmation', type: 'string', format: 'password', example: 'NewPassword123!', description: 'New password confirmation')
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: 'Password reset successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Password has been reset successfully.')
                    ]
                )
            ),
            new OA\Response(
                response: 400,
                description: 'Error resetting password (invalid or expired token)',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'This password reset token is invalid.')
                    ]
                )
            ),
            new OA\Response(
                response: 422,
                description: 'Validation error',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'The token field is required.'),
                        new OA\Property(
                            property: 'errors',
                            type: 'object',
                            example: ['token' => ['The token field is required.']]
                        )
                    ]
                )
            ),
            new OA\Response(
                response: 429,
                description: 'Too many requests - rate limit exceeded',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Too Many Attempts.')
                    ]
                )
            )
        ]
    )]
    public function reset(ResetPasswordRequest $request): JsonResponse
    {
        $this->passwordResetService->reset($request->validated());

        return response()->json([
            'message' => __('messages.password_reset_success'),
        ]);
    }
}
