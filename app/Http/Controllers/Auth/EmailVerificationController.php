<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Contracts\Auth\EmailVerificationServiceInterface;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use OpenApi\Attributes as OA;

class EmailVerificationController extends Controller
{
    public function __construct(
        private readonly EmailVerificationServiceInterface $emailVerificationService
    ) {}

    #[OA\Get(
        path: '/email/verify/{id}/{hash}',
        summary: 'Verify email',
        description: 'Verifies the user\'s email through the link sent by email. This endpoint uses signed URLs for security.',
        operationId: 'verifyEmail',
        tags: ['Email Verification'],
        parameters: [
            new OA\Parameter(
                name: 'id',
                in: 'path',
                required: true,
                description: 'User ID',
                schema: new OA\Schema(type: 'integer', example: 1)
            ),
            new OA\Parameter(
                name: 'hash',
                in: 'path',
                required: true,
                description: 'Email verification hash',
                schema: new OA\Schema(type: 'string', example: 'abc123def456...')
            ),
            new OA\Parameter(
                name: 'signature',
                in: 'query',
                required: true,
                description: 'URL signature (automatically generated)',
                schema: new OA\Schema(type: 'string')
            ),
            new OA\Parameter(
                name: 'expires',
                in: 'query',
                required: true,
                description: 'URL expiration timestamp',
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Email verified successfully or already verified',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Email verified successfully.')
                    ]
                )
            ),
            new OA\Response(
                response: 403,
                description: 'Invalid or expired verification link',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Invalid verification link.')
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'No query results for model [App\\Models\\User].')
                    ]
                )
            )
        ]
    )]
    public function verify(Request $request, int $id, string $hash): JsonResponse
    {
        $user = User::findOrFail($id);

        if (! hash_equals(sha1($user->getEmailForVerification()), $hash)) {
            return response()->json([
                'message' => __('messages.verification_link_invalid'),
            ], 403);
        }

        if (! $this->emailVerificationService->verify($user)) {
            return response()->json([
                'message' => __('messages.email_already_verified'),
            ]);
        }

        return response()->json([
            'message' => __('messages.email_verified'),
        ]);
    }

    #[OA\Post(
        path: '/email/resend',
        summary: 'Resend verification email',
        description: 'Resends the verification email to the authenticated user. Limited to 6 requests per minute.',
        operationId: 'resendVerificationEmail',
        security: [['sanctum' => []]],
        tags: ['Email Verification'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Verification email sent or email already verified',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Verification email sent.')
                    ]
                )
            ),
            new OA\Response(
                response: 401,
                description: 'Unauthenticated',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'message', type: 'string', example: 'Unauthenticated.')
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
    public function resend(Request $request): JsonResponse
    {
        if (! $this->emailVerificationService->resend($request->user())) {
            return response()->json([
                'message' => __('messages.email_already_verified'),
            ]);
        }

        return response()->json([
            'message' => __('messages.verification_email_sent'),
        ]);
    }
}
