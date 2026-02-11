<?php

namespace App\Http\Controllers;

use OpenApi\Attributes as OA;

#[OA\Info(
    version: '1.0.0',
    title: 'Money Tracker API',
    description: 'API for personal financial management',
    contact: new OA\Contact(
        name: 'API Support',
        email: 'support@moneytracker.com'
    )
)]
#[OA\Server(
    url: '/api',
    description: 'API Server'
)]
#[OA\SecurityScheme(
    securityScheme: 'sanctum',
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'JWT',
    description: 'Use the token returned from the login endpoint. Format: Bearer {token}'
)]
#[OA\Tag(
    name: 'Authentication',
    description: 'Endpoints for user authentication'
)]
#[OA\Tag(
    name: 'Email Verification',
    description: 'Endpoints for email verification'
)]
#[OA\Tag(
    name: 'Password Reset',
    description: 'Endpoints for password recovery'
)]
abstract class Controller
{
    //
}
