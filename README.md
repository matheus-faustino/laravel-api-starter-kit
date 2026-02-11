# Laravel API Starter Kit

A production-ready starter kit for building REST APIs with Laravel 12.

## What's Included

### Authentication (complete cycle)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user and receive a token |
| POST | `/api/auth/login` | Authenticate and receive a token |
| POST | `/api/auth/logout` | Revoke the current token |
| GET | `/api/auth/me` | Get the authenticated user |
| GET | `/api/email/verify/{id}/{hash}` | Verify email via signed URL |
| POST | `/api/email/resend` | Resend verification email |
| POST | `/api/password/forgot` | Send password reset link |
| POST | `/api/password/reset` | Reset password with token |

### Architecture

```
app/
  Contracts/Auth/             # Interfaces (dependency inversion)
    AuthServiceInterface
    EmailVerificationServiceInterface
    PasswordResetServiceInterface
    TokenServiceInterface

  Services/Auth/              # Concrete implementations
    AuthService
    EmailVerificationService
    PasswordResetService
    TokenService

  Http/
    Controllers/Auth/         # Thin controllers, delegate to services
    Requests/Auth/            # Form Request validation

  Models/
  Providers/
    AuthServiceProvider       # Interface -> Implementation bindings
```

Controllers never touch business logic directly. Every service has a corresponding interface, registered via Service Provider. Adding a new module follows the same pattern: define a contract, implement it, bind it.

### Security

- Bearer token authentication via **Laravel Sanctum**
- Password hashing with bcrypt
- Password complexity enforcement via `Password::defaults()`
- Signed URLs for email verification (tamper-proof, expiring)
- All existing tokens revoked on password reset
- Rate limiting on sensitive endpoints (`throttle:6,1`)

### Testing

```
tests/
  Feature/Auth/
    AuthControllerTest                  # 15 tests
    EmailVerificationControllerTest     # 11 tests
    PasswordResetControllerTest         # 14 tests
  Unit/Services/Auth/
    AuthServiceTest                     #  6 tests
    EmailVerificationServiceTest        #  7 tests
    PasswordResetServiceTest            #  7 tests
    TokenServiceTest                    #  8 tests
```

Tests run against SQLite in-memory with reduced bcrypt rounds for speed.

### API Documentation

Interactive Swagger UI powered by **l5-swagger** (OpenAPI 3.0), generated from PHP Attributes directly on controller methods. Available at `/api/documentation` with auto-regeneration in development.

### Docker Environment

Docker Compose setup via **Laravel Sail**:

| Service | Version | Port |
|---------|---------|------|
| PHP | 8.4 | 80 |
| MySQL | 8.4 | 3306 |
| Redis | Alpine | 6379 |
| Mailpit | latest | 8025 |

### Other

- `declare(strict_types=1)` enforced on every file
- Brazilian Portuguese (`pt_BR`) localization included
- Composer scripts for setup, dev, and test workflows

## Getting Started

### Requirements

- Docker & Docker Compose
- Composer
- Node.js & npm

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd <project-directory>

# Start the Docker environment
./vendor/bin/sail up -d

# Run the setup script (install deps, generate key, run migrations, build assets)
./vendor/bin/sail composer setup

### Environment

Copy `.env.example` and adjust as needed:

```bash
cp .env.example .env
php artisan key:generate
```

The default `.env.example` uses SQLite for a zero-config local setup. The Docker environment uses MySQL.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Framework | Laravel 12 |
| Language | PHP 8.2+ (strict types) |
| Auth | Laravel Sanctum |
| Database | MySQL 8.4 / SQLite |
| Cache & Queue | Redis via Predis |
| API Docs | l5-swagger (OpenAPI 3.0) |
| Testing | PHPUnit 11 |
| Code Style | Laravel Pint |
| DevOps | Docker Compose (Laravel Sail) |
