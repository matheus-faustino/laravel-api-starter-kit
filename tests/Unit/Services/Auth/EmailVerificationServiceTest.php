<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth;

use App\Models\User;
use App\Services\Auth\EmailVerificationService;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Tests\TestCase;

class EmailVerificationServiceTest extends TestCase
{
    use RefreshDatabase;

    private EmailVerificationService $emailVerificationService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->emailVerificationService = new EmailVerificationService();
    }

    public function test_verify_marks_email_as_verified(): void
    {
        $user = User::factory()->unverified()->create();

        $this->assertNull($user->email_verified_at);

        $result = $this->emailVerificationService->verify($user);

        $this->assertTrue($result);
        $this->assertNotNull($user->fresh()->email_verified_at);
    }

    public function test_verify_returns_false_if_already_verified(): void
    {
        $user = User::factory()->create();

        $this->assertNotNull($user->email_verified_at);

        $result = $this->emailVerificationService->verify($user);

        $this->assertFalse($result);
    }

    public function test_verify_dispatches_verified_event(): void
    {
        Event::fake([Verified::class]);

        $user = User::factory()->unverified()->create();

        $this->emailVerificationService->verify($user);

        Event::assertDispatched(Verified::class, function ($event) use ($user) {
            return $event->user->id === $user->id;
        });
    }

    public function test_verify_does_not_dispatch_event_if_already_verified(): void
    {
        Event::fake([Verified::class]);

        $user = User::factory()->create();

        $this->emailVerificationService->verify($user);

        Event::assertNotDispatched(Verified::class);
    }

    public function test_resend_returns_true_for_unverified_user(): void
    {
        $user = User::factory()->unverified()->create();

        $result = $this->emailVerificationService->resend($user);

        $this->assertTrue($result);
    }

    public function test_resend_returns_false_for_verified_user(): void
    {
        $user = User::factory()->create();

        $result = $this->emailVerificationService->resend($user);

        $this->assertFalse($result);
    }

    public function test_verify_sets_correct_timestamp(): void
    {
        $user = User::factory()->unverified()->create();

        $this->freezeTime();

        $this->emailVerificationService->verify($user);

        $verifiedAt = $user->fresh()->email_verified_at;

        $this->assertEquals(now()->toDateTimeString(), $verifiedAt->toDateTimeString());
    }
}
