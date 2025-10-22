<?php

namespace Tests\Unit;

use App\Models\RefreshToken;
use App\Models\User;
use App\Services\JWTService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class JWTServiceTest extends TestCase
{
    use RefreshDatabase;

    protected JWTService $jwtService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->jwtService = $this->app->make(JWTService::class);
    }

    public function test_create_access_token_has_three_parts_and_expected_claims()
    {
        $user = User::factory()->create();
        $token = $this->jwtService->createAccessToken($user);

        $parts = explode('.', $token);
        $this->assertCount(3, $parts, 'Token does not contain three parts');

        [$headerB64, $payloadB64, $sigB64] = $parts;

        $headerJson = json_decode($this->jwtService->base64UrlDecode($headerB64), true);
        $this->assertIsArray($headerJson);
        $this->assertEquals('JWT', $headerJson['typ']);
        $this->assertEquals('HS256', $headerJson['alg']);

        $payload = json_decode($this->jwtService->base64UrlDecode($payloadB64), true);
        $this->assertIsArray($payload);
        $this->assertArrayHasKey('sub', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertIsNumeric($payload['exp']);
    }

    public function test_verify_access_token_valid_and_rejects_tampered_payload()
    {
        $user = User::factory()->create();
        $token = $this->jwtService->createAccessToken($user);

        $userId = $this->jwtService->verifyAccessToken($token);
        $this->assertEquals((string)$user->id, (string)$userId);

        [$h, $p, $s] = explode('.', $token);
        $badPayload = $this->jwtService->base64UrlEncode(json_encode(['sub' => '99999']));
        $tampered = $h . '.' . $badPayload . '.' . $s;

        $this->expectException(\Exception::class);
        $this->jwtService->verifyAccessToken($tampered);
    }

    public function test_refresh_token_create_and_verify_and_revocation()
    {
        $user = User::factory()->create();

        $refresh = $this->jwtService->createRefreshToken($user)['token'];
        $this->assertIsString($refresh);
        $this->assertStringContainsString('.', $refresh);

        $model = $this->jwtService->verifyRefreshToken($refresh);
        $this->assertInstanceOf(RefreshToken::class, $model);
        $this->assertFalse($model->revoked);

        $model->update(['revoked' => true]);

        $this->expectException(\Exception::class);
        $this->jwtService->verifyRefreshToken($refresh);
    }
}
