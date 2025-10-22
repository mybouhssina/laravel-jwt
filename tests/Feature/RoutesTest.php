<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\JWTService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class RoutesTest extends TestCase
{
    use RefreshDatabase;

    public function test_login_and_access_protected_route_flow()
    {
        $user = User::factory()->create(['password' => bcrypt('secret123')]);

        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'secret123',
        ]);
        $response->assertStatus(200);
        $response->assertJsonStructure(['access-token']);
        $accessToken = $response->json('access-token');

        $profileResp = $this->withHeaders([
            'Authorization' => 'Bearer ' . $accessToken,
        ])->getJson('/api/profile');

        $profileResp->assertStatus(200);
    }

    public function test_refresh_endpoint_returns_new_access_token()
    {
        $user = User::factory()->create();
        $refresh = $this->app->make(JWTService::class)->createRefreshToken($user)['token'];
        $response = $this->withUnencryptedCookie('refresh-token', $refresh)->post('/api/refresh');
        $response->assertStatus(200);
        $response->assertJsonStructure(['access-token']);
    }
}
