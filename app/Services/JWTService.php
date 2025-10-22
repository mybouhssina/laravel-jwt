<?php

namespace App\Services;

use App\Models\RefreshToken;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class JWTService
{
    private const ALG = 'HS256';


    function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    function base64UrlDecode(string $data): string {
        $mod = strlen($data) % 4;
        if ($mod !== 0) {
            $data .= str_repeat('=', 4-$mod);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public function createAccessToken(User $user) {
        $header = $this->base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'HS256'], JSON_THROW_ON_ERROR));
        $payload = $this->base64UrlEncode(json_encode([
            'iss' => config('app.url'),
            'aud' => config('app.url'),
            'iat' => Carbon::now()->getTimestamp(),
            'exp' => Carbon::now()->addMinutes(30)->getTimestamp(),
            'sub' => (string)$user->id
        ], JSON_THROW_ON_ERROR));
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $header . '.' . $payload, config('auth.jwt.secret'), true));
        return $header . '.' . $payload . '.' . $signature;
    }

    public function createRefreshToken(User $user): array {
        $token = Str::random(32);
        $jti = Str::uuid()->toString();
        $model = RefreshToken::create([
            'token_hash' => \Hash::make($token),
            'jti' => $jti,
            'revoked' => false,
            'user_id' => $user->id,
            'expires_at' => Carbon::now()->addDays(7)
        ]);
        return [
            "model" => $model,
            "token" => "$jti.$token"
        ];
    }

    public function verifyAccessToken(string $token) {
        // validate format
        $parts = explode('.', $token);
        if(count($parts) != 3)
            throw new \Exception('invalid token');
        $encodedHeader = $parts[0];
        $header = json_decode($this->base64UrlDecode($encodedHeader), true);
        if(!$header ||
            !isset($header['alg']) || $header['alg'] !== self::ALG ||
            !isset($header['typ']) || $header['typ'] !== 'JWT')
            throw new \Exception('invalid header');
        $encodedPayload = $parts[1];
        $payload = json_decode($this->base64UrlDecode($encodedPayload), true);
        if(!$payload ||
            !isset($payload['iss']) || $payload['iss'] !== config('app.url') ||
            !isset($payload['aud']) || $payload['aud'] !== config('app.url') ||
            !isset($payload['exp'])
        ) {
            throw new \Exception('invalid payload');
        }
        // verify signature
        $encodedSignature = $parts[2];
        $signature = $this->base64UrlDecode($encodedSignature);
        if(!hash_equals(
            hash_hmac('sha256', $encodedHeader . '.' . $encodedPayload, config('auth.jwt.secret'), true),
            $signature)) {
            throw new \Exception('invalid signature');
        }
        // verify expiration date
        $expiresAt = $payload['exp'];
        if($expiresAt < time()) {
            throw new \Exception('expired token');
        }
        return $payload['sub'];
    }

    public function verifyRefreshToken($tokenCookie) {
        if(!$tokenCookie || !is_string($tokenCookie) ) {
            return response()->json(['msg' => 'invalid or missing refresh token'], 400);
        }
        $tokenArray = explode('.', $tokenCookie);
        if(count($tokenArray) != 2) {
            throw new \Exception('invalid refresh token format');
        }
        [$tokenJti, $tokenString] = [$tokenArray[0], $tokenArray[1]];
        $tokenModel = RefreshToken::where('jti', $tokenJti)
            ->where('expires_at', '>', now())
            ->where('revoked', false)
            ->first();
        if(!$tokenModel || !Hash::check($tokenString, $tokenModel->token_hash)) {
            throw new \Exception('invalid refresh token');
        }
        return $tokenModel;
    }
}
