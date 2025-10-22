<?php

use App\Models\RefreshToken;
use App\Models\User;
use App\Services\JWTService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/login', function (Request $request, JWTService $jwtService) {
    $data = $request->validate([
        'email' => ['required', 'email', 'min:3'],
        'password' => ['required', 'string', 'min:3'],
    ]);
    $user = User::query()->where('email', $data['email'])->first();
    /**
     * @var $user ?User
     */
    if(!$user || !Hash::check($data['password'], $user->password)) {
        return response()->json(['msg' => 'unauthorized'], 401);
    }
    $accessToken = $jwtService->createAccessToken($user);
    $refreshToken = $jwtService->createRefreshToken($user);

    /**
     * @var $model RefreshToken
     */
    $model = $refreshToken['model'];

    return response()->json([
        'access-token' => $accessToken
    ])->withCookie(cookie('refresh-token', $refreshToken['token'], minutes: floor(($model->expires_at->getTimestamp() - time())/60), httpOnly: true, sameSite: 'strict'));
});

Route::get('/profile', function (Request $request, JWTService $jwtService) {
    $token = $request->bearerToken();
    if(!$token) {
        return response()->json(['msg' => 'unauthorized'], 401);
    }
    try {
        $userId = $jwtService->verifyAccessToken($token);
    }catch(Exception) {
        return response()->json(['msg' => 'unauthorized'], 401);
    }
    $user = User::query()->find($userId);
    if(!$user) {
        return response()->json(['msg' => 'unauthorized'], 401);
    }
    return response()->json($user->only(['email','name']));
});


Route::post('/logout', function (Request $request, JWTService $jwtService) {
    $tokenCookie = $request->cookie('refresh-token');
    try {
        $tokenModel = $jwtService->verifyRefreshToken($tokenCookie);
    }catch(Exception $e) {
        return response()->json(['msg' => $e->getMessage()], 401);
    }
    $tokenModel->update([
        'revoked' => true
    ]);
    return response()->json(['msg' => 'successfully logged out'])->withCookie(Cookie::forget('refresh-token'));
});

Route::post('/refresh', function (Request $request, JWTService $jwtService) {
    $tokenCookie = $request->cookie('refresh-token');
    try {
        $oldRefreshToken = $jwtService->verifyRefreshToken($tokenCookie);
    }catch(Exception $e) {
        return response()->json(['msg' => $e->getMessage()], 401);
    }
    [$accessToken, $refreshToken] = DB::transaction(function () use ($oldRefreshToken, $jwtService) {
        $oldRefreshToken->lockForUpdate();
        $user = $oldRefreshToken->user;
        $accessToken = $jwtService->createAccessToken($user);
        $refreshToken = $jwtService->createRefreshToken($user);
        $oldRefreshToken->update(['revoked' => true]);
        return [$accessToken, $refreshToken];
    });

    return response()->json([
        'access-token' => $accessToken
    ])->withCookie(cookie('refresh-token', $refreshToken['token'], minutes: floor(($refreshToken['model']->expires_at->getTimestamp() - time())/60), httpOnly: true, sameSite: 'strict'));
});
