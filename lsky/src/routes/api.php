<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Api\V1\ImageController;
use App\Http\Controllers\Api\V1\AlbumController;
use App\Http\Controllers\Api\V1\TokenController;
use App\Http\Controllers\Api\V1\UserController;
use App\Http\Controllers\Api\V1\StrategyController;
use App\Http\Middleware\CheckIsEnableApi;
use App\Models\Image;
use App\Models\User;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group([
    'prefix' => 'v1',
    'middleware' => CheckIsEnableApi::class,
], function () {
    Route::get('strategies', [StrategyController::class, 'index']);
    Route::post('upload', [ImageController::class, 'upload']);
    Route::post('tokens', [TokenController::class, 'store'])->middleware('throttle:3,1');

    Route::group([
        'middleware' => 'auth:sanctum',
    ], function () {
        Route::get('images', [ImageController::class, 'images']);
        Route::delete('images/{key}', [ImageController::class, 'destroy']);
        Route::get('albums', [AlbumController::class, 'index']);
        Route::delete('albums/{id}', [AlbumController::class, 'destroy']);
        Route::delete('tokens', [TokenController::class, 'clear']);
        Route::get('profile', [UserController::class, 'index']);
    });
});

/*
|--------------------------------------------------------------------------
| Gallery（光影收藏）专用极简接口 —— 零挂载
|--------------------------------------------------------------------------
|
| 目的：Gallery 不再挂载/直读本应用的 lsky.sqlite，两个容器之间只剩 HTTP 这一条联系。
| 特点：只做校验与只读查询，不签发 Token、不写入任何状态。
| 鉴权：共享密钥取容器环境变量 GALLERY_VERIFY_SECRET，调用方用请求头
|       X-Gallery-Verify-Key 携带（未配置密钥则一律 403，失败关闭）。
| ⚠️ 这里是闭包路由，切勿执行 php artisan route:cache（闭包无法序列化）。
|
*/
$galleryAuthorized = function (\Illuminate\Http\Request $request): bool {
    $secret = env('GALLERY_VERIFY_SECRET');
    return is_string($secret) && $secret !== ''
        && hash_equals($secret, (string) $request->header('X-Gallery-Verify-Key', ''));
};

// POST /api/auth/verify  {email, password} —— 只校验账号密码，不签发 Token
Route::post('auth/verify', function (\Illuminate\Http\Request $request) use ($galleryAuthorized) {
    if (! $galleryAuthorized($request)) {
        return response()->json(['status' => false, 'message' => 'forbidden'], 403);
    }

    $credentials = $request->validate([
        'email' => 'required|email',
        'password' => 'required|string|max:255',
    ]);

    if (! Auth::validate($credentials)) {
        return response()->json(['status' => false, 'message' => 'invalid credentials'], 401);
    }

    $user = User::where('email', $credentials['email'])->first();

    return response()->json([
        'status' => true,
        'user_id' => $user?->id,
        'is_adminer' => (bool) $user?->is_adminer,
    ]);
})->middleware('throttle:30,1');

// GET /api/gallery/images —— 供 Gallery 同步图片元数据（等价原来的「读 lsky.sqlite」）
Route::get('gallery/images', function (\Illuminate\Http\Request $request) use ($galleryAuthorized) {
    if (! $galleryAuthorized($request)) {
        return response()->json(['status' => false, 'message' => 'forbidden'], 403);
    }

    $limit = max(1, min((int) $request->query('limit', 2000), 5000));

    $images = Image::query()
        ->orderByDesc('id')
        ->limit($limit)
        ->get(['id', 'key', 'path', 'name', 'origin_name', 'alias_name',
               'extension', 'md5', 'width', 'height', 'created_at']);

    return response()->json(['status' => true, 'data' => $images]);
})->middleware('throttle:60,1');
