<?php

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Route;
use App\Enums\GroupConfigKey;
use App\Enums\ConfigKey;

// 原图统一经 PHP 路由流式输出（光影收藏改造）：缓存头改由 Controller::output 直接设置
// （immutable + 1 年），故此处不再挂 Laravel 自带的 cache.headers 中间件。
$extensions = config('convention.group.accepted_file_suffixes');
Route::any('{key}.{extension}', [
    Controller::class, 'output',
])->where('extension', implode('|', array_merge(
    array_map('strtoupper', $extensions),
    array_map('strtolower', $extensions)
)))
    // ⚠️ 关键：本路由走「无会话」通道。默认的 web 中间件组会启动 Session 并下发
    // XSRF-TOKEN / lsky_pro_session 两个 Cookie，而 Cloudflare（以及绝大多数 CDN）
    // 见到响应带 Set-Cookie 就一律 BYPASS，边缘缓存彻底失效。这里把这些中间件排除掉，
    // 出图响应不带任何 Cookie，才能被边缘节点缓存（也顺带省掉每次出图的会话开销）。
    // 注意：出图是公开只读逻辑，不依赖登录态，排除会话中间件无副作用。
    ->withoutMiddleware([
        \App\Http\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
        \Illuminate\View\Middleware\ShareErrorsFromSession::class,
        \App\Http\Middleware\VerifyCsrfToken::class,
    ]);
