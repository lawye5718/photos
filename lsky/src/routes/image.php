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
)));
