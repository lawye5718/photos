<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Image Driver
    |--------------------------------------------------------------------------
    |
    | Intervention Image supports "GD Library" and "Imagick" to process images
    | internally. You may choose one of them according to your PHP
    | configuration. By default PHP's "GD Library" implementation is used.
    |
    | Supported: "gd", "imagick"
    |
    */

    // 改用 gd：群晖重建镜像后 imagick 对部分 PNG 子格式（灰度+alpha 等）解码异常且读“已上传”临时文件路径会失败；
    // GD 自带 libpng 可解所有 PNG 子格式，读上传文件稳定。如确需 imagick 高质量缩略图，需先修复镜像内 imagick 解码能力。
    'driver' => 'gd'
];
