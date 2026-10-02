#!/bin/sh
# 容器启动入口：按需生成 APP_KEY、初始化 SQLite、执行首次安装
# ⚠️ 安全要点：installed.lock 装在镜像层，容器重建后会丢失；若无条件重跑 lsky:install，
#    其内部的 migrate:fresh 会清空已有数据。故这里以「sqlite 文件是否已有内容」为准判定是否需要安装。
set -e

cd /var/www/lsky

# 宿主 ./storage 首次挂载是空目录，会把镜像里预建的子目录整个盖掉，这里补齐
mkdir -p storage/app/public storage/app/uploads storage/framework/cache/data \
         storage/framework/sessions storage/framework/views storage/logs bootstrap/cache

# 挂载出来的目录要属主正确，否则 artisan / 上传会失败
chown -R www-data:www-data storage bootstrap/cache 2>/dev/null || true

# 1) 生成 APP_KEY（写进挂载出来的 .env，容器重建也不会变）
if ! grep -Eq '^APP_KEY=.+' .env 2>/dev/null; then
    echo "[entrypoint] 生成 APP_KEY ..."
    su-exec www-data php artisan key:generate --force --no-interaction
fi

# 2) composer 阶段跳过了 scripts，这里补做包发现
su-exec www-data php artisan package:discover --no-interaction || true

# 3) 准备 SQLite 数据文件
if [ ! -f storage/app/lsky.sqlite ]; then
    echo "[entrypoint] 创建 SQLite 数据库文件 ..."
    touch storage/app/lsky.sqlite
    chown www-data:www-data storage/app/lsky.sqlite
fi

# 4) 安装判定（幂等，绝不重复执行 migrate:fresh）
if [ -f installed.lock ]; then
    echo "[entrypoint] 已安装，跳过初始化"
elif [ -s storage/app/lsky.sqlite ]; then
    echo "[entrypoint] 检测到已有数据但缺 installed.lock —— 补建锁文件，不重装"
    touch installed.lock
    chown www-data:www-data installed.lock
else
    echo "[entrypoint] 首次安装：迁移 + 种子数据 ..."
    su-exec www-data php artisan lsky:install \
        --connection=sqlite \
        --database=/var/www/lsky/storage/app/lsky.sqlite \
        --no-interaction
fi

exec "$@"
