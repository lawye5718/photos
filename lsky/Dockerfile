# Lsky Pro（兰空图床）群晖 Docker 镜像
# 上游源码：https://github.com/lsky-org/lsky-pro （MIT）  固定版本：38d52c46 (2025-11-24)
#
# 群晖环境下的四条硬约束（都是踩坑后固化下来的）：
#   1. 容器无法直连 GitHub → 源码 src/ 与 imagick.tgz 预先在宿主机下好，再 COPY 进镜像；
#      composer 依赖走阿里云镜像。
#   2. apk 默认源在容器内极慢 → 换阿里云镜像 + 构建期用 host 网络（见 docker-compose.yml）。
#   3. composer 官方镜像自带 PHP 8.3，本项目要求 PHP ≤ 8.2 → 在 php:8.2-fpm-alpine 内装依赖。
#   4. 编译依赖只装一次（gd 与 imagick 同一个 RUN），重复安装 gcc/g++ 会拖死构建。

FROM php:8.2-fpm-alpine3.20

ENV TZ=Asia/Shanghai \
    APP_ENV=prod \
    APP_DEBUG=false \
    COMPOSER_ALLOW_SUPERUSER=1

# 运行期依赖 + nginx + supervisor（单容器跑两个进程，备份/迁移只需挂一个卷）
# imagemagick 是 imagick 扩展的运行库（应用默认图片驱动就是 imagick，见 config/image.php）
RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.aliyun.com|g' /etc/apk/repositories \
    && apk add --no-cache \
        nginx supervisor tzdata su-exec unzip git imagemagick ffmpeg \
        libjpeg-turbo freetype libpng libwebp libwebp-tools libzip oniguruma libintl icu-libs sqlite-libs \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

COPY --from=composer:2.7.9 /usr/bin/composer /usr/bin/composer

# imagick 源码包（宿主机预下载，容器访问 pecl.php.net 不稳定）
COPY imagick.tgz /tmp/imagick.tgz

# 编译 PHP 扩展：gd（缩略图/水印）+ imagick（应用默认驱动）+ 常规依赖
RUN apk add --no-cache --virtual .build-deps \
        ${PHPIZE_DEPS} sqlite-dev imagemagick-dev \
        libjpeg-turbo-dev freetype-dev libpng-dev libwebp-dev libzip-dev oniguruma-dev icu-dev \
    && docker-php-ext-configure gd --with-jpeg --with-freetype --with-webp \
    && docker-php-ext-install -j"$(nproc)" gd pdo_sqlite pdo_mysql zip bcmath exif pcntl intl opcache ftp \
    && mkdir -p /tmp/imagick-src \
    && tar xzf /tmp/imagick.tgz -C /tmp/imagick-src --strip-components=1 \
    && cd /tmp/imagick-src \
    && phpize \
    && ./configure --with-php-config=/usr/local/bin/php-config \
    && make -j"$(nproc)" \
    && make install \
    && docker-php-ext-enable imagick \
    && cd / \
    && rm -rf /tmp/imagick-src /tmp/imagick.tgz \
    && apk del .build-deps

# 源码 + PHP 依赖
COPY src/ /var/www/lsky
WORKDIR /var/www/lsky
RUN composer config repositories.packagist composer https://mirrors.aliyun.com/composer/ \
    && composer install --no-interaction --no-scripts --no-dev --optimize-autoloader

# 移除 alpine 自带默认站，避免与我们的站点抢 80 端口默认站
RUN rm -f /etc/nginx/http.d/default.conf
COPY nginx-site.conf /etc/nginx/http.d/lsky.conf

# 上传限制覆盖（upload_max_filesize / post_max_size / memory_limit）
COPY php-custom.ini /usr/local/etc/php/conf.d/zz-lsky-upload.ini
COPY supervisord.conf /etc/supervisord.conf
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views \
               storage/logs storage/app/public bootstrap/cache \
    && chown -R www-data:www-data /var/www/lsky

VOLUME ["/var/www/lsky/storage"]
EXPOSE 80

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
