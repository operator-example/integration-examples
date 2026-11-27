FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --no-autoloader --no-scripts --ignore-platform-req=ext-apcu
COPY src ./src
RUN composer dump-autoload --no-dev --classmap-authoritative

FROM php:8.5.12-apache
RUN pecl install apcu && docker-php-ext-enable apcu
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php.ini "$PHP_INI_DIR/conf.d/zz-ed25519.ini"
COPY docker/apache.conf /etc/apache2/conf-enabled/ed25519.conf
WORKDIR /var/www/app
COPY --from=vendor /app/vendor ./vendor
COPY --from=vendor /app/src ./src
COPY public ./public
RUN sed -i 's#/var/www/html#/var/www/app/public#' /etc/apache2/sites-available/000-default.conf \
    && sed -i 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
    && sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' /etc/apache2/sites-available/000-default.conf
USER www-data
EXPOSE 8080
