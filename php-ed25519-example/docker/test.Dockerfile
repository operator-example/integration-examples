FROM php:8.5-cli
RUN pecl install apcu && docker-php-ext-enable apcu \
    && echo "apc.enable_cli=1" > /usr/local/etc/php/conf.d/apcu-cli.ini
CMD ["vendor/bin/phpunit"]
