# TYPO3 13 (Composer, SQLite) for the end-to-end test of Draco in front of an app without a Draco plugin.
FROM php:8.3-apache
RUN apt-get update -qq && apt-get install -y -qq libicu-dev libzip-dev libpng-dev libjpeg-dev libfreetype6-dev unzip git >/dev/null \
 && docker-php-ext-configure gd --with-freetype --with-jpeg >/dev/null \
 && docker-php-ext-install -j4 intl zip gd opcache >/dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
RUN composer create-project -q --no-interaction typo3/cms-base-distribution:^13 /var/www/typo3 \
 && sed -i 's#/var/www/html#/var/www/typo3/public#' /etc/apache2/sites-available/000-default.conf \
 && a2enmod rewrite >/dev/null && chown -R www-data:www-data /var/www/typo3
