FROM php:8.3.2-apache

WORKDIR /var/www/html

COPY . .

RUN apt-get update && \
    apt-get install -y libpng-dev && \
    docker-php-ext-install pdo pdo_mysql gd

EXPOSE 80

CMD ["apache2-foreground"]