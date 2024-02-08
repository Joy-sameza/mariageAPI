FROM php:8.3.2-apache

# Install PDO and other dependencies
RUN docker-php-ext-install pdo pdo_mysql

# Copy application code
COPY . /var/www/html

# RUN composer install
# RUN php /tmp/composer-setup.php --install-dir= /usr/local/bin --filename= composer
# RUN composer --version

RUN ls -l /tmp

# Install Composer dependencies
# RUN /usr/bin/composer install --optimize

# # Copy database schema
# COPY config/schema.sql /docker-entrypoint-initdb.d/

# # Expose port 80
# EXPOSE 80

# # Start Apache
# CMD ["apache2-foreground"]