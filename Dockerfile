FROM php:8.3.10-apache
# Install PDO and other dependencies
RUN docker-php-ext-install pdo pdo_mysql

# Copy application code
COPY . /var/www/html

# Copy database schema
COPY config/schema.sql /docker-entrypoint-initdb.d/

# Expose port 80
EXPOSE 80

# Start Apache
CMD ["apache2-foreground"]
