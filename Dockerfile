FROM php:8.2-apache

# Install GD dependencies and enable extensions
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg62-turbo-dev \
    libfreetype6-dev \
    libwebp-dev \
    libcurl4-openssl-dev \
    && docker-php-ext-configure gd \
        --with-freetype \
        --with-jpeg \
        --with-webp \
    && docker-php-ext-install -j$(nproc) gd curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set Apache to allow .htaccess
RUN sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

# PHP production settings
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" && \
    echo "upload_max_filesize = 6M" >> "$PHP_INI_DIR/php.ini" && \
    echo "post_max_size = 8M" >> "$PHP_INI_DIR/php.ini" && \
    echo "display_errors = Off" >> "$PHP_INI_DIR/php.ini"

# Copy project files
COPY . /var/www/html/

# Create data directories with proper permissions
RUN mkdir -p /var/www/html/fb_data /var/www/html/fb_images && \
    chown -R www-data:www-data /var/www/html/ && \
    chmod -R 755 /var/www/html/ && \
    chmod 777 /var/www/html/fb_data /var/www/html/fb_images

EXPOSE 80
