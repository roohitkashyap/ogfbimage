FROM php:8.2-cli

# Install GD dependencies
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

WORKDIR /app
COPY . /app/

# Create data directories
RUN mkdir -p /app/fb_data /app/fb_images && \
    chmod 777 /app/fb_data /app/fb_images

# PHP production settings
RUN echo "upload_max_filesize = 6M" >> /usr/local/etc/php/php.ini && \
    echo "post_max_size = 8M" >> /usr/local/etc/php/php.ini && \
    echo "display_errors = Off" >> /usr/local/etc/php/php.ini

EXPOSE ${PORT:-8080}

CMD php -S 0.0.0.0:${PORT:-8080} -t /app
