FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/www/html/wp-content/plugins/vulnerable-plugin && \
    echo "<?php /* Vulnerable plugin */ ?>" > /var/www/html/wp-content/plugins/vulnerable-plugin/index.php && \
    chmod -R 777 /var/www/html/wp-content/plugins
EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
