FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y apache2 libapache2-mod-php php && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Simulate Mr-Robot WordPress structure with 777 permissions (VULNERABLE)
RUN mkdir -p /var/www/html/wp-admin /var/www/html/wp-content/uploads && \
    echo "<html><body>Mr-Robot</body></html>" > /var/www/html/index.html && \
    echo "<?php // wp-login ?>" > /var/www/html/wp-login.php && \
    echo "dictionary" > /var/www/html/fsocity.dic && \
    chmod -R 777 /var/www/html


EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
