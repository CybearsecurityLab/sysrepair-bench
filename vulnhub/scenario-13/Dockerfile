FROM debian@sha256:c0a2ad73611131275b0e9a2e7544cfe3725f4268d4085d8c6f61fdd55aef7917
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && apt-get clean && rm -rf /var/lib/apt/lists/*
# Simulate outdated Drupal 8
RUN mkdir -p /var/www/html/core/lib/Drupal
RUN printf '<?php\nnamespace Drupal;\nclass Drupal {\n  const VERSION = '"'"'8.5.0'"'"';\n}\n?>' > /var/www/html/core/lib/Drupal.php
RUN printf '8.5.0' > /var/www/html/core/VERSION.txt
EXPOSE 80
CMD service mariadb start && apachectl -D FOREGROUND
