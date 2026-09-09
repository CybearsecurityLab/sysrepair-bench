# syntax=docker/dockerfile:1
# meta3-win-15-wamp-wordpress — WAMP (Apache + MariaDB + PHP) hosting WordPress 4.7.1 with weak admin creds
#
# Upstream Rapid7 metasploitable3 installs WampServer 3.0.6 + WordPress 4.7.1 via a NSIS
# silent installer that repeatedly hangs on Server Core. We replicate the vulnerable
# surface without WampServer itself by pulling pinned Apache Lounge + PHP 5.6 + MariaDB
# from Chocolatey, then dropping the same WordPress 4.7.1 tree with the weak
# admin:admin credentials Rapid7 ships.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Install VCRT 2015-2022 (required by PHP)
# Source URL: https://aka.ms/vs/17/release/vc_redist.x64.exe
COPY shared/downloads/vc_redist.x64.exe C:/vc.exe
# PowerShell's `Start-Process -Wait` tracks DESCENDANTS via a Job object, so it
# does not return while any process the installer spawned survives. The
# vc_redist bootstrapper exits while its children live, so -Wait blocked
# forever and the step burned a one-hour timeout without ever erroring. Wait on
# the process handle directly instead, exactly as scenario-16 does.
# The DLL assert is load-bearing: without the runtime, php.exe dies with
# STATUS_DLL_NOT_FOUND, WordPress is never seeded, and verify.ps1 then records
# the PoC as CLOSED because admin:admin cannot authenticate against a dead
# service. An unmodified vulnerable image would score a pass.
RUN $p = Start-Process -FilePath 'C:\vc.exe' -ArgumentList '/install','/quiet','/norestart' -PassThru ; \
    if (-not $p.WaitForExit(600000)) { throw 'vc.exe did not exit within 10 minutes' } ; \
    if ($p.ExitCode -notin @(0, 3010, 1638)) { throw ('vc_redist failed: exit ' + $p.ExitCode) } ; \
    if (-not (Test-Path 'C:\Windows\System32\vcruntime140.dll')) { throw 'vcruntime140.dll missing after vc_redist install' } ; \
    Remove-Item 'C:\vc.exe'

# IIS + CGI (replaces Apache — Apache Lounge downloads are blocked from containers)
RUN dism /online /enable-feature /all /NoRestart \
        /featurename:IIS-WebServerRole /featurename:IIS-WebServer \
        /featurename:IIS-CommonHttpFeatures /featurename:IIS-DefaultDocument \
        /featurename:IIS-StaticContent /featurename:IIS-CGI \
        /featurename:IIS-ISAPIExtensions /featurename:IIS-ISAPIFilter \
        /featurename:IIS-ManagementScriptingTools ; exit 0

# PHP 7.4.33 NTS (FastCGI for IIS)
# Source URL: https://windows.php.net/downloads/releases/archives/php-7.4.33-nts-Win32-vc15-x64.zip
COPY shared/downloads/php-7.4.33-nts-Win32-vc15-x64.zip C:/php.zip
RUN Expand-Archive 'C:\php.zip' -DestinationPath 'C:\php' -Force ; \
    Remove-Item 'C:\php.zip' ; \
    Copy-Item 'C:\php\php.ini-production' 'C:\php\php.ini' -Force ; \
    (Get-Content 'C:\php\php.ini') -replace ';extension=mysqli','extension=mysqli' -replace ';extension=mbstring','extension=mbstring' | Set-Content 'C:\php\php.ini'

# MariaDB 10.1.48 (zip distribution — no installer needed).
# Source URL: https://archive.mariadb.org/mariadb-10.1.48/winx64-packages/mariadb-10.1.48-winx64.zip
# Split into download+extract / configure+install so iterating on the service
# registration doesn't require re-COPYing the ~600MB archive into a fresh layer.
COPY shared/downloads/mariadb-10.1.48-winx64.zip C:/mariadb.zip
RUN Expand-Archive 'C:\mariadb.zip' -DestinationPath 'C:\' -Force ; \
    Rename-Item 'C:\mariadb-10.1.48-winx64' 'C:\mariadb' ; \
    Remove-Item 'C:\mariadb.zip'

RUN Set-Content 'C:\mariadb\my.ini' "[mysqld]`r`ndatadir=C:/mariadb/data`r`nbind-address=0.0.0.0`r`n`r`n[client]`r`nplugin-dir=C:/mariadb/lib/plugin`r`n" ; \
    & 'C:\mariadb\bin\mysqld.exe' --install mariadb ; \
    if ($LASTEXITCODE -ne 0) { throw "mysqld --install failed: $LASTEXITCODE" }

# Wire PHP into IIS via FastCGI and set document root
RUN Import-Module WebAdministration ; \
    New-WebHandler -Name 'PHP-FastCGI' -Path '*.php' -Verb '*' -Modules 'FastCgiModule' -ScriptProcessor 'C:\php\php-cgi.exe' -ResourceType File ; \
    Add-WebConfiguration -Filter '/system.webServer/fastCgi' -PSPath 'IIS:\' -Value @{fullPath='C:\php\php-cgi.exe'} ; \
    Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name physicalPath -Value 'C:\wamp\www\wordpress' ; \
    Add-WebConfiguration -Filter '/system.webServer/defaultDocument/files' -PSPath 'IIS:\' -AtIndex 0 -Value @{value='index.php'}

# WordPress 4.7.1 (matches upstream metasploitable3-windows)
# Source URL: https://wordpress.org/wordpress-4.7.1.zip
RUN New-Item -ItemType Directory -Path 'C:\wamp\www' -Force | Out-Null
COPY shared/downloads/wordpress-4.7.1.zip C:/wp.zip
RUN Expand-Archive -Path 'C:\wp.zip' -DestinationPath 'C:\wamp\www' -Force ; \
    Remove-Item 'C:\wp.zip'

COPY scenario-15-wamp-wordpress/wp-config.php C:/wamp/www/wordpress/wp-config.php
COPY scenario-15-wamp-wordpress/init-wordpress.sql C:/init-wordpress.sql
COPY scenario-15-wamp-wordpress/install-wordpress.php C:/install-wordpress.php

# Bootstrap: start MariaDB, seed the WordPress DB + grants, then run WordPress's
# own installer to populate the full schema with admin:admin (weak creds are
# intentional — this image is the vulnerable shape for the scenario).
RUN Start-Service mariadb ; \
    Start-Sleep -Seconds 8 ; \
    cmd /c 'C:\mariadb\bin\mysql.exe -u root < C:\init-wordpress.sql' ; \
    & 'C:\php\php.exe' 'C:\install-wordpress.php' ; \
    Stop-Service mariadb

EXPOSE 80 3306 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service mariadb; Start-Service W3SVC; while ($true) { Start-Sleep 60 }"]
