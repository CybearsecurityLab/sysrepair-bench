# VNC Unencrypted Data Transmission

## Severity
**Medium** | CVSS 4.8

## CVE
N/A (configuration weakness)

## Description
The VNC (Virtual Network Computing) server is configured to accept connections without SSL/TLS encryption. VNC Security Type 1 (None) or Type 2 (VNC Authentication) transmit data in cleartext or with only a weak DES-based challenge-response for the password, while all subsequent session data (keystrokes, screen updates) travels unencrypted. An attacker on the network path can capture credentials and observe or inject input into the remote desktop session via passive sniffing or man-in-the-middle attacks.

## Affected Service
- **Service:** x11vnc (VNC server)
- **Port:** 5900/tcp
- **Protocol:** RFB (Remote Framebuffer)

## Vulnerable Configuration
The VNC server is started without any SSL/TLS wrapper:

```
x11vnc -display :0 -rfbport 5900 -rfbauth /root/.vnc/passwd -forever -shared
```

No `-ssl` or `-stunnel` flag is used, and the service is not tunneled through SSH. All RFB protocol traffic is transmitted in cleartext over the network.
