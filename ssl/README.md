# SSL/TLS Certificate Setup

This directory is mounted into the Nginx container at `/etc/nginx/ssl`.

## Required Files

- `server.crt` — TLS certificate (PEM format)
- `server.key` — TLS private key (PEM format)

## Quick Start with Self-Signed Certificate (Development)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost"
```

## Production with Let's Encrypt

1. Install certbot and obtain a certificate:

```bash
certbot certonly --standalone -d your-domain.com
```

2. Copy the certificates:

```bash
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./server.crt
cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./server.key
```

3. Set correct permissions:

```bash
chmod 600 server.key
chmod 644 server.crt
```

4. Add auto-renewal to cron:

```bash
0 3 * * * certbot renew --quiet && docker compose restart nginx
```

## Security Notes

- Private key (`server.key`) must have `600` permissions
- Never commit certificate files to version control
- The `.gitignore` should exclude `ssl/*.crt` and `ssl/*.key`
