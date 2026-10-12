# Nginx 反代+HTTPS
proxy_pass http://127.0.0.1:8000；nginx -t 后 reload；certbot --nginx -d 域名.com 上HTTPS；certbot renew --dry-run 续期。
