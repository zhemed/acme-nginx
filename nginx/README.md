# nginx 通用反代配置（acme-nginx 部署资产）

两份通用 nginx 片段，用于任何反代站点：流式 SSE、大文件上传、WebSocket、不缓冲不缓存。

## 文件与部署位置

| 文件 | 部署到 | 上下文 |
| --- | --- | --- |
| `proxy-common-map.conf` | `/etc/nginx/conf.d/proxy-common-map.conf` | http 级（map 必须在此） |
| `proxy-stream-common.conf` | `/etc/nginx/snippets/proxy-stream-common.conf` | server / location 级 |

## 使用方式

站点配置（例如 `/etc/nginx/conf.d/<站点>.conf`）：

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/acme-nginx/fullchain.pem;
    ssl_certificate_key /etc/acme-nginx/privkey.pem;

    location / {
        include snippets/proxy-stream-common.conf;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

生效：

```bash
nginx -t && systemctl reload nginx
```

## 包含的参数

- HTTP/1.1 上游 + WebSocket 升级透传（`Upgrade` / `Connection`）
- SSE 流式：`proxy_buffering off`、`proxy_cache off`、`proxy_request_buffering off`
- 超时：`proxy_read_timeout 3600s`、`proxy_send_timeout 3600s`
- 上传上限：`client_max_body_size 100m`
- 转发头：Host / X-Real-IP / X-Forwarded-For / X-Forwarded-Proto