# acme-nginx 部署指南

本文档面向 Linux 服务器（Debian/Ubuntu/CentOS/Alpine），配合 Nginx 反向代理签发与续期 Let's Encrypt 证书。仓库为私有仓库，部署时请使用下面任一方式获取发布物。

## 前置条件

- 一台 Linux 服务器，有 root 权限（或可 sudo）。
- 已安装 Nginx（未安装时可在部署后自行安装：Debian/Ubuntu `apt install nginx`，CentOS `dnf install nginx`，Alpine `apk add nginx`）。
- 目标域名已解析到本服务器 IP。
- Cloudflare 账号：Account ID + API Token（Token 需要该域名所在 Zone 的 **Zone.Zone Read** 与 **Zone.DNS Edit** 权限）。
- 服务器能访问 GitHub（安装固定版本 acme.sh 时需要）。

## 一、获取并安装 acme-nginx

方式 A：从本机拷贝（仓库私有时的最简方式）

```bash
# 在 Windows 本机执行（PowerShell）
scp D:\xx\acme-nginx\acme-nginx.sh root@<服务器IP>:/usr/local/bin/acme-nginx
```

方式 B：服务器上用 GitHub CLI 拉取（服务器需先 `gh auth login`）

```bash
gh api repos/zhemed/acme-nginx/contents/acme-nginx.sh -H "Accept: application/vnd.github.raw" > /usr/local/bin/acme-nginx
chmod +x /usr/local/bin/acme-nginx
```

验证：

```bash
acme-nginx --version
```

## 二、安装 acme.sh 并生成配置模板

```bash
acme-nginx install
```

- 会安装固定版本 acme.sh（3.1.4，HTTPS 下载 + SHA-256 校验）到 `/etc/acme-nginx/acme`。
- 首次运行会生成配置模板 `/etc/acme-nginx.conf`（权限 600，仅 root 可读写）。

## 三、填写配置

```bash
vi /etc/acme-nginx.conf
```

```ini
CF_ACCOUNT_ID=0123456789abcdef0123456789abcdef
CF_TOKEN=你的CloudflareAPIToken
DOMAIN=example.com
WILDCARD=1        # 1 表示同时申请 *.example.com，0 只申请单域名
```

- `CF_ACCOUNT_ID`：Cloudflare 账号 ID，32 位十六进制。
- `CF_TOKEN`：Cloudflare API Token（Zone.DNS 编辑权限）。
- `DOMAIN`：主域名（必填）。
- `WILDCARD`：可选，默认 0。

## 四、首次签发

```bash
acme-nginx issue
```

签发成功后会：
- 以原子方式部署证书到 `/etc/acme-nginx/live`（generation 切换，失败自动回滚）。
- 生成稳定引用路径 `/etc/acme-nginx/fullchain.pem` 与 `/etc/acme-nginx/privkey.pem`。
- 安装 root crontab 自动续期任务（每天 03:17 / 09:17 / 15:17 / 21:17 检查）。
- 如果 Nginx 正在运行，会自动 reload 使新证书生效。

## 五、配置 Nginx

在对应 server 块中引用稳定路径：

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/acme-nginx/fullchain.pem;
    ssl_certificate_key /etc/acme-nginx/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

生效：

```bash
nginx -t && systemctl reload nginx        # systemd
# 或
nginx -t && rc-service nginx reload       # OpenRC (Alpine)
```

## 六、验证

```bash
acme-nginx status
```

应显示：证书有效、SAN 覆盖域名、公私钥匹配、自动续期正常、最近检查记录存在。

也可用浏览器访问 `https://example.com` 确认证书链正常。

## 七、日常维护

```bash
acme-nginx renew          # 手动续期检查（未到期不会重复签发）
acme-nginx force-renew    # 强制重签（注意 Let's Encrypt 频率限制）
acme-nginx status         # 查看证书与续期状态
acme-nginx uninstall      # 卸载（移除 cron、证书、状态与配置）
```

## 常见问题排查

| 现象 | 处理 |
| --- | --- |
| `issue` 报 DNS 验证失败 | 检查 Cloudflare Token 是否有 Zone.DNS Edit 权限；域名是否托管在对应账号 |
| `install` 报 acme.sh 下载失败 | 确认服务器可访问 GitHub，或临时设置代理后重试 |
| `status` 显示自动续期异常 | 检查 `systemctl status cron`（或 `rc-service crond status`）是否运行 |
| 证书已签发但 Nginx 未生效 | 手动 `nginx -t && systemctl reload nginx`，检查 server 块是否引用 `/etc/acme-nginx/fullchain.pem` |
| `force-renew` 后指纹未变化 | 可能是刚签过、触达频率限制，查看上方 acme.sh 输出 |

## 安全说明

- `/etc/acme-nginx.conf` 含 Cloudflare Token，权限必须为 600（工具会校验并拒绝非 600 的配置）。
- 证书与私钥文件权限均为 600，目录 700。
- 卸载时工具会移除配置与私钥，如仍需备份请先自行复制。
