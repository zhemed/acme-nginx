# acme-nginx

面向 **Nginx 反向代理** 的独立证书签发与管理工具（CLI，无交互面板）。它从 sb 项目中提取
证书模块，固定 acme.sh 版本并以 Cloudflare DNS-01 方式为域名签发 Let's Encrypt 证书，
签发/续期成功后自动 `reload nginx`，证书文件以原子方式切换，旧证书在切换失败时自动保留。

## 特性

- 固定 acme.sh `3.1.4`，下载来源仅 HTTPS 并核对项目内固定的 SHA-256。
- Cloudflare DNS-01 验证，支持单域名与 `*.example.com` 泛域名。
- 原子化证书部署：generation 指针 + symlink 切换，失败自动回滚。
- root crontab 自动续期（每天 03:17 / 09:17 / 15:17 / 21:17），续期成功自动 `reload nginx`。
- 无交互面板：全部通过子命令执行，适合脚本化与 cron。
- 证书/私钥校验：SAN、有效期、指纹、公私钥匹配全部校验后才切换。

## 使用

```bash
# 1. 安装固定版本 acme.sh 并生成配置模板
sudo acme-nginx install

# 2. 编辑 /etc/acme-nginx.conf，填入 Cloudflare 凭据与域名

# 3. 首次签发（签发后自动安装续期 cron 并 reload nginx）
sudo acme-nginx issue

# 4. 其他命令
sudo acme-nginx renew          # 续期检查（cron 内部使用，也可手动）
sudo acme-nginx force-renew    # 强制重签
sudo acme-nginx status         # 查看证书与续期状态
sudo acme-nginx uninstall      # 卸载（移除 cron、证书、状态与配置）
```

## 配置文件 `/etc/acme-nginx.conf`（root-only 0600）

```ini
CF_ACCOUNT_ID=0123456789abcdef0123456789abcdef
CF_TOKEN=你的CloudflareAPIToken
DOMAIN=example.com
WILDCARD=1        # 1 表示同时申请 *.example.com，0 只申请单域名
```

- `CF_ACCOUNT_ID`：Cloudflare 账号 ID，32 位十六进制。
- `CF_TOKEN`：Cloudflare API Token（需 Zone.DNS 编辑权限）。
- `DOMAIN`：主域名（必填）。
- `WILDCARD`：可选，默认 0。

## 固定路径

- 状态目录：`/etc/acme-nginx`（acme.sh home、`live/generations`、`identity`、`reload.sh`、`renew.sh`、`renew.state`）
- 证书文件（Nginx 引用这两个稳定路径，自动指向当前生效 generation）：
  - `/etc/acme-nginx/fullchain.pem`
  - `/etc/acme-nginx/privkey.pem`
- 续期后自动 reload：systemd 使用 `systemctl reload nginx`，OpenRC 使用 `rc-service nginx reload`。

## Nginx 配置示例

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

## 开发流程

正式发布物是根目录 `acme-nginx.sh`（由 `scripts/build.sh` 从 `src/` 拼接生成）。
只修改 `src/`，不要直接编辑生成物。

```bash
# 生成或更新正式发布物
bash scripts/build.sh

# 检查生成物是否与源码完全同步（不修改文件）
bash scripts/build.sh --check

# 构建、语法、ShellCheck（已安装时）与单测
bash tests/verify.sh
```

也可以使用 `make build`、`make check` 和 `make test`。

## 固定版本

- 当前版本：0.1.0
- acme.sh 固定为 `3.1.4`
- 上游下载仅 HTTPS，并在执行前核对项目内固定的 SHA-256
- 签发服务：Let's Encrypt（acme-v02）
