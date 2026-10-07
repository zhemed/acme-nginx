# nginx 通用反代配置（acme-nginx 部署资产）

四份资产，用于"反代一个本机服务"的站点：**流式 SSE、大文件上传、WebSocket、不缓冲不缓存**。

| 文件 | 形态 | 用途 |
| --- | --- | --- |
| `nginx.conf.template` | **整套 nginx.conf**（`<domain>` / `<port>` 占位） | 新机器首选：一次成型（全局 + http 层反代默认值 + 站点 + 兜底） |
| `site-template.conf` | 单个站点的两组 `server` 块（占位） | 给**已有**安装加站点 |
| `proxy-common-map.conf` | 单片段 | 只要那段 `map`（http 级） |
| `proxy-stream-common.conf` | 单片段 | 只要 `location` 内的默认值 |

## 路径一：整套 `nginx.conf` 模板（新机器首选）

一次把形态定死，**不用每台机器重新排查**：`/etc/nginx` 最终只有两个文件
（`nginx.conf` + `mime.types`，零多余目录），反代默认值在 http 层共享一次，末尾有 `default_server` 兜底。

### 一键落地（推荐，`--install`）

把「生成 → 整目录备份 → 替换 → **清理发行版默认残留** → `nginx -t` → reload」一次做完：

```bash
sudo scripts/new-nginx-conf.sh --domain example.com --port 8080 --install
```

- 会清掉发行版自带、而**新配置并未引用**的那批东西（新机 `apt install nginx` 之后的固定噪音）：
  目录 `sites-available/ sites-enabled/ snippets/ conf.d/ modules-available/ modules-enabled/`，
  文件 `fastcgi.conf fastcgi_params scgi_params uwsgi_params proxy_params koi-utf koi-win win-utf`。
  模板只 `include mime.types`，这些文件对运行**没有任何作用**，删掉只是让 `/etc/nginx` 回到干净的 2 文件形态。
- **安全闸门**：落地前先自检渲染结果 —— 只要它引用了上述任一路径，立即中止，一个文件都不改、也不产生备份。
- 备份 `/root/nginx-etc-backup-<UTC 时间戳>.tar.gz`；
  回滚 `tar xzf <备份> -C /etc && nginx -t && systemctl reload nginx`。
- **演练**（假根，完全不碰真机）：`scripts/new-nginx-conf.sh --domain example.com --port 8080 --install --root /tmp/fake-root`。
- 只想生成不落地：去掉 `--install`，按下面的手工三段式走。

### 手工三段式（不想用 `--install` 时）

```bash
# 1. 备份现有主配置
cp -a /etc/nginx/nginx.conf /root/nginx.conf.bak-$(date +%F-%H%M%S)

# 2. 渲染模板（替换 <domain> / <port>，<name> 只是注释里的站点名，可一并替换）
#    一台机器多个站点时：复制整组「站点」块再改 server_name 与 proxy_pass
sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' -e 's/<name>/app/g' nginx.conf.template > /tmp/nginx.conf.new

# 3. 三段式落地：先用 -c 预校验候选（线上配置零风险），再替换、真实校验、最后 reload
nginx -t -c /tmp/nginx.conf.new
install -m 644 /tmp/nginx.conf.new /etc/nginx/nginx.conf
nginx -t && systemctl reload nginx
```

**模板包含**：

- 全局：`user`（Debian/Ubuntu 为 `www-data`，其它发行版按需改）、`worker_processes auto`、`events`
- http 基础：`sendfile` / `tcp_nopush` / `types_hash_max_size`、**`server_tokens off`**
- TLS：`ssl_protocols TLSv1.2 TLSv1.3`（只留 1.2/1.3）、`ssl_prefer_server_ciphers on`
- 日志、`gzip on`（**不追加 `gzip_types`**：流式接口不宜压缩）
- **反代默认值 12 条**（WebSocket 升级、4 个转发头、三项 no-buffer/no-cache、两个 3600s 超时、100m 上传上限）
- `map $http_upgrade $connection_upgrade`（http 级，只一份）
- 一个站点：80→301 + 443/TLS + `location /`（**只有一行 `proxy_pass`**，其余继承 http 层）
- **兜底**：`default_server` + `return 444` —— 未匹配任何 `server_name` 的请求直接断开

> 把反代规则放在 **http 层共享**而不是每个 location 复写一遍，是为了加站点时"只写一行 proxy_pass"。
> 代价见模板里的警告注释：`proxy_set_header` **不合并、只继承** —— 某个 `server`/`location` 里只要
> 出现哪怕一条 `proxy_set_header`，上层那组就整体不再继承，要自定义就得把 6 条一并重写。

**代价（务必知道）**：`nginx.conf` 是**发行版管理的 conffile** ——
`dpkg-query -W -f='${Conffiles}' nginx-common` 里能看到它记录的原始 md5；你改过之后包升级就会走
conffile 流程（提示 / `--force-confold` / `--force-confnew`）。**若某次升级采用了发行版版本，
写在里面的站点会一起消失**：改前先备份，升级后核对站点是否还在。
（这个风险不是"内联"独有的：只要站点靠 `nginx.conf` 里的 include 加载，包版本一旦落地同样加载不到站点。）

## 路径二：给已有安装加一个站点

前提是 http 层已经有那套默认值与 `map`（即已按路径一建好）。把 `site-template.conf` 里的两组
`server` 块粘进 `nginx.conf` 的 `http {}` 内，改 `server_name` 与 `proxy_pass` 端口即可：

```bash
sed -e 's/<domain>/new.example.com/g' -e 's/<port>/9090/g' site-template.conf
# 粘进 nginx.conf 的 http {}（缩进与模板一致）→ nginx -t && systemctl reload nginx
```

**多站点**：每个站点文件/块**各自带一份**同名 `map` 也不报错（实测 nginx 1.18 下 `nginx -t` 通过），
但按模板的做法 **`map` 只在 http 层留一份**更干净。

## 路径三：片段 include（允许 conf.d / snippets 的机器）

| 文件 | 部署到 | 上下文 |
| --- | --- | --- |
| `proxy-common-map.conf` | `/etc/nginx/conf.d/proxy-common-map.conf` | http 级（map 必须在此） |
| `proxy-stream-common.conf` | `/etc/nginx/snippets/proxy-stream-common.conf` | server / location 级 |

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

## 唯一真源与漂移比对

同一套反代规则在本目录里有**两处**出现：`nginx.conf.template` 的「反代默认值」段（http 层共享，
路径一/二用）与 `proxy-stream-common.conf`（片段，路径三用）。**改一处就要同步另一处**，用下面的比对确认：

```bash
norm() { grep -vE '^[[:space:]]*#' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' | grep -v '^$'; }

# A. 整套模板（渲染后）vs 线上 /etc/nginx/nginx.conf —— 顺序敏感，无输出 = 一致
#    （线上恰好只有一个站点时可用；多站点请用 D）
diff <(sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' -e 's/<name>/app/g' nginx.conf.template | norm) \
     <(norm < /etc/nginx/nginx.conf)

# B. 模板 http 层的默认值 vs 片段 —— 顺序不敏感
#    注意：片段里保留着 proxy_cache off;（显式写法），模板刻意不写（它本就是默认值），故先把它滤掉
diff <(sed -n '/# ---- 反代默认值/,/# proxy_cache 默认/p' nginx.conf.template | norm | grep -E '^(proxy_|client_max_body_size)' | sort) \
     <(norm < proxy-stream-common.conf | grep -v '^proxy_cache off;' | sort)

# C. 模板里的站点块 vs site-template.conf —— 顺序敏感，无输出 = 两者同步
diff <(sed -n '/# ===== 站点：/,/# ---- 兜底/p' nginx.conf.template | norm | sed -n '/^server {/,$p') \
     <(norm < site-template.conf)

# D. 线上已有多个站点时：先把模板按该站点的实际值渲染到 /tmp，再与线上那一组比对
#    （awk 里的 app 换成线上该站点的注释名，例如 new-api）
sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' -e 's/<name>/app/g' nginx.conf.template > /tmp/nginx.conf.render
diff <(sed -n '/# ===== 站点：/,/# ---- 兜底/p' /tmp/nginx.conf.render | norm | sed -n '/^server {/,$p') \
     <(awk '/^# ===== 站点：/{f=($0 ~ /app/)} f' /etc/nginx/nginx.conf | norm | sed -n '/^server {/,$p')
```

> **为什么 B 忽略行序**：这些指令（`proxy_*`、`client_max_body_size`）彼此独立，行序不影响 nginx 行为。
> 语法与放置是否合法由 `nginx -t` 负责；A 与 C 保持顺序敏感，用来兜住"指令跑到别的 server 块"这类结构漂移。

## 改 `nginx.conf` 的三段式（务必照做）

1. **预校验**：候选写到 `/tmp`，`nginx -t -c /tmp/<候选>` —— 此时线上配置零风险；
2. **落地并复检**：替换真实文件后再跑**真实 `nginx -t`**，失败立即用备份还原；
3. **通过才 `reload`**。

> ⚠️ 别写成 `if nginx -t | sed …; then` —— `if` 判的是**管道最后一个命令**的退出码，会把失败当成功，
> 进而继续执行 `reload` 这类危险动作。要判就 `if out=$(nginx -t 2>&1); then`。
>
> ⚠️ `nginx -t` **不能证明"没丢东西"**：可选指令（`sendfile`、`access_log`、`gzip on`、`include mime.types`…）
> 被误删时配置照样合法、`nginx -t` 照样通过，只是悄悄走了默认值。改写配置要**比对生效行**
> （`nginx -T` 规范化后逐行 diff），并把差异与预期清单核对 —— 差异多于预期就是 bug。
>
> ⚠️ 探针/验证请求一律**带超时**，不要用大请求体做探针：在单核机器上足以把同机其它服务拖垮。
