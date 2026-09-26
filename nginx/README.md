# nginx 通用反代配置（acme-nginx 部署资产）

三份资产，用于任何"反代一个本机服务"的站点：**流式 SSE、大文件上传、WebSocket、不缓冲不缓存**。

| 文件 | 形态 | 覆盖范围 |
| --- | --- | --- |
| `site-template.conf` | 完整站点骨架（`<domain>` / `<port>` 占位） | `map` + 80→301 + 443/TLS + `location /` 与全部默认值 |
| `proxy-common-map.conf` | 单片段 | 仅那段 `map`（http 级） |
| `proxy-stream-common.conf` | 单片段 | 仅 `location` 内的默认值 |

## 路径一：站点模板（推荐，最小化服务器）

适合 `/etc/nginx` 只放必须文件、**不接受 `conf.d/` 与 `snippets/` 目录**的机器。

```bash
# 1. 取模板并替换占位符（<domain>、<port>）
sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' site-template.conf > /etc/nginx/example.com.conf

# 2. 在 nginx.conf 的 http 块内加一条 include
#    include /etc/nginx/example.com.conf;

# 3. 校验并生效
nginx -t && systemctl reload nginx
```

> 模板里的 `map` 必须留在**站点文件内**：`map` 只能位于 http 上下文，而站点文件正是被
> `nginx.conf` 以 `include` 引入 http 块；塞进 `server`/`location` 会直接报错。
> 占位符没替换就使用会导致 `nginx -t` 报错（有意如此，避免静默生效）。

**多站点**：每个站点文件**各自带一份**同名 `map` 是可行的 —— 实测 nginx 1.18 下 `nginx -t` 通过
（同名 `map` 重复定义不会报错，两个站点同时生效）。若不想重复，也可以按 nginx 惯用法把 `map`
提到 `nginx.conf` 的 http 块里只留一份，再删掉各站点文件里的那段。

## 路径二：全部内联进 `nginx.conf`（文件最少）

适合**站点数量少、要求 `/etc/nginx` 文件数最少**的机器：站点块直接住在 `nginx.conf` 的 `http {}` 里，
不要独立站点文件、也不要 include。最终 `/etc/nginx` 只剩两个文件 —— `nginx.conf` 与 `mime.types`。

```bash
# 1. 取模板并替换占位符（<domain>、<port>），得到一份完整站点内容
sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' site-template.conf

# 2. 把 map 之后的部分（两组 server 块）粘进 nginx.conf 的 http {} 内；
#    map 只保留一份（首个站点带来的那份），后续加站点不要再粘 map

# 3. 先预校验再落地（见下方"改 nginx.conf 的三段式"），然后
nginx -t && systemctl reload nginx
```

**代价（务必知道）**：`nginx.conf` 是**发行版管理的 conffile** ——
`dpkg-query -W -f='${Conffiles}' nginx-common` 里能看到它记录的原始 md5，你改过之后包升级就会走
conffile 流程（提示 / `--force-confold` / `--force-confnew`）。**若某次升级采用了发行版版本，
内联在里面的站点块会一起消失**：改前先备份，升级后核对站点是否还在。
（这个风险不是内联独有的：只要站点靠 `nginx.conf` 里的 include 加载，包版本一旦落地同样加载不到站点。）

## 路径三：片段 include（多站点复用）

适合允许 `conf.d/` 与 `snippets/` 目录、想多站点零重复的机器。

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

## 包含的默认值

- HTTP/1.1 上游 + WebSocket 升级透传（`Upgrade` / `Connection`，配合 `map`）
- SSE 流式：`proxy_buffering off`、`proxy_cache off`、`proxy_request_buffering off`
- 超时：`proxy_read_timeout 3600s`、`proxy_send_timeout 3600s`
- 上传上限：`client_max_body_size 100m`
- 转发头：Host / X-Real-IP / X-Forwarded-For / X-Forwarded-Proto

## 唯一真源与漂移比对

`site-template.conf` 的 `location` 段是 `proxy-stream-common.conf` 的**内联副本**（为了让模板在
不支持 include 目录的机器上也能一次成型）。**改任一份都要同步另一份**，然后用下面的比对确认：

```bash
norm() { grep -vE '^[[:space:]]*#' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' | grep -v '^$'; }

# A. 模板（按实际值渲染后）vs 线上站点文件 —— 顺序敏感，无输出 = 一致
diff <(sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' site-template.conf | norm) \
     <(norm < /etc/nginx/example.com.conf)

# B. 片段 vs 模板 location 段里的规则 —— 顺序不敏感（故两端各自 sort）
diff <(norm < proxy-stream-common.conf | sort) \
     <(sed -n '/location \//,/^    }/p' site-template.conf | norm | grep -E '^proxy_|^client_max_body_size' | grep -vE '^proxy_pass' | sort)
```

两条都无输出即为同步；有输出说明出现了漂移，按输出补齐。

**内联布局（路径二）下的比对**：没有独立站点文件，改成从 `nginx.conf` 里截出对应片段比对
（下面两条命令曾在真机上原样跑过，并跑过负例确认能报出差异）：

```bash
# C1. map 段：模板 vs nginx.conf（内联时 map 只有一份）
diff <(sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' site-template.conf | norm | sed -n '/^map /,/^}$/p') \
     <(norm < /etc/nginx/nginx.conf | sed -n '/^map /,/^}$/p')

# C2. 某个站点的两组 server 块：模板 vs nginx.conf 里该站点的块
#     （靠站点分隔注释定位；站点名与域名换成你自己的）
diff <(sed -e 's/<domain>/example.com/g' -e 's/<port>/8080/g' site-template.conf | norm | sed -n '/^server {/,$p') \
     <(sed -n '/# ===== 站点：example.com/,/# ===== 站点/p' /etc/nginx/nginx.conf | norm | sed -n '/^server {/,$p')
```

> **改 `nginx.conf` 的三段式**（尤其是内联布局，一处写错会让所有站点一起 reload 不成功）：
> ① 把候选配置写到 `/tmp`，用 `nginx -t -c /tmp/<候选>` **预校验**（线上配置零风险）；
> ② 安装后跑**真实 `nginx -t`**，失败立即用备份还原；③ 通过才 `reload`。
> **注意**：别写成 `if nginx -t | sed …; then` —— `if` 判的是管道最后一个命令的退出码，
> 会把失败当成功，进而继续执行 `reload` 这类危险动作。

> **为什么 B 忽略行序**：这些指令（`proxy_*`、`client_max_body_size`）彼此独立，行序不影响 nginx 行为
> —— 片段与模板目前就只差 `proxy_cache off;` 与 `proxy_request_buffering off;` 的先后。
> 语法与放置是否合法由 `nginx -t` 负责；A 保持顺序敏感，用来兜住"指令跑到别的 server 块"这类结构漂移。

