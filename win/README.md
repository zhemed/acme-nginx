# sshx - 本项目远程维护入口

`sshx.ps1` 是本项目（acme-nginx）的 Windows 端远程 shell 执行工具：通过标准 OpenSSH
把一条远程 bash 命令原样执行，避免 PowerShell 与 bash 之间的引号/转义冲突。

## 为什么这样设计

- 命令先在本地 UTF-8 编码为 base64，远程用 `printf %s <base64> | base64 -d | bash` 解码执行；
- base64 只含 `A-Za-z0-9+/=`，没有引号、`$`、空格，本地和远端都不会二次解释；
- 字节流与调用时传入的字符串完全一致，适合带引号和命令替换的复杂命令。

## 用法

```powershell
# 从任意目录调用（路径按实际位置写）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File D:\xx\acme-nginx\win\sshx.ps1 `
  -Target <user@host 或 SSH 配置别名> -Command '远程 bash 命令'

# 示例：查看服务器 acme-nginx 状态
... -Target my-server -Command 'acme-nginx status'

# 示例：一次性把私有仓库发布物装到服务器（服务器需已 gh auth login）
... -Target my-server -Command 'gh api repos/zhemed/acme-nginx/contents/acme-nginx.sh -H "Accept: application/vnd.github.raw" > /usr/local/bin/acme-nginx && chmod +x /usr/local/bin/acme-nginx'

# 示例：预演签发 / 正式签发 / 强制重签
... -Target my-server -Command 'acme-nginx issue'      # 先在 /etc/acme-nginx.conf 配好
... -Target my-server -Command 'acme-nginx renew'
... -Target my-server -Command 'acme-nginx force-renew'

# 自动化场景：预先编码，避免外层再解析引号
$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('echo "hi; there"'))
powershell -NoProfile -ExecutionPolicy Bypass -File D:\xx\acme-nginx\win\sshx.ps1 -Target my-server -Encoded $b
```

- `-Target` **必填**（`user@host` 或 SSH 配置别名）；仓库内不保存任何服务器地址。
- `-Command` 与 `-Encoded` 二选一；远程退出码会原样返回，调用方可立即失败。

## 安全策略（必须遵守）

- 每次远程操作都必须用 `-Target` 显式指定目标。
- 端口、密钥、跳板机、指纹一律放在用户自己的 SSH 配置与 `known_hosts`，**不进仓库**。
- 工具强制 `BatchMode=yes`（不弹密码）与 `StrictHostKeyChecking=yes`（未知/变化的主机密钥直接失败）。
- 每次调用只做一次远程变更，重试前先核对状态。
- 禁止绕过：不要绕过本工具直接用裸 `ssh` 执行维护命令，禁止用 `StrictHostKeyChecking=no` 凑合。

## 依赖

- Windows 自带 OpenSSH（`C:\Windows\System32\OpenSSH\ssh.exe`）。
- 目标服务器已配置好你的公钥（密钥认证）。

## 说明

- 名字沿用项目内部工具标签 `sshx`，与公网同名项目（WqyJh/sshx、ekzhang/sshx）无关。
