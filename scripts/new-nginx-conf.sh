#!/usr/bin/env bash
# 从 nginx/nginx.conf.template 生成一份 nginx.conf（替换 <domain>/<port> 占位符）。
#
# 两种落地方式：
#   1) 生成到文件/标准输出，按 DEPLOY.md 的「三段式」手工落地（先备份 → 预校验 → 替换 → reload）；
#   2) 加 --install 一键落地：生成 → 整目录备份 → 替换 → 清理**未被引用**的发行版默认残留
#      → nginx -t → reload。
#
# 为什么要有 (2)：新机 apt 装完 nginx，/etc/nginx 里会带一堆发行版默认文件
# （sites-enabled/、conf.d/、snippets/、fastcgi*、koi-* …）。本模板是自包含的
# （只 include mime.types），那些文件对运行**没有任何作用**，但每次部署都要手工删很烦。
# --install 把它们清掉，让 /etc/nginx 直接回到「nginx.conf + mime.types」的干净形态。
set -Eeuo pipefail
export LC_ALL=C
umask 022

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT_DIR
readonly TEMPLATE="$ROOT_DIR/nginx/nginx.conf.template"

# 发行版（Debian/Ubuntu 系）默认残留：本模板不引用，因此删除不影响运行时行为
readonly LEGACY_DIRS='sites-available sites-enabled snippets conf.d modules-available modules-enabled'
readonly LEGACY_FILES='fastcgi.conf fastcgi_params scgi_params uwsgi_params proxy_params koi-utf koi-win win-utf'
# 自检用：生成物（忽略注释行）一旦出现这些引用，说明并非自包含 → 拒绝落地与清理
readonly LEGACY_REFS='sites-enabled|sites-available|snippets|conf\.d|modules-enabled|fastcgi|scgi_params|uwsgi_params|proxy_params|koi-|win-utf'

usage() {
  cat <<'USAGE'
用法: new-nginx-conf.sh --domain <域名> --port <端口> [选项]

  --domain <域名>   站点域名（如 example.com；泛域名写 *.example.com）        [必填]
  --port <端口>     反代目标端口（本机回环端口，如 3000）                    [必填]
  --out <文件>      输出文件；缺省写到标准输出（--install 时缺省 <root>/etc/nginx/nginx.conf）
  --check           生成后执行 nginx -t -c <输出> 预校验（需已装 nginx）
  --force           --out 已存在时允许覆盖（默认拒绝）
  --install         一键落地：备份 → 替换 → 清理发行版默认残留 → nginx -t → reload
  --root <前缀>     根前缀（默认 /）；配合 --install 可在假根上演练，不碰真机
  --no-reload       --install 时只落地不 reload
  -h, --help        显示本帮助

说明: 模板为单站点示范。新增站点请复制整个 server 块（80 跳转 + 443 ssl），
      并另给 <domain>/<port>；反代默认值已在 http 层共享，站点 location 只写 proxy_pass。

示例:
  # 新机一键落地（含清理发行版默认残留）
  sudo scripts/new-nginx-conf.sh --domain example.com --port 3000 --install
  # 演练（不碰真机）
  scripts/new-nginx-conf.sh --domain example.com --port 3000 --install --root /tmp/fake-root
USAGE
}

die() {
  printf 'new-nginx-conf: %s\n' "$1" >&2
  exit "${2:-1}"
}

domain=""; port=""; out=""; do_check=0; force=0; do_install=0; root_arg="/"; do_reload=1
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:-}"; shift 2;;
    --port)   port="${2:-}";   shift 2;;
    --out)    out="${2:-}";    shift 2;;
    --check)  do_check=1; shift;;
    --force)  force=1; shift;;
    --install) do_install=1; shift;;
    --root)   root_arg="${2:-}"; shift 2;;
    --no-reload) do_reload=0; shift;;
    -h|--help) usage; exit 0;;
    *) die "未知参数: $1" 2;;
  esac
done

[ -f "$TEMPLATE" ] || die "找不到模板: $TEMPLATE" 1
[ -n "$domain" ] || { usage >&2; die "缺少 --domain" 2; }
[ -n "$port" ]   || { usage >&2; die "缺少 --port" 2; }
case "$domain" in *[[:space:]]*) die "--domain 不得含空白" 2;; esac
case "$port" in ''|*[!0-9]*) die "--port 必须是纯数字" 2;; esac

prefix="${root_arg%/}"                      # "/" → ""（真实根）；"/tmp/x/" → "/tmp/x"
[ -d "${prefix:-/}" ] || die "--root 前缀不存在: $root_arg" 2
if [ "$do_install" -eq 0 ] && [ -n "$out" ] && [ -e "$out" ] && [ "$force" -ne 1 ]; then
  die "输出文件已存在（确需覆盖请加 --force）: $out" 3
fi

tmp=$(mktemp "${TMPDIR:-/tmp}/new-nginx-conf.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
sed -e "s/<domain>/$domain/g" -e "s/<port>/$port/g" "$TEMPLATE" > "$tmp"

if [ "$do_install" -eq 0 ]; then
  if [ -n "$out" ]; then
    mkdir -p -- "$(dirname -- "$out")"
    install -m 0644 -- "$tmp" "$out"
    echo "已生成: $out"
  else
    cat -- "$tmp"
  fi
  if [ "$do_check" -eq 1 ]; then
    if command -v nginx >/dev/null 2>&1; then
      target=${out:-$tmp}
      if nginx -t -c "$target" >/dev/null 2>&1; then
        echo "预校验通过: $target"
      else
        echo "预校验未通过（常见原因：证书尚未签发/路径未就位）。先按 DEPLOY.md 签发证书再重试。" >&2
        nginx -t -c "$target" 2>&1 | tail -3 >&2
        exit 4
      fi
    else
      echo "未发现 nginx，跳过 --check 预校验" >&2
    fi
  fi
  exit 0
fi

# ---------------- 一键落地（--install） ----------------
etc_dir="$prefix/etc/nginx"
dest="${out:-$etc_dir/nginx.conf}"
backup_dir="$prefix/root"

[ -d "$etc_dir" ] || die "找不到 $etc_dir（确认已装 nginx，或用 --root 指定前缀）" 3
[ -f "$etc_dir/nginx.conf" ] || die "找不到 $etc_dir/nginx.conf" 3
if [ -n "$out" ] && [ -e "$out" ] && [ "$force" -ne 1 ]; then
  die "目标配置已存在（确需覆盖请加 --force）: $out" 3
fi

# 自检：确认生成物自包含（忽略注释行），否则拒绝清理 —— 避免误删仍被引用的文件
if grep -vE '^[[:space:]]*#' -- "$tmp" | grep -Eq "$LEGACY_REFS"; then
  die "生成物仍引用发行版默认路径，拒绝落地与清理（请检查模板是否自包含）" 5
fi

mkdir -p -- "$backup_dir"
stamp=$(date -u +%Y%m%d%H%M%S)
backup="$backup_dir/nginx-etc-backup-$stamp.tar.gz"
tar czf "$backup" -C "$prefix/etc" nginx
echo "已备份: $backup"

install -m 0644 -- "$tmp" "$dest"
echo "已落地: $dest"

removed=0
read -r -a legacy_dirs <<< "$LEGACY_DIRS"
read -r -a legacy_files <<< "$LEGACY_FILES"
for item in "${legacy_dirs[@]}"; do
  if [ -e "$etc_dir/$item" ]; then rm -rf -- "${etc_dir:?}/$item"; removed=$((removed + 1)); fi
done
for item in "${legacy_files[@]}"; do
  if [ -e "$etc_dir/$item" ]; then rm -f -- "$etc_dir/$item"; removed=$((removed + 1)); fi
done
echo "已清理发行版默认残留: $removed 项（新配置不引用它们，运行时行为不变）"
echo "顶层文件数: $(find "$etc_dir" -maxdepth 1 -type f | wc -l)（目标形态 2 = nginx.conf + mime.types）"

rollback="tar xzf $backup -C ${prefix}/etc && nginx -t && systemctl reload nginx"
if [ -z "$prefix" ]; then
  if command -v nginx >/dev/null 2>&1; then
    nginx -t || die "nginx -t 未通过；请回滚: $rollback" 6
    echo "nginx -t 通过"
    if [ "$do_reload" -eq 1 ]; then
      if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx; then
        systemctl reload nginx && echo "已 reload nginx（systemd）"
      elif command -v rc-service >/dev/null 2>&1; then
        rc-service nginx reload && echo "已 reload nginx（OpenRC）"
      else
        echo "未找到 nginx 服务管理器，请手工 reload" >&2
      fi
    fi
  else
    echo "未发现 nginx，跳过 nginx -t 与 reload" >&2
  fi
else
  echo "演练模式（--root $prefix）：跳过 nginx -t 与 reload" >&2
fi
echo "回滚: $rollback"
