#!/usr/bin/env bash
# 从 nginx/nginx.conf.template 生成一份 nginx.conf（替换 <domain>/<port> 占位符）。
# 生成物请按 DEPLOY.md「从模板生成 nginx 配置」一节的流程落地（先备份、再 nginx -t、最后 reload）。
set -Eeuo pipefail
export LC_ALL=C
umask 022

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT_DIR
readonly TEMPLATE="$ROOT_DIR/nginx/nginx.conf.template"

usage() {
  cat <<'USAGE'
用法: new-nginx-conf.sh --domain <域名> --port <端口> [--out <文件>] [--check] [--force]

  --domain  站点域名（如 example.com；泛域名写 *.example.com）
  --port    反代目标端口（本机回环端口，如 3000）
  --out     输出文件（缺省写到标准输出）
  --check   生成后执行 nginx -t -c <输出> 预校验（需已装 nginx；证书未就位时失败属预期）
  --force   --out 已存在时允许覆盖（默认拒绝）
  -h        显示本帮助

说明: 模板为单站点示范。新增站点请复制整个 server 块（80 跳转 + 443 ssl），
      并另给 <domain>/<port>；反代默认值已在 http 层共享，站点 location 只写 proxy_pass。
USAGE
}

domain=""; port=""; out=""; do_check=0; force=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:-}"; shift 2;;
    --port)   port="${2:-}";   shift 2;;
    --out)    out="${2:-}";    shift 2;;
    --check)  do_check=1; shift;;
    --force)  force=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2;;
  esac
done

[ -f "$TEMPLATE" ] || { echo "找不到模板: $TEMPLATE" >&2; exit 1; }
[ -n "$domain" ] || { echo "缺少 --domain" >&2; usage >&2; exit 2; }
[ -n "$port" ]   || { echo "缺少 --port" >&2;   usage >&2; exit 2; }
case "$domain" in *[[:space:]]*) echo "--domain 不得含空白" >&2; exit 2;; esac
case "$port" in ''|*[!0-9]*) echo "--port 必须是纯数字" >&2; exit 2;; esac
if [ -n "$out" ] && [ -e "$out" ] && [ "$force" -ne 1 ]; then
  echo "输出文件已存在（确需覆盖请加 --force）: $out" >&2; exit 3
fi

tmp=$(mktemp "${TMPDIR:-/tmp}/new-nginx-conf.XXXXXX")
trap 'rm -f "$tmp"' EXIT
sed -e "s/<domain>/$domain/g" -e "s/<port>/$port/g" "$TEMPLATE" > "$tmp"

if [ -n "$out" ]; then
  mkdir -p -- "$(dirname -- "$out")"
  install -m 0644 "$tmp" "$out"
  echo "已生成: $out"
else
  cat "$tmp"
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
