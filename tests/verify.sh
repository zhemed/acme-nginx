#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT_DIR
hook_candidate=

cleanup(){
  [[ -z $hook_candidate ]] || rm -f -- "$hook_candidate"
}
trap cleanup EXIT

fail(){
  printf 'verify: %s\n' "$1" >&2
  exit 1
}

bash "$ROOT_DIR/scripts/build.sh" --check
bash -n "$ROOT_DIR/acme-nginx.sh"
bash -n "$ROOT_DIR/scripts/build.sh"
bash -n "$ROOT_DIR/tests/unit.sh"
bash -n "$ROOT_DIR/tests/verify.sh"

[[ $(grep -Fxc 'ACME_VERSION="3.1.4"' "$ROOT_DIR/acme-nginx.sh" || true) -eq 1 ]] ||
  fail "acme.sh version is not pinned to 3.1.4"
[[ $(grep -Fxc 'ACME_ARCHIVE_SHA256="e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32"' "$ROOT_DIR/acme-nginx.sh" || true) -eq 1 ]] ||
  fail "acme.sh archive SHA-256 is not pinned"
grep -Fq -- "--proto '=https' --proto-redir '=https'" "$ROOT_DIR/acme-nginx.sh" ||
  fail "HTTPS-only download policy is missing"
grep -Fq -- 'https://codeload.github.com/acmesh-official/acme.sh/tar.gz/refs/tags/' \
  "$ROOT_DIR/acme-nginx.sh" || fail "verified acme.sh source archive download is missing"
if grep -Fq -- '--install-online' "$ROOT_DIR/acme-nginx.sh"; then
  fail "unverified acme.sh online installer remains"
fi
[[ $(grep -Fxc 'acme_nginx_version="v0.7.2"' "$ROOT_DIR/acme-nginx.sh" || true) -eq 1 ]] ||
  fail "script version is not 0.7.2"
[[ $(tr -d '\r\n' < "$ROOT_DIR/VERSION") == '0.7.2' ]] ||
  fail "VERSION file is not 0.7.2"
grep -Fq -- "当前版本：0.7.2" "$ROOT_DIR/README.md" ||
  fail "README project version is not 0.7.2"

for store_pattern in \
  'CERT_SOURCE=store' \
  'store_certificate_is_adoptable(){' \
  'adopt_store_certificate(){' \
  'store_publish(){' \
  'finalize_deployment(){' \
  'store_owner(){'; do
  grep -Fq -- "$store_pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "shared certificate store support is missing: $store_pattern"
done
for store_text in '/etc/cert-store' '共享证书库'; do
  grep -Fq -- "$store_text" "$ROOT_DIR/README.md" ||
    fail "README does not document the shared certificate store: $store_text"
done
for auto_pattern in \
  'default_cert_source(){' \
  'ensure_sb_restart_post_hook(){' \
  'systemctl restart sb'; do
  grep -Fq -- "$auto_pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "zero-touch integration is missing: $auto_pattern"
done
grep -Fq -- '/etc/cert-store' "$ROOT_DIR/scripts/new-nginx-conf.sh" ||
  fail "new-nginx-conf.sh does not auto-use shared certificate paths"
for owner_pattern in 'store_release_ownership(){' 'store_owner_present(){'; do
  grep -Fq -- "$owner_pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "dynamic ownership support is missing: $owner_pattern"
done
# v0.6.4：自动钩子按标记升级、store 锁内显式接管、owner 写回校验。
for takeover_pattern in \
  'post_reload_hook_is_managed(){' \
  'store_set_owner_locked(){' \
  'store_force_owner_none(){' \
  'reload_nginx_service(){' \
  'with_acme_lock issue_certificate 1' \
  '无法在共享证书库锁内交还续期责任' \
  'owner 未写回 acme-nginx' \
  'nginx 已 reload 并加载共享库中的新证书' \
  'store_read_meta(){' \
  'store_private_dir(){' \
  'store_private_file(){'; do
  grep -Fq -- "$takeover_pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "v0.6.4 store takeover support is missing: $takeover_pattern"
done
# 钩子升级判定不能再用 -F 与 -E 冲突的 grep 组合（GNU 报错、BusyBox 永不匹配）。
if grep -Fq -- 'grep -FqE' "$ROOT_DIR/acme-nginx.sh"; then
  fail "hook upgrade detection uses the invalid grep -FqE combination"
fi
# v0.6.5：hook 先发布 store 再 reload；发布/owner 判定在 store 锁内；runner 短暂持锁读 owner。
# shellcheck disable=SC2016
for ordering_pattern in \
  '# acme-nginx-reload-v5' \
  '# acme-nginx-renew-v7' \
  '共享证书库锁获取失败，跳过本次续期（无法确认续期负责人）' \
  'store_publish "$identity" || true' \
  '  if exec 8> "$store_root/.lock"; then' \
  '    if chmod 600 "$store_root/.lock" && flock -w 5 8; then' \
  'flock -u 8'; do
  grep -Fq -- "$ordering_pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "v0.6.5 ordering/locking support is missing: $ordering_pattern"
done
grep -Fq -- '签发前 double-check（B6）' "$ROOT_DIR/README.md" ||
  fail "README does not document the pre-issue owner double-check"
# shellcheck disable=SC2016
for claim_pattern in \
  'valid_store_root(){' \
  'store_root_is_current(){' \
  'store_claim_issuance(){' \
  'store_release_claim(){' \
  'STORE_CLAIM_PREVIOUS' \
  '拒绝重复签发（如需接管请运行 acme-nginx force-renew）' \
  'log_renewal_warning(){' \
  'write_skipped_state(){' \
  'command -v logger' \
  'arm_issue_claim_rollback(){' \
  'disarm_issue_claim_rollback(){' \
  'acm_claim_rollback_on_exit(){' \
  '共享证书库 meta 损坏，拒绝签发，请先修复' \
  'store_meta_is_valid(){' \
  'shared certificate store meta is corrupt; skip publish' \
  'shared certificate store already has a newer certificate; skip publishing older one' \
  '没有可用证书指纹时不能写 skipped' \
  'write_skipped_state "$current_fingerprint" || exit 1'; do
  grep -Fq -- "$claim_pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "v0.7.1 pre-issue claim/fail-closed support is missing: $claim_pattern"
done
grep -Fq -- 'own 模式' "$ROOT_DIR/README.md" ||
  fail "README does not document own-mode claim rejection"
# 负向门禁：reload hook 必须先发布共享库再 reload，否则 store 模式会加载上一代证书。
# 断言的是 reload 语句的“上一行”必须是发布语句（finalize_deployment 函数体内也有一处
# 相同文本，按第一个匹配取行号会得到假门禁）。
reload_line=$(grep -n '^if reload_nginx; then' "$ROOT_DIR/acme-nginx.sh" | head -n 1 | cut -d: -f1)
[[ -n $reload_line ]] || fail "reload hook reload sequence is missing"
((reload_line > 1)) || fail "reload hook publish line is missing"
publish_prev=$(sed -n "$((reload_line - 1))p" "$ROOT_DIR/acme-nginx.sh")
# shellcheck disable=SC2016  # literal generated hook text
[[ $publish_prev == 'store_publish "$identity" || true' ]] ||
  fail "reload hook must publish to the shared store immediately before reloading nginx"

# shellcheck disable=SC2016
for pattern in \
  'systemctl reload nginx' \
  'rc-service nginx reload' \
  'source_dir="$base/acme/stage"' \
  'switch_current "generations/${new_generation##*/}"' \
  'install_managed_link "$cert" '\''acme-live/current/fullchain.pem'\''' \
  'install_managed_link "$key" '\''acme-live/current/private.key'\''' \
  'ACMERELOAD' \
  'ACMERENEW' \
  '17 3,9,15,21 * * *' \
  'dns_huaweicloud_aksk' \
  'SDK-HMAC-SHA256'; do
  grep -Fq -- "$pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "missing generated behavior: $pattern"
done
# shellcheck disable=SC2016
for pattern in \
  'install)' \
  'issue)' \
  'renew)' \
  'force-renew)' \
  'status)' \
  'uninstall)' \
  '# acme-nginx-entrypoint'; do
  grep -Fq -- "$pattern" "$ROOT_DIR/acme-nginx.sh" ||
    fail "missing CLI surface: $pattern"
done
if grep -Fq -- 'HUAWEICLOUD_PASSWORD' "$ROOT_DIR/acme-nginx.sh"; then
  fail "legacy Huawei IAM credential key remains in the generated script"
fi
if grep -Fq -- 'readp' "$ROOT_DIR/acme-nginx.sh"; then
  fail "interactive panel prompt remains"
fi
if grep -Fq -- 'menu(){' "$ROOT_DIR/acme-nginx.sh"; then
  fail "interactive menu remains"
fi

for config_key in DNS_PROVIDER CF_ACCOUNT_ID CF_TOKEN HUAWEICLOUD_ACCESS_KEY_ID HUAWEICLOUD_SECRET_ACCESS_KEY HUAWEICLOUD_REGION STAGING DOMAIN WILDCARD; do
  grep -Fq -- "$config_key" "$ROOT_DIR/README.md" ||
    fail "README documents config key: $config_key"
done
grep -Fq -- '/etc/acme-nginx/fullchain.pem' "$ROOT_DIR/README.md" ||
  fail "README documents nginx certificate path"
grep -Fq -- '/etc/acme-nginx/privkey.pem' "$ROOT_DIR/README.md" ||
  fail "README documents nginx key path"
grep -Fq -- '/etc/acme-nginx.conf' "$ROOT_DIR/README.md" ||
  fail "README documents config path"

if command -v shellcheck >/dev/null 2>&1; then
  hook_candidate=$(mktemp "${TMPDIR:-/tmp}/acme-nginx-verify-hook.XXXXXX")
  awk '/<<'\''ACMERELOAD'\''/{inside=1; next} /^ACMERELOAD$/{inside=0} inside' \
    "$ROOT_DIR/acme-nginx.sh" > "$hook_candidate"
  [[ -s $hook_candidate ]] || fail "ACME reload hook extraction failed"
  shellcheck --shell=bash --severity=info "$ROOT_DIR/acme-nginx.sh"
  shellcheck --shell=bash --severity=info "$hook_candidate"
  shellcheck --shell=bash --severity=info \
    "$ROOT_DIR/scripts/build.sh" "$ROOT_DIR/scripts/new-nginx-conf.sh" \
    "$ROOT_DIR/tests/unit.sh" "$ROOT_DIR/tests/verify.sh"
else
  printf 'verify: shellcheck not found; static lint skipped\n' >&2
fi

for pattern in '--install' 'nginx-etc-backup-' 'sites-enabled' 'modules-enabled'; do
  grep -Fq -- "$pattern" "$ROOT_DIR/scripts/new-nginx-conf.sh" ||
    fail "new-nginx-conf.sh is missing the distro-leftover cleanup behavior: $pattern"
done
grep -Fq -- '--install' "$ROOT_DIR/DEPLOY.md" || fail "DEPLOY.md does not document --install"
grep -Fq -- '--install' "$ROOT_DIR/nginx/README.md" || fail "nginx/README.md does not document --install"

# --- 共享证书库：CLI 发布函数与 reload hook 发布函数的契约一致性 ---
store_main_body=$(awk '/^publish_own_certificate_to_store\(\)\{/{inside=1} inside{print} inside&&/^}/{exit}' "$ROOT_DIR/acme-nginx.sh")
store_main_body+=$'\n'$(awk '/^publish_own_certificate_to_store_locked\(\)\{/{inside=1} inside{print} inside&&/^}/{exit}' "$ROOT_DIR/acme-nginx.sh")
store_hook_body=$(awk '/^store_publish\(\)\{/{inside=1} inside{print} inside&&/^}/{exit}' "$ROOT_DIR/acme-nginx.sh")
[[ -n $store_main_body && -n $store_hook_body ]] ||
  fail "shared store publish implementations are missing"
store_main_fields=$(printf '%s\n' "$store_main_body" | grep -oE '"[a-z_]+=[^"]*"' | sed 's/^"//; s/=.*//' | sort -u)
store_hook_fields=$(printf '%s\n' "$store_hook_body" | grep -oE '"[a-z_]+=[^"]*"' | sed 's/^"//; s/=.*//' | sort -u)
[[ -n $store_main_fields && "$store_main_fields" == "$store_hook_fields" ]] ||
  fail "shared store meta field sets diverged between CLI and reload hook"
for marker in 'flock -w 30' 'mv -Tf' 'chmod 600' 'rm -rf'; do
  printf '%s\n' "$store_main_body" | grep -Fq -- "$marker" ||
    fail "CLI store publish lost: $marker"
  printf '%s\n' "$store_hook_body" | grep -Fq -- "$marker" ||
    fail "reload hook store publish lost: $marker"
done
grep -Fq 'sb) [[ -s /etc/sb/sb.json && -s /etc/sb/acme_server_name ]] ;;' "$ROOT_DIR/acme-nginx.sh" ||
  fail "sb owner liveness regressed to service state"
grep -Fq 'runner_config_uses_store(){' "$ROOT_DIR/acme-nginx.sh" ||
  fail "renew runner lost its store-mode check"

bash "$ROOT_DIR/tests/unit.sh"

digest=$(sha256sum "$ROOT_DIR/acme-nginx.sh" | awk '{print $1}')
printf 'verification passed: %s\n' "$digest"
