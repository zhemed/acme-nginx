#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2030,SC2031,SC2034,SC2329  # literal generated text; subshell-owned vars/stubs
set -Eeuo pipefail

export LC_ALL=C

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
TEMP_DIR=$(mktemp -d)
readonly ROOT_DIR TEMP_DIR
trap 'rm -rf -- "$TEMP_DIR"' EXIT

if ! command -v flock >/dev/null 2>&1; then
  mkdir -p "$TEMP_DIR/test-bin"
  printf '%s\n' '#!/bin/bash' 'exit 0' > "$TEMP_DIR/test-bin/flock"
  chmod 700 "$TEMP_DIR/test-bin/flock"
  export PATH="$TEMP_DIR/test-bin:$PATH"
fi

passed=0

pass(){
  passed=$((passed + 1))
  printf 'ok %d - %s\n' "$passed" "$1"
}

fail(){
  printf 'not ok %d - %s\n' "$((passed + 1))" "$1" >&2
  exit 1
}

expect_success(){
  local name=$1
  shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}

expect_failure(){
  local name=$1
  shift
  if "$@"; then fail "$name"; else pass "$name"; fi
}

sanitize_location(){
  tr '\r\n\t' '   ' | sed 's/[[:cntrl:]]//g; s/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//' | cut -c1-160
}

valid_ipv4(){ return 1; }
valid_ipv6(){ return 1; }

# shellcheck source=/dev/null
source "$ROOT_DIR/src/10-acme.sh"
# shellcheck source=/dev/null
source "$ROOT_DIR/src/60-cron.sh"

STATE_DIR="$TEMP_DIR/state"
export STATE_DIR
export CONFIG_FILE="$STATE_DIR/acme-nginx.conf"
export ACME_HOME="$STATE_DIR/acme"
export ACME_BIN="$ACME_HOME/acme.sh"
export ACME_RELOAD="$STATE_DIR/reload.sh"
export ACME_IDENTITY="$STATE_DIR/identity"
export ACME_CERT="$STATE_DIR/fullchain.pem"
export ACME_KEY="$STATE_DIR/privkey.pem"
export ACME_STAGE="$ACME_HOME/stage"
export ACME_STAGE_CERT="$ACME_STAGE/fullchain.pem"
export ACME_STAGE_KEY="$ACME_STAGE/private.key"
export ACME_LIVE="$STATE_DIR/acme-live"
export ACME_GENERATIONS="$ACME_LIVE/generations"
export ACME_CURRENT="$ACME_LIVE/current"
export ACME_LOCK="$STATE_DIR/acme.lock"
export ACME_CRON_MARKER="# acme-nginx-managed"
export ACME_RELOAD_IDENTITY="# acme-nginx-reload-v5"
export CERT_SOURCE=own
export STORE_DIR=/etc/cert-store
export ACME_RENEW_IDENTITY="# acme-nginx-renew-v6"
export ACME_VERSION="3.1.4"
export ACME_ARCHIVE_SHA256="e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32"
export ACME_RENEW_RUNNER="$STATE_DIR/renew.sh"
export ACME_RENEW_STATE="$STATE_DIR/renew.state"
mkdir -p "$STATE_DIR" "$ACME_HOME"

valid_hostname(){
  local name=$1 label
  local -a labels
  [[ ${#name} -le 253 && $name == *.* && $name != .* && $name != *. ]] || return 1
  IFS='.' read -r -a labels <<< "$name"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}
# --- hostname ---
expect_success "hostname is valid" valid_hostname sub.example.com
expect_failure "single-label hostname is invalid" valid_hostname localhost
expect_failure "leading-hyphen label is invalid" valid_hostname -bad.example.com
expect_failure "trailing-hyphen label is invalid" valid_hostname bad-.example.com
expect_failure "empty domain label is invalid" valid_hostname bad..example.com

# --- Cloudflare account id ---
expect_success "Cloudflare Account ID is valid" \
  valid_cloudflare_account_id 0123456789ABCDEF0123456789abcdef
expect_failure "short Cloudflare Account ID is invalid" valid_cloudflare_account_id 01234567
expect_failure "31-character Account ID is invalid" \
  valid_cloudflare_account_id 0123456789abcdef0123456789abcde
expect_failure "non-hex Account ID is invalid" \
  valid_cloudflare_account_id 0123456789abcdef0123456789abcdeg

# --- domain normalization ---
normalize_acme_domain ' Example.COM. ' || fail "single-domain normalization"
[[ $ACME_PRIMARY_DOMAIN == example.com && -z $ACME_WILDCARD_DOMAIN ]] ||
  fail "single-domain normalization values"
pass "single-domain normalization"

normalize_acme_domain '*.Example.COM' || fail "wildcard normalization"
[[ $ACME_PRIMARY_DOMAIN == example.com && $ACME_WILDCARD_DOMAIN == '*.example.com' ]] ||
  fail "wildcard normalization values"
pass "wildcard normalization"
expect_failure "embedded wildcard is invalid" normalize_acme_domain 'api.*.example.com'
expect_failure "single-label ACME domain is invalid" normalize_acme_domain localhost

config_mode_is_private(){
  local mode
  mode=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null || true)
  case $(uname -s 2>/dev/null) in
    MINGW*|MSYS*) return 0 ;;
    *) [[ $mode == 600 ]] ;;
  esac
}

config_is_present(){
  [[ -f $CONFIG_FILE && ! -L $CONFIG_FILE ]] || return 1
  config_mode_is_private
}

write_config_template(){
  if [[ -e $CONFIG_FILE || -L $CONFIG_FILE ]]; then
    [[ -f $CONFIG_FILE && ! -L $CONFIG_FILE ]] || return 1
    return 0
  fi
  local tmp
  tmp=$(mktemp "$STATE_DIR/.acme-nginx.conf.XXXXXX") || return 1
  if ! {
    printf '%s\n' '# acme-nginx 配置文件'
    printf '%s\n' '# DNS 供应商：cloudflare 或 huaweicloud'
    printf '%s\n' 'DNS_PROVIDER=cloudflare'
    printf '%s\n' '# --- Cloudflare 凭据（DNS_PROVIDER=cloudflare 时必填）---'
    printf '%s\n' '# Account ID 为 32 位十六进制'
    printf '%s\n' 'CF_ACCOUNT_ID='
    printf '%s\n' 'CF_TOKEN='
    printf '%s\n' '# --- 华为云凭据（DNS_PROVIDER=huaweicloud 时必填，AK/SK 模式）---'
    printf '%s\n' '# AK/SK：控制台“我的凭证”→“访问密钥”中创建'
    printf '%s\n' 'HUAWEICLOUD_ACCESS_KEY_ID='
    printf '%s\n' 'HUAWEICLOUD_SECRET_ACCESS_KEY='
    printf '%s\n' '# 区域（必填），国内建议 cn-north-4，如 cn-north-4/ap-southeast-1'
    printf '%s\n' 'HUAWEICLOUD_REGION='
    printf '%s\n' '# 联调用 Let''s Encrypt 预演服务器：1 开启，生产保持 0'
    printf '%s\n' 'STAGING=0'
    printf '%s\n' '# 主域名（必填）'
    printf '%s\n' 'DOMAIN='
    printf '%s\n' '# 是否同时申请泛域名证书：1 表示同时签 *.DOMAIN'
    printf '%s\n' 'WILDCARD=0'
  } > "$tmp" || ! chmod 600 "$tmp" || ! mv -fT -- "$tmp" "$CONFIG_FILE"; then
    rm -f "$tmp"
    return 1
  fi
}

load_config(){
  local line key value
  local provider_count=0 account_count=0 token_count=0 domain_count=0 wildcard_count=0
  local hw_ak_count=0 hw_sk_count=0 hw_region_count=0 staging_count=0
  local provider='' account='' token='' domain='' wildcard=''
  local hw_ak='' hw_sk='' hw_region='' staging=''
  [[ -f $CONFIG_FILE && ! -L $CONFIG_FILE ]] || return 1
  config_mode_is_private || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -n $line ]] || continue
    [[ $line == \#* ]] && continue
    [[ $line == *=* ]] || return 1
    key=${line%%=*}
    value=${line#*=}
    [[ $value != *"'"* && $value != *$'\r'* ]] || return 1
    case $key in
      DNS_PROVIDER)
        provider_count=$((provider_count + 1))
        provider=$value
        ;;
      CF_ACCOUNT_ID)
        account_count=$((account_count + 1))
        account=$value
        ;;
      CF_TOKEN)
        token_count=$((token_count + 1))
        token=$value
        ;;
      HUAWEICLOUD_ACCESS_KEY_ID)
        hw_ak_count=$((hw_ak_count + 1))
        hw_ak=$value
        ;;
      HUAWEICLOUD_SECRET_ACCESS_KEY)
        hw_sk_count=$((hw_sk_count + 1))
        hw_sk=$value
        ;;
      HUAWEICLOUD_REGION)
        hw_region_count=$((hw_region_count + 1))
        hw_region=$value
        ;;
      STAGING)
        staging_count=$((staging_count + 1))
        staging=$value
        ;;
      DOMAIN)
        domain_count=$((domain_count + 1))
        domain=$value
        ;;
      WILDCARD)
        wildcard_count=$((wildcard_count + 1))
        wildcard=$value
        ;;
      *) return 1 ;;
    esac
  done < "$CONFIG_FILE"
  [[ $provider_count -le 1 && $account_count -le 1 && $token_count -le 1 &&
     $hw_ak_count -le 1 && $hw_sk_count -le 1 && $hw_region_count -le 1 &&
     $staging_count -le 1 && $domain_count -eq 1 && $wildcard_count -eq 1 ]] || return 1
  provider=${provider:-cloudflare}
  valid_dns_provider "$provider" || return 1
  [[ $wildcard == 0 || $wildcard == 1 ]] || return 1
  staging=${staging:-0}
  [[ $staging == 0 || $staging == 1 ]] || return 1
  normalize_acme_domain "$domain" || return 1
  DNS_PROVIDER=$provider
  CF_ACCOUNT_ID=
  CF_TOKEN=
  HUAWEICLOUD_ACCESS_KEY_ID=
  HUAWEICLOUD_SECRET_ACCESS_KEY=
  HUAWEICLOUD_REGION=
  STAGING=$staging
  if [[ $wildcard == 1 ]]; then
    ACME_WILDCARD_DOMAIN="*.$ACME_PRIMARY_DOMAIN"
  else
    ACME_WILDCARD_DOMAIN=
  fi
  case $provider in
    cloudflare)
      [[ $account_count -eq 1 && $token_count -eq 1 ]] || return 1
      valid_cloudflare_account_id "$account" || return 1
      [[ $token =~ ^[A-Za-z0-9_-]{10,200}$ ]] || return 1
      # shellcheck disable=SC2034
      CF_ACCOUNT_ID=$account
      # shellcheck disable=SC2034
      CF_TOKEN=$token
      ;;
    huaweicloud)
      [[ $hw_ak_count -eq 1 && $hw_sk_count -eq 1 && $hw_region_count -eq 1 ]] || return 1
      [[ -n $hw_ak && -n $hw_sk && -n $hw_region ]] || return 1
      [[ $hw_ak =~ ^[A-Za-z0-9_-]{16,64}$ ]] || return 1
      [[ $hw_sk =~ ^[A-Za-z0-9+/=_-]{16,128}$ ]] || return 1
      [[ $hw_region =~ ^[A-Za-z0-9_-]{2,32}$ ]] || return 1
      HUAWEICLOUD_ACCESS_KEY_ID=$hw_ak
      HUAWEICLOUD_SECRET_ACCESS_KEY=$hw_sk
      HUAWEICLOUD_REGION=$hw_region
      ;;
  esac
}

write_config_fixture(){
  local provider=${1:-cloudflare} wildcard=${2:-0}
  mkdir -p "$STATE_DIR"
  cat > "$CONFIG_FILE" <<EOF
DNS_PROVIDER=$provider
CF_ACCOUNT_ID=0123456789abcdef0123456789abcdef
CF_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
HUAWEICLOUD_ACCESS_KEY_ID=0123456789abcdef0123456789ABCDEF
HUAWEICLOUD_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+Ab/
HUAWEICLOUD_REGION=cn-north-4
STAGING=0
DOMAIN=example.com
WILDCARD=$wildcard
EOF
  chmod 600 "$CONFIG_FILE"
}

# --- config parsing ---
write_config_fixture cloudflare 0
expect_success "valid config is loaded" load_config
[[ $CF_ACCOUNT_ID == 0123456789abcdef0123456789abcdef &&
   $CF_TOKEN == AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 &&
   $DNS_PROVIDER == cloudflare &&
   $ACME_PRIMARY_DOMAIN == example.com && -z $ACME_WILDCARD_DOMAIN ]] ||
  fail "valid config values"
pass "valid config values"

write_config_fixture cloudflare 1
expect_success "wildcard config is loaded" load_config
[[ $ACME_WILDCARD_DOMAIN == '*.example.com' ]] || fail "wildcard config value"
pass "wildcard config value"

sed -i '/^DOMAIN=/d' "$CONFIG_FILE"
expect_failure "missing DOMAIN key is rejected" load_config
write_config_fixture cloudflare 0
printf '%s\n' 'DOMAIN=other.com' >> "$CONFIG_FILE"
expect_failure "duplicate DOMAIN key is rejected" load_config
write_config_fixture cloudflare 0
sed -i 's/CF_ACCOUNT_ID=0123456789abcdef0123456789abcdef/CF_ACCOUNT_ID=short/' "$CONFIG_FILE"
expect_failure "short Account ID is rejected" load_config
write_config_fixture cloudflare 0
sed -i 's/CF_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/CF_TOKEN=short/' "$CONFIG_FILE"
expect_failure "short Cloudflare token is rejected" load_config
write_config_fixture cloudflare 2
expect_failure "invalid WILDCARD value is rejected" load_config
write_config_fixture cloudflare 0
printf '%s\n' 'UNKNOWN_KEY=1' >> "$CONFIG_FILE"
expect_failure "unknown config key is rejected" load_config
write_config_fixture cloudflare 0
chmod 644 "$CONFIG_FILE"
case $(uname -s 2>/dev/null) in
  MINGW*|MSYS*) ;;
  *) expect_failure "world-readable config is rejected" load_config ;;
esac
# --- DNS provider validation ---
write_config_fixture cloudflare 0
expect_success "default provider is cloudflare" load_config
[[ $DNS_PROVIDER == cloudflare ]] || fail "default provider value"
pass "default provider value"

sed -i '/^DNS_PROVIDER=/d' "$CONFIG_FILE"
expect_success "legacy config without DNS_PROVIDER loads as cloudflare" load_config
[[ $DNS_PROVIDER == cloudflare ]] || fail "legacy provider value"
pass "legacy provider value"

write_config_fixture cloudflare 0
sed -i 's/^DNS_PROVIDER=cloudflare/DNS_PROVIDER=huawei/' "$CONFIG_FILE"
expect_failure "unknown DNS_PROVIDER is rejected" load_config
write_config_fixture cloudflare 0
printf '%s\n' 'DNS_PROVIDER=huaweicloud' >> "$CONFIG_FILE"
expect_failure "duplicate DNS_PROVIDER is rejected" load_config

write_config_fixture huaweicloud 0
expect_success "huaweicloud config is loaded" load_config
[[ $DNS_PROVIDER == huaweicloud &&
   $HUAWEICLOUD_ACCESS_KEY_ID == 0123456789abcdef0123456789ABCDEF &&
   $HUAWEICLOUD_SECRET_ACCESS_KEY == AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+Ab/ &&
   $HUAWEICLOUD_REGION == cn-north-4 &&
   $STAGING == 0 &&
   $ACME_PRIMARY_DOMAIN == example.com ]] || fail "huaweicloud config values"
pass "huaweicloud config values"

write_config_fixture huaweicloud 0
sed -i '/^HUAWEICLOUD_ACCESS_KEY_ID=/d' "$CONFIG_FILE"
expect_failure "huaweicloud missing access key is rejected" load_config
write_config_fixture huaweicloud 0
sed -i '/^HUAWEICLOUD_SECRET_ACCESS_KEY=/d' "$CONFIG_FILE"
expect_failure "huaweicloud missing secret key is rejected" load_config
write_config_fixture huaweicloud 0
sed -i 's/^HUAWEICLOUD_ACCESS_KEY_ID=0123456789abcdef0123456789ABCDEF/HUAWEICLOUD_ACCESS_KEY_ID=short/' "$CONFIG_FILE"
expect_failure "huaweicloud invalid access key is rejected" load_config
write_config_fixture huaweicloud 0
sed -i 's|^HUAWEICLOUD_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+Ab/|HUAWEICLOUD_SECRET_ACCESS_KEY=short|' "$CONFIG_FILE"
expect_failure "huaweicloud invalid secret key is rejected" load_config
write_config_fixture huaweicloud 0
sed -i '/^HUAWEICLOUD_REGION=/d' "$CONFIG_FILE"
expect_failure "huaweicloud missing region is rejected" load_config
write_config_fixture huaweicloud 0
sed -i 's/^HUAWEICLOUD_REGION=cn-north-4/HUAWEICLOUD_REGION=bad_region!/' "$CONFIG_FILE"
expect_failure "huaweicloud invalid region is rejected" load_config
write_config_fixture huaweicloud 0
printf '%s\n' 'HUAWEICLOUD_PASSWORD=legacy-secret' >> "$CONFIG_FILE"
expect_failure "legacy IAM key is rejected" load_config
write_config_fixture huaweicloud 0
sed -i 's/^STAGING=0/STAGING=2/' "$CONFIG_FILE"
expect_failure "invalid STAGING value is rejected" load_config
write_config_fixture huaweicloud 0
sed -i 's/^STAGING=0/STAGING=1/' "$CONFIG_FILE"
expect_success "STAGING=1 is accepted" load_config
[[ $STAGING == 1 ]] || fail "STAGING value"
pass "STAGING value"
write_config_fixture huaweicloud 0
sed -i '/^STAGING=/d' "$CONFIG_FILE"
expect_success "config without STAGING defaults to 0" load_config
[[ $STAGING == 0 ]] || fail "STAGING default"
pass "STAGING default"

expect_success "cloudflare provider is valid" valid_dns_provider cloudflare
expect_success "huaweicloud provider is valid" valid_dns_provider huaweicloud
expect_failure "unknown provider is invalid" valid_dns_provider huawei
expect_failure "empty provider is invalid" valid_dns_provider ''

export DNS_PROVIDER=cloudflare
# --- Cloudflare credentials in acme.sh account.conf ---
mkdir -p "$ACME_HOME"
cat > "$ACME_HOME/account.conf" <<'EOF'
SAVED_CF_Token='AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
SAVED_CF_Account_ID='0123456789abcdef0123456789abcdef'
EOF
expect_success "stored Cloudflare credentials are present" dns_provider_credentials_present
rm -f "$ACME_HOME/account.conf"
expect_failure "missing stored Cloudflare credentials are absent" dns_provider_credentials_present
printf '%s\n' "SAVED_CF_Token='bad'" > "$ACME_HOME/account.conf"
expect_failure "malformed stored Cloudflare credentials are rejected" dns_provider_credentials_present
rm -f "$ACME_HOME/account.conf"

# --- Huawei Cloud credentials in acme.sh account.conf ---
export DNS_PROVIDER=huaweicloud
cat > "$ACME_HOME/account.conf" <<'EOF'
SAVED_HUAWEICLOUD_ACCESS_KEY_ID='0123456789abcdef0123456789ABCDEF'
SAVED_HUAWEICLOUD_SECRET_ACCESS_KEY='AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+Ab/'
EOF
expect_success "stored Huawei Cloud AK/SK are present" dns_provider_credentials_present
rm -f "$ACME_HOME/account.conf"
expect_failure "missing stored Huawei Cloud AK/SK are absent" dns_provider_credentials_present
printf '%s\n' "SAVED_HUAWEICLOUD_ACCESS_KEY_ID='0123456789abcdef0123456789ABCDEF'" > "$ACME_HOME/account.conf"
expect_failure "incomplete stored Huawei Cloud AK/SK are rejected" dns_provider_credentials_present
rm -f "$ACME_HOME/account.conf"
export DNS_PROVIDER=cloudflare

# --- identity roundtrip ---
expect_success "identity is written" write_acme_identity example.com
[[ $(read_acme_identity) == example.com ]] || fail "identity readback"
pass "identity readback"
printf '%s\n' $'example.com\nextra.com' > "$ACME_IDENTITY"
expect_failure "multi-line identity is rejected" read_acme_identity

# --- reload hook ---
expect_success "reload hook is written" write_acme_reload_hook
expect_success "reload hook is current" acme_reload_hook_is_current
grep -Fq 'systemctl reload nginx' "$ACME_RELOAD" || fail "hook contains systemd nginx reload"
grep -Fq 'rc-service nginx reload' "$ACME_RELOAD" || fail "hook contains OpenRC nginx reload"
grep -Fq 'shellcheck disable=SC2317,SC2329' "$ACME_RELOAD" || fail "hook disables SC2329"
pass "hook nginx reload integration"
bash -n "$ACME_RELOAD" || fail "hook passes bash -n"
pass "hook passes bash -n"

# v0.7.0：reload hook 的 store_root 必须按配置嵌入，且配置变更后 hook 判定过期。
reload_hook_embeds_configured_store_root(){
  (
    local custom="$TEMP_DIR/custom-store-root"
    STORE_DIR="$custom"
    write_acme_reload_hook || return 1
    grep -Fqx "store_root=\"$custom\"" "$ACME_RELOAD" || return 1
    acme_reload_hook_is_current || return 1
    # 配置改回默认后旧 hook 必须判定过期，重写后恢复当前
    STORE_DIR=/etc/cert-store
    ! acme_reload_hook_is_current || return 1
    write_acme_reload_hook || return 1
    acme_reload_hook_is_current || return 1
    # 非法共享库根（相对路径/空白/..）必须拒绝生成 hook
    STORE_DIR='relative/path'
    ! write_acme_reload_hook || return 1
    STORE_DIR='/etc/cert store'
    ! write_acme_reload_hook || return 1
    STORE_DIR='/etc/cert-store/../escape'
    ! write_acme_reload_hook || return 1
    STORE_DIR=/etc/cert-store
    write_acme_reload_hook
  )
}
expect_success "reload hook embeds the configured shared store root" \
  reload_hook_embeds_configured_store_root
pass "custom store root is embedded, config changes invalidate the hook, invalid roots are rejected"

# --- managed live layout uses acme-live (matches generated deploy script) ---
case $(uname -s 2>/dev/null) in
  MINGW*|MSYS*)
    pass "managed live layout is valid (skipped on Windows)"
    ;;
  *)
    mkdir -p "$ACME_LIVE/generations"
    gen_dir=$(mktemp -d "$ACME_LIVE/generations/gen.XXXXXX")
    printf 'cert-placeholder' > "$gen_dir/fullchain.pem"
    printf 'key-placeholder' > "$gen_dir/private.key"
    ln -s "generations/${gen_dir##*/}" "$ACME_LIVE/current"
    ln -s 'acme-live/current/fullchain.pem' "$ACME_CERT"
    ln -s 'acme-live/current/private.key' "$ACME_KEY"
    expect_success "managed live layout is valid" managed_acme_live_layout_is_valid
    ;;
esac
printf '%s\n' '#!/bin/bash' > "$ACME_RELOAD"
chmod 700 "$ACME_RELOAD"
expect_failure "unversioned hook is stale" acme_reload_hook_is_current
rm -f "$ACME_RELOAD"
expect_failure "missing hook is stale" acme_reload_hook_is_current

# --- renew runner ---
expect_success "renew runner is written" write_acme_renew_runner
expect_success "renew runner is current" acme_renew_runner_is_current
expect_success "renew runner is idempotent" write_acme_renew_runner
grep -Fq "$ACME_RENEW_IDENTITY" "$ACME_RENEW_RUNNER" || fail "runner identity missing"
pass "runner identity present"
bash -n "$ACME_RENEW_RUNNER" || fail "runner passes bash -n"
pass "runner passes bash -n"

runner_skips_when_config_uses_store(){
  (
    local store="$TEMP_DIR/runner-store" marker="$TEMP_DIR/runner-called"
    printf '%s\n' 'example.com' > "$ACME_IDENTITY"
    rm -rf "$store"
    mkdir -p "$store/example.com"
    chmod 700 "$store" "$store/example.com"
    printf 'owner=sb\n' > "$store/example.com/meta.env"
    chmod 600 "$store/example.com/meta.env"
    printf 'CERT_SOURCE=store\n' > "$CONFIG_FILE"
    rm -f "$marker"
    printf '%s\n' '#!/bin/bash' ": > '$marker'" 'exit 0' > "$ACME_BIN"
    chmod 700 "$ACME_BIN"
    STORE_DIR="$store" write_acme_renew_runner || return 1
    "$ACME_RENEW_RUNNER" || return 1
    [[ ! -e $marker ]] || return 1
    load_acme_renew_state || return 1
    [[ $ACME_RENEW_LAST_RESULT == skipped ]]
  )
}
expect_success "ACME runner skips renewal only when CERT_SOURCE=store and the owner is another tool" \
  runner_skips_when_config_uses_store
pass "non-owner runner defers only in store mode"

runner_renews_own_cert_when_config_is_own(){
  (
    local store="$TEMP_DIR/runner-store-own" marker="$TEMP_DIR/runner-called-own"
    printf '%s\n' 'example.com' > "$ACME_IDENTITY"
    rm -rf "$store"
    mkdir -p "$store/example.com"
    chmod 700 "$store" "$store/example.com"
    printf 'owner=sb\n' > "$store/example.com/meta.env"
    chmod 600 "$store/example.com/meta.env"
    printf 'CERT_SOURCE=own\n' > "$CONFIG_FILE"
    rm -f "$marker"
    printf '%s\n' '#!/bin/bash' ": > '$marker'" 'exit 0' > "$ACME_BIN"
    chmod 700 "$ACME_BIN"
    STORE_DIR="$store" write_acme_renew_runner || return 1
    "$ACME_RENEW_RUNNER" || return 1
    [[ -e $marker ]] || return 1
    load_acme_renew_state || return 1
    [[ $ACME_RENEW_LAST_RESULT != skipped ]]
  )
}
expect_success "ACME runner renews its own certificate when the store owner is another tool but CERT_SOURCE=own" \
  runner_renews_own_cert_when_config_is_own
pass "own-mode renewal is not skipped because another tool owns the shared store"

runner_fails_closed_when_store_lock_is_unavailable(){
  (
    local store="$TEMP_DIR/runner-lock-fail-store" marker="$TEMP_DIR/runner-lock-fail-called"
    local fakebin="$TEMP_DIR/fake-logger-bin" logger_log="$TEMP_DIR/fake-logger.log"
    local output fingerprint
    printf '%s\n' 'example.com' > "$ACME_IDENTITY"
    printf '%s\n' 'cert-body-for-fingerprint' > "$ACME_CERT"
    rm -rf "$store" "$marker" "$fakebin" "$logger_log"
    mkdir -p "$store" "$fakebin" && chmod 700 "$store" "$fakebin" || return 1
    # 用目录占住锁文件位置，模拟锁获取失败（无法确认 owner 时必须跳过本次）。
    mkdir "$store/.lock" || return 1
    printf '%s\n' '#!/bin/bash' "printf '%s\n' \"\$*\" >> '$logger_log'" 'exit 0' > "$fakebin/logger"
    chmod 700 "$fakebin/logger"
    printf '%s\n' '#!/bin/bash' ": > '$marker'" 'exit 0' > "$ACME_BIN"
    chmod 700 "$ACME_BIN"
    printf '%s\n' \
      'last_check_epoch=1700000000' \
      'last_result=unchanged' \
      'last_exit_code=0' \
      'last_renewal_epoch=0' \
      "cert_fingerprint=$(printf 'a%.0s' {1..64})" > "$ACME_RENEW_STATE"
    chmod 600 "$ACME_RENEW_STATE"
    STORE_DIR="$store" write_acme_renew_runner || return 1
    output=$(PATH="$fakebin:$PATH" "$ACME_RENEW_RUNNER" 2>&1) || return 1
    [[ ! -e $marker ]] || return 1
    [[ $output == *'共享证书库锁获取失败'* ]] || return 1
    grep -Fq '共享证书库锁获取失败' "$logger_log" || return 1
    load_acme_renew_state || return 1
    fingerprint=$(sha256sum "$ACME_CERT" | awk '{print $1}')
    [[ $ACME_RENEW_LAST_RESULT == skipped &&
       $ACME_RENEW_LAST_EXIT_CODE -eq 0 &&
       $ACME_RENEW_LAST_RENEWAL_EPOCH -eq 0 &&
       $ACME_RENEW_FINGERPRINT == "$fingerprint" ]]
  )
}
expect_success "ACME runner fails closed when the shared store lock is unavailable" \
  runner_fails_closed_when_store_lock_is_unavailable
pass "store lock failure skips the run and warns instead of renewing blindly"
printf 'CERT_SOURCE=own\n' > "$CONFIG_FILE"
write_acme_renew_runner || fail "failed to restore the canonical renewal runner"

# --- cron entry ---
expected_cron=$(acme_renew_cron_entry)
expect_success "canonical ACME cron is current" acme_renew_cron_is_current "$expected_cron"
expect_success "user cron may coexist" acme_renew_cron_is_current \
  "15 2 * * * /root/user-task
$expected_cron"
expect_failure "marker-only ACME cron is stale" acme_renew_cron_is_current '# acme-nginx-managed'
expect_failure "wrong ACME command is stale" acme_renew_cron_is_current \
  '0 0 * * * false # acme-nginx-managed'
expect_failure "duplicate ACME cron is stale" acme_renew_cron_is_current \
  "$expected_cron
$expected_cron"

# --- lock ---
expect_success "ACME lock is acquired" acquire_acme_lock
expect_success "ACME lock is reentrant" acquire_acme_lock
expect_success "ACME lock is released" release_acme_lock
expect_success "ACME lock can be re-acquired" acquire_acme_lock
release_acme_lock >/dev/null 2>&1 || true

# --- renewal state ---
state_epoch=1700000000
write_state_fixture(){
  cat > "$ACME_RENEW_STATE" <<EOF
last_check_epoch=$state_epoch
last_result=unchanged
last_exit_code=0
last_renewal_epoch=0
cert_fingerprint=$(printf 'a%.0s' {1..64})
EOF
  chmod 600 "$ACME_RENEW_STATE"
}
write_state_fixture
expect_success "renewal state is parsed" load_acme_renew_state
[[ $ACME_RENEW_LAST_RESULT == unchanged && $ACME_RENEW_LAST_CHECK_EPOCH == "$state_epoch" ]] ||
  fail "renewal state values"
pass "renewal state values"
printf '%s\n' 'broken' > "$ACME_RENEW_STATE"
expect_failure "broken renewal state is rejected" load_acme_renew_state
write_state_fixture
sed -i 's/last_result=unchanged/last_result=failed/' "$ACME_RENEW_STATE"
expect_failure "failed renewal state without nonzero exit is rejected" load_acme_renew_state

# --- certificate metadata with a real self-signed certificate ---
CERT_DIR="$TEMP_DIR/cert"
mkdir -p "$CERT_DIR"
printf 'openssl: %s\n' "$(openssl version 2>/dev/null | head -1)"
(
  cd "$CERT_DIR" || exit 1
  openssl ecparam -genkey -name prime256v1 -out key.pem 2>/dev/null
  MSYS2_ARG_CONV_EXCL='*' openssl req -new -x509 -days 90 -key key.pem -out cert.pem \
    -subj '/CN=example.com' \
    -addext 'subjectAltName=DNS:example.com,DNS:www.example.com' 2>/dev/null
)
chmod 600 "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem"
if load_certificate_metadata "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"; then
  pass "certificate metadata is loaded"
else
  printf 'metadata load failed: state=%s dns=%s issuer=%s subject=%s fp=%s\n' \
    "${CERT_META_STATE-}" "${CERT_META_DNS_NAMES-}" "${CERT_META_ISSUER-}" \
    "${CERT_META_SUBJECT-}" "${CERT_META_FINGERPRINT-}" >&2
  fail "certificate metadata is loaded"
fi
[[ $CERT_META_STATE == valid ]] || fail "self-signed certificate state"
pass "self-signed certificate state"
[[ $CERT_META_DNS_NAMES == *example.com* ]] || fail "certificate SAN names"
pass "certificate SAN names"
expect_success "certificate identity matches" certificate_identity_matches \
  "$CERT_DIR/cert.pem" example.com
expect_failure "certificate identity mismatch is rejected" certificate_identity_matches \
  "$CERT_DIR/cert.pem" other.com
expect_success "certificate key matches" certificate_key_matches \
  "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"

# --- configured-domain coverage: guards issue/force-renew against SAN drift ---
WILD_CERT_DIR="$TEMP_DIR/cert-wild"
mkdir -p "$WILD_CERT_DIR"
(
  cd "$WILD_CERT_DIR" || exit 1
  openssl ecparam -genkey -name prime256v1 -out key.pem 2>/dev/null
  MSYS2_ARG_CONV_EXCL='*' openssl req -new -x509 -days 90 -key key.pem -out cert.pem \
    -subj '/CN=example.com' \
    -addext 'subjectAltName=DNS:example.com,DNS:*.example.com' 2>/dev/null
)
chmod 600 "$WILD_CERT_DIR/key.pem" "$WILD_CERT_DIR/cert.pem"

saved_primary_domain=${ACME_PRIMARY_DOMAIN-}
saved_wildcard_domain=${ACME_WILDCARD_DOMAIN-}
ACME_PRIMARY_DOMAIN=example.com
ACME_WILDCARD_DOMAIN=
expect_success "certificate covers single-domain config" certificate_covers_configured_domains \
  "$CERT_DIR/cert.pem"
ACME_PRIMARY_DOMAIN=other.com
expect_failure "certificate missing configured primary domain is rejected" \
  certificate_covers_configured_domains "$CERT_DIR/cert.pem"
ACME_PRIMARY_DOMAIN=example.com
ACME_WILDCARD_DOMAIN='*.example.com'
expect_failure "single-domain certificate does not satisfy wildcard config" \
  certificate_covers_configured_domains "$CERT_DIR/cert.pem"
expect_success "wildcard certificate satisfies wildcard config" \
  certificate_covers_configured_domains "$WILD_CERT_DIR/cert.pem"
ACME_WILDCARD_DOMAIN=
expect_success "wildcard certificate still satisfies single-domain config" \
  certificate_covers_configured_domains "$WILD_CERT_DIR/cert.pem"
ACME_PRIMARY_DOMAIN=
expect_failure "unconfigured primary domain is rejected" certificate_covers_configured_domains \
  "$CERT_DIR/cert.pem"
ACME_PRIMARY_DOMAIN=$saved_primary_domain
ACME_WILDCARD_DOMAIN=$saved_wildcard_domain

expect_success "exact domain list is covered" certificate_covers_domains \
  "$CERT_DIR/cert.pem" example.com www.example.com
expect_failure "missing domain in list is rejected" certificate_covers_domains \
  "$CERT_DIR/cert.pem" example.com api.example.com
expect_success "domain match is case-insensitive" certificate_covers_domains \
  "$CERT_DIR/cert.pem" EXAMPLE.com
expect_failure "non-certificate path is rejected" certificate_covers_domains \
  "$CERT_DIR/missing.pem" example.com

# --- ACME schedule accepts staging API in staging mode, production otherwise ---
SCHEDULE_DIR="$ACME_HOME/certs/cs.miio.cc_ecc"
mkdir -p "$SCHEDULE_DIR"
SCHEDULE_CONF="$SCHEDULE_DIR/cs.miio.cc.conf"
cat > "$SCHEDULE_CONF" <<'EOF'
Le_Domain='cs.miio.cc'
Le_API='https://acme-staging-v02.api.letsencrypt.org/directory'
Le_CertCreateTime='1720000000'
Le_NextRenewTime='1725000000'
Le_InstallCertSuccessTime='1720000100'
EOF
chmod 600 "$SCHEDULE_CONF"
STAGING=1
expect_success "staging schedule is accepted in staging mode" \
  load_acme_certificate_schedule cs.miio.cc
STAGING=0
expect_failure "staging schedule is rejected in production mode" \
  load_acme_certificate_schedule cs.miio.cc
sed -i 's#https://acme-staging-v02.api.letsencrypt.org/directory#https://acme-v02.api.letsencrypt.org/directory#' \
  "$SCHEDULE_CONF"
expect_success "production schedule is accepted in production mode" \
  load_acme_certificate_schedule cs.miio.cc
STAGING=1
expect_failure "production schedule is rejected in staging mode" \
  load_acme_certificate_schedule cs.miio.cc
STAGING=0

# --- Huawei Cloud AK/SK plugin ---
export DNS_PROVIDER=huaweicloud
mkdir -p "$ACME_HOME/dnsapi"
expect_success "huawei aksk plugin is written" write_huawei_aksk_plugin
expect_success "huawei aksk plugin is current" huawei_aksk_plugin_ok
bash -n "$ACME_HOME/dnsapi/dns_huaweicloud_aksk.sh" || fail "plugin passes bash -n"
pass "plugin passes bash -n"

# --- install_official_acme restores missing huawei plugin (v0.3.0 fix) ---
cat > "$ACME_BIN" <<'EOF'
#!/bin/bash
[[ ${1:-} == --version ]] && echo "v3.1.4"
exit 0
EOF
chmod 700 "$ACME_BIN"
rm -f "$ACME_HOME/dnsapi/dns_huaweicloud_aksk.sh"
expect_success "install_official_acme restores missing huawei plugin" install_official_acme
expect_success "huawei plugin is current after restore" huawei_aksk_plugin_ok

_err(){ :; }
_readaccountconf_mutable(){ :; }
_saveaccountconf_mutable(){ :; }
# shellcheck source=/dev/null
source "$ACME_HOME/dnsapi/dns_huaweicloud_aksk.sh"
export HUAWEICLOUD_ACCESS_KEY_ID="0123456789abcdef0123456789ABCDEF"
export HUAWEICLOUD_SECRET_ACCESS_KEY="AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+Ab/"
export HUAWEICLOUD_REGION="cn-north-4"

sdk_date=20240101T000000Z
headers="content-type:application/json
host:dns.cn-north-4.myhuaweicloud.com
x-sdk-date:$sdk_date
"
signed_headers="content-type;host;x-sdk-date"
canonical="GET
/v2/zones/
type=public&name=example.com
$headers
$signed_headers
$(printf '' | openssl dgst -sha256 -hex | sed 's/^.*= //')"
string2sign="SDK-HMAC-SHA256
$sdk_date
$(printf '%s' "$canonical" | openssl dgst -sha256 -hex | sed 's/^.*= //')"
expected_signature=$(printf '%s' "$string2sign" | openssl dgst -sha256 -hmac "$HUAWEICLOUD_SECRET_ACCESS_KEY" -binary | od -An -tx1 | tr -d ' \n')
actual=$(HUAWEICLOUD_ACCESS_KEY_ID="$HUAWEICLOUD_ACCESS_KEY_ID" HUAWEICLOUD_SECRET_ACCESS_KEY="$HUAWEICLOUD_SECRET_ACCESS_KEY" \
  _hwak_sign GET "/v2/zones" "type=public&name=example.com" "$headers" "$signed_headers" "" "$sdk_date")
expected="SDK-HMAC-SHA256 Access=$HUAWEICLOUD_ACCESS_KEY_ID, SignedHeaders=$signed_headers, Signature=$expected_signature"
[[ $actual == "$expected" ]] || fail "AK/SK signing vector"
pass "AK/SK signing vector"

headers_no_nl=$(printf 'content-type:application/json\nhost:dns.cn-north-4.myhuaweicloud.com\nx-sdk-date:%s' "$sdk_date")
actual2=$(HUAWEICLOUD_ACCESS_KEY_ID="$HUAWEICLOUD_ACCESS_KEY_ID" HUAWEICLOUD_SECRET_ACCESS_KEY="$HUAWEICLOUD_SECRET_ACCESS_KEY" \
  _hwak_sign GET "/v2/zones" "type=public&name=example.com" "$headers_no_nl" "$signed_headers" "" "$sdk_date")
[[ $actual2 == "$expected" ]] || fail "AK/SK signing vector without trailing header newline"
pass "AK/SK signing vector without trailing header newline"

expect_success "canonical query is produced" _hwak_canonical_query 'type=public&name=example.com'
[[ $(_hwak_canonical_query 'type=public&name=example.com') == 'name=example.com&type=public' ]] ||
  fail "canonical query order"
pass "canonical query order"
pass "AK/SK signing vector"

headers_no_nl=$(printf 'content-type:application/json\nhost:dns.cn-north-4.myhuaweicloud.com\nx-sdk-date:%s' "$sdk_date")
actual2=$(HUAWEICLOUD_ACCESS_KEY_ID="$HUAWEICLOUD_ACCESS_KEY_ID" HUAWEICLOUD_SECRET_ACCESS_KEY="$HUAWEICLOUD_SECRET_ACCESS_KEY" \
  _hwak_sign GET "/v2/zones" "type=public&name=example.com" "$headers_no_nl" "$signed_headers" "" "$sdk_date")
[[ $actual2 == "$expected" ]] || fail "AK/SK signing vector without trailing header newline"
pass "AK/SK signing vector without trailing header newline"

HW_ZONE_JSON='{"zones":[{"id":"zone-1","name":"example.com."}]}'
HW_RS_JSON='{"recordsets":[]}'
curl(){
  local out='' url='' method=GET body=''
  while [ $# -gt 0 ]; do
    case "$1" in
      -o) out=$2; shift 2 ;;
      -w) shift 2 ;;
      -X) method=$2; shift 2 ;;
      --data) body=$2; shift 2 ;;
      *) url=$1; shift ;;
    esac
  done
  printf 'CURL %s %s BODY=[%s]\n' "$method" "$url" "$body" >> "$TEMP_DIR/curl.log"
  case "$url" in
    *"/v2/zones?"*) printf '%s' "$HW_ZONE_JSON" > "$out" ;;
    *"/v2/recordsets?"*) printf '%s' "$HW_RS_JSON" > "$out" ;;
    *) printf '%s' '{"id":"rs-new"}' > "$out" ;;
  esac
  printf '200'
}
: > "$TEMP_DIR/curl.log"
expect_success "aksk add creates a TXT record" dns_huaweicloud_aksk_add _acme-challenge.example.com abc123
grep -Fq 'CURL GET https://dns.cn-north-4.myhuaweicloud.com/v2/zones?name=example.com&type=public' "$TEMP_DIR/curl.log" ||
  fail "zone lookup URL"
grep -Fq 'CURL POST https://dns.cn-north-4.myhuaweicloud.com/v2/zones/zone-1/recordsets' "$TEMP_DIR/curl.log" ||
  fail "recordset create URL"
grep -Fq 'BODY=[{"name":"_acme-challenge.example.com.","type":"TXT","ttl":300,"records":["\"abc123\""]}]' "$TEMP_DIR/curl.log" ||
  fail "recordset create body"
pass "aksk add flow"

HW_RS_JSON='{"recordsets":[{"id":"rs-1","name":"_acme-challenge.example.com.","type":"TXT","records":["\"old\""]}]}'
: > "$TEMP_DIR/curl.log"
expect_success "aksk add appends to existing recordset" dns_huaweicloud_aksk_add _acme-challenge.example.com abc123
grep -Fq 'CURL PUT https://dns.cn-north-4.myhuaweicloud.com/v2/zones/zone-1/recordsets/rs-1' "$TEMP_DIR/curl.log" ||
  fail "recordset update URL"
pass "aksk append flow"

HW_RS_JSON='{"recordsets":[{"id":"rs-1","name":"_acme-challenge.example.com.","type":"TXT","records":["\"abc123\""]}]}'
: > "$TEMP_DIR/curl.log"
expect_success "aksk rm deletes the recordset" dns_huaweicloud_aksk_rm _acme-challenge.example.com abc123
grep -Fq 'CURL DELETE https://dns.cn-north-4.myhuaweicloud.com/v2/zones/zone-1/recordsets/rs-1' "$TEMP_DIR/curl.log" ||
  fail "recordset delete URL"
pass "aksk rm flow"

HW_RS_JSON='{"recordsets":[{"id":"rs-1","name":"_acme-challenge.example.com.","type":"TXT","records":["\"abc123\"","\"keep\""]}]}'
: > "$TEMP_DIR/curl.log"
expect_success "aksk rm keeps other records" dns_huaweicloud_aksk_rm _acme-challenge.example.com abc123
grep -Fq 'CURL PUT https://dns.cn-north-4.myhuaweicloud.com/v2/zones/zone-1/recordsets/rs-1' "$TEMP_DIR/curl.log" ||
  fail "recordset update on rm URL"
pass "aksk rm keeps others"

export DNS_PROVIDER=cloudflare
unset HW_ZONE_JSON HW_RS_JSON
# --- source modules have formal markers ---
for module in "$ROOT_DIR"/src/*.sh; do
  [[ $(grep -Fc -- '# acme-nginx-module:' "$module" || true) -eq 1 ]] ||
    fail "module marker missing in ${module##*/}"
done
pass "source module markers present"

# --- scripts/new-nginx-conf.sh：--install 一键落地（假根演练，不碰真机） ---
fake_root="$TEMP_DIR/nginx-install-root"
mkdir -p "$fake_root/etc/nginx"/{sites-enabled,sites-available,snippets,conf.d,modules-available,modules-enabled} "$fake_root/root"
printf '%s\n' 'user www-data;' > "$fake_root/etc/nginx/nginx.conf"
printf '%s\n' 'mime' > "$fake_root/etc/nginx/mime.types"
for legacy in fastcgi.conf fastcgi_params scgi_params uwsgi_params proxy_params koi-utf koi-win win-utf; do
  printf '%s\n' 'x' > "$fake_root/etc/nginx/$legacy"
done
printf '%s\n' 'x' > "$fake_root/etc/nginx/sites-enabled/default"
printf '%s\n' 'x' > "$fake_root/etc/nginx/snippets/fastcgi-php.conf"
printf '%s\n' 'x' > "$fake_root/etc/nginx/modules-enabled/50-module.conf"
[[ $(find "$fake_root/etc/nginx" -maxdepth 1 -type f | wc -l) -eq 10 ]] || fail "fake root fixture"

expect_success "install renders and tidies distro leftovers in a fake root" \
  bash "$ROOT_DIR/scripts/new-nginx-conf.sh" --domain example.com --port 8080 --install --root "$fake_root"

grep -Fq 'server_name example.com;' "$fake_root/etc/nginx/nginx.conf" || fail "rendered server_name"
grep -Fq 'proxy_pass http://127.0.0.1:8080;' "$fake_root/etc/nginx/nginx.conf" || fail "rendered proxy_pass"
[[ $(find "$fake_root/etc/nginx" -maxdepth 1 -type f | wc -l) -eq 2 ]] || fail "top-level files after install is not 2"
[[ -f "$fake_root/etc/nginx/mime.types" ]] || fail "mime.types must be kept"
for legacy in sites-enabled sites-available snippets conf.d modules-available modules-enabled; do
  [[ ! -e "$fake_root/etc/nginx/$legacy" ]] || fail "legacy dir remains: $legacy"
done
for legacy in fastcgi.conf fastcgi_params scgi_params uwsgi_params proxy_params koi-utf koi-win win-utf; do
  [[ ! -e "$fake_root/etc/nginx/$legacy" ]] || fail "legacy file remains: $legacy"
done
compgen -G "$fake_root/root/nginx-etc-backup-*.tar.gz" >/dev/null || fail "backup tarball missing"
pass "install tidy result"

expect_success "install is idempotent" \
  bash "$ROOT_DIR/scripts/new-nginx-conf.sh" --domain example.com --port 8080 --install --root "$fake_root"
[[ $(find "$fake_root/etc/nginx" -maxdepth 1 -type f | wc -l) -eq 2 ]] || fail "idempotent run changed the file count"
pass "install idempotence"

# 自检闸门：渲染结果一旦引用发行版路径，必须在改动任何文件之前中止（不改配置、不留备份）
guard_repo="$TEMP_DIR/nginx-guard-repo"
mkdir -p "$guard_repo/scripts" "$guard_repo/nginx" "$guard_repo/etc/nginx"
cp "$ROOT_DIR/scripts/new-nginx-conf.sh" "$guard_repo/scripts/"
cp "$ROOT_DIR/nginx/nginx.conf.template" "$guard_repo/nginx/"
printf '%s\n' 'include /etc/nginx/sites-enabled/*;' >> "$guard_repo/nginx/nginx.conf.template"
printf '%s\n' 'PRESERVE-ME' > "$guard_repo/etc/nginx/nginx.conf"
expect_failure "install aborts when the rendered conf references distro paths" \
  bash "$guard_repo/scripts/new-nginx-conf.sh" --domain example.com --port 8080 --install --root "$guard_repo"
grep -Fq 'PRESERVE-ME' "$guard_repo/etc/nginx/nginx.conf" || fail "guarded abort must leave the existing conf untouched"
if compgen -G "$guard_repo/root/nginx-etc-backup-*.tar.gz" >/dev/null; then
  fail "guarded abort must not create a backup"
fi
pass "install self-check guard"

# --- shared certificate store (v0.4.0) ---
write_config_fixture cloudflare 0
expect_success "config defaults to own certificate source" load_config
[[ $CERT_SOURCE == own && $STORE_DIR == /etc/cert-store ]] || fail "store defaults"
pass "config defaults to own source and /etc/cert-store"
CERT_SOURCE=store
STORE_DIR="$TEMP_DIR/store-config-check"
[[ $(store_root) == "$STORE_DIR" ]] || fail "store root value"
pass "store root honours STORE_DIR"
CERT_SOURCE=own
STORE_DIR=/etc/cert-store

store_dir="$TEMP_DIR/shared-cert-store"
rm -rf "$store_dir"
mkdir -p "$store_dir/example.com/generations/gen.TEST1"
chmod 700 "$store_dir" "$store_dir/example.com" \
  "$store_dir/example.com/generations" "$store_dir/example.com/generations/gen.TEST1"
cp -p "$CERT_DIR/cert.pem" "$store_dir/example.com/generations/gen.TEST1/fullchain.pem"
cp -p "$CERT_DIR/key.pem" "$store_dir/example.com/generations/gen.TEST1/private.key"
chmod 600 "$store_dir/example.com/generations/gen.TEST1/fullchain.pem" \
  "$store_dir/example.com/generations/gen.TEST1/private.key"
ln -s generations/gen.TEST1 "$store_dir/example.com/current"
store_fingerprint=$(sha256sum "$CERT_DIR/cert.pem" | awk '{print $1}')
store_now=$(date +%s)
printf 'version=1\ndomain=example.com\nalt=\nowner=acme-nginx\nissuer=letsencrypt\nissued_at=%s\nnot_after=%s\nfingerprint=%s\nupdated_at=%s\nupdated_by=acme-nginx\n' \
  "$store_now" "$store_now" "$store_fingerprint" "$store_now" > "$store_dir/example.com/meta.env"
chmod 600 "$store_dir/example.com/meta.env"
CERT_SOURCE=store
STORE_DIR="$store_dir"
ACME_PRIMARY_DOMAIN=example.com
ACME_WILDCARD_DOMAIN=
expect_success "store mode is enabled" store_mode
[[ $(store_owner) == acme-nginx ]] || fail "store owner value"
pass "store owner is readable"
expect_success "store certificate is adoptable" store_certificate_is_adoptable
[[ $STORE_CERT == "$store_dir/example.com/current/fullchain.pem" &&
   $STORE_KEY == "$store_dir/example.com/current/private.key" ]] ||
  fail "adopted store certificate paths"
pass "store certificate adoption exposes stable paths"
CERT_SOURCE=own
expect_failure "store adoption requires store mode" store_certificate_is_adoptable

# --- v0.6.4：自动钩子按标记升级（P1-1），store 锁与显式接管原语 ---
post_reload_hook_is_managed_matches_known_markers(){
  local dir="$TEMP_DIR/post-reload-markers"
  mkdir -p "$dir" || return 1
  printf '%s\n' '#!/bin/bash' '# shared-cert-store peer hook v1' > "$dir/v1"
  printf '%s\n' '#!/bin/bash' '# acme-nginx-managed sb restart hook' > "$dir/legacy"
  printf '%s\n' '#!/bin/bash' '# my custom hook' > "$dir/custom"
  post_reload_hook_is_managed "$dir/v1" &&
    post_reload_hook_is_managed "$dir/legacy" &&
    ! post_reload_hook_is_managed "$dir/custom" &&
    ! post_reload_hook_is_managed "$dir/missing"
}
expect_success "managed peer hook markers are recognized" \
  post_reload_hook_is_managed_matches_known_markers
pass "custom peer hooks are never treated as managed"

post_reload_hook_upgrade_is_marker_scoped(){
  (
    local hook="$STATE_DIR/post_reload.sh" first_hash
    # shellcheck disable=SC2317,SC2329  # stubs are invoked indirectly by ensure_sb_restart_post_hook
    systemctl(){ return 0; }
    # shellcheck disable=SC2317,SC2329
    yellow(){ :; }
    # shellcheck disable=SC2317,SC2329
    red(){ :; }
    # shellcheck disable=SC2317,SC2329
    green(){ :; }
    rm -f "$hook"
    printf '%s\n' '#!/bin/bash' '# acme-nginx-managed sb restart hook' \
      'systemctl restart sb' > "$hook"
    chmod 700 "$hook"
    ensure_sb_restart_post_hook || return 1
    grep -Fq '# shared-cert-store peer hook v2' "$hook" || return 1
    post_reload_hook_is_managed "$hook" || return 1
    first_hash=$(sha256sum "$hook" | awk '{print $1}')
    ensure_sb_restart_post_hook || return 1
    [[ $(sha256sum "$hook" | awk '{print $1}') == "$first_hash" ]] || return 1
    printf '%s\n' '#!/bin/bash' '# my custom hook' 'echo custom' > "$hook"
    chmod 700 "$hook"
    ensure_sb_restart_post_hook || return 1
    grep -Fqx '# my custom hook' "$hook"
  )
}
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  expect_success "auto-created sb restart hook upgrades only managed markers" \
    post_reload_hook_upgrade_is_marker_scoped
  pass "old auto-created hook is upgraded, current hook is idempotent, custom hook is kept"
else
  pass "auto-created sb restart hook upgrade is covered on systemd CI"
fi

write_owner_meta_fixture(){
  local dir=$1 owner=$2 now
  now=$(date +%s) || return 1
  printf '%s\n' \
    'version=1' "domain=${dir##*/}" 'alt=' "owner=$owner" 'issuer=letsencrypt' \
    "issued_at=$now" "not_after=$now" \
    "fingerprint=$(printf 'a%.0s' {1..64})" "updated_at=$now" "updated_by=$owner" \
    > "$dir/meta.env" || return 1
  chmod 600 "$dir/meta.env"
}

store_force_owner_none_takes_over_other_owner(){
  (
    local store="$TEMP_DIR/store-force-owner"
    rm -rf "$store"
    mkdir -p "$store/example.com" || return 1
    chmod 700 "$store" "$store/example.com" || return 1
    write_owner_meta_fixture "$store/example.com" sb || return 1
    STORE_DIR="$store" ACME_PRIMARY_DOMAIN=example.com store_force_owner_none || return 1
    [[ $(sed -n 's/^owner=//p' "$store/example.com/meta.env" | head -n 1) == none ]] || return 1
    grep -Fqx 'updated_by=acme-nginx' "$store/example.com/meta.env" || return 1
    STORE_DIR="$store" ACME_PRIMARY_DOMAIN=example.com store_force_owner_none || return 1
    [[ $(sed -n 's/^owner=//p' "$store/example.com/meta.env" | head -n 1) == none ]] || return 1
    # 没有 meta 时不报错，直接返回 0
    rm -rf "$store/example.com"
    STORE_DIR="$store" ACME_PRIMARY_DOMAIN=example.com store_force_owner_none
  )
}
expect_success "store takeover only clears another tool's owner under the store lock" \
  store_force_owner_none_takes_over_other_owner
pass "owner=none is idempotent and a missing meta is tolerated"

store_release_ownership_uses_store_lock(){
  (
    local store="$TEMP_DIR/store-release-lock"
    rm -rf "$store"
    mkdir -p "$store/example.com" || return 1
    chmod 700 "$store" "$store/example.com" || return 1
    write_owner_meta_fixture "$store/example.com" acme-nginx || return 1
    STORE_DIR="$store" store_release_ownership acme-nginx || return 1
    [[ $(sed -n 's/^owner=//p' "$store/example.com/meta.env" | head -n 1) == none ]] || return 1
    [[ -f $store/.lock && ! -L $store/.lock ]] || return 1
    [[ $(stat -c '%a' "$store/.lock") == 600 ]] || return 1
    # 交还后再次调用不改变 owner，也不报错
    STORE_DIR="$store" store_release_ownership acme-nginx || return 1
    [[ $(sed -n 's/^owner=//p' "$store/example.com/meta.env" | head -n 1) == none ]]
  )
}
expect_success "store ownership release runs under the shared store lock" \
  store_release_ownership_uses_store_lock
pass "store lock file is private and release is idempotent"

# --- v0.6.5：reload hook 先发布 store 再 reload；owner 判定在 store 锁内 ---
reload_hook_publishes_store_before_reload(){
  (
    local hook="$ACME_RELOAD" publish_prev flock_line owner_line reload_line
    write_acme_reload_hook || return 1
    reload_line=$(grep -n '^if reload_nginx; then' "$hook" | head -n 1 | cut -d: -f1)
    flock_line=$(grep -n 'flock -w 30 7 || exit 1' "$hook" | head -n 1 | cut -d: -f1)
    owner_line=$(grep -n 'owner=$(sed -n' "$hook" | tail -n 1 | cut -d: -f1)
    [[ -n $reload_line && -n $flock_line && -n $owner_line ]] || return 1
    ((reload_line > 1)) || return 1
    # 必须是 reload 语句的“上一行”发布（函数体内也有一处相同文本，不能用第一个匹配）。
    publish_prev=$(sed -n "$((reload_line - 1))p" "$hook")
    [[ $publish_prev == 'store_publish "$identity" || true' ]] || return 1
    ((flock_line < owner_line))
  )
}
expect_success "reload hook publishes the shared store before reloading nginx" \
  reload_hook_publishes_store_before_reload
pass "store publish happens before nginx reload and owner checks are inside the store lock"

renew_runner_reads_store_owner_under_lock(){
  (
    write_acme_renew_runner || return 1
    # shellcheck disable=SC2016  # generated runner text is matched literally
    grep -Fq '  if exec 8> "$store_root/.lock"; then' "$ACME_RENEW_RUNNER" || return 1
    grep -Fq 'flock -w 5 8' "$ACME_RENEW_RUNNER" || return 1
    grep -Fq 'flock -u 8' "$ACME_RENEW_RUNNER" || return 1
    # shellcheck disable=SC2016  # generated runner text is matched literally
    grep -Fq 'if [[ -n $store_owner && $store_owner != acme-nginx ]]; then' \
      "$ACME_RENEW_RUNNER"
  )
}
expect_success "renew runner reads the store owner under a short store lock" \
  renew_runner_reads_store_owner_under_lock
pass "non-owner skip semantics are unchanged"

# --- v0.6.5：领养校验矩阵（D）---
write_adoptable_store_fixture(){
  local store=$1 dir fp now
  rm -rf "$store"
  dir="$store/example.com"
  mkdir -p "$dir/generations/gen.ABC123" || return 1
  chmod 700 "$store" "$dir" "$dir/generations" "$dir/generations/gen.ABC123" || return 1
  cp -p "$CERT_DIR/cert.pem" "$dir/generations/gen.ABC123/fullchain.pem" || return 1
  cp -p "$CERT_DIR/key.pem" "$dir/generations/gen.ABC123/private.key" || return 1
  chmod 600 "$dir/generations/gen.ABC123/fullchain.pem" \
    "$dir/generations/gen.ABC123/private.key" || return 1
  ln -s generations/gen.ABC123 "$dir/current" || return 1
  fp=$(sha256sum "$CERT_DIR/cert.pem" | awk '{print $1}') || return 1
  now=$(date +%s) || return 1
  printf 'version=1\ndomain=example.com\nalt=\nowner=acme-nginx\nissuer=letsencrypt\nissued_at=%s\nnot_after=%s\nfingerprint=%s\nupdated_at=%s\nupdated_by=acme-nginx\n' \
    "$now" "$now" "$fp" "$now" > "$dir/meta.env" || return 1
  chmod 600 "$dir/meta.env"
}

store_adoption_matrix_is_strict(){
  (
    local store="$TEMP_DIR/store-adopt-matrix" dir meta_bak
    CERT_SOURCE=store
    STORE_DIR="$store"
    ACME_PRIMARY_DOMAIN=example.com
    ACME_WILDCARD_DOMAIN=
    write_adoptable_store_fixture "$store" || return 1
    store_certificate_is_adoptable || return 1
    dir="$store/example.com"
    meta_bak="$TEMP_DIR/store-adopt-meta.bak"
    cp -p "$dir/meta.env" "$meta_bak" || return 1
    restore_meta(){ cp -p "$meta_bak" "$dir/meta.env" && chmod 600 "$dir/meta.env"; }
    # meta 缺失
    rm -f "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    # version/domain/owner/时间戳/指纹格式
    sed -i 's/^version=1$/version=2/' "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    sed -i 's/^domain=example.com$/domain=other.com/' "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    sed -i 's/^owner=acme-nginx$/owner=other/' "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    sed -i 's/^not_after=.*/not_after=not-a-time/' "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    sed -i 's/^fingerprint=.*/fingerprint=zzzz/' "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    sed -i 's/^fingerprint=.*/fingerprint=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
      "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    # alt 与 WILDCARD 不一致
    sed -i 's/^alt=$/alt=*.example.com/' "$dir/meta.env" && chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    # 权限错误：root/域名目录 755、meta 644
    chmod 755 "$store"
    ! store_certificate_is_adoptable || return 1
    chmod 700 "$store"
    chmod 755 "$dir"
    ! store_certificate_is_adoptable || return 1
    chmod 700 "$dir"
    chmod 644 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    chmod 600 "$dir/meta.env"
    # current 非法 / cert 为符号链接
    ln -sfn 'generations/bad-name' "$dir/current"
    ! store_certificate_is_adoptable || return 1
    ln -sfn 'generations/gen.ABC123' "$dir/current"
    rm -f "$dir/generations/gen.ABC123/fullchain.pem"
    ln -s "$CERT_DIR/cert.pem" "$dir/generations/gen.ABC123/fullchain.pem"
    ! store_certificate_is_adoptable || return 1
    rm -f "$dir/generations/gen.ABC123/fullchain.pem"
    cp -p "$CERT_DIR/cert.pem" "$dir/generations/gen.ABC123/fullchain.pem"
    chmod 600 "$dir/generations/gen.ABC123/fullchain.pem"
    # meta 含未知字段 / 缺 updated_by
    printf '%s\n' 'unknown=1' >> "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    grep -v '^updated_by=' "$meta_bak" > "$dir/meta.env"
    chmod 600 "$dir/meta.env"
    ! store_certificate_is_adoptable || return 1
    restore_meta || return 1
    # generation 目录权限 755
    chmod 755 "$dir/generations/gen.ABC123"
    ! store_certificate_is_adoptable || return 1
    chmod 700 "$dir/generations/gen.ABC123"
    # private.key 为符号链接
    rm -f "$dir/generations/gen.ABC123/private.key"
    ln -s "$CERT_DIR/key.pem" "$dir/generations/gen.ABC123/private.key"
    ! store_certificate_is_adoptable || return 1
    rm -f "$dir/generations/gen.ABC123/private.key"
    cp -p "$CERT_DIR/key.pem" "$dir/generations/gen.ABC123/private.key"
    chmod 600 "$dir/generations/gen.ABC123/private.key"
    # 恢复后仍可领养
    store_certificate_is_adoptable
  )
}
expect_success "store adoption enforces the full metadata/permission/layout contract" \
  store_adoption_matrix_is_strict
pass "missing or malformed meta, wrong permissions and invalid current are all refused"

# --- v0.7.0：B6 签发前 claim（owner double-check + 失败回滚）---
write_claim_meta(){
  local dir=$1 owner=$2 now fp
  now=$(date +%s)
  fp=$(printf 'b%.0s' {1..64})
  printf 'version=1\ndomain=example.com\nalt=\nowner=%s\nissuer=letsencrypt\nissued_at=%s\nnot_after=%s\nfingerprint=%s\nupdated_at=%s\nupdated_by=acme-nginx\n' \
    "$owner" "$now" "$now" "$fp" "$now" > "$dir/meta.env"
  chmod 600 "$dir/meta.env"
}

store_claim_issuance_checks_live_owner_and_rolls_back(){
  (
    local store="$TEMP_DIR/store-claim"
    local dir="$store/example.com"
    CERT_SOURCE=store
    STORE_DIR="$store"
    ACME_PRIMARY_DOMAIN=example.com
    mkdir -p "$dir" || return 1
    chmod 700 "$store" "$dir" || return 1
    # 存活的对方 owner：拒绝，且不改 meta
    write_claim_meta "$dir" sb
    store_owner_present(){ [[ ${1-} == sb ]]; }
    ! store_claim_issuance acme-nginx || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == sb ]] || return 1
    # 失联的对方 owner：占位成功并记录 previous，失败回滚恢复
    store_owner_present(){ return 1; }
    write_claim_meta "$dir" sb
    store_claim_issuance acme-nginx || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == acme-nginx ]] || return 1
    [[ $STORE_CLAIM_PREVIOUS == sb ]] || return 1
    store_release_claim acme-nginx "$STORE_CLAIM_PREVIOUS" || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == sb ]] || return 1
    # owner=none：占位成功，previous=none，回滚回 none
    write_claim_meta "$dir" none
    store_claim_issuance acme-nginx || return 1
    [[ $STORE_CLAIM_PREVIOUS == none ]] || return 1
    store_release_claim acme-nginx none || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == none ]] || return 1
    # meta 缺失：claim 为 no-op 成功
    rm -f "$dir/meta.env"
    store_claim_issuance acme-nginx || return 1
    [[ -z $STORE_CLAIM_PREVIOUS ]] || return 1
    # meta 存在但损坏（未知字段）：claim 拒绝（返回 3），meta 不变
    local claim_rc=0 corrupt_before=''
    write_claim_meta "$dir" none
    printf 'unknown=1\n' >> "$dir/meta.env"
    chmod 600 "$dir/meta.env"
    corrupt_before=$(cat "$dir/meta.env")
    store_claim_issuance acme-nginx || claim_rc=$?
    [[ $claim_rc -eq 3 ]] || return 1
    [[ $(cat "$dir/meta.env") == "$corrupt_before" ]] || return 1
    # meta 换成符号链接也算损坏
    rm -f "$dir/meta.env"
    printf '%s\n' 'version=1' > "$TEMP_DIR/claim-meta-target"
    ln -s "$TEMP_DIR/claim-meta-target" "$dir/meta.env"
    claim_rc=0
    store_claim_issuance acme-nginx || claim_rc=$?
    [[ $claim_rc -eq 3 ]] || return 1
    rm -f "$dir/meta.env"
  )
}
expect_success "store claim rejects a live other owner and rolls back on failure" \
  store_claim_issuance_checks_live_owner_and_rolls_back
pass "claim placeholder and rollback keep the store owner consistent"

issue_certificate_claims_before_issuing(){
  (
    local store="$TEMP_DIR/issue-claim-store"
    local dir="$store/example.com"
    local marker="$TEMP_DIR/issue-claim-called"
    CERT_SOURCE=store
    STORE_DIR="$store"
    ACME_PRIMARY_DOMAIN=example.com
    red(){ :; }
    yellow(){ :; }
    green(){ :; }
    mkdir -p "$dir" || return 1
    chmod 700 "$store" "$dir" || return 1
    rm -f "$marker"
    # 存活的其他工具 owner：必须在调用签发 core 之前拒绝
    write_claim_meta "$dir" sb
    store_owner_present(){ [[ ${1-} == sb ]]; }
    issue_certificate_core(){ : > "$marker"; return 0; }
    ! issue_certificate || return 1
    [[ ! -e $marker ]] || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == sb ]] || return 1
    # 失联的其他工具 owner：签发失败时回滚 owner
    store_owner_present(){ return 1; }
    write_claim_meta "$dir" sb
    issue_certificate_core(){ return 1; }
    ! issue_certificate || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == sb ]] || return 1
    # meta 损坏：claim 拒绝（3），签发 core 不被调用
    write_claim_meta "$dir" none
    printf 'unknown=1\n' >> "$dir/meta.env"
    chmod 600 "$dir/meta.env"
    rm -f "$marker"
    issue_certificate_core(){ : > "$marker"; return 0; }
    ! issue_certificate || return 1
    [[ ! -e $marker ]] || return 1
    # 显式 skip_claim=1：存活的其他工具 owner 也允许签发（接管意图）
    write_claim_meta "$dir" sb
    store_owner_present(){ [[ ${1-} == sb ]]; }
    issue_certificate 0 1 || return 1
    [[ -e $marker ]] || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == sb ]] || return 1
    # 崩溃回滚：core 收到 TERM 时 EXIT trap 恢复原 owner
    store_owner_present(){ return 1; }
    write_claim_meta "$dir" sb
    issue_certificate_core(){ kill -TERM "$BASHPID"; sleep 5; return 0; }
    local rc=0
    ( issue_certificate ) || rc=$?
    [[ $rc -eq 143 ]] || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == sb ]] || return 1
    # 成功路径不回滚：owner 保持 claim 占位
    issue_certificate_core(){ return 0; }
    issue_certificate || return 1
    [[ $(sed -n 's/^owner=//p' "$dir/meta.env" | head -n 1) == acme-nginx ]]
  )
}
expect_success "issue certificate claims before issuing and releases on failure" \
  issue_certificate_claims_before_issuing
pass "live other owner blocks issuance and failed issuance restores the previous owner"

# --- v0.7.1：runner 锁失败且无证书指纹时写 failed（不是非法 skipped）---
runner_fails_closed_records_failed_without_fingerprint(){
  (
    local store="$TEMP_DIR/runner-lock-fail-store2" marker="$TEMP_DIR/runner-lock-fail-called2"
    local fakebin="$TEMP_DIR/fake-logger-bin2" logger_log="$TEMP_DIR/fake-logger2.log"
    local output
    printf '%s\n' 'example.com' > "$ACME_IDENTITY"
    rm -rf "$store" "$marker" "$fakebin" "$logger_log"
    rm -f "$ACME_CERT" "$ACME_RENEW_STATE"
    mkdir -p "$store" "$fakebin" && chmod 700 "$store" "$fakebin" || return 1
    mkdir "$store/.lock" || return 1
    printf '%s\n' '#!/bin/bash' "printf '%s\n' \"\$*\" >> '$logger_log'" 'exit 0' > "$fakebin/logger"
    chmod 700 "$fakebin/logger"
    printf '%s\n' '#!/bin/bash' ": > '$marker'" 'exit 0' > "$ACME_BIN"
    chmod 700 "$ACME_BIN"
    STORE_DIR="$store" write_acme_renew_runner || return 1
    output=$(PATH="$fakebin:$PATH" "$ACME_RENEW_RUNNER" 2>&1) || return 1
    [[ ! -e $marker ]] || return 1
    [[ $output == *'共享证书库锁获取失败'* ]] || return 1
    load_acme_renew_state || return 1
    [[ $ACME_RENEW_LAST_RESULT == failed &&
       $ACME_RENEW_LAST_EXIT_CODE -eq 1 &&
       -z $ACME_RENEW_FINGERPRINT ]] || return 1
    write_acme_renew_runner
  )
}
expect_success "runner writes a loadable failed state when no certificate fingerprint exists" \
  runner_fails_closed_records_failed_without_fingerprint
pass "empty fingerprint is recorded as failed instead of an invalid skipped state"

# --- v0.7.1：reload hook store_publish 的损坏 meta / 旧证书闸 ---
hook_store_publish_skips_corrupt_meta_and_older_cert(){
  (
    local hook="$TEMP_DIR/hook-publish-reload.sh"
    local store="$TEMP_DIR/hook-publish-store" fn="$TEMP_DIR/hook-publish-fn.sh"
    local messages="$TEMP_DIR/hook-publish-messages" dir="$store/example.com"
    local certdir="$TEMP_DIR/hook-publish-certs" before=''
    rm -rf "$store" "$fn" "$messages" "$certdir"
    mkdir -p "$store" "$certdir" && chmod 700 "$store" "$certdir" || return 1
    STORE_DIR="$store" ACME_RELOAD="$hook" write_acme_reload_hook || return 1
    awk '/^store_meta_is_valid\(\)\{/{inside=1} inside{print} inside && /^}$/{exit}' "$hook" >> "$fn" || return 1
    awk '/^store_publish\(\)\{/{inside=1} inside{print} inside && /^}$/{exit}' "$hook" >> "$fn" || return 1
    [[ -s $fn ]] || return 1
    # shellcheck source=/dev/null
    source "$fn"
    store_root="$store"
    warn_post_reload(){ printf '%s\n' "$1" >> "$messages"; }
    cat > "$certdir/cert.cnf" <<'CERTCONFIG'
[req]
distinguished_name = subject
x509_extensions = extensions
prompt = no

[subject]
CN = example.com

[extensions]
subjectAltName = DNS:example.com,DNS:*.example.com
CERTCONFIG
    openssl ecparam -genkey -name prime256v1 -out "$certdir/newer.key" >/dev/null 2>&1 || return 1
    openssl req -new -x509 -days 30 -key "$certdir/newer.key" \
      -out "$certdir/newer.pem" -config "$certdir/cert.cnf" >/dev/null 2>&1 || return 1
    openssl ecparam -genkey -name prime256v1 -out "$certdir/older.key" >/dev/null 2>&1 || return 1
    openssl req -new -x509 -days 1 -key "$certdir/older.key" \
      -out "$certdir/older.pem" -config "$certdir/cert.cnf" >/dev/null 2>&1 || return 1
    cert="$certdir/newer.pem"
    key="$certdir/newer.key"
    identity=example.com
    # 损坏 meta：存在但字段不全 → 跳过发布并 warn
    mkdir -p "$dir" && chmod 700 "$dir" || return 1
    printf '%s\n' 'owner=sb' > "$dir/meta.env"
    chmod 600 "$dir/meta.env"
    store_publish example.com || return 1
    [[ ! -e $dir/current ]] || return 1
    grep -Fq 'meta is corrupt; skip publish' "$messages" || return 1
    # 正常发布 newer 后，再发布 older 应跳过且 current 不变
    rm -f "$dir/meta.env" "$messages"
    store_publish example.com || return 1
    before=$(readlink "$dir/current") || return 1
    cert="$certdir/older.pem"
    key="$certdir/older.key"
    store_publish example.com || return 1
    [[ $(readlink "$dir/current") == "$before" ]] || return 1
    grep -Fq 'skip publishing older one' "$messages"
  )
}
expect_success "reload hook store_publish skips corrupt meta and older certificates" \
  hook_store_publish_skips_corrupt_meta_and_older_cert
pass "hook-side publish gate warns and keeps the current generation"

# --- v0.7.1：load_config 校验 STORE_DIR ---
store_dir_config_validation_rejects_invalid_paths(){
  (
    # 其余用例使用测试桩；这里加载真实 bootstrap + 10-acme 以验证真实 load_config。
    # shellcheck source=/dev/null
    source "$ROOT_DIR/src/00-bootstrap.sh"
    # shellcheck source=/dev/null
    source "$ROOT_DIR/src/10-acme.sh"
    CONFIG_FILE="$TEMP_DIR/store-dir-config.conf"
    write_store_dir_config(){
      local value=${1-}
      {
        printf '%s\n' \
          'DNS_PROVIDER=cloudflare' \
          'CF_ACCOUNT_ID=0123456789abcdef0123456789abcdef' \
          'CF_TOKEN=fixture_token_123' \
          'STAGING=0' \
          'DOMAIN=example.com' \
          'WILDCARD=0' \
          'CERT_SOURCE=store'
        [[ -z $value ]] || printf 'STORE_DIR=%s\n' "$value"
      } > "$CONFIG_FILE"
      chmod 600 "$CONFIG_FILE"
    }
    write_store_dir_config '/etc/cert-store'
    load_config >/dev/null 2>&1 || return 1
    [[ $STORE_DIR == /etc/cert-store ]] || return 1
    write_store_dir_config ''
    load_config >/dev/null 2>&1 || return 1
    [[ $STORE_DIR == /etc/cert-store ]] || return 1
    local bad
    for bad in 'relative/path' '/etc/cert store' '/etc/../escape' '/etc/cert-store/' \
               '/etc/cert-store/..' '/etc/cert-store"x'; do
      write_store_dir_config "$bad"
      ! load_config >/dev/null 2>&1 || return 1
    done
    :
  )
}
expect_success "load_config rejects invalid STORE_DIR values" \
  store_dir_config_validation_rejects_invalid_paths
pass "STORE_DIR must be a clean absolute path without .. or trailing slash"
