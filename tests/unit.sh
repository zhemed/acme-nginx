#!/usr/bin/env bash
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
export ACME_LIVE="$STATE_DIR/live"
export ACME_GENERATIONS="$ACME_LIVE/generations"
export ACME_CURRENT="$ACME_LIVE/current"
export ACME_LOCK="$STATE_DIR/acme.lock"
export ACME_CRON_MARKER="# acme-nginx-managed"
export ACME_RELOAD_IDENTITY="# acme-nginx-reload-v1"
export ACME_RENEW_IDENTITY="# acme-nginx-renew-v1"
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

# --- Huawei Cloud AK/SK plugin ---
export DNS_PROVIDER=huaweicloud
mkdir -p "$ACME_HOME/dnsapi"
expect_success "huawei aksk plugin is written" write_huawei_aksk_plugin
expect_success "huawei aksk plugin is current" huawei_aksk_plugin_ok
bash -n "$ACME_HOME/dnsapi/dns_huaweicloud_aksk.sh" || fail "plugin passes bash -n"
pass "plugin passes bash -n"

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
grep -Fq 'CURL GET https://dns.cn-north-4.myhuaweicloud.com/v2/zones?type=public&name=example.com' "$TEMP_DIR/curl.log" ||
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
