# acme-nginx-module: 10-acme
# Certificate functions (DNS-01 + atomic generation deployment)
certificate_san_text(){
  local cert=$1
  if openssl x509 -help 2>&1 | grep -q -- '-ext'; then
    openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null
  else
    openssl x509 -in "$cert" -noout -text 2>/dev/null | \
      awk '/X509v3 Subject Alternative Name/{getline; print; exit}'
  fi
}

certificate_identity_matches(){
  local cert=$1 identity=$2 san
  if valid_ipv4 "$identity" || valid_ipv6 "$identity"; then
    san=$(certificate_san_text "$cert") || return 1
    printf '%s\n' "$san" | grep -oE 'IP Address:[^,[:space:]]+' | cut -d: -f2- | grep -Fxq -- "$identity"
  elif valid_hostname "$identity"; then
    san=$(certificate_san_text "$cert") || return 1
    printf '%s\n' "$san" | grep -oE 'DNS:[^,[:space:]]+' | cut -d: -f2- | grep -Fxiq -- "$identity"
  else
    return 1
  fi
}

certificate_time_valid(){
  local cert=$1 not_before not_before_epoch now
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || return 1
  not_before=$(openssl x509 -in "$cert" -noout -startdate 2>/dev/null | cut -d= -f2-) || return 1
  [[ -n $not_before ]] || return 1
  not_before_epoch=$(date -d "$not_before" +%s 2>/dev/null) || return 1
  now=$(date +%s) || return 1
  ((not_before_epoch <= now))
}

certificate_key_matches(){
  local cert=$1 key=$2 cert_public key_public
  cert_public=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null) || return 1
  key_public=$(openssl pkey -in "$key" -pubout 2>/dev/null) || return 1
  [[ -n $cert_public && $cert_public == "$key_public" ]]
}

format_epoch_utc(){
  local epoch=$1
  [[ $epoch =~ ^[0-9]{1,12}$ ]] || return 1
  date -u -d "@$epoch" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null
}

certificate_dns_names(){
  local cert=$1 san
  san=$(certificate_san_text "$cert") || return 1
  printf '%s\n' "$san" | grep -oE 'DNS:[^,[:space:]]+' | cut -d: -f2- |
    awk 'NF { if (result != "") result = result ", "; result = result $0 }
         END { if (result == "") exit 1; print result }'
}

load_certificate_metadata(){
  local cert=$1 key=$2 not_before not_after now remaining issuer subject
  CERT_META_NOT_BEFORE_EPOCH=
  CERT_META_NOT_AFTER_EPOCH=
  CERT_META_NOT_BEFORE=
  CERT_META_NOT_AFTER=
  CERT_META_REMAINING_DAYS=
  CERT_META_ISSUER=
  CERT_META_SUBJECT=
  CERT_META_DNS_NAMES=
  CERT_META_FINGERPRINT=
  CERT_META_KEY_MATCH=0
  CERT_META_STATE=invalid

  if [[ -L $cert || -L $key ]]; then
    [[ $cert == "${ACME_CERT:-}" && $key == "${ACME_KEY:-}" ]] || return 1
    managed_acme_live_layout_is_valid || return 1
  else
    [[ -f $cert && -f $key ]] || return 1
  fi
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || return 1
  not_before=$(openssl x509 -in "$cert" -noout -startdate 2>/dev/null | cut -d= -f2-) || return 1
  not_after=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2-) || return 1
  CERT_META_NOT_BEFORE_EPOCH=$(date -d "$not_before" +%s 2>/dev/null) || return 1
  CERT_META_NOT_AFTER_EPOCH=$(date -d "$not_after" +%s 2>/dev/null) || return 1
  CERT_META_NOT_BEFORE=$(format_epoch_utc "$CERT_META_NOT_BEFORE_EPOCH") || return 1
  CERT_META_NOT_AFTER=$(format_epoch_utc "$CERT_META_NOT_AFTER_EPOCH") || return 1
  now=$(date +%s) || return 1
  if ((CERT_META_NOT_AFTER_EPOCH >= now)); then
    remaining=$(((CERT_META_NOT_AFTER_EPOCH - now + 86399) / 86400))
  else
    remaining=$((-((now - CERT_META_NOT_AFTER_EPOCH + 86399) / 86400)))
  fi
  CERT_META_REMAINING_DAYS=$remaining

  issuer=$(openssl x509 -in "$cert" -noout -issuer -nameopt RFC2253 2>/dev/null ||
    openssl x509 -in "$cert" -noout -issuer 2>/dev/null) || return 1
  subject=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 2>/dev/null ||
    openssl x509 -in "$cert" -noout -subject 2>/dev/null) || return 1
  CERT_META_ISSUER=$(printf '%s\n' "${issuer#issuer=}" | sanitize_location)
  CERT_META_SUBJECT=$(printf '%s\n' "${subject#subject=}" | sanitize_location)
  CERT_META_DNS_NAMES=$(certificate_dns_names "$cert" 2>/dev/null || true)
  CERT_META_FINGERPRINT=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null |
    cut -d= -f2- | tr -d '\r\n')
  [[ -n $CERT_META_ISSUER && -n $CERT_META_SUBJECT && -n $CERT_META_FINGERPRINT ]] || return 1

  if certificate_key_matches "$cert" "$key"; then
    CERT_META_KEY_MATCH=1
  fi
  if ((CERT_META_NOT_BEFORE_EPOCH > now)); then
    CERT_META_STATE=not_yet_valid
  elif ((CERT_META_NOT_AFTER_EPOCH < now)); then
    CERT_META_STATE=expired
  elif [[ $CERT_META_KEY_MATCH -ne 1 ]]; then
    CERT_META_STATE=key_mismatch
  else
    CERT_META_STATE=valid
  fi
}

managed_acme_live_layout_is_valid(){
  local current_target generation cert_target key_target
  [[ -d ${ACME_LIVE:-} && ! -L $ACME_LIVE &&
     -d ${ACME_GENERATIONS:-} && ! -L $ACME_GENERATIONS &&
     -L ${ACME_CURRENT:-} && -L ${ACME_CERT:-} && -L ${ACME_KEY:-} ]] || return 1
  [[ $(readlink "$ACME_CERT" 2>/dev/null) == 'acme-live/current/fullchain.pem' &&
     $(readlink "$ACME_KEY" 2>/dev/null) == 'acme-live/current/private.key' ]] || return 1
  current_target=$(readlink "$ACME_CURRENT" 2>/dev/null) || return 1
  [[ $current_target =~ ^generations/gen\.[A-Za-z0-9]+$ ]] || return 1
  generation="$ACME_LIVE/$current_target"
  [[ -d $generation && ! -L $generation &&
     -f $generation/fullchain.pem && ! -L $generation/fullchain.pem &&
     -f $generation/private.key && ! -L $generation/private.key ]] || return 1
  cert_target=$(readlink -f "$ACME_CERT" 2>/dev/null) || return 1
  key_target=$(readlink -f "$ACME_KEY" 2>/dev/null) || return 1
  [[ $cert_target == "$generation/fullchain.pem" &&
     $key_target == "$generation/private.key" ]]
}

acme_domain_conf_path(){
  local identity=$1
  valid_hostname "$identity" || return 1
  printf '%s/certs/%s_ecc/%s.conf\n' "$ACME_HOME" "$identity" "$identity"
}

read_acme_domain_conf_value(){
  local identity=$1 key=$2 conf prefix line value='' count=0 expected
  case "$key" in
    Le_Domain|Le_API|Le_CertCreateTime|Le_NextRenewTime|Le_InstallCertSuccessTime|\
      Le_RealCertPath|Le_RealCACertPath|Le_RealKeyPath|Le_RealFullChainPath|Le_ReloadCmd) ;;
    *) return 1 ;;
  esac
  conf=$(acme_domain_conf_path "$identity") || return 1
  [[ -f $conf && ! -L $conf ]] || return 1
  prefix="${key}='"
  while IFS= read -r line; do
    [[ $line == "$prefix"* ]] || continue
    [[ $line == *"'" ]] || return 1
    value=${line#"$prefix"}
    value=${value%"'"}
    [[ $value != *"'"* && $value != *$'\r'* ]] || return 1
    count=$((count + 1))
  done < "$conf"
  [[ $count -eq 1 ]] || return 1
  case "$key" in
    Le_Domain) valid_hostname "$value" ;;
    Le_API) [[ $value == 'https://acme-v02.api.letsencrypt.org/directory' ]] ;;
    Le_CertCreateTime|Le_NextRenewTime|Le_InstallCertSuccessTime)
      [[ $value =~ ^[0-9]{1,12}$ ]]
      ;;
    Le_RealCertPath|Le_RealCACertPath) [[ -z $value ]] ;;
    Le_RealKeyPath) [[ $value == "$ACME_STAGE_KEY" ]] ;;
    Le_RealFullChainPath) [[ $value == "$ACME_STAGE_CERT" ]] ;;
    Le_ReloadCmd)
      expected=$(printf '%s' "$ACME_RELOAD" | base64 | tr -d '\r\n') || return 1
      [[ $value == "__ACME_BASE64__START_${expected}__ACME_BASE64__END_" ]]
      ;;
  esac || return 1
  printf '%s\n' "$value"
}

acme_deployment_config_is_current(){
  local identity=$1 key
  for key in Le_RealCertPath Le_RealCACertPath Le_RealKeyPath Le_RealFullChainPath Le_ReloadCmd; do
    read_acme_domain_conf_value "$identity" "$key" >/dev/null || return 1
  done
}

load_acme_certificate_schedule(){
  local identity=$1 configured_domain
  ACME_META_CREATED_EPOCH=
  ACME_META_NEXT_RENEW_EPOCH=
  ACME_META_DEPLOYED_EPOCH=
  ACME_META_CREATED=
  ACME_META_NEXT_RENEW=
  ACME_META_DEPLOYED=
  ACME_META_CA=
  configured_domain=$(read_acme_domain_conf_value "$identity" Le_Domain) || return 1
  [[ $configured_domain == "$identity" ]] || return 1
  read_acme_domain_conf_value "$identity" Le_API >/dev/null || return 1
  ACME_META_CA="Let's Encrypt"
  ACME_META_CREATED_EPOCH=$(read_acme_domain_conf_value "$identity" Le_CertCreateTime) || return 1
  ACME_META_NEXT_RENEW_EPOCH=$(read_acme_domain_conf_value "$identity" Le_NextRenewTime) || return 1
  ACME_META_CREATED=$(format_epoch_utc "$ACME_META_CREATED_EPOCH") || return 1
  ACME_META_NEXT_RENEW=$(format_epoch_utc "$ACME_META_NEXT_RENEW_EPOCH") || return 1
  if ACME_META_DEPLOYED_EPOCH=$(read_acme_domain_conf_value "$identity" Le_InstallCertSuccessTime); then
    ACME_META_DEPLOYED=$(format_epoch_utc "$ACME_META_DEPLOYED_EPOCH") || ACME_META_DEPLOYED=
  else
    ACME_META_DEPLOYED_EPOCH=
  fi
}

dns_provider_credentials_present(){
  local account_conf="$ACME_HOME/account.conf"
  [[ -f $account_conf && ! -L $account_conf ]] || return 1
  case ${DNS_PROVIDER:-cloudflare} in
    cloudflare)
      [[ $(grep -Ec "^SAVED_CF_Token='[A-Za-z0-9_-]+'$" "$account_conf" 2>/dev/null || true) -eq 1 &&
         $(grep -Ec "^SAVED_CF_Account_ID='[0-9A-Fa-f]{32}'$" "$account_conf" 2>/dev/null || true) -eq 1 ]]
      ;;
    huaweicloud)
      [[ $(grep -Ec "^SAVED_HUAWEICLOUD_ACCESS_KEY_ID='[^']+'$" "$account_conf" 2>/dev/null || true) -eq 1 &&
         $(grep -Ec "^SAVED_HUAWEICLOUD_SECRET_ACCESS_KEY='[^']+'$" "$account_conf" 2>/dev/null || true) -eq 1 ]]
      ;;
    *) return 1 ;;
  esac
}

read_acme_identity(){
  local identity
  local -a identity_lines=()
  [[ -f $ACME_IDENTITY && ! -L $ACME_IDENTITY ]] || return 1
  mapfile -t identity_lines < "$ACME_IDENTITY" || return 1
  [[ ${#identity_lines[@]} -eq 1 ]] || return 1
  identity=${identity_lines[0]}
  valid_hostname "$identity" || return 1
  printf '%s\n' "$identity"
}

write_acme_identity(){
  local identity=$1 identity_tmp
  valid_hostname "$identity" || return 1
  identity_tmp=$(mktemp "$STATE_DIR/.acme-identity.XXXXXX") || return 1
  if ! printf '%s\n' "$identity" > "$identity_tmp" ||
     ! chmod 600 "$identity_tmp" || ! mv -fT -- "$identity_tmp" "$ACME_IDENTITY"; then
    rm -f "$identity_tmp"
    return 1
  fi
}

detect_acme_identity(){
  local identity san
  [[ -s $ACME_CERT && -s $ACME_KEY ]] || return 1
  openssl x509 -in "$ACME_CERT" -noout >/dev/null 2>&1 || return 1
  certificate_time_valid "$ACME_CERT" || return 1
  certificate_key_matches "$ACME_CERT" "$ACME_KEY" || return 1
  if identity=$(read_acme_identity 2>/dev/null); then
    if certificate_identity_matches "$ACME_CERT" "$identity"; then
      printf '%s\n' "$identity"
      return 0
    fi
  fi
  san=$(certificate_san_text "$ACME_CERT") || return 1
  identity=$(printf '%s\n' "$san" | grep -oE 'DNS:[^,[:space:]]+' | cut -d: -f2- | grep -v '^\*\.' | head -n 1)
  valid_hostname "$identity" && certificate_identity_matches "$ACME_CERT" "$identity" || return 1
  printf '%s\n' "$identity"
}

normalize_acme_domain(){
  local value=${1,,}
  value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  value=${value%.}
  ACME_PRIMARY_DOMAIN=
  ACME_WILDCARD_DOMAIN=
  if [[ $value == \*.* ]]; then
    ACME_PRIMARY_DOMAIN=${value#\*.}
    valid_hostname "$ACME_PRIMARY_DOMAIN" || return 1
    ACME_WILDCARD_DOMAIN="*.$ACME_PRIMARY_DOMAIN"
  elif [[ $value == *\** ]]; then
    return 1
  else
    valid_hostname "$value" || return 1
    ACME_PRIMARY_DOMAIN=$value
  fi
}

valid_cloudflare_account_id(){
  [[ $1 =~ ^[0-9A-Fa-f]{32}$ ]]
}

valid_dns_provider(){
  [[ $1 == cloudflare || $1 == huaweicloud ]]
}

dns_provider_plugin_file(){
  case ${DNS_PROVIDER:-cloudflare} in
    cloudflare) printf '%s\n' 'dns_cf.sh' ;;
    huaweicloud) printf '%s\n' 'dns_huaweicloud_aksk.sh' ;;
    *) return 1 ;;
  esac
}

write_huawei_aksk_plugin(){
  local plugin plugin_tmp
  plugin=$(dns_provider_plugin_file) || return 1
  if [[ -f $ACME_HOME/dnsapi/$plugin && ! -L $ACME_HOME/dnsapi/$plugin ]] &&
     huawei_aksk_plugin_ok; then
    return 0
  fi
  plugin_tmp=$(mktemp "$ACME_HOME/.aksk-plugin.XXXXXX") || return 1
  if ! cat > "$plugin_tmp" <<'HWAKSK'
#!/bin/sh
# acme-nginx-huaweicloud-aksk: v1
# Custom Huawei Cloud DNS dnsapi plugin for acme.sh using AK/SK signing (DNS v2 API).
# Requires: curl, openssl, jq. Uses acme.sh helpers when sourced.
export LANG=en_US.UTF-8

_hwak_sha256_hex(){
  openssl dgst -sha256 -hex | sed 's/^.*= //'
}

_hwak_hmac_hex(){
  openssl dgst -sha256 -hmac "$1" -binary | od -An -tx1 | tr -d ' \n'
}

_hwak_urlencode(){
  printf '%s' "$1" | jq -sRr @uri
}

_hwak_canonical_query(){
  printf '%s' "$1" | tr '&' '\n' | grep -v '^$' | sort | \
    awk -F= '{ if (sep) printf "&"; printf "%s=%s", $1, $2; sep=1 }'
}

_hwak_sign(){
  local method=$1 path=$2 query=$3 headers=$4 signed=$5 body=$6 sdk_date=$7
  local payload_hash canonical string2sign signature
  case $path in
    */) ;;
    *) path="$path/" ;;
  esac
  payload_hash=$(printf '%s' "$body" | _hwak_sha256_hex) || return 1
  canonical=$(printf '%s\n%s\n%s\n%s\n%s\n%s' \
    "$method" "$path" "$query" "$headers" "$signed" "$payload_hash") || return 1
  string2sign=$(printf 'SDK-HMAC-SHA256\n%s\n%s' \
    "$sdk_date" "$(printf '%s' "$canonical" | _hwak_sha256_hex)") || return 1
  signature=$(printf '%s' "$string2sign" | _hwak_hmac_hex "$HUAWEICLOUD_SECRET_ACCESS_KEY") || return 1
  printf 'SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s' \
    "$HUAWEICLOUD_ACCESS_KEY_ID" "$signed" "$signature"
}

_hwak_request(){
  local method=$1 path=$2 query=$3 body=$4
  local sdk_date endpoint headers signed auth url code response out
  [ -n "$HUAWEICLOUD_ACCESS_KEY_ID" ] || return 1
  [ -n "$HUAWEICLOUD_SECRET_ACCESS_KEY" ] || return 1
  [ -n "$HUAWEICLOUD_REGION" ] || return 1
  sdk_date=$(date -u +%Y%m%dT%H%M%SZ) || return 1
  endpoint="dns.$HUAWEICLOUD_REGION.myhuaweicloud.com"
  headers=$(printf 'content-type:application/json\nhost:%s\nx-sdk-date:%s\n' "$endpoint" "$sdk_date")
  signed='content-type;host;x-sdk-date'
  auth=$(_hwak_sign "$method" "$path" "$query" "$headers" "$signed" "$body" "$sdk_date") || return 1
  url="https://$endpoint$path"
  [ -z "$query" ] || url="$url?$query"
  out=$(mktemp "${TMPDIR:-/tmp}/hwak.XXXXXX") || return 1
  if [ -n "$body" ]; then
    code=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" \
      -H "Content-Type: application/json" -H "Host: $endpoint" \
      -H "X-Sdk-Date: $sdk_date" -H "Authorization: $auth" \
      --connect-timeout 10 --max-time 30 --data "$body" "$url" 2>/dev/null) || { rm -f "$out"; return 1; }
  else
    code=$(curl -sS -o "$out" -w '%{http_code}' -X "$method" \
      -H "Content-Type: application/json" -H "Host: $endpoint" \
      -H "X-Sdk-Date: $sdk_date" -H "Authorization: $auth" \
      --connect-timeout 10 --max-time 30 "$url" 2>/dev/null) || { rm -f "$out"; return 1; }
  fi
  response=$(cat "$out" 2>/dev/null)
  rm -f "$out"
  case $code in
    2??) ;;
    *) _err "huaweicloud aksk: HTTP $code $response"; return 1 ;;
  esac
  printf '%s' "$response"
}

_hwak_find_zone(){
  local fulldomain=$1 zone resp id
  zone=$fulldomain
  while :; do
    case $zone in
      *.*) zone=${zone#*.} ;;
      *) break ;;
    esac
    resp=$(_hwak_request GET "/v2/zones" "type=public&name=$(_hwak_urlencode "$zone")" "") || return 1
    id=$(printf '%s' "$resp" | jq -r --arg z "$zone" '.zones[]? | select(.name == ($z + ".")) | .id' | head -n 1)
    [ -n "$id" ] || continue
    printf '%s' "$id"
    return 0
  done
  return 1
}

_hwak_find_recordset(){
  local fulldomain=$1 resp
  resp=$(_hwak_request GET "/v2/recordsets" "type=TXT&name=$(_hwak_urlencode "$fulldomain")" "") || return 1
  printf '%s' "$resp" | jq -c --arg f "$fulldomain" '.recordsets[]? | select(.name == ($f + "."))'
}

_hwak_append_record(){
  local zone_id=$1 fulldomain=$2 txtvalue=$3 rs=$4
  local id records new_records_json body
  id=$(printf '%s' "$rs" | jq -r '.id')
  [ -n "$id" ] || return 1
  records=$(printf '%s' "$rs" | jq -r '.records[]?')
  new_records_json=$(printf '%s\n' "$records" | \
    awk -v v="\"$txtvalue\"" 'BEGIN{found=0} {if ($0==v) found=1; else print} END{if (!found) print v}' | \
    jq -Rsc 'split("\n") | map(select(length>0))')
  body=$(jq -nc --arg name "$fulldomain." --argjson records "$new_records_json" \
    '{name:$name, type:"TXT", ttl:300, records:$records}')
  _hwak_request PUT "/v2/zones/$zone_id/recordsets/$id" "" "$body" >/dev/null || return 1
}

dns_huaweicloud_aksk_add(){
  local fulldomain=$1 txtvalue=$2 zone_id rs body
  HUAWEICLOUD_ACCESS_KEY_ID="${HUAWEICLOUD_ACCESS_KEY_ID:-$(_readaccountconf_mutable HUAWEICLOUD_ACCESS_KEY_ID)}"
  HUAWEICLOUD_SECRET_ACCESS_KEY="${HUAWEICLOUD_SECRET_ACCESS_KEY:-$(_readaccountconf_mutable HUAWEICLOUD_SECRET_ACCESS_KEY)}"
  HUAWEICLOUD_REGION="${HUAWEICLOUD_REGION:-$(_readaccountconf_mutable HUAWEICLOUD_REGION)}"
  if [ -z "$HUAWEICLOUD_ACCESS_KEY_ID" ] || [ -z "$HUAWEICLOUD_SECRET_ACCESS_KEY" ] || [ -z "$HUAWEICLOUD_REGION" ]; then
    _err "Not enough information provided to dns_huaweicloud_aksk!"
    return 1
  fi
  _saveaccountconf_mutable HUAWEICLOUD_ACCESS_KEY_ID "$HUAWEICLOUD_ACCESS_KEY_ID"
  _saveaccountconf_mutable HUAWEICLOUD_SECRET_ACCESS_KEY "$HUAWEICLOUD_SECRET_ACCESS_KEY"
  _saveaccountconf_mutable HUAWEICLOUD_REGION "$HUAWEICLOUD_REGION"
  zone_id=$(_hwak_find_zone "$fulldomain") || { _err "huaweicloud aksk: cannot find zone for $fulldomain"; return 1; }
  rs=$(_hwak_find_recordset "$fulldomain") || return 1
  if [ -z "$rs" ]; then
    body=$(printf '{"name":"%s.","type":"TXT","ttl":300,"records":["\\"%s\\""]}' "$fulldomain" "$txtvalue")
    _hwak_request POST "/v2/zones/$zone_id/recordsets" "" "$body" >/dev/null || return 1
  else
    _hwak_append_record "$zone_id" "$fulldomain" "$txtvalue" "$rs" || return 1
  fi
}

dns_huaweicloud_aksk_rm(){
  local fulldomain=$1 txtvalue=$2 zone_id rs id records new_records_json body
  HUAWEICLOUD_ACCESS_KEY_ID="${HUAWEICLOUD_ACCESS_KEY_ID:-$(_readaccountconf_mutable HUAWEICLOUD_ACCESS_KEY_ID)}"
  HUAWEICLOUD_SECRET_ACCESS_KEY="${HUAWEICLOUD_SECRET_ACCESS_KEY:-$(_readaccountconf_mutable HUAWEICLOUD_SECRET_ACCESS_KEY)}"
  HUAWEICLOUD_REGION="${HUAWEICLOUD_REGION:-$(_readaccountconf_mutable HUAWEICLOUD_REGION)}"
  [ -n "$HUAWEICLOUD_ACCESS_KEY_ID" ] && [ -n "$HUAWEICLOUD_SECRET_ACCESS_KEY" ] && [ -n "$HUAWEICLOUD_REGION" ] || return 1
  zone_id=$(_hwak_find_zone "$fulldomain") || return 0
  rs=$(_hwak_find_recordset "$fulldomain") || return 0
  [ -n "$rs" ] || return 0
  id=$(printf '%s' "$rs" | jq -r '.id')
  [ -n "$id" ] || return 1
  records=$(printf '%s' "$rs" | jq -r '.records[]?')
  new_records_json=$(printf '%s\n' "$records" | awk -v v="\"$txtvalue\"" '$0 != v' | jq -Rsc 'split("\n") | map(select(length>0))')
  if [ "$new_records_json" = "[]" ]; then
    _hwak_request DELETE "/v2/zones/$zone_id/recordsets/$id" "" "" >/dev/null || return 1
  else
    body=$(jq -nc --arg name "$fulldomain." --argjson records "$new_records_json" \
      '{name:$name, type:"TXT", ttl:300, records:$records}')
    _hwak_request PUT "/v2/zones/$zone_id/recordsets/$id" "" "$body" >/dev/null || return 1
  fi
}
HWAKSK
  then
    rm -f "$plugin_tmp"
    return 1
  fi
  if ! chmod 700 "$plugin_tmp" || ! mv -fT -- "$plugin_tmp" "$ACME_HOME/dnsapi/$plugin"; then
    rm -f "$plugin_tmp"
    return 1
  fi
  huawei_aksk_plugin_ok
}

huawei_aksk_plugin_ok(){
  local plugin count
  plugin=$(dns_provider_plugin_file) || return 1
  [[ -f $ACME_HOME/dnsapi/$plugin && ! -L $ACME_HOME/dnsapi/$plugin ]] || return 1
  count=$(grep -Fxc -- '# acme-nginx-huaweicloud-aksk: v1' "$ACME_HOME/dnsapi/$plugin" 2>/dev/null || true)
  [[ $count -eq 1 ]] || return 1
  bash -n "$ACME_HOME/dnsapi/$plugin" >/dev/null 2>&1
}

install_official_acme(){
  local temp_dir archive source_dir actual_sha256 installed_version plugin
  plugin=$(dns_provider_plugin_file) || return 1
  if [[ -x $ACME_BIN && -f $ACME_HOME/dnsapi/$plugin ]]; then
    installed_version=$(HOME="$STATE_DIR" "$ACME_BIN" --version 2>/dev/null)
    if printf '%s\n' "$installed_version" | grep -Fxq "v$ACME_VERSION"; then
      if [[ ${DNS_PROVIDER:-cloudflare} == huaweicloud ]]; then
        write_huawei_aksk_plugin || return 1
      fi
      return 0
    fi
  fi
  temp_dir=$(mktemp -d "$STATE_DIR/.acme-install.XXXXXX") || return 1
  archive="$temp_dir/acme.sh.tar.gz"
  source_dir="$temp_dir/acme.sh-$ACME_VERSION"
  green "正在从 acme.sh 官方仓库安装 v${ACME_VERSION}……"
  if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --retry 2 --connect-timeout 10 --max-time 60 -o "$archive" \
      "https://codeload.github.com/acmesh-official/acme.sh/tar.gz/refs/tags/${ACME_VERSION}"; then
    rm -rf "$temp_dir"
    red "官方 acme.sh 下载失败"
    return 1
  fi
  actual_sha256=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}')
  if [[ $actual_sha256 != "$ACME_ARCHIVE_SHA256" ]]; then
    rm -rf "$temp_dir"
    red "官方 acme.sh 压缩包 SHA-256 校验失败，拒绝执行"
    return 1
  fi
  if ! tar -xzf "$archive" -C "$temp_dir" || [[ ! -f $source_dir/acme.sh ]] || \
     [[ ! -f $source_dir/dnsapi/$plugin ]] || \
     ! (cd "$source_dir" && HOME="$STATE_DIR" bash ./acme.sh --install \
       --home "$ACME_HOME" --config-home "$ACME_HOME" --cert-home "$ACME_HOME/certs" \
       --no-cron --no-profile); then
    rm -rf "$temp_dir"
    red "官方 acme.sh 安装失败"
    return 1
  fi
  rm -rf "$temp_dir"
  installed_version=$(HOME="$STATE_DIR" "$ACME_BIN" --version 2>/dev/null)
  if [[ ! -x $ACME_BIN || ! -f $ACME_HOME/dnsapi/$plugin ]] || \
     ! printf '%s\n' "$installed_version" | grep -Fxq "v$ACME_VERSION"; then
    red "官方 acme.sh 安装不完整"
    return 1
  fi
  chmod 700 "$ACME_HOME" "$ACME_BIN"
  if [[ ${DNS_PROVIDER:-cloudflare} == huaweicloud ]]; then
    write_huawei_aksk_plugin || return 1
  fi
}

write_acme_reload_hook(){
  local hook_tmp
  hook_tmp=$(mktemp "$STATE_DIR/.acme_reload.XXXXXX") || return 1
  if [[ -e $ACME_RELOAD || -L $ACME_RELOAD ]] && \
     [[ ! -f $ACME_RELOAD || -L $ACME_RELOAD ]]; then
    rm -f "$hook_tmp"
    return 1
  fi
  if ! cat > "$hook_tmp" <<'ACMERELOAD'
#!/bin/bash
# Signal handlers and EXIT cleanup functions are invoked indirectly by Bash.
# shellcheck disable=SC2317,SC2329
# acme-nginx-reload-v1
export LANG=en_US.UTF-8
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
base="/etc/acme-nginx"
cert="/etc/acme-nginx/fullchain.pem"
key="/etc/acme-nginx/privkey.pem"
identity_file="/etc/acme-nginx/identity"
stage_cert=
stage_key=
new_generation=
old_current_target=
deployment_started=0
created_layout=0
restore_managed_links=0

cleanup_deploy_files(){
  [[ -z $stage_cert ]] || rm -f -- "$stage_cert"
  [[ -z $stage_key ]] || rm -f -- "$stage_key"
}

switch_current(){
  local target=$1 pointer_tmp
  [[ $target =~ ^generations/gen\.[A-Za-z0-9]+$ ]] || return 1
  pointer_tmp=$(mktemp "$base/acme-live/.current.XXXXXX") || return 1
  rm -f -- "$pointer_tmp" || return 1
  if ! ln -s -- "$target" "$pointer_tmp" ||
     ! mv -Tf -- "$pointer_tmp" "$base/acme-live/current"; then
    rm -f -- "$pointer_tmp"
    return 1
  fi
}

install_managed_link(){
  local destination=$1 target=$2 link_tmp
  link_tmp=$(mktemp "$base/.acme-link.XXXXXX") || return 1
  rm -f -- "$link_tmp" || return 1
  if ! ln -s -- "$target" "$link_tmp" || ! mv -Tf -- "$link_tmp" "$destination"; then
    rm -f -- "$link_tmp"
    return 1
  fi
}

rollback_deployment(){
  local failed=0 pointer_released=0 new_target current_after
  [[ $deployment_started -eq 1 ]] || return 0
  if [[ -n $old_current_target ]]; then
    if switch_current "$old_current_target"; then
      pointer_released=1
    else
      failed=1
    fi
  elif [[ $created_layout -eq 1 ]]; then
    if rm -f -- "$cert" "$key" "$base/acme-live/current"; then
      pointer_released=1
    else
      failed=1
    fi
  fi
  if [[ $restore_managed_links -eq 1 && -n $old_current_target ]]; then
    install_managed_link "$cert" 'acme-live/current/fullchain.pem' || failed=1
    install_managed_link "$key" 'acme-live/current/private.key' || failed=1
    if [[ ! -L $cert || ! -L $key ]] ||
       [[ $(readlink "$cert" 2>/dev/null) != 'acme-live/current/fullchain.pem' ]] ||
       [[ $(readlink "$key" 2>/dev/null) != 'acme-live/current/private.key' ]]; then
      failed=1
    fi
  fi
  if [[ -n $new_generation ]]; then
    new_target="generations/${new_generation##*/}"
    current_after=$(readlink "$base/acme-live/current" 2>/dev/null || true)
    [[ $current_after != "$new_target" ]] && pointer_released=1
  fi
  if [[ $pointer_released -eq 1 && -n $new_generation ]]; then
    rm -rf -- "$new_generation" || failed=1
  fi
  [[ $failed -eq 0 ]] || return 1
  deployment_started=0
  restore_managed_links=0
}

commit_deployment(){
  local current_target generation
  deployment_started=0
  current_target=$(readlink "$base/acme-live/current" 2>/dev/null || true)
  [[ $current_target =~ ^generations/gen\.[A-Za-z0-9]+$ ]] || return 0
  for generation in "$base/acme-live/generations"/gen.*; do
    [[ -e $generation || -L $generation ]] || continue
    [[ $generation == "$base/acme-live/$current_target" ]] && continue
    [[ -d $generation && ! -L $generation && ${generation##*/} =~ ^gen\.[A-Za-z0-9]+$ ]] || continue
    rm -rf -- "$generation" || true
  done
}

handle_deploy_signal(){
  trap '' HUP INT TERM
  rollback_deployment || true
  exit 1
}

nginx_service_active(){
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl is-active --quiet nginx
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service nginx status >/dev/null 2>&1
  else
    return 1
  fi
}

reload_nginx(){
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl reload nginx >/dev/null 2>&1
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service nginx reload >/dev/null 2>&1
  else
    return 1
  fi
}

trap cleanup_deploy_files EXIT
trap handle_deploy_signal HUP INT TERM
[[ -d $base && ! -L $base && -f $identity_file && ! -L $identity_file ]] || exit 1
mapfile -t identity_lines < "$identity_file" || exit 1
[[ ${#identity_lines[@]} -eq 1 ]] || exit 1
identity=${identity_lines[0]}
[[ ${#identity} -le 253 && $identity == *.* && $identity != *..* &&
   $identity =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] || exit 1
IFS=. read -r -a identity_labels <<< "$identity"
for label in "${identity_labels[@]}"; do
  [[ ${#label} -le 63 && $label != -* && $label != *- ]] || exit 1
done
source_dir="$base/acme/stage"
source_cert="$source_dir/fullchain.pem"
source_key="$source_dir/private.key"
[[ -d $base/acme && ! -L $base/acme && -d $source_dir && ! -L $source_dir &&
   -f $source_cert && ! -L $source_cert && -f $source_key && ! -L $source_key ]] || exit 1
stage_cert=$(mktemp "$base/.acme-cert.deploy.XXXXXX") || exit 1
stage_key=$(mktemp "$base/.acme-key.deploy.XXXXXX") || exit 1
if ! cp -- "$source_cert" "$stage_cert" || ! cp -- "$source_key" "$stage_key" ||
   ! chmod 600 "$stage_cert" "$stage_key"; then
  exit 1
fi
openssl x509 -in "$stage_cert" -noout -checkend 0 >/dev/null 2>&1 || exit 1
not_before=$(openssl x509 -in "$stage_cert" -noout -startdate 2>/dev/null | cut -d= -f2-) || exit 1
not_before_epoch=$(date -d "$not_before" +%s 2>/dev/null) || exit 1
[[ $not_before_epoch -le $(date +%s) ]] || exit 1
if openssl x509 -help 2>&1 | grep -q -- '-ext'; then
  san=$(openssl x509 -in "$stage_cert" -noout -ext subjectAltName 2>/dev/null) || exit 1
else
  san=$(openssl x509 -in "$stage_cert" -noout -text 2>/dev/null | awk '/X509v3 Subject Alternative Name/{getline; print; exit}') || exit 1
fi
printf '%s\n' "$san" | grep -oE 'DNS:[^,[:space:]]+' | cut -d: -f2- | grep -Fxiq -- "$identity" || exit 1
cert_public=$(openssl x509 -in "$stage_cert" -pubkey -noout 2>/dev/null) || exit 1
key_public=$(openssl pkey -in "$stage_key" -pubout 2>/dev/null) || exit 1
[[ -n "$cert_public" && "$cert_public" == "$key_public" ]] || exit 1
if [[ -e $base/acme-live || -L $base/acme-live ]]; then
  [[ -d $base/acme-live && ! -L $base/acme-live ]] || exit 1
else
  mkdir "$base/acme-live" || exit 1
  chmod 700 "$base/acme-live" || exit 1
fi
if [[ -e $base/acme-live/generations || -L $base/acme-live/generations ]]; then
  [[ -d $base/acme-live/generations && ! -L $base/acme-live/generations ]] || exit 1
else
  mkdir "$base/acme-live/generations" || exit 1
  chmod 700 "$base/acme-live/generations" || exit 1
fi
new_generation=$(mktemp -d "$base/acme-live/generations/gen.XXXXXX") || exit 1
chmod 700 "$new_generation" || exit 1
deployment_started=1
if ! mv -fT -- "$stage_cert" "$new_generation/fullchain.pem" ||
   ! mv -fT -- "$stage_key" "$new_generation/private.key" ||
   ! chmod 600 "$new_generation/fullchain.pem" "$new_generation/private.key"; then
  rollback_deployment || true
  exit 1
fi
stage_cert=
stage_key=

current_valid=0
if [[ -e $base/acme-live/current || -L $base/acme-live/current ]]; then
  [[ -L $base/acme-live/current ]] || { rollback_deployment || true; exit 1; }
  current_target=$(readlink "$base/acme-live/current" 2>/dev/null) || {
    rollback_deployment || true
    exit 1
  }
  if [[ $current_target =~ ^generations/gen\.[A-Za-z0-9]+$ &&
        -d $base/acme-live/$current_target && ! -L $base/acme-live/$current_target &&
        -f $base/acme-live/$current_target/fullchain.pem &&
        ! -L $base/acme-live/$current_target/fullchain.pem &&
        -f $base/acme-live/$current_target/private.key &&
        ! -L $base/acme-live/$current_target/private.key ]]; then
    current_public=$(openssl x509 -in "$base/acme-live/$current_target/fullchain.pem" \
      -pubkey -noout 2>/dev/null) || current_public=
    current_key_public=$(openssl pkey -in "$base/acme-live/$current_target/private.key" \
      -pubout 2>/dev/null) || current_key_public=
    if [[ -n $current_public && $current_public == "$current_key_public" ]]; then
      current_valid=1
    fi
  fi
  [[ $current_valid -eq 1 ]] || { rollback_deployment || true; exit 1; }
fi

cert_exists=0
key_exists=0
cert_managed=0
key_managed=0
[[ -e $cert || -L $cert ]] && cert_exists=1
[[ -e $key || -L $key ]] && key_exists=1
if [[ -L $cert ]]; then
  [[ $(readlink "$cert" 2>/dev/null) == 'acme-live/current/fullchain.pem' ]] || {
    rollback_deployment || true
    exit 1
  }
  cert_managed=1
elif [[ $cert_exists -eq 1 && ! -f $cert ]]; then
  rollback_deployment || true
  exit 1
fi
if [[ -L $key ]]; then
  [[ $(readlink "$key" 2>/dev/null) == 'acme-live/current/private.key' ]] || {
    rollback_deployment || true
    exit 1
  }
  key_managed=1
elif [[ $key_exists -eq 1 && ! -f $key ]]; then
  rollback_deployment || true
  exit 1
fi

if [[ $cert_exists -eq 1 && $key_exists -eq 1 ]]; then
  old_cert_public=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null) || old_cert_public=
  old_key_public=$(openssl pkey -in "$key" -pubout 2>/dev/null) || old_key_public=
  [[ -n $old_cert_public && $old_cert_public == "$old_key_public" ]] || {
    rollback_deployment || true
    exit 1
  }
  if [[ $cert_managed -eq 0 && $key_managed -eq 0 ]]; then
    preserved_generation=$(mktemp -d "$base/acme-live/generations/gen.XXXXXX") || {
      rollback_deployment || true
      exit 1
    }
    if ! chmod 700 "$preserved_generation" ||
       ! cp -- "$cert" "$preserved_generation/fullchain.pem" ||
       ! cp -- "$key" "$preserved_generation/private.key" ||
       ! chmod 600 "$preserved_generation/fullchain.pem" "$preserved_generation/private.key"; then
      rm -rf -- "$preserved_generation"
      rollback_deployment || true
      exit 1
    fi
    old_current_target="generations/${preserved_generation##*/}"
    switch_current "$old_current_target" || {
      rm -rf -- "$preserved_generation"
      rollback_deployment || true
      exit 1
    }
  else
    [[ $current_valid -eq 1 ]] || { rollback_deployment || true; exit 1; }
    old_current_target=$current_target
  fi
  if [[ $cert_managed -eq 0 || $key_managed -eq 0 ]]; then
    restore_managed_links=1
  fi
  if [[ $cert_managed -eq 0 ]] &&
     ! install_managed_link "$cert" 'acme-live/current/fullchain.pem'; then
    rollback_deployment || true
    exit 1
  fi
  if [[ $key_managed -eq 0 ]] &&
     ! install_managed_link "$key" 'acme-live/current/private.key'; then
    rollback_deployment || true
    exit 1
  fi
  switch_current "generations/${new_generation##*/}" || {
    rollback_deployment || true
    exit 1
  }
elif [[ $cert_exists -eq 0 && $key_exists -eq 0 ]]; then
  created_layout=1
  switch_current "generations/${new_generation##*/}" || {
    rollback_deployment || true
    exit 1
  }
  install_managed_link "$cert" 'acme-live/current/fullchain.pem' || {
    rollback_deployment || true
    exit 1
  }
  install_managed_link "$key" 'acme-live/current/private.key' || {
    rollback_deployment || true
    exit 1
  }
else
  rollback_deployment || true
  exit 1
fi

if ! nginx_service_active; then
  commit_deployment
  exit 0
fi
if reload_nginx; then
  commit_deployment
  exit 0
fi
rollback_deployment || true
exit 1
ACMERELOAD
  then
    rm -f "$hook_tmp"
    return 1
  fi
  if ! chmod 700 "$hook_tmp" || ! mv -fT -- "$hook_tmp" "$ACME_RELOAD"; then
    rm -f "$hook_tmp"
    return 1
  fi
  acme_reload_hook_is_current
}

acme_reload_hook_is_current(){
  # Dollar-prefixed names in the grep patterns are literal generated-hook text.
  # shellcheck disable=SC2016
  [[ -f $ACME_RELOAD && ! -L $ACME_RELOAD && -x $ACME_RELOAD ]] &&
    [[ $(grep -Fxc "$ACME_RELOAD_IDENTITY" "$ACME_RELOAD" 2>/dev/null || true) -eq 1 ]] &&
    grep -Fqx 'base="/etc/acme-nginx"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'cert="/etc/acme-nginx/fullchain.pem"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'key="/etc/acme-nginx/privkey.pem"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'identity_file="/etc/acme-nginx/identity"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'source_dir="$base/acme/stage"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'source_cert="$source_dir/fullchain.pem"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'source_key="$source_dir/private.key"' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'deployment_started=1' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx '    restore_managed_links=1' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'if reload_nginx; then' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx '  commit_deployment' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx '  exit 0' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'rollback_deployment || true' "$ACME_RELOAD" 2>/dev/null &&
    grep -Fqx 'exit 1' "$ACME_RELOAD" 2>/dev/null &&
    bash -n "$ACME_RELOAD" >/dev/null 2>&1
}

prepare_acme_deploy_stage(){
  local path
  if [[ -e $ACME_STAGE || -L $ACME_STAGE ]]; then
    [[ -d $ACME_STAGE && ! -L $ACME_STAGE ]] || return 1
  else
    mkdir "$ACME_STAGE" || return 1
  fi
  chmod 700 "$ACME_STAGE" || return 1
  for path in "$ACME_STAGE_CERT" "$ACME_STAGE_KEY"; do
    [[ -e $path || -L $path ]] || continue
    [[ -f $path && ! -L $path ]] || return 1
  done
}

valid_acme_renewal_identity(){
  local identity plugin
  plugin=$(dns_provider_plugin_file) || return 1
  [[ -x $ACME_BIN && -f $ACME_HOME/dnsapi/$plugin ]] || return 1
  identity=$(read_acme_identity 2>/dev/null) || return 1
  if ! load_certificate_metadata "$ACME_CERT" "$ACME_KEY" ||
     [[ $CERT_META_STATE != valid ]] ||
     ! certificate_identity_matches "$ACME_CERT" "$identity" ||
     ! load_acme_certificate_schedule "$identity"; then
    return 1
  fi
  printf '%s\n' "$identity"
}

recover_acme_renewal_identity(){
  local identity
  identity=$(detect_acme_identity 2>/dev/null) || return 1
  load_acme_certificate_schedule "$identity" || return 1
  write_acme_identity "$identity" || return 1
  printf '%s\n' "$identity"
}

register_acme_certificate_deployment(){
  local identity=$1 initial_install=${2:-0}
  [[ $initial_install == 0 || $initial_install == 1 ]] || return 1
  valid_hostname "$identity" || return 1
  acme_reload_hook_is_current || return 1
  prepare_acme_deploy_stage || return 1
  if ! HOME="$STATE_DIR" "$ACME_BIN" \
      --home "$ACME_HOME" --config-home "$ACME_HOME" \
      --install-cert -d "$identity" --ecc \
      --key-file "$ACME_STAGE_KEY" --fullchain-file "$ACME_STAGE_CERT" \
      --reloadcmd "$ACME_RELOAD"; then
    return 1
  fi
  managed_acme_live_layout_is_valid &&
    acme_deployment_config_is_current "$identity" &&
    load_certificate_metadata "$ACME_CERT" "$ACME_KEY" &&
    [[ $CERT_META_STATE == valid ]] &&
    certificate_identity_matches "$ACME_CERT" "$identity"
}

issue_certificate(){
  local -a issue_args
  local provider plugin
  provider=${DNS_PROVIDER:-cloudflare}
  [[ -n ${ACME_PRIMARY_DOMAIN:-} ]] || return 1
  valid_dns_provider "$provider" || return 1
  case $provider in
    cloudflare)
      [[ -n ${CF_TOKEN:-} && -n ${CF_ACCOUNT_ID:-} ]] || return 1
      valid_cloudflare_account_id "$CF_ACCOUNT_ID" || return 1
      [[ $CF_TOKEN =~ ^[A-Za-z0-9_-]{10,200}$ ]] || return 1
      ;;
    huaweicloud)
      [[ -n ${HUAWEICLOUD_ACCESS_KEY_ID:-} && -n ${HUAWEICLOUD_SECRET_ACCESS_KEY:-} &&
         -n ${HUAWEICLOUD_REGION:-} ]] || return 1
      ;;
  esac
  plugin=$(dns_provider_plugin_file) || return 1
  install_official_acme || return 1
  write_acme_reload_hook || return 1
  issue_args=(--home "$ACME_HOME" --config-home "$ACME_HOME" --issue \
    --dns "${plugin%.sh}" --keylength ec-256 -d "$ACME_PRIMARY_DOMAIN")
  if [[ ${STAGING:-0} == 1 ]]; then
    issue_args+=(--server https://acme-staging-v02.api.letsencrypt.org/directory)
  else
    issue_args+=(--server letsencrypt)
  fi
  if [[ -n ${ACME_WILDCARD_DOMAIN:-} ]]; then
    issue_args+=(-d "$ACME_WILDCARD_DOMAIN")
    blue "将申请：$ACME_PRIMARY_DOMAIN + $ACME_WILDCARD_DOMAIN"
  else
    blue "将申请单域名证书：$ACME_PRIMARY_DOMAIN"
  fi
  case $provider in
    cloudflare)
      if ! HOME="$STATE_DIR" CF_Token="$CF_TOKEN" CF_Account_ID="$CF_ACCOUNT_ID" \
          CF_Zone_ID='' CF_Key='' CF_Email='' \
          "$ACME_BIN" "${issue_args[@]}"; then
        red "Cloudflare DNS 验证或证书签发失败"
        return 1
      fi
      ;;
    huaweicloud)
      if ! HOME="$STATE_DIR" HUAWEICLOUD_ACCESS_KEY_ID="$HUAWEICLOUD_ACCESS_KEY_ID" \
          HUAWEICLOUD_SECRET_ACCESS_KEY="$HUAWEICLOUD_SECRET_ACCESS_KEY" \
          HUAWEICLOUD_REGION="$HUAWEICLOUD_REGION" \
          "$ACME_BIN" "${issue_args[@]}"; then
        red "华为云 DNS 验证或证书签发失败"
        return 1
      fi
      ;;
  esac
  if ! write_acme_identity "$ACME_PRIMARY_DOMAIN"; then
    red "写入 ACME 身份失败"
    return 1
  fi
  if ! register_acme_certificate_deployment "$ACME_PRIMARY_DOMAIN" 0; then
    red "证书签发成功，但部署到 $STATE_DIR 失败"
    return 1
  fi
  green "DNS API 证书申请完成（${provider}）"
}

show_certificate_metadata(){
  local label=$1 cert=$2 key=$3 identity=${4:-}
  green "证书类型: $label"
  if ! load_certificate_metadata "$cert" "$key"; then
    red "证书状态: 无法读取或文件不完整"
    return 1
  fi
  case $CERT_META_STATE in
    valid) green "证书状态: 有效" ;;
    expired) red "证书状态: 已过期" ;;
    not_yet_valid) red "证书状态: 尚未生效" ;;
    key_mismatch) red "证书状态: 证书与私钥不匹配" ;;
    *) red "证书状态: 无效" ;;
  esac
  printf '覆盖域名: %s\n' "${CERT_META_DNS_NAMES:-未提供 SAN}"
  printf '签发机构: %s\n' "$CERT_META_ISSUER"
  printf '生效时间: %s\n' "$CERT_META_NOT_BEFORE"
  printf '到期时间: %s\n' "$CERT_META_NOT_AFTER"
  if ((CERT_META_REMAINING_DAYS < 0)); then
    red "剩余有效期: 已过期 $((-CERT_META_REMAINING_DAYS)) 天"
  elif ((CERT_META_REMAINING_DAYS <= 30)); then
    yellow "剩余有效期: ${CERT_META_REMAINING_DAYS} 天"
  else
    green "剩余有效期: ${CERT_META_REMAINING_DAYS} 天"
  fi
  if [[ $CERT_META_KEY_MATCH -eq 1 ]]; then
    green "证书/私钥: 匹配"
  else
    red "证书/私钥: 不匹配"
  fi
  if [[ -n $identity ]]; then
    if certificate_identity_matches "$cert" "$identity"; then
      green "TLS 身份: $identity（证书已覆盖）"
    else
      red "TLS 身份: $identity（证书未覆盖）"
    fi
  fi
  printf 'SHA-256 指纹: %s\n' "$CERT_META_FINGERPRINT"
}

show_acme_certificate_schedule(){
  local identity=$1
  if load_acme_certificate_schedule "$identity"; then
    printf 'ACME 服务: %s\n' "$ACME_META_CA"
    printf '最近签发/续期: %s\n' "$ACME_META_CREATED"
    printf '当前计划续期: %s\n' "$ACME_META_NEXT_RENEW"
    printf '最近部署成功: %s\n' "${ACME_META_DEPLOYED:-暂无记录}"
  else
    yellow "ACME 时间记录: 无法安全读取"
    return 1
  fi
}
