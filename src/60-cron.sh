# acme-nginx-module: 60-cron
# Manage only acme-nginx-owned crontab entries.
load_current_crontab(){
  local error_file error_text temp_base=$STATE_DIR
  CURRENT_CRONTAB=
  [[ -d $temp_base ]] || temp_base=/tmp
  error_file=$(mktemp "$temp_base/.crontab-error.XXXXXX") || return 1
  if CURRENT_CRONTAB=$(crontab -l 2>"$error_file"); then
    rm -f "$error_file"
    return 0
  fi
  error_text=$(cat "$error_file" 2>/dev/null)
  rm -f "$error_file"
  if printf '%s\n' "$error_text" | grep -qi 'no crontab for'; then
    return 0
  fi
  if printf '%s\n' "$error_text" | grep -qi 'no such file or directory' && \
     [[ ! -e /var/spool/cron/crontabs/root && ! -e /var/spool/cron/root ]]; then
    return 0
  fi
  red "读取root crontab失败，拒绝覆盖现有定时任务"
  return 1
}

acme_lock_path(){
  printf '%s\n' "${ACME_LOCK:-$STATE_DIR/acme.lock}"
}

release_acme_lock(){
  local failed=0
  if [[ ${ACME_LOCK_FD:-} =~ ^[0-9]+$ ]]; then
    flock -u "$ACME_LOCK_FD" || failed=1
    if ! exec {ACME_LOCK_FD}>&-; then
      failed=1
    fi
    ACME_LOCK_FD=
  fi
  ACME_LOCK_HELD=0
  return "$failed"
}

acquire_acme_lock(){
  local lock path
  [[ ${ACME_LOCK_HELD:-0} -eq 1 ]] && return 0
  lock=$(acme_lock_path)
  [[ -d $STATE_DIR && ! -L $STATE_DIR ]] || return 1
  if [[ -e $lock || -L $lock ]]; then
    [[ -f $lock && ! -L $lock ]] || return 1
  fi
  ACME_LOCK_FD=
  exec {ACME_LOCK_FD}> "$lock" || return 1
  if ! chmod 600 "$lock" || ! flock -w 30 "$ACME_LOCK_FD"; then
    release_acme_lock >/dev/null 2>&1 || true
    return 1
  fi
  ACME_LOCK_HELD=1
}

with_acme_lock(){
  local owned=0 status
  if [[ ${ACME_LOCK_HELD:-0} -ne 1 ]]; then
    acquire_acme_lock || {
      red "另一个证书或续期操作正在执行，请稍后重试"
      return 1
    }
    owned=1
  fi
  if "$@"; then status=0; else status=$?; fi
  if [[ $owned -eq 1 ]] && ! release_acme_lock; then
    red "释放 ACME 操作锁失败"
    [[ $status -ne 0 ]] || status=1
  fi
  return "$status"
}

acme_renew_runner_path(){
  printf '%s\n' "${ACME_RENEW_RUNNER:-$STATE_DIR/renew.sh}"
}

acme_renew_state_path(){
  printf '%s\n' "${ACME_RENEW_STATE:-$STATE_DIR/renew.state}"
}

acme_renew_runner_identity(){
  printf '%s\n' "${ACME_RENEW_IDENTITY:-# acme-nginx-renew-v1}"
}

# Parsed values are consumed by the certificate management module.
# shellcheck disable=SC2034
load_acme_renew_state(){
  local state line key value mode
  local check_epoch='' result='' exit_code='' renewal_epoch='' fingerprint=''
  local check_count=0 result_count=0 exit_count=0 renewal_count=0 fingerprint_count=0
  ACME_RENEW_LAST_CHECK_EPOCH=
  ACME_RENEW_LAST_CHECK=
  ACME_RENEW_LAST_RESULT=
  ACME_RENEW_LAST_EXIT_CODE=
  ACME_RENEW_LAST_RENEWAL_EPOCH=
  ACME_RENEW_LAST_RENEWAL=
  ACME_RENEW_FINGERPRINT=
  state=$(acme_renew_state_path)
  [[ -f $state && ! -L $state ]] || return 1
  mode=$(stat -c '%a' "$state" 2>/dev/null || true)
  case $(uname -s 2>/dev/null) in
    MINGW*|MSYS*) ;;
    *) [[ $mode == 600 ]] || return 1 ;;
  esac
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == *=* ]] || return 1
    key=${line%%=*}
    value=${line#*=}
    case $key in
      last_check_epoch)
        check_count=$((check_count + 1))
        check_epoch=$value
        ;;
      last_result)
        result_count=$((result_count + 1))
        result=$value
        ;;
      last_exit_code)
        exit_count=$((exit_count + 1))
        exit_code=$value
        ;;
      last_renewal_epoch)
        renewal_count=$((renewal_count + 1))
        renewal_epoch=$value
        ;;
      cert_fingerprint)
        fingerprint_count=$((fingerprint_count + 1))
        fingerprint=$value
        ;;
      *) return 1 ;;
    esac
  done < "$state"
  [[ $check_count -eq 1 && $result_count -eq 1 && $exit_count -eq 1 &&
     $renewal_count -eq 1 && $fingerprint_count -eq 1 ]] || return 1
  [[ $check_epoch =~ ^[1-9][0-9]{0,11}$ ]] || return 1
  [[ $result == renewed || $result == unchanged || $result == failed ]] || return 1
  [[ $exit_code =~ ^(0|[1-9][0-9]{0,2})$ ]] && ((exit_code <= 255)) || return 1
  [[ $renewal_epoch =~ ^(0|[1-9][0-9]{0,11})$ ]] &&
    ((renewal_epoch <= check_epoch)) || return 1
  [[ -z $fingerprint || $fingerprint =~ ^[0-9a-f]{64}$ ]] || return 1
  if [[ $result != failed ]]; then
    [[ $exit_code -eq 0 && -n $fingerprint ]] || return 1
  else
    [[ $exit_code -ne 0 ]] || return 1
  fi
  [[ $result != renewed || $renewal_epoch -eq $check_epoch ]] || return 1
  ACME_RENEW_LAST_CHECK=$(format_epoch_utc "$check_epoch") || return 1
  if [[ $renewal_epoch -ne 0 ]]; then
    ACME_RENEW_LAST_RENEWAL=$(format_epoch_utc "$renewal_epoch") || return 1
  fi
  ACME_RENEW_LAST_CHECK_EPOCH=$check_epoch
  ACME_RENEW_LAST_RESULT=$result
  ACME_RENEW_LAST_EXIT_CODE=$exit_code
  ACME_RENEW_LAST_RENEWAL_EPOCH=$renewal_epoch
  ACME_RENEW_FINGERPRINT=$fingerprint
}

crontab_has_acme_entries(){
  local content=$1 runner
  runner=$(acme_renew_runner_path)
  printf '%s\n' "$content" | grep -Fq "$ACME_CRON_MARKER" ||
    printf '%s\n' "$content" | grep -Fq "$ACME_BIN --cron" ||
    printf '%s\n' "$content" | grep -Fq "$runner"
}

acme_renew_cron_entry(){
  local runner
  runner=$(acme_renew_runner_path)
  printf '%s\n' "17 3,9,15,21 * * * $runner > /dev/null 2>&1 $ACME_CRON_MARKER"
}

acme_renew_cron_is_current(){
  local content=$1 entry runner exact_count marker_count runner_count direct_count
  entry=$(acme_renew_cron_entry)
  runner=$(acme_renew_runner_path)
  exact_count=$(printf '%s\n' "$content" | grep -Fxc -- "$entry" || true)
  marker_count=$(printf '%s\n' "$content" | grep -Fc -- "$ACME_CRON_MARKER" || true)
  runner_count=$(printf '%s\n' "$content" | grep -Fc -- "$runner" || true)
  direct_count=$(printf '%s\n' "$content" | grep -Fc -- "$ACME_BIN --cron" || true)
  [[ $exact_count -eq 1 && $marker_count -eq 1 && $runner_count -eq 1 && $direct_count -eq 0 ]]
}

filter_acme_cron_entries(){
  local runner
  runner=$(acme_renew_runner_path)
  grep -Fv "$ACME_CRON_MARKER" |
    grep -Fv "$ACME_BIN --cron" |
    grep -Fv "$runner"
}

acme_renew_runner_is_current(){
  local runner identity mode expected_cron_command expected_force_command expected_state_dir
  local expected_acme_bin expected_acme_home expected_cert_file expected_state_file
  local expected_identity_file expected_lock_file
  runner=$(acme_renew_runner_path)
  identity=$(acme_renew_runner_identity)
  expected_cron_command="  HOME=\"\$state_dir\" \"\$acme_bin\" --cron --home \"\$acme_home\" --config-home \"\$acme_home\""
  expected_force_command="  HOME=\"\$state_dir\" \"\$acme_bin\" --home \"\$acme_home\" --config-home \"\$acme_home\" --renew -d \"\$acme_identity\" --ecc --force"
  printf -v expected_state_dir 'state_dir=%q' "$STATE_DIR"
  printf -v expected_acme_bin 'acme_bin=%q' "$ACME_BIN"
  printf -v expected_acme_home 'acme_home=%q' "$ACME_HOME"
  printf -v expected_cert_file 'cert_file=%q' "${ACME_CERT:-$STATE_DIR/fullchain.pem}"
  printf -v expected_state_file 'state_file=%q' "$(acme_renew_state_path)"
  printf -v expected_identity_file 'identity_file=%q' "$ACME_IDENTITY"
  printf -v expected_lock_file 'lock_file=%q' "$(acme_lock_path)"
  [[ -f $runner && ! -L $runner && -x $runner ]] || return 1
  mode=$(stat -c '%a' "$runner" 2>/dev/null || true)
  case $(uname -s 2>/dev/null) in
    MINGW*|MSYS*) ;;
    *) [[ $mode == 700 ]] || return 1 ;;
  esac
  # Dollar-prefixed names below are literal generated-runner text.
  # shellcheck disable=SC2016
  [[ $(grep -Fxc -- "$identity" "$runner" 2>/dev/null || true) -eq 1 ]] &&
    grep -Fqx -- "$expected_state_dir" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_acme_bin" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_acme_home" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_cert_file" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_state_file" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_identity_file" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_lock_file" "$runner" 2>/dev/null &&
    grep -Fqx -- "  1) [[ \${1-} == --force ]] || exit 2; force=1 ;;" "$runner" 2>/dev/null &&
    grep -Fqx -- '  *) exit 2 ;;' "$runner" 2>/dev/null &&
    grep -Fqx -- 'exec 9> "$lock_file" || exit 1' "$runner" 2>/dev/null &&
    grep -Fqx -- 'if ! flock -n 9; then' "$runner" 2>/dev/null &&
    grep -Fqx -- "  acme_identity=\$(read_runner_acme_identity) || exit 1" "$runner" 2>/dev/null &&
    grep -Fqx -- 'state_read_epoch=$(date +%s) || exit 1' "$runner" 2>/dev/null &&
    grep -Fqx -- '  if [[ -n $previous_renewal ]] && ((previous_renewal <= state_read_epoch)); then' "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_cron_command" "$runner" 2>/dev/null &&
    grep -Fqx -- "$expected_force_command" "$runner" 2>/dev/null &&
    grep -Fqx -- "before_fingerprint=\$(certificate_fingerprint || true)" "$runner" 2>/dev/null &&
    grep -Fqx -- "after_fingerprint=\$(certificate_fingerprint || true)" "$runner" 2>/dev/null &&
    grep -Fqx -- "state_tmp=\$(mktemp \"\$state_dir/.acme_renew.state.XXXXXX\") || exit 1" "$runner" 2>/dev/null &&
    grep -Fq -- "mv -fT -- \"\$state_tmp\" \"\$state_file\"" "$runner" 2>/dev/null &&
    bash -n "$runner" >/dev/null 2>&1
}

write_acme_renew_runner(){
  local runner state identity runner_tmp
  runner=$(acme_renew_runner_path)
  state=$(acme_renew_state_path)
  identity=$(acme_renew_runner_identity)
  if acme_renew_runner_is_current; then
    return 0
  fi
  runner_tmp=$(mktemp "$STATE_DIR/.acme_renew.XXXXXX") || return 1
  if ! {
    printf '%s\n' '#!/bin/bash' "$identity" 'set -u' 'umask 077'
    printf 'state_dir=%q\n' "$STATE_DIR"
    printf 'acme_bin=%q\n' "$ACME_BIN"
    printf 'acme_home=%q\n' "$ACME_HOME"
    printf 'cert_file=%q\n' "${ACME_CERT:-$STATE_DIR/fullchain.pem}"
    printf 'state_file=%q\n' "$state"
    printf 'identity_file=%q\n' "$ACME_IDENTITY"
    printf 'lock_file=%q\n' "$(acme_lock_path)"
    cat <<'ACMERENEW'

certificate_fingerprint(){
  local fingerprint
  [[ -s $cert_file ]] || return 1
  fingerprint=$(sha256sum "$cert_file" 2>/dev/null | awk '{print $1}') || return 1
  [[ $fingerprint =~ ^[0-9a-fA-F]{64}$ ]] || return 1
  printf '%s\n' "${fingerprint,,}"
}

valid_acme_identity(){
  local name=$1 label
  local -a labels
  [[ ${#name} -le 253 && $name == *.* && $name != .* && $name != *. ]] || return 1
  IFS='.' read -r -a labels <<< "$name"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

read_runner_acme_identity(){
  local identity
  local -a identity_lines=()
  [[ -f $identity_file && ! -L $identity_file ]] || return 1
  mapfile -t identity_lines < "$identity_file" || return 1
  [[ ${#identity_lines[@]} -eq 1 ]] || return 1
  identity=${identity_lines[0]}
  valid_acme_identity "$identity" || return 1
  printf '%s\n' "$identity"
}

force=0
case $# in
  0) ;;
  1) [[ ${1-} == --force ]] || exit 2; force=1 ;;
  *) exit 2 ;;
esac
if [[ -e $lock_file || -L $lock_file ]]; then
  [[ -f $lock_file && ! -L $lock_file ]] || exit 1
fi
exec 9> "$lock_file" || exit 1
if ! chmod 600 "$lock_file"; then
  exec 9>&-
  exit 1
fi
if ! flock -n 9; then
  exec 9>&-
  exit 75
fi
if ((force)); then
  acme_identity=$(read_runner_acme_identity) || exit 1
fi

last_renewal_epoch=0
state_read_epoch=$(date +%s) || exit 1
if [[ -f $state_file && ! -L $state_file ]]; then
  previous_renewal=$(awk -F= '$1 == "last_renewal_epoch" && $2 ~ /^[0-9]+$/ &&
    length($2) <= 12 && ($2 == "0" || $2 !~ /^0/) { print $2; exit }' "$state_file" 2>/dev/null)
  if [[ -n $previous_renewal ]] && ((previous_renewal <= state_read_epoch)); then
    last_renewal_epoch=$previous_renewal
  fi
fi

before_fingerprint=$(certificate_fingerprint || true)
if ((force)); then
  HOME="$state_dir" "$acme_bin" --home "$acme_home" --config-home "$acme_home" --renew -d "$acme_identity" --ecc --force
else
  HOME="$state_dir" "$acme_bin" --cron --home "$acme_home" --config-home "$acme_home"
fi
exit_code=$?
after_fingerprint=$(certificate_fingerprint || true)
check_epoch=$(date +%s)

if [[ -n $after_fingerprint && $before_fingerprint != "$after_fingerprint" ]]; then
  last_renewal_epoch=$check_epoch
fi

if ((exit_code != 0)); then
  result=failed
elif [[ -z $after_fingerprint ]]; then
  result=failed
  exit_code=1
elif [[ $before_fingerprint != "$after_fingerprint" ]]; then
  result=renewed
else
  result=unchanged
fi

state_tmp=$(mktemp "$state_dir/.acme_renew.state.XXXXXX") || exit 1
trap 'rm -f -- "$state_tmp"' EXIT
trap 'exit 1' HUP INT TERM
if ! printf '%s\n' \
  "last_check_epoch=$check_epoch" \
  "last_result=$result" \
  "last_exit_code=$exit_code" \
  "last_renewal_epoch=$last_renewal_epoch" \
  "cert_fingerprint=$after_fingerprint" > "$state_tmp" ||
   ! chmod 600 "$state_tmp" ||
   ! mv -fT -- "$state_tmp" "$state_file"; then
  exit 1
fi
trap - EXIT HUP INT TERM
exit "$exit_code"
ACMERENEW
  } > "$runner_tmp" || ! chmod 700 "$runner_tmp" || ! mv -fT -- "$runner_tmp" "$runner"; then
    rm -f "$runner_tmp"
    return 1
  fi
  acme_renew_runner_is_current
}

remove_acme_renew_artifacts(){
  local runner state
  runner=$(acme_renew_runner_path)
  state=$(acme_renew_state_path)
  rm -f "$runner" "$state"
}

acme_renew_artifacts_exist(){
  local runner state
  runner=$(acme_renew_runner_path)
  state=$(acme_renew_state_path)
  [[ -e $runner || -L $runner || -e $state || -L $state ]]
}

remove_acme_renew_cron(){
  local current filtered
  load_current_crontab || return 1
  current=$CURRENT_CRONTAB
  if ! crontab_has_acme_entries "$current"; then
    remove_acme_renew_artifacts
    return
  fi
  filtered=$(printf '%s\n' "$current" | filter_acme_cron_entries || true)
  printf '%s\n' "$filtered" | crontab - >/dev/null 2>&1 || return 1
  load_current_crontab || return 1
  if crontab_has_acme_entries "$CURRENT_CRONTAB"; then
    return 1
  fi
  remove_acme_renew_artifacts
}

setup_acme_renew_cron(){
  local current filtered entry identity
  if ! cron_daemon_is_active; then
    red "cron/crond 服务未运行，拒绝写入无法执行的 ACME 续期任务"
    return 1
  fi
  if ! identity=$(valid_acme_renewal_identity 2>/dev/null); then
    identity=$(recover_acme_renewal_identity 2>/dev/null) || {
      red "ACME 身份、证书或域名配置校验失败，无法修复自动续期"
      return 1
    }
  fi
  dns_provider_credentials_present || return 1
  write_acme_reload_hook || return 1
  if ! managed_acme_live_layout_is_valid ||
     ! acme_deployment_config_is_current "$identity"; then
    yellow "正在把 ACME 证书迁移到原子部署模式……"
    register_acme_certificate_deployment "$identity" 0 || return 1
  fi
  identity=$(valid_acme_renewal_identity 2>/dev/null) || return 1
  acme_deployment_config_is_current "$identity" || return 1
  write_acme_renew_runner || return 1
  load_current_crontab || return 1
  current=$CURRENT_CRONTAB
  filtered=$(printf '%s\n' "$current" | filter_acme_cron_entries || true)
  entry=$(acme_renew_cron_entry)
  { printf '%s\n' "$filtered"; printf '%s\n' "$entry"; } | crontab - >/dev/null 2>&1 || return 1
  load_current_crontab || return 1
  acme_renew_runner_is_current && acme_renew_cron_is_current "$CURRENT_CRONTAB"
}

ensure_acme_renew_cron(){
  if acme_renew_artifacts_exist; then
    setup_acme_renew_cron
  else
    return 0
  fi
}
