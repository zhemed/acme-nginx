# acme-nginx-module: 90-main
# Command-line entry (no interactive panel)
usage(){
  cat <<'USAGE'
用法: acme-nginx <命令>

命令:
  install       安装固定版本 acme.sh，并生成 /etc/acme-nginx.conf 配置模板
  issue         读取配置并首次签发证书（已有有效证书时提示使用 renew/force-renew）
  renew         续期检查（cron 使用；证书变化后自动 reload nginx）
  force-renew   强制重新签发当前证书并 reload nginx
  status        显示证书与自动续期状态
  uninstall     移除 cron、续期检查器、证书与状态（含配置文件）
  -h|--help     显示本帮助
USAGE
}

cmd_install(){
  if ! core_dependencies_ready; then
    red "缺少必要命令，请先安装依赖（awk curl flock jq openssl crontab 等）"
    return 1
  fi
  prepare_state_dir || { red "初始化状态目录失败：$STATE_DIR"; return 1; }
  if ! config_is_present; then
    write_config_template || { red "生成配置模板失败"; return 1; }
    yellow "已生成配置模板：$CONFIG_FILE"
    yellow "请填写 DNS_PROVIDER、DOMAIN 与对应供应商凭据后运行 acme-nginx issue"
  else
    load_config || { red "配置文件格式或权限异常：$CONFIG_FILE"; return 1; }
    blue "配置文件校验通过：供应商 ${DNS_PROVIDER:-cloudflare}，主域名 $ACME_PRIMARY_DOMAIN"
    [[ -n $ACME_WILDCARD_DOMAIN ]] && blue "同时申请泛域名：$ACME_WILDCARD_DOMAIN"
  fi
  install_official_acme || return 1
  green "acme.sh v${ACME_VERSION} 安装完成"
}

cmd_issue(){
  if ! core_dependencies_ready; then
    red "缺少必要命令，请先安装依赖"
    return 1
  fi
  if ! config_is_present || ! load_config; then
    red "配置文件缺失或无效：$CONFIG_FILE（先运行 acme-nginx install 生成模板）"
    return 1
  fi
  prepare_state_dir || { red "初始化状态目录失败：$STATE_DIR"; return 1; }
  if identity=$(read_acme_identity 2>/dev/null) &&
     load_certificate_metadata "$ACME_CERT" "$ACME_KEY" 2>/dev/null &&
     [[ $CERT_META_STATE == valid ]] &&
     certificate_identity_matches "$ACME_CERT" "$identity"; then
    yellow "已存在有效证书（$identity），无需重复签发；如需重签请运行 acme-nginx force-renew"
    return 0
  fi
  if ! with_acme_lock issue_certificate; then
    return 1
  fi
  if ! with_acme_lock setup_acme_renew_cron; then
    yellow "证书已签发，但自动续期任务设置失败，请检查 root crontab 与 cron 服务"
  else
    green "自动续期任务已安装（每天 03:17 / 09:17 / 15:17 / 21:17 检查）"
  fi
  green "签发完成。Nginx 可引用："
  printf '  ssl_certificate     %s;\n' "$ACME_CERT"
  printf '  ssl_certificate_key %s;\n' "$ACME_KEY"
}

cmd_renew(){
  if ! core_dependencies_ready; then
    red "缺少必要命令，请先安装依赖"
    return 1
  fi
  if ! config_is_present || ! load_config; then
    red "配置文件缺失或无效：$CONFIG_FILE"
    return 1
  fi
  prepare_state_dir || { red "初始化状态目录失败：$STATE_DIR"; return 1; }
  if ! with_acme_lock setup_acme_renew_cron; then
    red "自动续期组件修复失败，无法执行检查"
    return 1
  fi
  local runner
  runner=$(acme_renew_runner_path) || return 1
  green "正在执行 ACME 续期检查；未到计划时间时不会重复签发……"
  if "$runner"; then
    green "续期检查完成"
  else
    red "续期检查失败，请查看上方 acme.sh 输出"
    return 1
  fi
}

nginx_running(){
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl is-active --quiet nginx
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service nginx status >/dev/null 2>&1
  else
    return 1
  fi
}

cmd_force_renew(){
  if ! core_dependencies_ready; then
    red "缺少必要命令，请先安装依赖"
    return 1
  fi
  if ! config_is_present || ! load_config; then
    red "配置文件缺失或无效：$CONFIG_FILE"
    return 1
  fi
  prepare_state_dir || { red "初始化状态目录失败：$STATE_DIR"; return 1; }
  if ! with_acme_lock setup_acme_renew_cron; then
    red "自动续期组件修复失败，无法执行强制重签"
    return 1
  fi
  local runner
  runner=$(acme_renew_runner_path) || return 1
  yellow "强制重签会立即联系 Let's Encrypt，并计入证书签发频率限制"
  green "正在强制重新签发当前证书……"
  if ! "$runner" --force; then
    red "强制重签失败，请查看上方 acme.sh 输出"
    return 1
  fi
  if ! load_acme_renew_state || [[ $ACME_RENEW_LAST_RESULT != renewed ]]; then
    red "重签命令已结束，但托管证书没有发生变化，不能确认重签成功"
    return 1
  fi
  if nginx_running; then
    green "证书已重新签发，nginx 已通过回调 reload 并加载新证书"
  else
    yellow "证书已重新签发；nginx 当前未运行，下次启动时会加载新证书"
  fi
}

inspect_acme_renewal_health(){
  local current state now identity reference_epoch
  ACME_RENEW_HEALTH=normal
  ACME_RENEW_HEALTH_DETAIL=正常
  local plugin
  if ! plugin=$(dns_provider_plugin_file) ||
     [[ ! -x $ACME_BIN || ! -f $ACME_HOME/dnsapi/$plugin || ! -s $ACME_IDENTITY ]]; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="acme.sh 组件不完整"
  elif ! dns_provider_credentials_present; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="DNS 供应商凭据缺失或格式异常"
  elif ! identity=$(read_acme_identity 2>/dev/null); then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="ACME 身份文件损坏"
  elif ! load_certificate_metadata "$ACME_CERT" "$ACME_KEY" ||
       [[ $CERT_META_STATE != valid ]] ||
       ! certificate_identity_matches "$ACME_CERT" "$identity"; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="当前证书无效或未覆盖 ACME 身份"
  elif ! load_acme_certificate_schedule "$identity"; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="ACME 域名配置或续期时间记录异常"
  elif ! managed_acme_live_layout_is_valid; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="证书原子部署目录或 current 指针异常"
  elif ! acme_deployment_config_is_current "$identity"; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="acme.sh 部署目标不是受管暂存目录"
  elif ! cron_daemon_is_active; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="cron/crond 未运行"
  elif ! acme_reload_hook_is_current; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="证书生效回调缺失或过期"
  elif ! acme_renew_runner_is_current; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="续期检查器缺失或过期"
  elif ! load_current_crontab; then
    ACME_RENEW_HEALTH=error
    ACME_RENEW_HEALTH_DETAIL="无法读取 root crontab"
  else
    current=$CURRENT_CRONTAB
    if ! acme_renew_cron_is_current "$current"; then
      ACME_RENEW_HEALTH=error
      ACME_RENEW_HEALTH_DETAIL="定时任务缺失或不规范"
    fi
  fi
  if [[ $ACME_RENEW_HEALTH == normal ]]; then
    state=$(acme_renew_state_path)
    if load_acme_renew_state; then
      now=$(date +%s 2>/dev/null || true)
      if [[ $ACME_RENEW_LAST_RESULT == failed ]]; then
        ACME_RENEW_HEALTH=error
        ACME_RENEW_HEALTH_DETAIL="最近一次检查失败，退出码 $ACME_RENEW_LAST_EXIT_CODE"
      elif [[ $now =~ ^[0-9]+$ ]] && ((now - ACME_RENEW_LAST_CHECK_EPOCH > 86400)); then
        ACME_RENEW_HEALTH=error
        ACME_RENEW_HEALTH_DETAIL="超过 24 小时没有成功检查"
      elif [[ $now =~ ^[0-9]+$ ]] && ((ACME_RENEW_LAST_CHECK_EPOCH > now + 300)); then
        ACME_RENEW_HEALTH=error
        ACME_RENEW_HEALTH_DETAIL="最近检查时间晚于系统时间"
      fi
    elif [[ -e $state || -L $state ]]; then
      ACME_RENEW_HEALTH=error
      ACME_RENEW_HEALTH_DETAIL="续期状态记录损坏或权限异常"
    else
      now=$(date +%s 2>/dev/null || true)
      reference_epoch=${ACME_META_DEPLOYED_EPOCH:-$ACME_META_CREATED_EPOCH}
      if [[ $now =~ ^[0-9]+$ && $reference_epoch =~ ^[0-9]+$ ]] &&
         ((now - reference_epoch > 28800)); then
        ACME_RENEW_HEALTH=error
        ACME_RENEW_HEALTH_DETAIL="证书部署超过 8 小时但没有续期检查记录"
      fi
    fi
  fi
}

cmd_status(){
  local identity
  if ! identity=$(read_acme_identity 2>/dev/null); then
    red "尚未找到 ACME 身份，证书可能未签发"
    return 1
  fi
  show_certificate_metadata "Let's Encrypt (acme-nginx)" "$ACME_CERT" "$ACME_KEY" "$identity"
  show_acme_certificate_schedule "$identity" || true
  printf 'Nginx 引用路径: %s / %s\n' "$ACME_CERT" "$ACME_KEY"
  printf '定时检查: 每天 03:17 / 09:17 / 15:17 / 21:17（服务器时间）\n'
  inspect_acme_renewal_health
  if [[ $ACME_RENEW_HEALTH == normal ]]; then
    green "自动续期: 正常"
  else
    red "自动续期: 异常（$ACME_RENEW_HEALTH_DETAIL）"
  fi
  if load_acme_renew_state; then
    printf '最近自动检查: %s\n' "$ACME_RENEW_LAST_CHECK"
    case $ACME_RENEW_LAST_RESULT in
      renewed) green "最近检查结果: 已续期并执行证书生效回调" ;;
      unchanged) green "最近检查结果: 成功，暂不需要续期" ;;
      failed) red "最近检查结果: 失败（退出码 $ACME_RENEW_LAST_EXIT_CODE）" ;;
    esac
    if [[ $ACME_RENEW_LAST_RENEWAL_EPOCH != 0 ]]; then
      printf '最近自动续期: %s\n' "$ACME_RENEW_LAST_RENEWAL"
    fi
  else
    if [[ -e $(acme_renew_state_path) || -L $(acme_renew_state_path) ]]; then
      red "最近自动检查: 状态记录损坏或权限异常"
    else
      yellow "最近自动检查: 暂无记录"
    fi
  fi
  if nginx_running; then
    green "续期生效方式: 成功续期后自动 reload nginx"
  else
    yellow "续期生效方式: nginx 当前未运行，续期不会强制启动"
  fi
}

cmd_uninstall(){
  if ! with_acme_lock remove_acme_renew_cron; then
    red "移除续期定时任务失败"
    return 1
  fi
  local path failed=0
  for path in "$ACME_LIVE" "$ACME_HOME" "$ACME_CERT" "$ACME_KEY" \
              "$ACME_IDENTITY" "$ACME_RELOAD" "$STATE_DIR" "$CONFIG_FILE"; do
    if [[ -e $path || -L $path ]]; then
      rm -rf -- "$path" || failed=1
    fi
  done
  if [[ $failed -eq 0 ]]; then
    green "acme-nginx 已卸载：cron、证书、状态与配置均已移除"
  else
    red "卸载不完整，请手动检查 $STATE_DIR 与 $CONFIG_FILE"
    return 1
  fi
}

main(){
  case ${1-} in
    install) shift; cmd_install ;;
    issue) shift; cmd_issue ;;
    renew) shift; cmd_renew ;;
    force-renew) shift; cmd_force_renew ;;
    status) shift; cmd_status ;;
    uninstall) shift; cmd_uninstall ;;
    -h|--help|help) usage ;;
    -V|--version) printf 'acme-nginx %s\n' "$acme_nginx_version" ;;
    *) usage >&2; exit 2 ;;
  esac
}

# acme-nginx-entrypoint
main "$@"
