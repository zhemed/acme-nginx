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
[[ $(grep -Fxc 'acme_nginx_version="v0.1.0"' "$ROOT_DIR/acme-nginx.sh" || true) -eq 1 ]] ||
  fail "script version is not 0.1.0"
[[ $(tr -d '\r\n' < "$ROOT_DIR/VERSION") == '0.1.0' ]] ||
  fail "VERSION file is not 0.1.0"
grep -Fq -- "当前版本：0.1.0" "$ROOT_DIR/README.md" ||
  fail "README project version is not 0.1.0"

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
  '17 3,9,15,21 * * *'; do
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
if grep -Fq -- 'readp' "$ROOT_DIR/acme-nginx.sh"; then
  fail "interactive panel prompt remains"
fi
if grep -Fq -- 'menu(){' "$ROOT_DIR/acme-nginx.sh"; then
  fail "interactive menu remains"
fi

for config_key in CF_ACCOUNT_ID CF_TOKEN DOMAIN WILDCARD; do
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
    "$ROOT_DIR/scripts/build.sh" "$ROOT_DIR/tests/unit.sh" "$ROOT_DIR/tests/verify.sh"
else
  printf 'verify: shellcheck not found; static lint skipped\n' >&2
fi

bash "$ROOT_DIR/tests/unit.sh"

digest=$(sha256sum "$ROOT_DIR/acme-nginx.sh" | awk '{print $1}')
printf 'verification passed: %s\n' "$digest"
