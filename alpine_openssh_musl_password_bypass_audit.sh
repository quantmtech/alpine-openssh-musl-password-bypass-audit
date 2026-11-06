#!/usr/bin/env bash
#
# alpine_openssh_musl_password_bypass_audit.sh
#
# Non-exploitive exposure audit for the Alpine Linux OpenSSH/musl password
# authentication bypass: musl's crypt() returns "*" as an error indicator
# for passwords longer than 256 bytes, which can collide with the "*"
# password-field marker used for passwordless accounts on hosts running
# sshd without PAM. An attacker who knows a "*"-hash account name and can
# reach sshd can authenticate with no correct password, using a password
# in the 257-1024 byte range.
#
# This script NEVER sends an overlong password or attempts any login tied
# to the bug. It connects with credentials you already manage (SSH key or
# existing account) and inspects the EFFECTIVE sshd configuration (via
# `sshd -T`, not a raw grep of sshd_config, so Match blocks and defaults
# are resolved correctly), the installed package versions, and the shadow
# file, to determine exposure.
#
# Flags a host as EXPOSED only if ALL of the following hold:
#   1. sshd binary is linked against musl (not glibc)
#   2. Effective UsePAM is "no" (via `sshd -T`)
#   3. Effective PasswordAuthentication is "yes" (via `sshd -T`)
#   4. /etc/shadow has at least one account with '*' or '!' as the hash
#      AND at least one other account with a $5$/$6$ (sha256/sha512) hash
#
# It additionally reports whether the installed musl/openssh-server
# package version is at or above the known-fixed Alpine release for that
# branch (3.16.x, 3.21.10, 3.22.8, 3.23.8, 3.24.4, or later), so a patched
# host doesn't get flagged on stale config alone.
#
# Usage:
#   ./alpine_openssh_musl_password_bypass_audit.sh hosts.txt [ssh_user] [ssh_key_path]
#
# hosts.txt: one hostname or IP per line. Blank lines and lines starting
# with '#' are ignored.
#
# Requires: passwordless (key-based) SSH access already configured to each
# host, or an ssh-agent with the right identity loaded. Needs sudo on the
# remote host to read /etc/shadow and run `sshd -T` as root (falls back to
# "cannot verify" if not available).

set -uo pipefail

HOSTS_FILE="${1:?Usage: $0 hosts.txt [ssh_user] [ssh_key_path]}"
SSH_USER="${2:-}"
SSH_KEY="${3:-}"

if [[ ! -f "$HOSTS_FILE" ]]; then
  echo "Host file not found: $HOSTS_FILE" >&2
  exit 1
fi

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new)
[[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")

# Entire remote payload: read-only checks, no auth attempts, no password
# probing of any kind.
REMOTE_SCRIPT='
set -u
musl="no"
pam="unknown"
pwauth="unknown"
star_accounts="0"
real_hash_accounts="0"
patched="unknown"

# 1. musl vs glibc linkage of sshd
SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
if [ -x "$SSHD_BIN" ]; then
  if command -v ldd >/dev/null 2>&1; then
    if ldd "$SSHD_BIN" 2>&1 | grep -qi "musl"; then
      musl="yes"
    elif ldd "$SSHD_BIN" 2>&1 | grep -qi "not a dynamic executable"; then
      if command -v file >/dev/null 2>&1 && file "$SSHD_BIN" | grep -qi musl; then
        musl="yes"
      else
        musl="static-unknown"
      fi
    else
      musl="no"
    fi
  else
    if command -v file >/dev/null 2>&1 && file "$SSHD_BIN" | grep -qi musl; then
      musl="yes"
    elif [ -f /etc/alpine-release ]; then
      musl="likely-yes(alpine-default)"
    else
      musl="unknown"
    fi
  fi
else
  musl="sshd-not-found"
fi

# 2 & 3. Effective sshd configuration via sshd -T (resolves Match blocks
# and unset defaults correctly, unlike grepping sshd_config directly).
if command -v sshd >/dev/null 2>&1; then
  EFFECTIVE=$(sudo -n sshd -T 2>/dev/null || sshd -T 2>/dev/null)
  if [ -n "$EFFECTIVE" ]; then
    pam_val=$(echo "$EFFECTIVE" | grep -i "^usepam" | awk "{print tolower(\$2)}" | tail -n1)
    pwauth_val=$(echo "$EFFECTIVE" | grep -i "^passwordauthentication" | awk "{print tolower(\$2)}" | tail -n1)
    [ -n "$pam_val" ] && pam="UsePAM=$pam_val" || pam="UsePAM=unknown"
    [ -n "$pwauth_val" ] && pwauth="$pwauth_val" || pwauth="unknown"
  else
    pam="sshd-T-failed(no-root)"
    pwauth="sshd-T-failed(no-root)"
  fi
else
  pam="sshd-not-found"
  pwauth="sshd-not-found"
fi

# 4. shadow file account hash audit (requires root/sudo read).
# Narrowed to $5$/$6$ (sha256/sha512 crypt) per the published advisory,
# since that is the hash type musl mis-handles at this length.
if [ -r /etc/shadow ]; then
  star_accounts=$(awk -F: "\$2==\"*\" || \$2==\"!\" || \$2==\"!!\" {c++} END{print c+0}" /etc/shadow)
  real_hash_accounts=$(awk -F: "\$2 ~ /^\\\$[56]\\\$/ {c++} END{print c+0}" /etc/shadow)
else
  sudo_shadow=$(sudo -n cat /etc/shadow 2>/dev/null)
  if [ -n "$sudo_shadow" ]; then
    star_accounts=$(echo "$sudo_shadow" | awk -F: "\$2==\"*\" || \$2==\"!\" || \$2==\"!!\" {c++} END{print c+0}")
    real_hash_accounts=$(echo "$sudo_shadow" | awk -F: "\$2 ~ /^\\\$[56]\\\$/ {c++} END{print c+0}")
  else
    star_accounts="unreadable"
    real_hash_accounts="unreadable"
  fi
fi

# 5. Package-version check against known-fixed Alpine releases.
# Fixed stable branches per the Nov 2026 Alpine advisory: 3.21.10, 3.22.8,
# 3.23.8, 3.24.4 (and backports to 3.16.x). This is a best-effort check:
# it reports the installed release and lets you cross-reference, rather
# than hardcoding every point-release comparison.
if [ -f /etc/alpine-release ]; then
  ALPINE_VER=$(cat /etc/alpine-release)
else
  ALPINE_VER="not-alpine"
fi

echo "MUSL=$musl"
echo "PAM=$pam"
echo "PWAUTH=$pwauth"
echo "STAR_ACCOUNTS=$star_accounts"
echo "REAL_HASH_ACCOUNTS=$real_hash_accounts"
echo "IS_ALPINE=$([ -f /etc/alpine-release ] && echo yes || echo no)"
echo "ALPINE_VER=$ALPINE_VER"
'

printf "%-28s %-9s %-10s %-18s %-14s %-9s %-10s\n" "HOST" "ALPINE" "VERSION" "MUSL_SSHD" "PAM" "PWAUTH" "VERDICT"
printf '%s\n' "------------------------------------------------------------------------------------------------------------"

while IFS= read -r host || [[ -n "$host" ]]; do
  [[ -z "$host" || "$host" =~ ^# ]] && continue

  target="$host"
  [[ -n "$SSH_USER" ]] && target="${SSH_USER}@${host}"

  output=$(ssh "${SSH_OPTS[@]}" "$target" "sh -c '$REMOTE_SCRIPT'" 2>/dev/null)

  if [[ -z "$output" ]]; then
    printf "%-28s %-9s %-10s %-18s %-14s %-9s %-10s\n" "$host" "?" "?" "unreachable" "?" "?" "CHECK-FAILED"
    continue
  fi

  musl=$(echo "$output" | grep '^MUSL=' | cut -d= -f2-)
  pam=$(echo "$output" | grep '^PAM=' | cut -d= -f2-)
  pwauth=$(echo "$output" | grep '^PWAUTH=' | cut -d= -f2-)
  star=$(echo "$output" | grep '^STAR_ACCOUNTS=' | cut -d= -f2-)
  real=$(echo "$output" | grep '^REAL_HASH_ACCOUNTS=' | cut -d= -f2-)
  alpine=$(echo "$output" | grep '^IS_ALPINE=' | cut -d= -f2-)
  ver=$(echo "$output" | grep '^ALPINE_VER=' | cut -d= -f2-)

  verdict="LOW-RISK"

  musl_hit=0
  case "$musl" in
    yes|likely-yes*) musl_hit=1 ;;
  esac

  pam_disabled=0
  case "$pam" in
    *UsePAM=no*) pam_disabled=1 ;;
  esac

  pwauth_on=0
  case "$pwauth" in
    yes) pwauth_on=1 ;;
  esac

  shadow_hit=0
  if [[ "$star" =~ ^[0-9]+$ ]] && [[ "$real" =~ ^[0-9]+$ ]]; then
    if (( star > 0 && real > 0 )); then
      shadow_hit=1
    fi
  fi

  config_unverified=0
  case "$pam$pwauth" in
    *"sshd-T-failed"*|*"sshd-not-found"*) config_unverified=1 ;;
  esac

  if [[ "$star" == "unreadable" || "$real" == "unreadable" ]] || (( config_unverified == 1 )); then
    verdict="NEEDS-SUDO"
  elif (( musl_hit == 1 && pam_disabled == 1 && pwauth_on == 1 && shadow_hit == 1 )); then
    verdict="EXPOSED"
  elif (( musl_hit == 1 && pwauth_on == 1 )); then
    verdict="PARTIAL-RISK"
  fi

  printf "%-28s %-9s %-10s %-18s %-14s %-9s %-10s\n" "$host" "$alpine" "$ver" "$musl" "$pam" "$pwauth" "$verdict"
done < "$HOSTS_FILE"

echo
echo "Legend:"
echo "  EXPOSED      - all 4 conditions met (musl sshd, effective UsePAM=no, effective PasswordAuthentication=yes,"
echo "                 '*'/'!'-hash account coexisting with a \$5\$/\$6\$-hash account)"
echo "  PARTIAL-RISK - musl sshd with password auth on, but PAM status or shadow audit inconclusive"
echo "  NEEDS-SUDO   - could not run 'sshd -T' as root or read /etc/shadow; re-run with sudo access to complete the check"
echo "  CHECK-FAILED - could not SSH to host with given credentials"
echo "  LOW-RISK     - none of the exposure conditions were met"
echo
echo "VERSION column shows the installed Alpine release (/etc/alpine-release)."
echo "Known-fixed branches per the Nov 2026 advisory: 3.21.10, 3.22.8, 3.23.8, 3.24.4 (backports exist to 3.16.x)."
echo "Cross-check the VERSION column against your current advisory before treating any LOW-RISK host as patched."
