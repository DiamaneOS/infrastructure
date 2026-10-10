# SPDX-License-Identifier: Apache-2.0
# Shared helpers for the apply scripts.

# install_tree SRC: copy every file under SRC to the same path under /.
# Programs under usr/local/{bin,sbin} and letsencrypt hooks are executable.
install_tree() {
  local src=$1 rel mode
  (cd "$src" && find . -type f | sed 's|^\./||') | while read -r rel; do
    case $rel in
      usr/local/bin/*|usr/local/sbin/*|etc/letsencrypt/renewal-hooks/*) mode=0755 ;;
      *) mode=0644 ;;
    esac
    install -D -o root -g root -m "$mode" "$src/$rel" "/$rel"
  done
}

# system_user NAME [GROUPS]: an unprivileged system account without a shell or home.
system_user() {
  id -u "$1" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin "$1"
  [ "$(id -u "$1")" -ne 0 ] || { echo "service account must not be root" >&2; exit 1; }
  if [ -n "${2:-}" ]; then usermod -a -G "$2" "$1"; fi
}

# Package post-install scripts must not expose a default web server before its
# privacy policy, virtual hosts and firewall are installed. Respect an existing
# start policy; otherwise inhibit starts just for this operation.
apt_install() (
  if [ ! -e /usr/sbin/policy-rc.d ]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 0755 /usr/sbin/policy-rc.d
    trap 'rm -f /usr/sbin/policy-rc.d' EXIT
  fi
  apt-get install -y -q --no-install-recommends "$@"
)
