#!/bin/sh
set -eu
umask 077
# RWO alone permits multiple pods on one node. Keep this lock for the entire
# init/service/archive process; --no-fork preserves signal delivery to service.
[ "$(id -u)" != 0 ] || { echo 'Refusing root: use UID/GID 10001' >&2; exit 1; }
[ "$#" -ge 1 ] || { echo 'Expected serve, init, backup or restore' >&2; exit 2; }
mkdir -p /var/lib/keyrack/metadata /var/lib/keyrack/tokens
mode=$1
shift
case "$mode" in
  serve) [ "$#" -eq 0 ]; set -- keyrack-service ;;
  init) [ "$#" -eq 0 ]; set -- keyrack-softhsm-init ;;
  backup|restore) [ "$#" -eq 1 ]; set -- keyrack-softhsm-archive "$mode" "$1" ;;
  *) echo 'Expected serve, init, backup or restore' >&2; exit 2 ;;
esac
exec flock --nonblock --conflict-exit-code 75 --no-fork /var/lib/keyrack/.writer.lock "$@"
