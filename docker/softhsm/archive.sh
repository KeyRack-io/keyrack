#!/bin/sh
set -eu
umask 077
# Called under the same exclusive writer lock as the service and initializer.
mode=$1
archive=$2
case "$archive" in
  /backup/*.tar) ;;
  *) echo 'Archive must be a .tar path under /backup' >&2; exit 2 ;;
esac
case "$archive" in *..*) echo 'Archive traversal is forbidden' >&2; exit 2 ;; esac
case "$mode" in
  backup)
    [ -f /var/lib/keyrack/metadata/keyrack.db ] || { echo 'No metadata database to back up' >&2; exit 1; }
    [ ! -e "$archive" ] || { echo 'Refusing to overwrite an archive' >&2; exit 1; }
    tar -C /var/lib/keyrack -cpf "$archive" metadata tokens
    ;;
  restore)
    [ -f "$archive" ]
    [ -z "$(find /var/lib/keyrack/metadata /var/lib/keyrack/tokens -mindepth 1 -print -quit)" ] || {
      echo 'Restore requires an empty destination; existing data is never overwritten' >&2; exit 1;
    }
    # Operator-supplied trusted archive only. Permit the two profile directories.
    tar -tf "$archive" | while IFS= read -r entry; do
      case "$entry" in metadata/|metadata/*|tokens/|tokens/*) ;; *) exit 1 ;; esac
      case "$entry" in *../*|*/..|/*) exit 1 ;; esac
    done
    tar -C /var/lib/keyrack --no-same-owner -xpf "$archive"
    ;;
  *) exit 2 ;;
esac
