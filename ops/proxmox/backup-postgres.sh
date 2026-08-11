#!/bin/sh
set -eu

umask 077

stack_dir=/opt/blog-v2/ops/hedgedoc
backup_dir=/opt/blog-v2/ops/hedgedoc/backups/postgres

mkdir -p "$backup_dir"
resolved_backup_dir=$(readlink -f "$backup_dir")
if [ "$resolved_backup_dir" != "$backup_dir" ] || [ -L "$backup_dir" ]; then
  echo "Unsafe backup directory: $resolved_backup_dir" >&2
  exit 1
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
hedgedoc_tmp="$backup_dir/hedgedoc-$stamp.dump.tmp"
publisher_tmp="$backup_dir/publisher-$stamp.dump.tmp"
hedgedoc_dump=${hedgedoc_tmp%.tmp}
publisher_dump=${publisher_tmp%.tmp}

cleanup() {
  rm -f -- "$hedgedoc_tmp" "$publisher_tmp"
}
trap cleanup EXIT HUP INT TERM

cd "$stack_dir"
docker compose exec -T database pg_dump -U hedgedoc -d hedgedoc --format=custom >"$hedgedoc_tmp"
docker compose exec -T publisher_database pg_dump -U publisher -d publisher --format=custom >"$publisher_tmp"

test -s "$hedgedoc_tmp"
test -s "$publisher_tmp"
mv "$hedgedoc_tmp" "$hedgedoc_dump"
mv "$publisher_tmp" "$publisher_dump"

# These dumps are included in the 03:30 LXC backup. Keep five weeks locally;
# Proxmox applies the authoritative 7 daily / 4 weekly snapshot retention.
find "$backup_dir" -maxdepth 1 -type f -name '*.dump' -mtime +35 -print -delete

printf 'Created %s and %s\n' "$hedgedoc_dump" "$publisher_dump"
