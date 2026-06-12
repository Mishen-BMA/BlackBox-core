#!/usr/bin/env sh
set -eu

backup_dir="backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
cp -R data logs "$backup_dir"
echo "Backup written to $backup_dir"

