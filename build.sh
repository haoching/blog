#!/usr/bin/env bash
set -euo pipefail

required_hugo="0.164.0"
hugo_bin="${HUGO_BIN:-hugo}"
actual_hugo="$("${hugo_bin}" version | sed -n 's/^hugo v\([0-9.]*\).*/\1/p')"
if [[ "${actual_hugo}" != "${required_hugo}" ]]; then
  echo "Expected Hugo ${required_hugo}, found ${actual_hugo:-unknown}" >&2
  exit 1
fi

git config core.quotepath false
"${hugo_bin}" mod get
"${hugo_bin}" --gc --minify --environment production
