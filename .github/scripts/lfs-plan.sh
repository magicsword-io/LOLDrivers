#!/usr/bin/env bash
# Decide which Git LFS objects a workflow job should download.
#
# LFS tracking is the wildcard in drivers/.gitattributes (`*.bin`), read via
# `git check-attr filter`. This script does not download objects.
#
# Policies:
#   metadata   YAML/filename checks. Always hydrate the two real samples the
#              native unit test reads, plus any LFS paths this change edits
#              so those filenames are checked against file bytes.
#   indicator  Same samples, plus a native corpus scan when it needs bytes.
#   rules      Malicious-rule byte scan only (no unit-test samples).
#
# Scan results:
#   all        Every sample must be hydrated. Default YARA validator.
#   partial    Changed drivers (and the unit-test samples, for indicator)
#              are hydrated. The validator must be passed --allow-unhydrated.
#   skip       No corpus scan. Pointer checks still run in other steps.
#
# Usage:
#   lfs-plan.sh --policy metadata|indicator|rules \
#               --event pull_request|push|merge_group \
#               --ref refs/heads/main \
#               --base <sha-or-empty> --head <sha>
#
# Writes fetch, scan, and include to $GITHUB_OUTPUT when set, and prints the
# same KEY=value lines on stdout.

set -euo pipefail

policy=""
event=""
ref=""
base=""
head="HEAD"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --policy) policy="$2"; shift 2 ;;
    --event) event="$2"; shift 2 ;;
    --ref) ref="$2"; shift 2 ;;
    --base) base="$2"; shift 2 ;;
    --head) head="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$policy" in
  metadata|indicator|rules) ;;
  *) echo "Unknown policy: ${policy:-<empty>}" >&2; exit 2 ;;
esac

# CatalogEngineControls.test_real_affected_driver_and_unrelated_product_from_same_leaf_signer
# matches these two hydrated samples (WDTKernel vs CPUID, same leaf signer).
required_bins=(
  drivers/3a00cd7cb37b2b4bfaa9e7715fdd13d5.bin
  drivers/8ff0f73158ec15de8e548b00608c5822.bin
)

safe_lfs_path() {
  [[ "$1" =~ ^drivers/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$ ]]
}

# Paths whose bytes the native rule scan must see. README and the pip pin
# do not change match behavior.
rules_changed() {
  local path diff_file
  diff_file="$(mktemp)"
  # 0 = rule bytes changed, 1 = no, 2 = diff failed.
  if ! git diff --name-only --diff-filter=ACMRT "$base" "$head" -- detections/yara bin/yara-generator > "$diff_file"; then
    rm -f "$diff_file"
    return 2
  fi
  while IFS= read -r path; do
    case "$path" in
      ""|bin/yara-generator/README.md|bin/yara-generator/requirements.txt) continue ;;
      detections/yara/*|bin/yara-generator/*) rm -f "$diff_file"; return 0 ;;
    esac
  done < "$diff_file"
  rm -f "$diff_file"
  return 1
}

# LFS-tracked paths added or edited between the two trees. Deletions are
# omitted. `git check-attr` applies drivers/.gitattributes, including nested
# `*.bin` files.
changed=()
read_changed_paths() {
  local file
  file="$(mktemp)"
  if ! lfs_changed_paths > "$file"; then
    rm -f "$file"
    return 1
  fi
  changed=()
  mapfile -t changed < "$file"
  rm -f "$file"
}

lfs_changed_paths() {
  local diff_file status
  diff_file="$(mktemp)"
  if ! git diff --name-only --diff-filter=ACMRT -z "$base" "$head" > "$diff_file"; then
    rm -f "$diff_file"
    return 1
  fi
  if [ ! -s "$diff_file" ]; then
    rm -f "$diff_file"
    return 0
  fi
  # Called from `if`, so set -e will not stop the pipeline. Capture its status.
  status=0
  git check-attr -z --stdin filter < "$diff_file" | python3 -c '
import sys
data = sys.stdin.buffer.read().split(b"\0")
if data and data[-1] == b"":
    data = data[:-1]
if len(data) % 3:
    sys.stderr.write("unexpected git check-attr output\n")
    sys.exit(1)
for index in range(0, len(data), 3):
    path, attr, value = data[index:index + 3]
    if attr == b"filter" and value == b"lfs":
        sys.stdout.buffer.write(path + b"\n")
' || status=$?
  rm -f "$diff_file"
  return "$status"
}

needs_full_corpus() {
  case "$event" in
    merge_group) return 0 ;;
    push) [ "$ref" = "refs/heads/main" ] ;;
    *) return 1 ;;
  esac
}

require_base() {
  if [ -z "$base" ] || ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
    echo "Base commit is not available; cannot tell which LFS objects changed." >&2
    exit 1
  fi
}

paths=()
scan="skip"
full=false

if [ "$policy" = "metadata" ] || [ "$policy" = "indicator" ]; then
  paths=("${required_bins[@]}")
fi

if [ "$policy" != "metadata" ] && needs_full_corpus; then
  # Push to main and the merge queue keep the full native scan.
  full=true
elif [ "$policy" != "metadata" ]; then
  require_base
  rule_status=0
  rules_changed || rule_status=$?
  if [ "$rule_status" -eq 0 ]; then
    # Rule or generator changes have to be matched against every sample.
    full=true
  elif [ "$rule_status" -ne 1 ]; then
    echo "Could not diff YARA rule paths." >&2
    exit 1
  else
    read_changed_paths
    if [ "${#changed[@]}" -gt 0 ]; then
      scan="partial"
      for path in "${changed[@]}"; do
        if ! safe_lfs_path "$path"; then
          echo "::error::Refusing to build a Git LFS include from unexpected path: $path" >&2
          exit 1
        fi
        paths+=("$path")
      done
    fi
  fi
elif [ -n "$base" ]; then
  # Metadata jobs can still hash changed driver bytes. A missing base is not
  # fatal: pointer checks cover the rest of the tree.
  if git cat-file -e "${base}^{commit}" 2>/dev/null; then
    read_changed_paths
    for path in "${changed[@]}"; do
      if ! safe_lfs_path "$path"; then
        echo "::error::Refusing to build a Git LFS include from unexpected path: $path" >&2
        exit 1
      fi
      paths+=("$path")
    done
  fi
fi

fetch="none"
include=""
if [ "$full" = true ]; then
  fetch="all"
  scan="all"
elif [ "${#paths[@]}" -gt 0 ]; then
  include="$(printf '%s\n' "${paths[@]}" | LC_ALL=C sort -u | paste -sd, -)"
  fetch="include"
fi

emit() {
  printf '%s\n' "fetch=${fetch}" "scan=${scan}" "include=${include}"
}

emit
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  emit >> "$GITHUB_OUTPUT"
fi
