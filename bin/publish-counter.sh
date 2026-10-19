#!/usr/bin/env bash
# Publish only the README badge, recalculating after each concurrent main update.
set -euo pipefail

counter_repo=$(git rev-parse --show-toplevel)
counter_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
counter_temp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/loldrivers-counter.XXXXXX")
counter_checkout="$counter_temp/checkout"
cleanup() {
  git -C "$counter_repo" worktree remove --force "$counter_checkout" 2>/dev/null || true
  rm -rf -- "$counter_temp"
}
trap cleanup EXIT

for attempt in 1 2 3 4 5; do
  git -C "$counter_repo" fetch --no-tags origin main
  counter_base=$(git -C "$counter_repo" rev-parse FETCH_HEAD)
  # Keep the caller's checkout intact; driver binaries are not needed to count.
  GIT_LFS_SKIP_SMUDGE=1 git -C "$counter_repo" worktree add --detach "$counter_checkout" "$counter_base"
  python3 "$counter_script_dir/gen-counter.py" \
    --folder "$counter_checkout/yaml" --readme "$counter_checkout/README.md"

  if git -C "$counter_checkout" diff --quiet -- README.md; then
    echo 'Driver counter is already current; no commit needed.'
    exit 0
  fi

  git -C "$counter_checkout" add -- README.md
  git -C "$counter_checkout" -c user.name='publish bot' -c user.email='bot@magicsword.io' \
    commit -m 'updating drivers count in README.md [ci skip]'
  if git -C "$counter_checkout" push origin HEAD:refs/heads/main; then
    exit 0
  fi

  # Retry only when main moved. Permission/network failures must remain failures.
  git -C "$counter_repo" fetch --no-tags origin main
  if [ "$(git -C "$counter_repo" rev-parse FETCH_HEAD)" = "$counter_base" ]; then
    echo 'Counter push failed without a concurrent main update.' >&2
    exit 1
  fi
  git -C "$counter_repo" worktree remove --force "$counter_checkout"
  echo "Main advanced during attempt $attempt; recounting from its latest revision."
  if [ "$attempt" -lt 5 ]; then
    sleep "$attempt"
  fi
done

echo 'Counter could not be published after five concurrent main updates.' >&2
exit 1
