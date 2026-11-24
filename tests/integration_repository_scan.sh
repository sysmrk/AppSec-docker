#!/usr/bin/env bash
set -euo pipefail
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
mkdir "$dir/repo" "$dir/reports"
git -C "$dir/repo" init -q
git -C "$dir/repo" config user.email fixture@example.invalid
git -C "$dir/repo" config user.name Fixture
printf 'hello world\n' > "$dir/repo/README.md"
git -C "$dir/repo" add .
git -C "$dir/repo" commit -qm fixture
image=zricethezav/gitleaks:v8.30.1
docker pull "$image"
for mode in dir git; do
  docker run --rm --pull=never --network none -v "$dir/repo:/scan:ro" -v "$dir/reports:/reports" "$image" "$mode" /scan --report-format json --report-path "/reports/$mode.json" --redact=100 --exit-code=17
  python -c 'import json,sys; assert json.load(open(sys.argv[1])) in ([],None)' "$dir/reports/$mode.json"
done
