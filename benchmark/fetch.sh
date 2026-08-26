#!/usr/bin/env bash
set -euo pipefail

# Fetch the benchmark corpus via SSH (avoids GitHub HTTPS network issues).
# Usage: bash benchmark/fetch.sh
cd "$(dirname "$0")"

python3 - <<'PY' > /tmp/mcp-bench-repos.tsv
import tomllib
with open("manifest.toml", "rb") as f:
    m = tomllib.load(f)
for r in m.get("repo", []):
    print(r["slug"], r["url"], r["commit"], sep="\t")
PY

mkdir -p corpus
while IFS=$'\t' read -r slug url commit; do
  dest="corpus/$slug"
  if [ -d "$dest/.git" ]; then
    echo "exists: $slug"
    git -C "$dest" fetch --depth 1 origin "$commit" || true
  else
    echo "cloning: $slug"
    git clone "$url" "$dest"
  fi
  git -C "$dest" checkout "$commit"
done < /tmp/mcp-bench-repos.tsv
rm -f /tmp/mcp-bench-repos.tsv
echo "done. corpus under benchmark/corpus/"
