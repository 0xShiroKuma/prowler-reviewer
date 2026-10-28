#!/bin/sh
# Copy compliance benchmarks and check metadata out of a Prowler git checkout.
# Usage: fetch-prowler-data.sh <prowler-checkout> <output-dir>
set -eu

SRC="${1:-/src}"
OUT="${2:-/out}"
REPO="${PROWLER_REPO:-https://github.com/prowler-cloud/prowler.git}"
REF="${PROWLER_REF:-master}"

if [ ! -d "$SRC/prowler/compliance" ] || [ ! -d "$SRC/prowler/providers" ]; then
  echo "Prowler checkout at $SRC is missing prowler/compliance or prowler/providers" >&2
  exit 1
fi

case "$REF" in
  *[!A-Za-z0-9._/-]*)
    echo "Refusing to record unsafe PROWLER_REF value" >&2
    exit 1
    ;;
esac

mkdir -p "$OUT/compliance" "$OUT/check-metadata"
cp -a "$SRC/prowler/compliance/." "$OUT/compliance/"

find "$SRC/prowler/providers" -name '*.metadata.json' | while IFS= read -r file; do
  rel="${file#"$SRC/prowler/providers"/}"
  dest="$OUT/check-metadata/$rel"
  mkdir -p "$(dirname "$dest")"
  cp "$file" "$dest"
done

commit="unknown"
if command -v git >/dev/null 2>&1 && [ -d "$SRC/.git" ]; then
  commit="$(git -C "$SRC" rev-parse HEAD)"
fi

json_count="$(find "$OUT/compliance" -name '*.json' | wc -l | tr -d ' ')"
meta_count="$(find "$OUT/check-metadata" -name '*.metadata.json' | wc -l | tr -d ' ')"

if [ "$json_count" -eq 0 ] || [ "$meta_count" -eq 0 ]; then
  echo "Prowler catalog is empty (compliance=$json_count metadata=$meta_count)" >&2
  exit 1
fi

cat > "$OUT/catalog.json" <<EOF
{
  "repo": "$REPO",
  "ref": "$REF",
  "commit": "$commit",
  "complianceFiles": $json_count,
  "metadataFiles": $meta_count
}
EOF

echo "Prowler catalog ${REF}@${commit}: ${json_count} compliance files, ${meta_count} check metadata files"
