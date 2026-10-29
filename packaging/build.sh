#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/build}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
VERSION=${SYNOHARBOR_VERSION:-0.1.0-1}
cd "$ROOT/web"
npm run check
npm run build
cd "$ROOT"
for arch in amd64 arm64; do
 stage=$(mktemp -d "$OUT/.spk-$arch.XXXXXX")
 mkdir -p "$stage/package/bin" "$stage/package/ui"
 GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$stage/package/bin/synoharbor" ./cmd/synoharbor
 cp -R packaging/spk/ui/. "$stage/package/ui/"
 cp -R web/dist/. "$stage/package/ui/"
 cp LICENSE NOTICE "$stage/package/"
 chmod 755 "$stage/package/ui/api.cgi"
 (cd "$stage/package" && tar -czf "$stage/package.tgz" bin ui LICENSE NOTICE)
 cp -R packaging/spk/scripts packaging/spk/conf packaging/spk/WIZARD_UIFILES "$stage/"
 chmod 755 "$stage/scripts/"*
 dsmarch=x86_64;[ "$arch" = arm64 ] && dsmarch=aarch64
 sed -e "s/^arch=.*/arch=\"$dsmarch\"/" -e "s/^version=.*/version=\"$VERSION\"/" packaging/spk/INFO > "$stage/INFO"
 for pair in 'package_icon:64' 'package_icon_256:256'; do
  key=${pair%:*};size=${pair#*:}
  printf '%s="%s"\n' "$key" "$(base64 < "packaging/spk/ui/images/synoharbor_$size.png" | tr -d '\n')" >> "$stage/INFO"
 done
 (cd "$stage" && tar -cf "$OUT/synoharbor-$arch.spk" INFO package.tgz scripts conf WIZARD_UIFILES)
 rm -rf "$stage"
 printf '%s\n' "$OUT/synoharbor-$arch.spk"
done
