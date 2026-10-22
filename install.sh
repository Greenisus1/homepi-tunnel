#!/bin/sh
set -eu
BASE_URL=https://raw.githubusercontent.com/Greenisus1/homepi-tunnel/main
DEST=${HOMEPI_TUNNEL_INSTALL_DIR:-$HOME/.local/share/homepi-tunnel-app}
BIN=${HOMEPI_TUNNEL_BIN_DIR:-$HOME/.local/bin}
mkdir -p "$DEST" "$BIN"
fetch() {
    if command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1";
    elif command -v curl >/dev/null 2>&1; then curl -fLsS "$1" -o "$2";
    else echo 'Install wget or curl first.' >&2; exit 1; fi
}
for file in hptunnel.py app-store.sh VERSION; do
    tmp=$(mktemp "$DEST/.download.XXXXXX")
    if fetch "$BASE_URL/$file" "$tmp"; then mv "$tmp" "$DEST/$file";
    else rm -f "$tmp"; exit 1; fi
done
sh "$DEST/app-store.sh" install
cat > "$BIN/homepi-tunnel" <<LAUNCH
#!/bin/sh
exec sh "$DEST/app-store.sh" run "\$@"
LAUNCH
chmod +x "$BIN/homepi-tunnel"
echo "Installed. Run: homepi-tunnel"
