#!/bin/sh
# pi-app-store: 1
# pi-app-store-category: apps
set -eu
cd -- "$(dirname -- "$0")"
ensure_python() {
    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import curses' 2>/dev/null; then
        if command -v apt-get >/dev/null 2>&1; then
            if [ "$(id -u)" -eq 0 ]; then apt-get update && apt-get install -y python3;
            else sudo apt-get update && sudo apt-get install -y python3; fi
        else echo 'Install Python 3 with curses using your package manager.' >&2; exit 1; fi
    fi
}
case "${1:-run}" in
    install) ensure_python; python3 -m py_compile hptunnel.py; echo 'HomePi Tunnel ready. No desktop or pip dependencies.' ;;
    run) shift || true; ensure_python; exec python3 hptunnel.py "$@" ;;
    *) echo 'Use: bash app-store.sh install or bash app-store.sh run'; exit 1 ;;
esac
