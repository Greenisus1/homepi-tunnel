# HomePi Tunnel

Share your Home Pi's console over a free Cloudflare quick tunnel. No
Cloudflare account, no keys, no tokens, nothing secret in this repo.

Run it on the Pi. Its screen shows a `https://....trycloudflare.com`
address and a 6-digit PIN. Open the address on any phone or computer,
type the PIN, and you see the Pi's console live and can type on it.
Press `q` on the Pi to close the tunnel and end every session.

## Use

    python3 hptunnel.py

First run downloads the pinned `cloudflared` binary (version and sha256
are baked in; a bad download is refused). The web side listens on
localhost only; the tunnel is the only way in. The PIN is random every
run, lasts 10 minutes, and 5 wrong tries locks the door for 5 minutes.
Sessions are per-boot HMAC cookies.

The tunnel address is **ephemeral** - it changes every time you start the
app. The current address is always on the Pi's own screen, so glance at
the Pi when you want to connect.

On Home Pi, console reading and key injection reuse the installed
`hpremote`. On plain Raspberry Pi OS it still shows the console (read
from `/dev/vcsa`); typing needs `hpremote`.

## Test

    python3 test_hptunnel.py

Runs unit tests (PIN gate, sessions, endpoints) and a full PTY test that
boots the app against a stub `cloudflared` and checks the screen.

Built with AI assistance from my design.
