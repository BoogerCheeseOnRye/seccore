#!/data/data/com.termux/files/usr/bin/bash
# seccore Termux setup: packages, deps, and optional boot autostart / service.
# Usage: bash scripts/termux-setup.sh [--service] [--boot]
#   --service  register a termux-services (runit) service "seccore" (sv up/down seccore)
#   --boot     start seccore at device boot (needs the Termux:Boot app, opened once)
# For an encrypted identity, the service/boot script reads the passphrase from
# ~/.seccore/passphrase (mode 600) if present. That's a trade-off: the file can be read by anyone with access to the device.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE=0; BOOT=0
for a in "$@"; do case "$a" in --service) SERVICE=1;; --boot) BOOT=1;; *) echo "unknown flag $a"; exit 2;; esac; done

if [ -z "${PREFIX:-}" ] || [ ! -d "$PREFIX" ]; then echo "this script is for Termux"; exit 1; fi
pkg update -y
pkg install -y nodejs-lts git libqrencode termux-services termux-api || pkg install -y nodejs git libqrencode termux-services

cd "$REPO"
npm ci --omit=dev --no-audit --no-fund
# Verify: no native addons (pure JS only), so nothing needs a compiler on Android.
if find node_modules -name '*.node' -o -name binding.gyp | grep -q .; then echo "native module found: not Android-safe"; exit 1; fi
node -e "require('crypto').generateKeyPairSync('x25519');require('crypto').createCipheriv('chacha20-poly1305',Buffer.alloc(32),Buffer.alloc(12),{authTagLength:16});console.log('crypto OK')"

mkdir -p "$HOME/.seccore" && chmod 700 "$HOME/.seccore"
[ -e "$HOME/.seccore/identity.pem" ] || [ -e "$HOME/.seccore/identity.pem.enc" ] || node cli.mjs keygen
mkdir -p "$PREFIX/bin"
cat > "$PREFIX/bin/seccore" <<EOS
#!/data/data/com.termux/files/usr/bin/sh
exec node "$REPO/cli.mjs" "\$@"
EOS
chmod 700 "$PREFIX/bin/seccore"

RUN="$HOME/.seccore/run-daemon.sh"
cat > "$RUN" <<EOS
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock 2>/dev/null || true
[ -f "\$HOME/.seccore/passphrase" ] && export SECCORE_PASSPHRASE="\$(cat "\$HOME/.seccore/passphrase")"
exec node "$REPO/cli.mjs" daemon
EOS
chmod 700 "$RUN"

if [ "$SERVICE" = 1 ]; then
  SV="$PREFIX/var/service/seccore"; mkdir -p "$SV/log"
  printf '#!/data/data/com.termux/files/usr/bin/sh\nexec 2>&1\nexec %s\n' "$RUN" > "$SV/run"
  printf '#!/data/data/com.termux/files/usr/bin/sh\nexec svlogger\n' > "$SV/log/run" 2>/dev/null || ln -sf "$PREFIX/share/termux-services/svlogger" "$SV/log/run"
  chmod 700 "$SV/run" "$SV/log/run"
  echo "service installed. Restart Termux once, then: sv up seccore ; logs: \$PREFIX/var/log/sv/seccore/current"
fi
if [ "$BOOT" = 1 ]; then
  mkdir -p "$HOME/.termux/boot"
  printf '#!/data/data/com.termux/files/usr/bin/sh\n%s >> "$HOME/.seccore/daemon.log" 2>&1 &\n' "$RUN" > "$HOME/.termux/boot/seccore"
  chmod 700 "$HOME/.termux/boot/seccore"
  echo "boot script installed (install + open the Termux:Boot app once)."
fi
echo
echo "fingerprint: $(node cli.mjs fingerprint)"
echo "next: seccore mesh-init --name <this-device> [--host <LAN IP> --port 7400] [--canary <shared secret>]"
echo "      seccore pair    (show bundle/QR) ; seccore pair --import <bundle>"
echo "      seccore daemon  (or sv up seccore)"
