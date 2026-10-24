# seccore — authenticated, encrypted device-to-device channel

Built only from vetted building blocks: Node's built-in crypto plus `@noble/post-quantum` (audited) for ML-KEM.

| Layer | Primitive |
|---|---|
| Device identity | Ed25519 key, stored once per device (`~/.seccore/identity.pem`, mode 600) |
| Key exchange | Ephemeral X25519 **+ ML-KEM-768** hybrid (an attacker has to break both) |
| Authentication | Both sides sign the handshake transcript with Ed25519; the peer key is pinned by fingerprint |
| Key derivation | HKDF-SHA256, salt = transcript hash, separate c2s/s2c keys, encrypted key-confirmation frame |
| Transport | Length-prefixed frames, ChaCha20-Poly1305, 64-bit counter nonce, header in AAD |
| Replay/reorder | Receiver accepts only the exact next counter. Any failure closes the connection |
| Rekey | HKDF ratchet after N messages or bytes (default 2^20 msgs / 1 GiB), counter resets |

## Two devices (e.g. Linux box + Android Termux)

```sh
# both devices (Termux: pkg install nodejs git)
git clone https://github.com/BoogerCheeseOnRye/seccore && cd seccore && npm install
node cli.mjs keygen          # once per device
node cli.mjs fingerprint     # read it to the other person / compare in person
```
Device B (listener), on its LAN IP or tunnel address:
```sh
node cli.mjs listen --host 192.168.1.20 --port 7400 --peer <A's fingerprint>
```
Device A:
```sh
node cli.mjs connect --host 192.168.1.20 --port 7400 --peer <B's fingerprint>
```
Type on one side and it shows up on the other. `--tofu` pins the first key seen (saved in
`~/.seccore/known_peers.json`) instead of `--peer`. It's weaker, because the very first connection could be the attacker.
The default bind is `127.0.0.1`. Pass `--host` on purpose to expose it.

Library: `import { listen, connect, loadIdentity } from './seccore.mjs'`. You get a `SecureChannel`
with `send(buf)`, `'message'`, `'error'`, `'close'`.

## Threat model
**Protects against:** passive eavesdroppers (confidentiality, forward secrecy from ephemeral keys,
harvest-now-decrypt-later through the ML-KEM hybrid), active network MITM (pinned identities + signed
transcript), tampering, injection, replay, reordering or dropping frames (AEAD + strict counters, close on failure).

**Does NOT protect against:** a compromised device or a stolen `identity.pem` (it isn't encrypted at rest, so use
device encryption), a wrong fingerprint accepted by the user or a TOFU first contact with an attacker,
traffic analysis (message sizes and timing are visible), DoS, or bugs in this unaudited code. The message format is
not yet a reviewed protocol (it's modeled on Noise/SIGMA patterns). For production, prefer WireGuard or
Noise underneath and put this on top.

## Tests
`npm test`: handshake + echo, wrong pin rejected, MITM rejected (own identity and spliced ephemeral key),
tampered ciphertext rejected, replay rejected, rekey, passive observer sees no plaintext, no `Math.random`.

## Mesh: many devices, one encrypted fabric (`mesh.mjs`)

Each device runs one **node**. Every link between two nodes is a seccore channel (as described above),
so mesh traffic is never sent in plaintext and can't come from an unpinned key.

- **Peers:** one listener accepts any number of *pinned* peers. Outbound links to the configured peers
  reconnect with jittered exponential backoff. When both sides listen, the side with the lower fingerprint dials. A phone
  that has no listener (no `port`) just dials out.
- **Messaging:** `send(to, body)`, `broadcast(body)`, `request(to, body) → result`. A message's sender
  is always the authenticated channel identity, never a field the peer wrote itself.
- **Liveness:** encrypted heartbeats with RTT. A peer that's silent longer than `deadMs` gets dropped and redialed.
  `seccore daemon` restarts a crashed node (backoff up to 60 s).
- **Intrusion detection:**
  - *Canary:* nodes share a `canarySecret` that's separate from the identity keys. Every node challenges
    its peers to answer `HMAC(secret, nonce‖asker‖answerer)`. A wrong answer marks the peer untrusted: the link is closed,
    future handshakes are refused and an alert is logged. Two missed answers do the same.
    `seccore retrust NAME` clears the flag after you've investigated.
  - *Decoy:* the optional `decoyPort` is a listener that no legitimate peer ever uses. Any touch raises an alert.
  - Alerts go to `~/.seccore/alerts.log` (JSONL) and `seccore status`.
- **Local control API:** HTTP on **127.0.0.1 only** and requires `Authorization: Bearer <~/.seccore/control.token>`
  (32 random bytes, mode 600). Requests carrying a browser `Origin` header are refused. The CLI uses it.
- **Request handler:** by default the node answers only `{"op":"ping"}` / `{"op":"echo"}`. To let agents run
  tasks, set `"handler": "handler.mjs"` in `mesh.json`, pointing to a module that does
  `export default async (body, fromPeer) => result`. You decide what's allowed, so whitelist tasks. Don't `eval` or shell out
  to arbitrary input.

### Setup on Termux (Android) + Linux

On **every** device:
```sh
pkg install nodejs git            # Termux; on Linux use your package manager
git clone https://github.com/BoogerCheeseOnRye/seccore && cd seccore && npm install
alias seccore="node $PWD/cli.mjs"
seccore keygen && seccore fingerprint
```
On the **first** device (e.g. the Linux box, LAN IP 192.168.1.10):
```sh
seccore mesh-init --name box --host 192.168.1.10 --port 7400
grep canarySecret ~/.seccore/mesh.json      # copy this value to the other devices in person, never over chat
```
On each **other** device (here a tablet that also listens on 192.168.1.20):
```sh
seccore mesh-init --name tablet --host 192.168.1.20 --port 7400 --canary <secret from box>
```
(For a phone that only dials out, `--host 127.0.0.1` is fine.)
Then pin everyone on every device. Compare the fingerprints in person:
```sh
seccore add-peer --name box    --fp <box fp>    --host 192.168.1.10 --port 7400
seccore add-peer --name tablet --fp <tablet fp> --host 192.168.1.20 --port 7400
seccore add-peer --name phone  --fp <phone fp>               # no host = it dials us
```
Run it and use it:
```sh
seccore daemon &                                   # Termux: `termux-wake-lock` first to keep it alive
seccore peers
seccore send tablet '{"note":"hi"}'
seccore broadcast '{"alert":"rotate keys tonight"}'
seccore request box '{"op":"ping"}'
seccore inbox                                      # messages received by this node
seccore status                                     # peers, liveness, RTT, trust, alerts
```
If your devices aren't on the same LAN, open the port on one reachable host or join them over a VPN you trust.
Seccore authenticates and encrypts on its own, so the network underneath doesn't need to be trusted.

### Mesh limitations
- Routing is direct only: two nodes have to be configured as peers to talk (no multi-hop relay yet).
- The canary catches a stolen identity key used *without* the canary secret, plus mis-configured or modified nodes. It can't catch
  an attacker who fully controls a device, because they'd have both secrets.
- `mesh.json` stores the canary secret in plaintext (mode 600), and `identity.pem` isn't passphrase-protected.
- Request/response has no rate limiting yet. Your handler is the trust boundary.
