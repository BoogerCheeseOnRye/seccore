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
git clone <repo> && cd secmesh && git checkout seccore && cd seccore && npm install
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
