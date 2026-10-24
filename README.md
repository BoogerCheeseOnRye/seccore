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
# Termux
pkg install -y git && git clone https://github.com/BoogerCheeseOnRye/seccore && cd seccore
bash scripts/termux-setup.sh --service --boot      # deps, `seccore` launcher, keygen, autostart
# Linux: git clone ... && cd seccore && npm ci && alias seccore="node $PWD/cli.mjs" && seccore keygen
```
To encrypt the key at rest, run `seccore keygen --encrypt` instead of plain `keygen`, or `seccore encrypt-secrets` later.

Create the mesh. One device generates the canary secret and the others reuse it:
```sh
seccore mesh-init --name box --host 192.168.1.10 --port 7400        # first device
grep canarySecret ~/.seccore/mesh.json                               # copy this value in person
seccore mesh-init --name tablet --host 192.168.1.20 --port 7400 --canary <secret>
seccore mesh-init --name phone --canary <secret>                     # dial-only phone (no listener needed)
```
Pair the devices (instead of typing fingerprints by hand):
```sh
seccore pair                       # prints SECCORE1:… bundle (+ QR if qrencode is installed)
seccore pair --import SECCORE1:…   # on the other device; shows PAIRING CODE 123-456
```
Do it in both directions. **The pairing code must be the same on both screens.** If it isn't, someone swapped a bundle.
Bundles carry name, fingerprint and address only, never the canary secret.
Devices don't have to be paired with *everyone*. A phone paired only with `box` can still reach `tablet`
through `box` (relay) as long as `phone` and `tablet` have pinned each other. To pin a device without its address, export its bundle with `seccore pair --no-addr`,
or run `seccore add-peer --name tablet --fp <fp>`.

Run it:
```sh
sv up seccore            # Termux with --service (or: termux-wake-lock; seccore daemon &)
seccore daemon &         # Linux
seccore peers ; seccore status
seccore send tablet '{"note":"hi"}' ; seccore broadcast '{"alert":"x"}' ; seccore inbox
seccore request box '{"op":"ping"}'
```
If identity/canary are encrypted, the daemon unlocks, in this order, from `SECCORE_PASSPHRASE`, then the **Android Keystore**
(`seccore keystore-setup` once; needs the Termux:API app + `pkg install termux-api`), then a TTY prompt. With none of those,
it starts **locked**: only `/status` and `/unlock` answer (token-protected, loopback) until you run `seccore unlock`.
No plaintext passphrase file is needed. Off-LAN devices need one reachable host or a network you
already have between them. seccore doesn't trust the network underneath.

## Tasks: letting agents on one device run things on another (`tasks.mjs`)

A peer can only run tasks declared in `~/.seccore/tasks.json` on the *target* device. There's no shell, and interpreters
(`sh`, `bash`, `python`, `node`, `env`, `sudo`, …) are refused unless the config sets both
`"allowInterpreters": true` and that task's `"allowInterpreter": true`. Rules:
- `argv[0]` is a literal program. A placeholder like `{prompt}` must be a *whole* argv element, and its value has to match
  the arg's regex, which is always auto-anchored (`^(?:…)$`). Unknown args, missing args and NUL bytes are rejected.
- `peers` lists who may call the task (`["*"]` = any trusted peer). Jobs are visible only to the peer that submitted them.
- `spawn` without a shell, scrubbed env (`PATH`, `HOME`, `LANG`, `TMPDIR` + the task's own `env`), `cwd`, `timeoutMs`,
  `maxOutput` (the process is killed when exceeded), and a global `maxConcurrent` job cap.

```json
{
  "maxConcurrent": 2,
  "tasks": {
    "opencode": { "description": "Run an opencode prompt", "argv": ["opencode", "run", "{prompt}"],
                  "args": { "prompt": "[^\\u0000]{1,4000}" }, "cwd": "~/work",
                  "timeoutMs": 900000, "maxOutput": 1048576, "peers": ["box", "tablet"] },
    "uptime":   { "argv": ["uptime"], "peers": ["*"] }
  }
}
```
(Also in `examples/tasks.json`.) Note that `opencode run` is itself an agent that can edit files in `cwd`. Point it at a
dedicated work directory and only allow peers you trust with that power.

```sh
seccore tasks box                                   # what am I allowed to run on box?
seccore task box opencode '{"prompt":"fix the failing test"}'      # async -> {"id": "..."}
seccore job box <id> status | result | cancel ; seccore jobs box
seccore task box uptime --wait                      # synchronous
```
Requests and messages also work over relay, so a task can be submitted to a device you aren't directly linked to.

## Rate limits
Per-peer token bucket on messages, requests and relay frames (default 50/s, burst 100; over budget = dropped, and requests get
`rate limited`), plus a per-IP budget checked *before* the handshake (default 2/s, burst 10). Tune with
`"limits": {"peerRate":…, "peerBurst":…, "handshakeRate":…, "handshakeBurst":…}` in `mesh.json`.

## Multi-hop relay (forward-secret) and routing
Every node publishes a signed **node record**: Ed25519 identity, a sequence number, a **rotating prekey**
(X25519 + ML-KEM-768, rotated hourly by default) and its list of directly connected peers. Records gossip mesh-wide.
- **Envelopes** are sealed to the recipient's current prekey (ephemeral X25519 ⊕ ML-KEM encapsulation → HKDF →
  ChaCha20-Poly1305, header as AAD) and signed by the sender's identity. Prekey private keys exist **only in memory**
  and are destroyed after the grace window (current + 2 previous), so stealing a device later, identity key included,
  doesn't decrypt relayed messages captured earlier. A restart also destroys them.
- **Routing:** link-state. A node runs BFS over edges that *both* ends' signed records confirm (a single forged claim can't
  create a path). It sends to the next hop, or falls back to flooding (TTL + path loop check) when no route is known. The tables are bounded
  (`maxDirectory`, 64 neighbours per record), and configured peers can't be crowded out by junk records.
- **Replay:** relay ids are deduplicated in a persisted, bounded store (`~/.seccore/replay.json`), and envelopes older than 5 min are
  refused, so replays fail across restarts too.

## Revocation
`seccore revoke NAME|FP|self [--reason …]` creates a signed notice that gossips mesh-wide. A notice takes effect if it's signed by
the target itself, by an admin key, or by a quorum of trusted peers (co-signatures merge as it spreads):
```json
"revocation": { "admins": ["<admin fp>"], "quorum": 2 }
```
Applied revocations are persisted (`revoked.json`). The device is disconnected immediately and refused everywhere: handshakes,
relay, routing, `retrust`. Revocation is permanent, so to come back a device needs a new key and has to re-pair. Self-revoke from a backup if a phone is
stolen. With `quorum: 2`, two of your other devices can jointly cut off a compromised one.

## Task sandboxing and audit
Per-task options in `tasks.json` (on top of the allowlist rules):
```json
"cat-note": { "argv": ["cat", "{file}"], "args": { "file": "[^\\u0000]{1,200}" },
  "pathArgs": { "file": { "roots": ["~/work/notes"], "type": "file" } },
  "cwd": "~/work", "limits": { "cpuSeconds": 30, "memoryMB": 512, "fileSizeMB": 50, "nproc": 64, "nofile": 256 },
  "requireLimits": true, "sandbox": { "wrapper": ["proot", "-b", "/data/data/com.termux/files/home/work"] },
  "peers": ["box"] }
```
- `pathArgs`: the value is resolved with `realpath` (symlinks followed) and has to stay inside one of `roots`. `..`, absolute escapes and
  symlink escapes are refused. `type` can be `file`, `dir` or `any`.
- `cwd` must exist, and `/` is refused. Give every agent task its own work dir.
- `limits` are enforced with `prlimit` (`pkg install util-linux`). With `requireLimits`, the task refuses to run without it.
- `sandbox.wrapper` is a literal argv prefix, e.g. `proot` (`pkg install proot`) to bind-mount only the work dir.
  Shells can't be wrappers.
- Jobs run in their own process group, so timeouts and cancels kill the whole tree.
- **Audit log** `~/.seccore/audit.log`: every start, end and refusal (peer, task, argv, with long args truncated + hashed, exit code,
  duration), hash-chained and HMAC'd with a key derived from the device identity. `seccore audit-verify` detects edited, deleted or
  reordered entries. It shows tampering, but can't stop an attacker who fully controls the device from writing new
  entries.

## Security review notes
An internal adversarial pass (not an independent audit) fixed:
- unbounded pre-auth handshake buffering (now 16 KiB frames, ≤4 queued, ≤64 concurrent handshakes, per-IP gate);
- missing ML-KEM length checks;
- no TCP connect timeout;
- `error` events crashing processes without a listener;
- gossip/canary traffic outside the rate limits (now a separate control budget, billed per signed item);
- oversized results tearing down links;
- a NaN timestamp bypassing the relay age check;
- directory crowd-out;
- unclamped TTL.

`test/fuzz.test.mjs` throws random and mutated input at the frame/handshake listener, bundles, records, envelopes, secret boxes,
revocations, task args and every mesh message type.

## Threat model updates
- **Compromised relay:** it can't read, forge or alter relayed payloads, but it can drop them, delay them (within 5 min) and see
  who talks to whom, when, and how much.
- **Compromised peer:** it can do whatever its allowed tasks permit on the devices that granted them. Keep task lists tight and
  regexes narrow. The canary flags nodes that lack the mesh secret, but not an attacker who has fully taken over a node.
- **Stolen device:** with `encrypt-secrets`, the identity key and canary secret need the passphrase (scrypt, N=2^15). The
  Keystore unlock binds it to this phone's hardware key, so a thief who unlocks the phone (or roots it) can still use it in place.
  Revoke the device from another one, or self-revoke, right away.
- **Past relayed traffic:** protected by prekey rotation and deletion (forward secrecy within the rotation window). Messages
  sent during the current window can be read if the device is seized *with* the daemon running.
- **Revocation abuse:** a stolen key can self-revoke (harmless). Admin keys and a quorum can cut devices off, so guard admin keys.
- **Floods:** rate limits bound CPU spent on handshakes and requests. They don't stop a network-level DoS.

### Remaining limitations
- Relay FS is per prekey window (hourly by default), not per message. There's no Double Ratchet, so no post-compromise
  self-healing inside a window. Direct links have per-connection FS.
- Link-state routing is unweighted (hop count) and is recomputed per message, which is fine for tens of nodes.
- Revocation is permanent and can't be undone. Admin and quorum settings must match on all devices.
- `prlimit`/`proot` enforcement depends on what's installed. Android doesn't give unprivileged apps namespaces or seccomp.
- Locked-mode unlock after a crash: the supervisor restarts the node locked again unless the Keystore or the env var is set up.
- None of this has been independently audited. Fingerprints are 80-bit.
