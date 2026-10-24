#!/usr/bin/env node
// seccore CLI: keygen | fingerprint | listen | connect
import path from 'node:path';
import readline from 'node:readline';
import * as sc from './seccore.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const a = {}; for (let i = 0; i < rest.length; i++){ if (rest[i].startsWith('--')){ const k = rest[i].slice(2); a[k] = rest[i + 1]?.startsWith('--') || rest[i + 1] == null ? true : rest[++i]; } }
const dir = a.home || sc.defaultDir();
const usage = `usage:
  seccore keygen [--home DIR]
  seccore fingerprint [--home DIR]
  seccore listen  --port P [--host 127.0.0.1] (--peer FP | --tofu)
  seccore connect --host H --port P (--peer FP | --tofu)
FP = the other device's fingerprint (compare out-of-band!). Pins saved in DIR/known_peers.json.`;

function opts(){
  const pins = new sc.PinStore(path.join(dir, 'known_peers.json'));
  if (!a.peer && !a.tofu && !Object.keys(pins.pins).length) { console.error('need --peer FP or --tofu (no pinned peers yet)'); process.exit(2); }
  return { identity: sc.loadIdentity(dir), pins, peerFingerprint: typeof a.peer === 'string' ? a.peer : undefined, tofu: !!a.tofu, port: Number(a.port), host: a.host };
}
function chat(ch){
  console.error('secure channel up · peer ' + ch.peerFingerprint);
  ch.on('message', (m) => process.stdout.write(m));
  ch.on('error', (e) => { console.error('channel closed: ' + e.message); process.exit(1); });
  ch.on('close', () => process.exit(0));
  process.stdin.on('data', (d) => ch.send(d));
  process.stdin.on('end', () => ch.close());
}

if (cmd === 'keygen'){
  const id = sc.generateIdentity();
  try { console.log('wrote ' + sc.saveIdentity(id, dir)); } catch (e) { console.error(e.code === 'EEXIST' ? 'identity already exists in ' + dir : e.message); process.exit(1); }
  console.log('fingerprint ' + sc.fingerprint(id.raw));
} else if (cmd === 'fingerprint'){
  console.log(sc.fingerprint(sc.loadIdentity(dir).raw));
} else if (cmd === 'listen'){
  const o = opts(); let busy = false;
  const srv = sc.listen({ ...o, host: o.host || '127.0.0.1' }, (ch) => { if (busy) return ch.close(); busy = true; chat(ch); }, (e) => console.error('rejected: ' + e.message));
  srv.on('listening', () => console.error('listening on ' + (o.host || '127.0.0.1') + ':' + o.port + ' · my fp ' + sc.fingerprint(o.identity.raw)));
} else if (cmd === 'connect'){
  sc.connect(opts()).then(chat, (e) => { console.error('handshake failed: ' + e.message); process.exit(1); });
} else { console.log(usage); process.exit(cmd ? 2 : 0); }
