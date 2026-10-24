#!/usr/bin/env node
// seccore CLI: keygen | fingerprint | listen | connect
import path from 'node:path';
import readline from 'node:readline';
import * as sc from './seccore.mjs';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MeshNode, startControl, ensureToken, loadMeshConfig } from './mesh.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const a = {}, pos = [];
for (let i = 0; i < rest.length; i++){
  if (rest[i].startsWith('--')){ const k = rest[i].slice(2); a[k] = rest[i + 1] == null || rest[i + 1].startsWith('--') ? true : rest[++i]; }
  else pos.push(rest[i]);
}
const dir = a.home || sc.defaultDir();
const usage = `usage:
  seccore keygen [--home DIR]
  seccore fingerprint [--home DIR]
  seccore listen  --port P [--host 127.0.0.1] (--peer FP | --tofu)
  seccore connect --host H --port P (--peer FP | --tofu)
Mesh (config: DIR/mesh.json, control token: DIR/control.token):
  seccore mesh-init --name NAME [--host 0.0.0.0|LAN-IP] [--port 7400] [--control-port 7401]
  seccore add-peer --name NAME --fp FP [--host H --port P]
  seccore node                     run the mesh node in the foreground
  seccore daemon                   run the node under an auto-restart supervisor
  seccore peers | status           query the local node
  seccore send TO JSON | broadcast JSON | request TO JSON [--timeout MS] | inbox | retrust NAME
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

const meshFile = path.join(dir, 'mesh.json');
const tokenFile = path.join(dir, 'control.token');
const saveMesh = (c) => fs.writeFileSync(meshFile, JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
const parseJson = (s) => { try { return JSON.parse(s); } catch { return s; } };
async function ctl(method, p, body){
  const c = loadMeshConfig(meshFile);
  const r = await fetch('http://127.0.0.1:' + (c.controlPort ?? 7401) + p, {
    method, headers: { authorization: 'Bearer ' + fs.readFileSync(tokenFile, 'utf8').trim(), 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  }).catch((e) => { console.error('node not reachable: ' + e.message); process.exit(1); });
  const j = await r.json(); console.log(JSON.stringify(j, null, 2)); process.exit(j.ok ? 0 : 1);
}
async function runNode(){
  const c = loadMeshConfig(meshFile);
  let handler = async (body) => {
    if (body?.op === 'ping') return { pong: Date.now() };
    if (body?.op === 'echo') return body;
    throw new Error('no handler configured for this request (set "handler" in mesh.json)');
  };
  if (c.handler) handler = (await import(pathToFileURL(path.resolve(dir, c.handler)).href)).default;
  const alertLog = path.join(dir, 'alerts.log');
  const node = new MeshNode({ identity: sc.loadIdentity(dir), name: c.name, host: c.host || '127.0.0.1', port: c.port,
    peers: c.peers, canarySecret: c.canarySecret, decoyPort: c.decoyPort, alertLog, handler,
    heartbeatMs: c.heartbeatMs, deadMs: c.deadMs, canaryMs: c.canaryMs });
  node.inbox = [];
  const log = (...x) => console.log(new Date().toISOString(), ...x);
  node.on('peer-up', (n, d) => log('peer up', n, d));
  node.on('peer-down', (n) => log('peer down', n));
  node.on('alert', (a) => log('ALERT', a.kind, a.peer ?? '', a.detail));
  node.on('message', (m) => { node.inbox.push({ ts: Date.now(), ...m }); if (node.inbox.length > 1000) node.inbox.shift(); log('msg from', m.from, JSON.stringify(m.body)); });
  await node.start();
  await startControl(node, { port: c.controlPort ?? 7401, token: ensureToken(tokenFile) });
  log('node', c.name, 'fp', node.fp, 'listening', node.port ? (c.host || '127.0.0.1') + ':' + node.port : '(dial-only)', 'control 127.0.0.1:' + (c.controlPort ?? 7401));
  const bye = () => node.stop().then(() => process.exit(0));
  process.on('SIGINT', bye); process.on('SIGTERM', bye);
}

if (cmd === 'mesh-init'){
  if (fs.existsSync(meshFile)) { console.error(meshFile + ' exists'); process.exit(1); }
  if (!a.name) { console.error('--name required'); process.exit(2); }
  saveMesh({ name: a.name, host: a.host || '127.0.0.1', port: Number(a.port || 7400), controlPort: Number(a['control-port'] || 7401),
    canarySecret: a.canary || crypto.randomBytes(32).toString('hex'), peers: [] });
  ensureToken(tokenFile);
  console.log('wrote ' + meshFile + '\\nIMPORTANT: every node in the mesh must use the same canarySecret. Copy it from the first node to the others over a channel you trust (in person, or over an established seccore link).');
} else if (cmd === 'add-peer'){
  const c = loadMeshConfig(meshFile);
  if (!a.name || !a.fp) { console.error('--name and --fp required'); process.exit(2); }
  c.peers = c.peers.filter((p) => p.name !== a.name);
  c.peers.push({ name: a.name, fingerprint: a.fp, ...(a.host ? { host: a.host, port: Number(a.port || 7400) } : {}) });
  saveMesh(c); console.log('peer ' + a.name + ' pinned');
} else if (cmd === 'node'){
  await runNode();
} else if (cmd === 'daemon'){
  // Supervisor: restart the node on crash with capped exponential backoff.
  let delay = 1000, startedAt = 0, child = null, stopping = false;
  const self = fileURLToPath(import.meta.url);
  const run = () => {
    startedAt = Date.now();
    child = spawn(process.execPath, [self, 'node', '--home', dir], { stdio: 'inherit' });
    child.on('exit', (code, sig) => {
      if (stopping) process.exit(0);
      if (Date.now() - startedAt > 60_000) delay = 1000;
      console.error(new Date().toISOString() + ' supervisor: node exited (' + (code ?? sig) + '), restarting in ' + delay + 'ms');
      setTimeout(run, delay); delay = Math.min(delay * 2, 60_000);
    });
  };
  const stop = () => { stopping = true; child?.kill('SIGTERM'); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  run();
} else if (cmd === 'status'){ await ctl('GET', '/status');
} else if (cmd === 'peers'){ await ctl('GET', '/peers');
} else if (cmd === 'inbox'){ await ctl('GET', '/inbox');
} else if (cmd === 'send'){ await ctl('POST', '/send', { to: pos[0], body: parseJson(pos[1]) });
} else if (cmd === 'broadcast'){ await ctl('POST', '/broadcast', { body: parseJson(pos[0]) });
} else if (cmd === 'request'){ await ctl('POST', '/request', { to: pos[0], body: parseJson(pos[1]), timeoutMs: a.timeout ? Number(a.timeout) : undefined });
} else if (cmd === 'retrust'){ await ctl('POST', '/retrust', { peer: pos[0] });
} else if (cmd === 'keygen'){
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
