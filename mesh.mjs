// seccore mesh: multi-peer node on top of SecureChannel.
// Every peer link is a seccore channel (pinned Ed25519 identity, hybrid KEX, AEAD).
// Adds: named routing, send/broadcast/request-response, heartbeats/liveness,
// reconnect with backoff, canary HMAC challenges, decoy listener, local control API.
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import * as sc from './seccore.mjs';
import { KeyedLimiter } from './ratelimit.mjs';
import * as e2e from './e2e.mjs';

const MAX_CTL_BODY = 256 * 1024;
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

export function loadMeshConfig(file){
  const c = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!c.name) throw new Error('mesh config: name required');
  c.peers = (c.peers || []).map((p) => {
    if (!p.name || !p.fingerprint) throw new Error('mesh config: each peer needs name + fingerprint');
    return { ...p };
  });
  return c;
}

export class MeshNode extends EventEmitter {
  /**
   * opts: { identity, name, host='127.0.0.1', port (0/undefined = no listener), peers:[{name,host,port,fingerprint}],
   *         canarySecret (hex, shared by all mesh members), heartbeatMs=5000, deadMs=15000, canaryMs=30000,
   *         backoffMinMs=500, backoffMaxMs=30000, decoyPort, alertLog, handler: async (body, from) => result }
   */
  constructor(opts){
    super();
    this.o = { host: '127.0.0.1', heartbeatMs: 5000, deadMs: 15000, canaryMs: 30000, backoffMinMs: 500, backoffMaxMs: 30000, requestTimeoutMs: 15000, ...Object.fromEntries(Object.entries(opts).filter(([, v]) => v !== undefined)) };
    this.id = opts.identity; this.name = opts.name; this.fp = sc.fingerprint(this.id.raw);
    this.peers = new Map();                       // name -> state
    this.byFp = new Map();                        // fingerprint -> name
    for (const p of opts.peers || []) this.addPeer(p, false);
    // Per-peer message/request budget and per-IP handshake budget.
    this.msgLimit = new KeyedLimiter(this.o.peerRate ?? 50, this.o.peerBurst ?? 100);
    this.hsLimit = new KeyedLimiter(this.o.handshakeRate ?? 2, this.o.handshakeBurst ?? 10);
    // Relay state: box key + signed announcement, directory of verified box keys, dedupe set.
    this.box = e2e.boxKeyFromIdentity(this.id);
    this.ann = e2e.makeAnnouncement(this.id, this.box);
    this.directory = new Map();                   // fp -> { x, ed }
    this.seen = new Map();                        // relay id -> ts
    this.pending = new Map();                     // request id -> {resolve,reject,timer}
    this.alerts = [];
    this.stopped = false;
  }

  addPeer(p, dial = true){
    if (!p?.name || !p.fingerprint) throw new Error('peer needs name + fingerprint');
    if (p.fingerprint === this.fp) return;
    this.peers.set(p.name, { cfg: { ...p }, ch: null, lastSeen: 0, rtt: null, trusted: true, strikes: 0, attempt: 0, timer: null, since: null, pendingCanary: null });
    this.byFp.set(p.fingerprint, p.name);
    if (dial && this.hbTimer && this._shouldDial(p.name)) this._dial(p.name);
  }

  // Pins = exactly the configured, still-trusted peers. Everyone else fails the handshake.
  _pins(){ return { has: (fp) => { const n = this.byFp.get(fp); return !!n && this.peers.get(n).trusted; } }; }

  async start(){
    const tasks = [];
    if (this.o.port != null){
      this.server = sc.listen({ host: this.o.host, port: this.o.port, identity: this.id, pins: this._pins(), rekeyMessages: this.o.rekeyMessages, gate: (sock) => this._gate(sock) },
        (ch) => this._attach(ch, 'in'),
        (e) => this._alert('handshake-rejected', null, e.message));
      tasks.push(new Promise((r, j) => { this.server.once('listening', r); this.server.once('error', j); }));
    }
    if (this.o.decoyPort != null){
      this.decoy = net.createServer((s) => {
        this._alert('decoy-touched', null, 'connection to decoy port from ' + s.remoteAddress + ':' + s.remotePort);
        s.destroy();
      }).listen(this.o.decoyPort, this.o.decoyHost || this.o.host);
      tasks.push(new Promise((r) => this.decoy.once('listening', r)));
    }
    await Promise.all(tasks);
    for (const [name] of this.peers) if (this._shouldDial(name)) this._dial(name);
    this.hbTimer = setInterval(() => this._tick(), this.o.heartbeatMs); this.hbTimer.unref?.();
    if (this.o.canarySecret){ this.canaryTimer = setInterval(() => this._canaryAll(), this.o.canaryMs); this.canaryTimer.unref?.(); }
    return this;
  }
  _gate(sock){
    const ip = sock.remoteAddress || '?';
    if (this.hsLimit.take(ip)) return true;
    this._rlAlert('handshake-rate', null, ip);
    return false;
  }
  // Throttle alert spam: at most one rate-limit alert per key per 10 s.
  _rlAlert(kind, peer, key){
    this._rlSeen ??= new Map(); const k = kind + '|' + key, now = Date.now();
    if (now - (this._rlSeen.get(k) || 0) < 10_000) return;
    this._rlSeen.set(k, now); this._alert(kind, peer, 'rate limit exceeded by ' + key);
  }
  get port(){ return this.server?.address()?.port; }
  get decoyPort(){ return this.decoy?.address()?.port; }

  // Avoid duplicate links: if both sides listen, the lower fingerprint dials.
  _shouldDial(name){
    const p = this.peers.get(name).cfg;
    if (!p.host || !p.port) return false;
    return this.o.port == null || p.dial === true || this.fp < p.fingerprint;
  }
  _dial(name){
    const st = this.peers.get(name);
    if (this.stopped || !st || st.ch || !st.trusted || st.timer) return;
    sc.connect({ host: st.cfg.host, port: st.cfg.port, identity: this.id, peerFingerprint: st.cfg.fingerprint, rekeyMessages: this.o.rekeyMessages })
      .then((ch) => { if (this.stopped) return ch.close(); this._attach(ch, 'out'); },
        (e) => { this.emit('dial-failed', name, e); this._scheduleDial(name); });
  }
  _scheduleDial(name){
    const st = this.peers.get(name);
    if (this.stopped || !st || !st.trusted || st.timer || !this._shouldDial(name)) return;
    const base = Math.min(this.o.backoffMaxMs, this.o.backoffMinMs * 2 ** Math.min(st.attempt++, 16));
    const delay = Math.floor(base / 2) + crypto.randomInt(Math.max(1, Math.floor(base / 2)));
    st.timer = setTimeout(() => { st.timer = null; this._dial(name); }, delay); st.timer.unref?.();
  }

  _attach(ch, dir){
    const name = this.byFp.get(ch.peerFingerprint);
    const st = name && this.peers.get(name);
    if (!st || !st.trusted) return ch.close();
    if (st.ch && st.ch !== ch){ const old = st.ch; st.ch = null; old.removeAllListeners('close'); old.close(); }
    st.ch = ch; st.lastSeen = Date.now(); st.attempt = 0; st.since = Date.now(); st.dir = dir;
    ch.on('message', (m) => this._onMessage(name, ch, m));
    ch.on('error', (e) => this.emit('channel-error', name, e));
    ch.on('close', () => {
      if (st.ch !== ch) return;
      st.ch = null; st.since = null; this.emit('peer-down', name);
      this._scheduleDial(name);
    });
    this.emit('peer-up', name, dir);
    this._safeWrite(name, { t: 'ann', anns: [this.ann, ...[...this.directory.values()].map((d) => d.ann)] });
    if (this.o.canarySecret) this._canary(name);
  }

  _write(name, obj){
    const st = this.peers.get(name);
    if (!st) throw new Error('unknown peer ' + name);
    if (!st.trusted) throw new Error('peer ' + name + ' is untrusted');
    if (!st.ch || st.ch.closed) throw new Error('peer ' + name + ' not connected');
    st.ch.send(JSON.stringify(obj));
  }

  async _onMessage(name, ch, raw){
    const st = this.peers.get(name); st.lastSeen = Date.now();
    let m; try { m = JSON.parse(raw.toString('utf8')); } catch { return this._alert('malformed', name, 'non-JSON frame'); }
    if (!m || typeof m !== 'object') return;
    // `from` is always the authenticated channel identity, never a field the peer wrote.
    if ((m.t === 'msg' || m.t === 'req' || m.t === 'relay') && !this.msgLimit.take(name)){
      this._rlAlert('peer-rate', name, name);
      if (m.t === 'req') this._safeWrite(name, { t: 'res', id: m.id, ok: false, error: 'rate limited' });
      return;
    }
    switch (m.t){
      case 'hb': return this._safeWrite(name, { t: 'hbAck', ts: m.ts });
      case 'hbAck': if (typeof m.ts === 'number') st.rtt = Date.now() - m.ts; return;
      case 'canary': return this._safeWrite(name, { t: 'canaryRes', c: m.c, mac: this._canaryMac(m.c, st.cfg.fingerprint, this.fp) });
      case 'canaryRes': return this._checkCanary(name, m);
      case 'ann': return this._onAnn(name, m);
      case 'relay': return this._onRelay(name, m);
      case 'msg': if (st.trusted) this.emit('message', { from: name, body: m.body }); return;
      case 'req': {
        if (!st.trusted) return;
        let res;
        try {
          if (!this.o.handler) throw new Error('no handler on ' + this.name);
          res = { t: 'res', id: m.id, ok: true, result: await this.o.handler(m.body, name) };
        } catch (e) { res = { t: 'res', id: m.id, ok: false, error: String(e?.message || e) }; }
        return this._safeWrite(name, res);
      }
      case 'res': {
        const p = this.pending.get(m.id);
        if (!p || p.peer !== name || p.viaRelay) return;   // only the peer we asked can answer
        this.pending.delete(m.id); clearTimeout(p.timer);
        return m.ok ? p.resolve(m.result) : p.reject(new Error(m.error || 'remote error'));
      }
      default: this._alert('unknown-type', name, String(m.t));
    }
  }
  _safeWrite(name, obj){ try { this._write(name, obj); } catch {} }

  // ── public API ──────────────────────────────────────────────────────────
  // `to` = configured peer name or a fingerprint. Uses the direct link when up, else relays end-to-end sealed.
  _resolve(to){
    const n = this.peers.has(to) ? to : this.byFp.get(to);
    if (n && !this.peers.get(n).trusted) throw new Error('peer ' + n + ' is untrusted');
    if (this.peers.has(to)) return { name: to, fp: this.peers.get(to).cfg.fingerprint };
    if (this.byFp.has(to)) return { name: this.byFp.get(to), fp: to };
    if (/^[0-9a-f]{4}(:[0-9a-f]{4}){9}$/.test(to)) return { name: null, fp: to };
    throw new Error('unknown peer ' + to);
  }
  _direct(r){ const st = r.name && this.peers.get(r.name); return !!(st && st.ch && !st.ch.closed && st.trusted); }
  send(to, body){
    const r = this._resolve(to);
    if (this._direct(r)) return this._write(r.name, { t: 'msg', body });
    this._relaySend(r.fp, { k: 'msg', body });
  }
  broadcast(body){
    const sent = [];
    for (const [n, st] of this.peers) if (st.ch && st.trusted){ try { this._write(n, { t: 'msg', body }); sent.push(n); } catch {} }
    // Pinned peers that aren't directly connected but are reachable via relay.
    if (this.o.broadcastRelay !== false) for (const [n, st] of this.peers) if (!st.ch && st.trusted && this.directory.has(st.cfg.fingerprint)){ try { this._relaySend(st.cfg.fingerprint, { k: 'msg', body }); sent.push(n + ' (relay)'); } catch {} }
    return sent;
  }
  request(to, body, timeoutMs = this.o.requestTimeoutMs){
    return new Promise((resolve, reject) => {
      const id = crypto.randomBytes(12).toString('hex');
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('request timeout')); }, timeoutMs);
      try {
        const r = this._resolve(to);
        if (this._direct(r)){ this.pending.set(id, { resolve, reject, timer, peer: r.name }); this._write(r.name, { t: 'req', id, body }); }
        else { this.pending.set(id, { resolve, reject, timer, peerFp: r.fp, viaRelay: true }); this._relaySend(r.fp, { k: 'req', rid: id, body }); }
      } catch (e) { clearTimeout(timer); this.pending.delete(id); reject(e); }
    });
  }
  status(){
    const now = Date.now();
    return {
      name: this.name, fingerprint: this.fp, listen: this.port ? this.o.host + ':' + this.port : null, decoy: this.decoyPort ?? null,
      peers: [...this.peers].map(([n, st]) => ({
        name: n, fingerprint: st.cfg.fingerprint, connected: !!st.ch, direction: st.dir ?? null,
        alive: !!st.ch && now - st.lastSeen < this.o.deadMs, lastSeenMsAgo: st.lastSeen ? now - st.lastSeen : null,
        rttMs: st.rtt, trusted: st.trusted, strikes: st.strikes,
      })),
      alerts: this.alerts.slice(-50),
    };
  }
  // Operator action after investigating: re-trust a peer that was flagged.
  retrust(name){ const st = this.peers.get(name); if (!st) return false; st.trusted = true; st.strikes = 0; this._scheduleDial(name); return true; }

  // ── multi-hop relay ─────────────────────────────────────────────────────
  _onAnn(from, m){
    if (!Array.isArray(m.anns)) return;
    const fresh = [];
    for (const ann of m.anns.slice(0, 256)){
      let v; try { v = e2e.verifyAnnouncement(ann); } catch { this._alert('bad-announcement', from, 'invalid signed box key'); continue; }
      if (v.fp === this.fp) continue;
      const cur = this.directory.get(v.fp);
      if (cur && cur.x.equals(v.x)) continue;
      if (!cur && this.directory.size >= (this.o.maxDirectory ?? 1000)) continue;
      this.directory.set(v.fp, { x: v.x, ed: v.ed, ann }); fresh.push(ann);
    }
    if (fresh.length) for (const [n, st] of this.peers) if (n !== from && st.ch && st.trusted) this._safeWrite(n, { t: 'ann', anns: fresh });
  }
  _markSeen(id){
    const now = Date.now();
    if (this.seen.size > 20_000) for (const [k, t] of this.seen){ if (now - t > 600_000 || this.seen.size > 15_000) this.seen.delete(k); else break; }
    if (this.seen.has(id)) return false;
    this.seen.set(id, now); return true;
  }
  _relaySend(dstFp, inner){
    const d = this.directory.get(dstFp);
    if (!d) throw new Error('no route/key for ' + dstFp + ' (not yet announced in the mesh)');
    const id = crypto.randomBytes(16).toString('hex');
    const sealed = e2e.seal({ identity: this.id, dstFp, dstX: d.x, body: inner, id });
    this._markSeen(id);
    const n = this._forward({ t: 'relay', id, dst: dstFp, ttl: this.o.maxHops ?? 8, path: [this.fp], sealed }, null);
    if (!n) throw new Error('no connected peers to relay through');
  }
  // Flood to trusted neighbours not already on the path; straight to the destination if it is a neighbour.
  _forward(frame, from){
    const dstName = this.byFp.get(frame.dst);
    if (dstName && this._direct({ name: dstName })){ this._safeWrite(dstName, frame); return 1; }
    let n = 0;
    for (const [name, st] of this.peers){
      if (name === from || !st.ch || !st.trusted || frame.path.includes(st.cfg.fingerprint)) continue;
      this._safeWrite(name, frame); n++;
    }
    return n;
  }
  _onRelay(from, m){
    if (typeof m.id !== 'string' || !/^[0-9a-f]{32}$/.test(m.id) || typeof m.dst !== 'string' || !Number.isInteger(m.ttl) || !Array.isArray(m.path) || m.path.length > 32 || !m.sealed) return this._alert('bad-relay', from, 'malformed relay frame');
    if (!this._markSeen(m.id)) return;                                   // dedupe
    if (m.dst !== this.fp){
      if (m.path.includes(this.fp)) return;                              // loop
      if (m.ttl <= 1) return this.emit('relay-dropped', m.id, 'ttl');    // hop limit
      return this._forward({ ...m, ttl: m.ttl - 1, path: [...m.path, this.fp] }, from);
    }
    let env;
    try { env = e2e.open(m.sealed, this.id, this.box); } catch (e) { return this._alert('relay-open-failed', from, e.message); }
    if (env.id !== m.id) return this._alert('relay-open-failed', from, 'outer/inner id mismatch');
    if (Math.abs(Date.now() - env.ts) > (this.o.relayMaxAgeMs ?? 300_000)) return this._alert('relay-stale', from, 'envelope too old/new');
    const srcName = this.byFp.get(env.src);
    const acc = this.o.acceptRelayFrom || [];
    const ok = (srcName && this.peers.get(srcName).trusted) || acc.includes('*') || acc.includes(env.src);
    if (!ok) return this._alert('relay-unknown-sender', from, 'dropped e2e message from unpaired ' + env.src);
    const who = srcName || env.src, b = env.body || {};
    if (b.k === 'msg') return this.emit('message', { from: who, fromFp: env.src, via: from, body: b.body });
    if (b.k === 'req'){
      (async () => {
        let res;
        try { if (!this.o.handler) throw new Error('no handler on ' + this.name); res = { k: 'res', rid: b.rid, ok: true, result: await this.o.handler(b.body, who) }; }
        catch (e) { res = { k: 'res', rid: b.rid, ok: false, error: String(e?.message || e) }; }
        try { this._relaySend(env.src, res); } catch (e) { this.emit('relay-dropped', b.rid, e.message); }
      })();
      return;
    }
    if (b.k === 'res'){
      const p = this.pending.get(b.rid);
      if (!p || !p.viaRelay || p.peerFp !== env.src) return;
      this.pending.delete(b.rid); clearTimeout(p.timer);
      return b.ok ? p.resolve(b.result) : p.reject(new Error(b.error || 'remote error'));
    }
  }

  // ── liveness ────────────────────────────────────────────────────────────
  _tick(){
    const now = Date.now();
    for (const [n, st] of this.peers){
      if (!st.ch) continue;
      if (now - st.lastSeen > this.o.deadMs){ this.emit('peer-dead', n); st.ch.fail(new Error('heartbeat timeout')); continue; }
      this._safeWrite(n, { t: 'hb', ts: now });
    }
  }

  // ── canary challenge-response ───────────────────────────────────────────
  // A node holding the mesh canary secret answers HMAC(secret, c ‖ asker ‖ answerer).
  // A peer whose identity key was stolen and replayed elsewhere (without the separately
  // stored canary secret), or that is running modified code, fails and is marked untrusted.
  _canaryMac(c, askerFp, answererFp){
    if (!this.o.canarySecret) return null;
    return crypto.createHmac('sha256', Buffer.from(this.o.canarySecret, 'hex')).update('seccore-canary|' + c + '|' + askerFp + '|' + answererFp).digest('hex');
  }
  _canaryAll(){ for (const [n, st] of this.peers) if (st.ch && st.trusted) this._canary(n); }
  _canary(name){
    const st = this.peers.get(name);
    if (st.pendingCanary) return this._canaryFail(name, 'no canary answer');
    const c = crypto.randomBytes(16).toString('hex');
    st.pendingCanary = { c, timer: setTimeout(() => { if (st.pendingCanary?.c === c){ st.pendingCanary = null; this._canaryFail(name, 'canary timeout'); } }, this.o.canaryTimeoutMs ?? 10000) };
    st.pendingCanary.timer.unref?.();
    this._safeWrite(name, { t: 'canary', c });
  }
  _checkCanary(name, m){
    const st = this.peers.get(name), p = st.pendingCanary;
    if (!p || m.c !== p.c) return this._canaryFail(name, 'unsolicited canary answer');
    clearTimeout(p.timer); st.pendingCanary = null;
    if (typeof m.mac === 'string' && safeEq(m.mac, this._canaryMac(p.c, this.fp, st.cfg.fingerprint))){ st.strikes = 0; this.emit('canary-ok', name); return; }
    this._canaryFail(name, 'canary HMAC wrong');
  }
  _canaryFail(name, why){
    const st = this.peers.get(name);
    st.strikes++;
    this._alert('canary-fail', name, why + ' (strike ' + st.strikes + ')');
    // A wrong HMAC is proof of compromise; timeouts get one more chance.
    if (why === 'canary HMAC wrong' || st.strikes >= 2){
      st.trusted = false;
      this._alert('peer-untrusted', name, 'marked untrusted: ' + why);
      if (st.ch) st.ch.close();
    }
  }

  _alert(kind, peer, detail){
    const a = { ts: new Date().toISOString(), node: this.name, kind, peer, detail };
    this.alerts.push(a); if (this.alerts.length > 500) this.alerts.shift();
    if (this.o.alertLog) { try { fs.appendFileSync(this.o.alertLog, JSON.stringify(a) + '\n', { mode: 0o600 }); } catch {} }
    this.emit('alert', a);
  }

  async stop(){
    this.stopped = true;
    clearInterval(this.hbTimer); clearInterval(this.canaryTimer);
    for (const [, st] of this.peers){ clearTimeout(st.timer); st.timer = null; if (st.pendingCanary) clearTimeout(st.pendingCanary.timer); if (st.ch){ const c = st.ch; st.ch = null; c.sock.destroy(); } }
    for (const [, p] of this.pending){ clearTimeout(p.timer); p.reject(new Error('node stopped')); }
    this.pending.clear();
    await Promise.all([this.server, this.decoy, this.ctl].filter(Boolean).map((s) => new Promise((r) => s.close(() => r()))));
  }
}

// ── local control interface (127.0.0.1 HTTP, bearer token mandatory) ─────
export function ensureToken(file){
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const t = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, t + '\n', { mode: 0o600 });
  return t;
}
export function startControl(node, { port = 0, token }){
  if (!token || token.length < 32) throw new Error('control token required (>=32 chars)');
  const reply = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const srv = http.createServer((req, res) => {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ') || !safeEq(auth.slice(7), token)) return reply(res, 401, { ok: false, error: 'missing or bad token' });
    // Block browser-originated requests (DNS rebinding / CSRF): require our own host header, no Origin.
    if (req.headers.origin) return reply(res, 403, { ok: false, error: 'browser origin refused' });
    let size = 0; const chunks = [];
    req.on('data', (d) => { size += d.length; if (size > MAX_CTL_BODY){ reply(res, 413, { ok: false, error: 'too large' }); req.destroy(); } else chunks.push(d); });
    req.on('end', async () => {
      if (res.writableEnded) return;
      let b = {};
      try { if (chunks.length) b = JSON.parse(Buffer.concat(chunks).toString()); } catch { return reply(res, 400, { ok: false, error: 'bad json' }); }
      try {
        const u = new URL(req.url, 'http://x');
        if (req.method === 'GET' && u.pathname === '/status') return reply(res, 200, { ok: true, ...node.status() });
        if (req.method === 'GET' && u.pathname === '/peers') return reply(res, 200, { ok: true, peers: node.status().peers });
        if (req.method === 'POST' && u.pathname === '/send'){ node.send(b.to, b.body); return reply(res, 200, { ok: true }); }
        if (req.method === 'POST' && u.pathname === '/broadcast') return reply(res, 200, { ok: true, sent: node.broadcast(b.body) });
        if (req.method === 'POST' && u.pathname === '/request') return reply(res, 200, { ok: true, result: await node.request(b.to, b.body, b.timeoutMs) });
        if (req.method === 'POST' && u.pathname === '/retrust') return reply(res, 200, { ok: node.retrust(b.peer) });
        if (req.method === 'GET' && u.pathname === '/inbox'){ const m = node.inbox?.splice(0) ?? []; return reply(res, 200, { ok: true, messages: m }); }
        return reply(res, 404, { ok: false, error: 'not found' });
      } catch (e) { return reply(res, 502, { ok: false, error: String(e.message || e) }); }
    });
  });
  srv.listen(port, '127.0.0.1');            // never exposed beyond loopback
  node.ctl = srv;
  return new Promise((r) => srv.once('listening', () => r(srv)));
}
