// Allowlisted task runner. Peers can only run tasks declared in tasks.json, with
// argv templates (no shell), anchored per-argument regexes, per-peer authorization,
// scrubbed env, timeouts, output caps, and a concurrent job cap.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ash', 'fish', 'ksh', 'csh', 'tcsh', 'busybox', 'env', 'sudo', 'su', 'doas', 'xargs', 'nohup', 'eval', 'cmd', 'cmd.exe', 'powershell', 'pwsh', 'python', 'python3', 'node', 'perl', 'ruby', 'php', 'lua']);
const PLACEHOLDER = /^\{([a-zA-Z_][a-zA-Z0-9_]*)\}$/;
const expandHome = (p) => (p && p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p);

export function loadTasks(file){
  if (!fs.existsSync(file)) return { tasks: {} };
  return validateTasks(JSON.parse(fs.readFileSync(file, 'utf8')));
}

export function validateTasks(cfg){
  const out = { __validated: true, allowInterpreters: cfg.allowInterpreters === true, maxConcurrent: cfg.maxConcurrent ?? 2, tasks: {} };
  for (const [name, t] of Object.entries(cfg.tasks || {})){
    if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) throw new Error('bad task name ' + name);
    if (!Array.isArray(t.argv) || !t.argv.length || !t.argv.every((x) => typeof x === 'string')) throw new Error(name + ': argv must be a non-empty string array');
    if (PLACEHOLDER.test(t.argv[0]) || t.argv[0].includes('{')) throw new Error(name + ': argv[0] must be a literal program');
    const prog = path.basename(t.argv[0]);
    if (SHELLS.has(prog) && !(out.allowInterpreters && t.allowInterpreter === true))
      throw new Error(name + ': "' + prog + '" is a shell/interpreter; disabled unless allowInterpreters and allowInterpreter are both true');
    const args = {};
    for (const el of t.argv.slice(1)){
      if (el.includes('{') && !PLACEHOLDER.test(el)) throw new Error(name + ': placeholders must be a whole argv element, got ' + el);
      const m = el.match(PLACEHOLDER);
      if (m){
        const pat = t.args?.[m[1]];
        if (typeof pat !== 'string') throw new Error(name + ': no pattern for arg ' + m[1]);
        args[m[1]] = new RegExp('^(?:' + pat + ')$', 'u');          // always anchored
      }
    }
    const pathArgs = {};
    for (const [k, spec] of Object.entries(t.pathArgs || {})){
      if (!args[k]) throw new Error(name + ': pathArgs.' + k + ' is not a placeholder arg');
      if (!Array.isArray(spec.roots) || !spec.roots.length) throw new Error(name + ': pathArgs.' + k + '.roots required');
      pathArgs[k] = { roots: spec.roots.map(expandHome), mustExist: spec.mustExist !== false, type: spec.type || 'any' };
    }
    const limits = t.limits || null;
    if (limits) for (const [k, v] of Object.entries(limits)) if (!['cpuSeconds', 'memoryMB', 'fileSizeMB', 'nproc', 'nofile'].includes(k) || !Number.isInteger(v) || v <= 0) throw new Error(name + ': bad limit ' + k);
    const wrapper = t.sandbox?.wrapper || null;
    if (wrapper && (!Array.isArray(wrapper) || !wrapper.every((x) => typeof x === 'string' && !x.includes('{')))) throw new Error(name + ': sandbox.wrapper must be literal strings');
    if (wrapper && SHELLS.has(path.basename(wrapper[0]))) throw new Error(name + ': sandbox.wrapper cannot be a shell/interpreter');
    const cwd = expandHome(t.cwd) || os.homedir();
    if (path.resolve(cwd) === '/') throw new Error(name + ': cwd "/" refused; use a dedicated work directory');
    if (!Array.isArray(t.peers)) throw new Error(name + ': peers must list who may call it (["*"] for all trusted peers)');
    out.tasks[name] = {
      argv: t.argv, args, peers: t.peers, cwd, pathArgs, limits, wrapper, requireLimits: t.requireLimits === true,
      timeoutMs: t.timeoutMs ?? 60_000, maxOutput: t.maxOutput ?? 1 << 20,
      env: t.env || {}, description: t.description || '',
    };
  }
  return out;
}

// Resolve symlinks and require the path to stay inside one of the allowed roots.
function checkPath(v, cwd, spec, name){
  const abs = path.resolve(cwd, v);
  let real;
  try { real = fs.realpathSync(abs); }
  catch { if (spec.mustExist) throw new Error('path arg ' + name + ' does not exist'); real = path.join(fs.realpathSync(path.dirname(abs)), path.basename(abs)); }
  const inside = spec.roots.some((r) => { let rr; try { rr = fs.realpathSync(r); } catch { return false; } return real === rr || real.startsWith(rr + path.sep); });
  if (!inside) throw new Error('path arg ' + name + ' is outside the allowed roots');
  if (spec.mustExist && spec.type !== 'any'){ const st = fs.statSync(real); if (spec.type === 'file' ? !st.isFile() : !st.isDirectory()) throw new Error('path arg ' + name + ' must be a ' + spec.type); }
  return real;
}
let prlimitOk;
function hasPrlimit(){ if (prlimitOk === undefined){ const r = spawnSync('prlimit', ['--version'], { stdio: 'ignore' }); prlimitOk = r.status === 0; } return prlimitOk; }
function limitArgv(l){
  const o = [];
  if (l.cpuSeconds) o.push('--cpu=' + l.cpuSeconds);
  if (l.memoryMB) o.push('--as=' + l.memoryMB * 1024 * 1024);
  if (l.fileSizeMB) o.push('--fsize=' + l.fileSizeMB * 1024 * 1024);
  if (l.nproc) o.push('--nproc=' + l.nproc);
  if (l.nofile) o.push('--nofile=' + l.nofile);
  return ['prlimit', ...o, '--'];
}
function killTree(child, sig){ try { process.kill(-child.pid, sig); } catch { try { child.kill(sig); } catch {} } }
const digest = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 16);

export class TaskRunner {
  constructor(cfg, { maxJobsKept = 200, audit = null } = {}){
    this.cfg = cfg.__validated ? cfg : validateTasks(cfg);
    this.audit = audit;
    this.jobs = new Map(); this.running = 0; this.maxJobsKept = maxJobsKept;
  }
  allowed(peer){ return Object.entries(this.cfg.tasks).filter(([, t]) => t.peers.includes('*') || t.peers.includes(peer)).map(([n, t]) => ({ name: n, description: t.description, args: Object.keys(t.args) })); }

  buildArgv(name, args = {}){
    const t = this.cfg.tasks[name];
    if (!t) throw new Error('unknown task ' + name);
    if (args === null || typeof args !== 'object') throw new Error('args must be an object');
    for (const k of Object.keys(args)) if (!t.args[k]) throw new Error('unexpected arg ' + k);
    return t.argv.map((el, i) => {
      const m = i > 0 && el.match(PLACEHOLDER);
      if (!m) return el;
      const v = args[m[1]];
      if (typeof v !== 'string') throw new Error('missing arg ' + m[1]);
      if (v.includes('\0')) throw new Error('NUL in arg ' + m[1]);
      if (v.length > 65536) throw new Error('arg ' + m[1] + ' too long');
      if (!t.args[m[1]].test(v)) throw new Error('arg ' + m[1] + ' does not match allowed pattern');
      if (t.pathArgs[m[1]]) return checkPath(v, t.cwd, t.pathArgs[m[1]], m[1]);
      return v;
    });
  }

  _audit(e){ try { this.audit?.append(e); } catch {} }
  submit(peer, name, args){
    try { return this._submit(peer, name, args); }
    catch (e) { this._audit({ event: 'refused', peer, task: String(name).slice(0, 64), reason: e.message }); throw e; }
  }
  _submit(peer, name, args){
    const t = this.cfg.tasks[name];
    if (!t || !(t.peers.includes('*') || t.peers.includes(peer))) throw new Error('task ' + name + ' not permitted for ' + peer);
    let argv = this.buildArgv(name, args);
    if (!fs.existsSync(t.cwd) || !fs.statSync(t.cwd).isDirectory()) throw new Error('task cwd ' + t.cwd + ' does not exist');
    const sandbox = { limits: 'none', wrapper: !!t.wrapper };
    if (t.limits){
      if (hasPrlimit()){ argv = [...limitArgv(t.limits), ...argv]; sandbox.limits = 'prlimit'; }
      else if (t.requireLimits) throw new Error('resource limits required but prlimit is unavailable (pkg install util-linux)');
      else sandbox.limits = 'unenforced (no prlimit)';
    }
    if (t.wrapper) argv = [...t.wrapper, ...argv];
    if (this.running >= this.cfg.maxConcurrent) throw new Error('busy: ' + this.running + ' jobs running (cap ' + this.cfg.maxConcurrent + ')');
    const id = crypto.randomBytes(12).toString('hex');
    const job = { id, peer, task: name, sandbox, state: 'running', startedAt: Date.now(), endedAt: null, exitCode: null, signal: null, stdout: '', stderr: '', truncated: false, error: null };
    const env = { PATH: process.env.PATH, HOME: os.homedir(), LANG: process.env.LANG || 'C.UTF-8', TMPDIR: process.env.TMPDIR || os.tmpdir(), ...t.env };
    let child;
    // Own process group (detached) so timeout/cancel kills the whole tree, not just the leader.
    try { child = spawn(argv[0], argv.slice(1), { cwd: t.cwd, env, shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true }); }
    catch (e) { throw new Error('spawn failed: ' + e.message); }
    this.running++; job.child = child;
    let size = 0;
    const take = (key) => (d) => {
      if (job.truncated) return;
      size += d.length;
      if (size > t.maxOutput){ job.truncated = true; job[key] += d.subarray(0, Math.max(0, d.length - (size - t.maxOutput))).toString(); killTree(child, 'SIGKILL'); return; }
      job[key] += d.toString();
    };
    child.stdout.on('data', take('stdout')); child.stderr.on('data', take('stderr'));
    const timer = setTimeout(() => { job.timedOut = true; killTree(child, 'SIGTERM'); setTimeout(() => killTree(child, 'SIGKILL'), 2000).unref(); }, t.timeoutMs);
    timer.unref?.();
    const done = new Promise((resolve) => {
      let finished = false;
      const fin = (code, sig, err) => {
        if (finished) return; finished = true;
        clearTimeout(timer); this.running--; delete job.child;
        job.exitCode = code; job.signal = sig; job.endedAt = Date.now();
        if (err) job.error = err.message;
        job.state = job.state === 'cancelled' ? 'cancelled' : job.timedOut ? 'timeout' : err ? 'error' : code === 0 ? 'done' : 'failed';
        this._audit({ event: 'end', peer, task: name, job: id, state: job.state, exitCode: code, signal: sig, ms: job.endedAt - job.startedAt, outBytes: size, truncated: job.truncated });
        resolve(this.view(job, true));
      };
      child.on('error', (e) => fin(null, null, e));
      child.on('close', (code, sig) => fin(code, sig));
    });
    job.done = done;
    this._audit({ event: 'start', peer, task: name, job: id, argv: argv.map((x) => (x.length > 120 ? x.slice(0, 120) + '…#' + digest(x) : x)), sandbox });
    this.jobs.set(id, job); this._gc();
    return { id, task: name, state: 'running' };
  }
  _get(peer, id){ const j = this.jobs.get(id); if (!j || j.peer !== peer) throw new Error('no such job'); return j; }
  view(j, full = false){
    const v = { id: j.id, task: j.task, state: j.state, startedAt: j.startedAt, endedAt: j.endedAt, exitCode: j.exitCode, signal: j.signal, truncated: j.truncated, error: j.error };
    return full ? { ...v, stdout: j.stdout, stderr: j.stderr } : v;
  }
  status(peer, id){ return this.view(this._get(peer, id)); }
  result(peer, id){ const j = this._get(peer, id); return j.state === 'running' ? this.view(j) : this.view(j, true); }
  async wait(peer, id){ return this._get(peer, id).done; }
  cancel(peer, id){ const j = this._get(peer, id); if (j.state === 'running'){ j.state = 'cancelled'; j.child && killTree(j.child, 'SIGTERM'); } return this.view(j); }
  list(peer){ return [...this.jobs.values()].filter((j) => j.peer === peer).map((j) => this.view(j)); }
  _gc(){ if (this.jobs.size <= this.maxJobsKept) return; for (const [id, j] of this.jobs){ if (j.state !== 'running'){ this.jobs.delete(id); if (this.jobs.size <= this.maxJobsKept) break; } } }
  stopAll(){ for (const j of this.jobs.values()) if (j.state === 'running'){ j.state = 'cancelled'; j.child && killTree(j.child, 'SIGKILL'); } }
}

// Request handler for MeshNode: {op:'task.list'|'task.submit'|'task.run'|'task.status'|'task.result'|'task.cancel'|'task.jobs'|'ping'|'echo'}
export function taskHandler(runner, fallback){
  return async (body, from) => {
    const op = body?.op;
    if (op === 'ping') return { pong: Date.now() };
    if (op === 'echo') return body;
    if (runner){
      if (op === 'task.list') return runner.allowed(from);
      if (op === 'task.submit') return runner.submit(from, body.task, body.args || {});
      if (op === 'task.run'){ const j = runner.submit(from, body.task, body.args || {}); return runner.wait(from, j.id); }
      if (op === 'task.status') return runner.status(from, body.id);
      if (op === 'task.result') return runner.result(from, body.id);
      if (op === 'task.cancel') return runner.cancel(from, body.id);
      if (op === 'task.jobs') return runner.list(from);
    }
    if (fallback) return fallback(body, from);
    throw new Error('unsupported op ' + String(op));
  };
}
