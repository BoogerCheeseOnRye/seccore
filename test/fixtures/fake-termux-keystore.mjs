#!/usr/bin/env node
// Test double for termux-keystore: a per-"device" secret stands in for the hardware key.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const dir = process.env.FAKE_KS_DIR; fs.mkdirSync(dir, { recursive: true });
const [cmd, alias] = process.argv.slice(2);
const kf = (a) => path.join(dir, a + '.key');
if (cmd === 'list'){ console.log(JSON.stringify(fs.readdirSync(dir).map((f) => ({ alias: f.replace(/\.key$/, '') })))); }
else if (cmd === 'generate'){ fs.writeFileSync(kf(alias), crypto.randomBytes(32)); }
else if (cmd === 'sign'){
  const k = fs.readFileSync(kf(alias)); const data = fs.readFileSync(0);
  const out = []; for (let i = 0; i < 8; i++) out.push(crypto.createHmac('sha256', k).update(Buffer.from([i])).update(data).digest());
  process.stdout.write(Buffer.concat(out));
} else process.exit(1);
