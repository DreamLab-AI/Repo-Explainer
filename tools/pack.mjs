#!/usr/bin/env node
// Encrypt an explainer pack for publication on a host that has no access control of its own.
//
// The rule this enforces: EVERYTHING in a pack is encrypted. Encrypting the prose and leaving
// the media beside it in the clear is the obvious mistake and the worst one, because a clip
// shows the product working and its captions are a transcript of someone explaining it. A
// static host serves whatever path is asked for, so any file left readable is published.
//
// What ships in the clear is exactly two things: the landing page, which contains no client
// material, and the loader that asks for the passphrase.
//
//   pack.mjs --pack <name> --src <dir> --out <dir> --passphrase <phrase> [--entry index.html]
//
// Each file becomes <out>/enc/<pack>/<sha256 of its path>.bin — the ciphertext, and nothing
// about the name. The manifest maps real paths to those blobs and is itself encrypted, so the
// repository does not even disclose the shape of what it holds.
import { createHash, pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';

const ITERATIONS = 600_000;      // slow enough to make a weak passphrase costly to attack
const SALT_BYTES = 16;
const IV_BYTES = 12;

const args = (() => { const a = {}; const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i++) { if (!v[i].startsWith('--')) continue;
    const k = v[i].slice(2), n = v[i + 1]; a[k] = n === undefined || n.startsWith('--') ? true : (i++, n); }
  return a; })();
for (const need of ['pack', 'src', 'out', 'passphrase']) {
  if (!args[need]) { console.error(`pack.mjs: --${need} is required`); process.exit(2); }
}
if (!existsSync(args.src)) { console.error(`pack.mjs: no such directory: ${args.src}`); process.exit(2); }

const TYPES = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json',
  '.md': 'text/markdown', '.txt': 'text/plain', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.mp4': 'video/mp4',
  '.webm': 'video/webm', '.wav': 'audio/wav', '.mp3': 'audio/mpeg', '.vtt': 'text/vtt',
  '.srt': 'application/x-subrip', '.mmd': 'text/plain', '.ts': 'text/plain', '.py': 'text/plain',
};

// Skip what a reader does not need and what should never leave the engagement: the pack's own
// production record, anything a run left in a scratch directory, and version-control metadata.
const SKIP_DIR = new Set(['.git', 'node_modules', 'production', 'record', 'scratch', '__pycache__']);

const walk = (dir, out = []) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIR.has(e.name) || e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
};

const salt = randomBytes(SALT_BYTES);
const key = pbkdf2Sync(args.passphrase, salt, ITERATIONS, 32, 'sha256');

const seal = (plaintext) => {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // iv ‖ ciphertext ‖ tag, which is what the browser's WebCrypto expects once the iv is split off
  return Buffer.concat([iv, body, cipher.getAuthTag()]);
};

const files = walk(args.src);
const encDir = join(args.out, 'enc', args.pack);
mkdirSync(encDir, { recursive: true });

const entries = [];
let plainBytes = 0;
for (const f of files) {
  const rel = relative(args.src, f).split('\\').join('/');
  const raw = readFileSync(f);
  plainBytes += raw.length;
  const blob = createHash('sha256').update(`${args.pack}/${rel}`).digest('hex').slice(0, 32);
  writeFileSync(join(encDir, `${blob}.bin`), seal(raw));
  entries.push({ path: rel, blob, type: TYPES[extname(f).toLowerCase()] ?? 'application/octet-stream', size: raw.length });
}

// The manifest names every real path, so it is encrypted too: a public repository should not
// even disclose that a pack has a chapter called "failure and recovery".
const manifest = { pack: args.pack, entry: args.entry ?? 'index.html', built: new Date().toISOString().slice(0, 19) + 'Z', entries };
writeFileSync(join(args.out, 'enc', `${args.pack}.manifest.bin`), seal(Buffer.from(JSON.stringify(manifest))));

// Only the key-derivation parameters are public, which is normal and necessary: they tell the
// browser how to turn the passphrase into the same key, and they help an attacker not at all.
const paramsPath = join(args.out, 'enc', `${args.pack}.params.json`);
writeFileSync(paramsPath, JSON.stringify({
  pack: args.pack, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS,
  salt: salt.toString('base64'), cipher: 'AES-256-GCM', ivBytes: IV_BYTES,
}, null, 2) + '\n');

const encBytes = files.length ? readdirSync(encDir).reduce((n, f) => n + statSync(join(encDir, f)).size, 0) : 0;
console.log(`${args.pack}: ${entries.length} files sealed, ${(plainBytes / 1e6).toFixed(1)} MB in, ${(encBytes / 1e6).toFixed(1)} MB out`);
console.log(`  nothing readable was written: ${encDir}/*.bin plus an encrypted manifest`);
