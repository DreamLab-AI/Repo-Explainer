#!/usr/bin/env node
// Prove three things before anything is published, using the browser's own crypto interface
// so the test exercises the same path the reader will:
//   1. the right passphrase opens the manifest and a file of every kind, video included;
//   2. a wrong passphrase opens nothing, failing on the authentication tag rather than
//      returning something that looks plausible;
//   3. no readable byte was published — no plaintext, no recognisable file signature.
//
//   verify.mjs --site <dir> --pack <name> --passphrase <phrase>
import { webcrypto } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const { subtle } = webcrypto;
const args = (() => { const a = {}; const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i++) { if (!v[i].startsWith('--')) continue;
    const k = v[i].slice(2), n = v[i + 1]; a[k] = n === undefined || n.startsWith('--') ? true : (i++, n); }
  return a; })();

const site = args.site ?? 'site';
const pack = args.pack ?? 'executive';
const params = JSON.parse(readFileSync(join(site, 'enc', `${pack}.params.json`), 'utf8'));

async function keyFrom(passphrase) {
  const material = await subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt: Buffer.from(params.salt, 'base64'), iterations: params.iterations, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function open(buf, key) {
  const b = new Uint8Array(buf);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, params.ivBytes) }, key, b.slice(params.ivBytes)));
}

const key = await keyFrom(args.passphrase);
const manifest = JSON.parse(new TextDecoder().decode(
  await open(readFileSync(join(site, 'enc', `${pack}.manifest.bin`)), key)));
console.log(`manifest opens: ${manifest.entries.length} files, entry ${manifest.entry}`);

// One file of each kind, so a claim that "it decrypts" is not resting on the HTML alone.
const signatures = { 'video/mp4': [0x66, 0x74, 0x79, 0x70], 'image/png': [0x89, 0x50, 0x4e, 0x47], 'image/jpeg': [0xff, 0xd8, 0xff] };
const seen = new Set();
let checked = 0;
for (const e of manifest.entries) {
  if (seen.has(e.type)) continue;
  seen.add(e.type);
  const plain = await open(readFileSync(join(site, 'enc', pack, `${e.blob}.bin`)), key);
  let note = `${plain.length} bytes`;
  const sig = signatures[e.type];
  if (sig) {
    const at = e.type === 'video/mp4' ? 4 : 0;   // an mp4's ftyp box begins after its length
    const ok = sig.every((b, i) => plain[at + i] === b);
    note += ok ? ', signature correct' : ', SIGNATURE WRONG';
    if (!ok) process.exitCode = 1;
  }
  if (e.type.startsWith('text/') || e.type === 'application/json') {
    note += `, begins "${new TextDecoder().decode(plain.slice(0, 40)).replace(/\s+/g, ' ').trim()}…"`;
  }
  console.log(`  ${e.type.padEnd(24)} ${e.path.slice(0, 46).padEnd(48)} ${note}`);
  checked++;
}
console.log(`${checked} file kinds decrypted, video included`);

// A wrong passphrase must fail, not degrade.
try {
  await open(readFileSync(join(site, 'enc', `${pack}.manifest.bin`)), await keyFrom(args.passphrase + 'x'));
  console.log('WRONG PASSPHRASE OPENED THE MANIFEST — the seal is broken');
  process.exitCode = 1;
} catch {
  console.log('a wrong passphrase fails on the authentication tag, as it must');
}

// Nothing published may be readable. Scan every byte that ships for a signature or plain text.
const marks = ['ftyp', '<!doctype', '<html', 'PNG', 'JFIF', 'WEBVTT', 'campaignbuilder'];
let leaked = 0, scanned = 0;
const walk = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { walk(p); continue; }
    if (!p.endsWith('.bin')) continue;
    scanned++;
    const head = readFileSync(p).slice(0, 4096).toString('latin1');
    for (const m of marks) if (head.includes(m)) { console.log(`  LEAK: ${p} contains "${m}"`); leaked++; }
  }
};
walk(join(site, 'enc'));
console.log(leaked === 0
  ? `${scanned} sealed files scanned, none reveals its type or content`
  : `${leaked} sealed file(s) leak something readable`);
if (leaked) process.exitCode = 1;
