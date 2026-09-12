#!/usr/bin/env node
// Prove three things before anything is published, using the browser's own crypto interface
// so the test exercises the same path the reader will:
//   1. the right passphrase opens the manifest and a file of every kind, video included;
//   2. a wrong passphrase opens nothing, failing on the authentication tag rather than
//      returning something that looks plausible;
//   3. no readable byte was published — delegated to refuse-plaintext.mjs, which is the same
//      check the deploy gate runs, so a build cannot pass here and fail there.
//
//   verify.mjs --site <dir> --pack <name> --passphrase <phrase>
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

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

// Every reference a page makes must resolve inside the pack. The reader has no filesystem to
// fall back on: a path the manifest does not carry is a broken image or a dead link with no
// way to recover it. This matters more after excluding anything from the seal, and it is the
// mirror of the fault that prompted it — seven clips and seven diagrams sat in this pack for a
// day, gated and sealed, referenced by no page at all.
{
  const paths = new Set(manifest.entries.map((e) => e.path));
  const pages = manifest.entries.filter((e) => e.type === 'text/html');
  const dangling = [], citations = [];
  let refs = 0;
  for (const page of pages) {
    const html = new TextDecoder().decode(await open(readFileSync(join(site, 'enc', pack, `${page.blob}.bin`)), key));
    const dir = page.path.includes('/') ? page.path.slice(0, page.path.lastIndexOf('/') + 1) : '';
    for (const m of html.matchAll(/\s(?:src|href|poster)\s*=\s*"([^"]+)"/g)) {
      const raw = m[1];
      if (/^(https?:|mailto:|data:|blob:|#|\/)/i.test(raw)) continue;
      refs++;
      const target = new URL(dir + raw.split('#')[0], 'http://x/').pathname.slice(1);
      if (!target || paths.has(target)) continue;
      // A path that climbs out of the pack is a citation into the repository the pack was
      // written from. Those are deliberate, the viewer shows them as text, and they are not a
      // fault. A path that stays inside the pack and resolves to nothing is.
      (raw.startsWith('../../') ? citations : dangling).push(`${page.path} -> ${target}`);
    }
  }
  console.log(dangling.length === 0
    ? `${refs} references across ${pages.length} pages resolve, ${citations.length} of them `
      + 'citations into the repository which the viewer shows as text'
    : `${dangling.length} reference(s) point at nothing in this pack:`);
  for (const d of dangling.slice(0, 20)) console.log('  ' + d);
  if (dangling.length) process.exitCode = 1;
}

// Media a reader can actually reach. A pack whose clips are produced, gated and sealed but
// embedded in no page passes every other check here and delivers none of them.
{
  const pages = manifest.entries.filter((e) => e.type === 'text/html');
  let withVideo = 0, withImage = 0, withCaptions = 0;
  for (const page of pages) {
    const html = new TextDecoder().decode(await open(readFileSync(join(site, 'enc', pack, `${page.blob}.bin`)), key));
    if (/<video\b/i.test(html)) withVideo++;
    if (/<img\b/i.test(html)) withImage++;
    if (/<track\b/i.test(html)) withCaptions++;
  }
  const clips = manifest.entries.filter((e) => e.type.startsWith('video/')).length;
  console.log(`${clips} clip(s) sealed; ${withVideo} of ${pages.length} pages embed a player, `
    + `${withCaptions} carry captions, ${withImage} show a picture`);
  if (clips > 0 && withVideo === 0) {
    console.log('  no page embeds a clip: the video ships but no reader can reach it');
    process.exitCode = 1;
  }
}

// Nothing published may be readable. The check lives in refuse-plaintext.mjs so that this
// verification and the deploy gate cannot drift apart, and so neither can be satisfied by a
// looser test than the other. Pass --marker <word> to also refuse a build containing a name
// that should not travel (a client's, a product's); the word stays on the command line rather
// than in this file, which is public.
const markers = [];
for (let i = 2; i < process.argv.length; i++) if (process.argv[i] === '--marker') markers.push(process.argv[++i]);
const gate = spawnSync(process.execPath,
  [join(import.meta.dirname, 'refuse-plaintext.mjs'), join(site, 'enc'),
   ...markers.flatMap((m) => ['--extra', m])],
  { encoding: 'utf8' });
process.stdout.write(gate.stdout ?? '');
process.stderr.write(gate.stderr ?? '');
if (gate.status !== 0) process.exitCode = 1;
