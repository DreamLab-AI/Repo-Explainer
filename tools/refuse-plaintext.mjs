#!/usr/bin/env node
// Decide whether anything under a sealed directory is readable, and be right about it.
//
// The naive test — search each file for "PNG" or "ftyp" and fail on a hit — is wrong, and
// wrong in the direction that matters. Ciphertext is indistinguishable from random bytes, so a
// three-byte marker turns up in it by chance: across 700 files of 4KB each that is about one
// expected hit per run. A gate that cries leak on a healthy build is a gate people learn to
// wave through, which is worse than no gate.
//
// The property actually worth testing is narrower and checkable: no published file IS a
// readable file of a known kind. A readable file carries its signature at a fixed offset, so
// that is where this looks. Longer markers, the ones chance cannot produce, are still searched
// for anywhere.
//
//   refuse-plaintext.mjs <dir> [--extra <marker>]...
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// A signature at its canonical offset means the file is that kind of file.
const SIGNATURES = [
  { name: 'PNG image',  at: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { name: 'JPEG image', at: 0, bytes: [0xff, 0xd8, 0xff] },
  { name: 'GIF image',  at: 0, text: 'GIF8' },
  { name: 'MP4 video',  at: 4, text: 'ftyp' },
  { name: 'WebM video', at: 0, bytes: [0x1a, 0x45, 0xdf, 0xa3] },
  { name: 'RIFF/WAV',   at: 0, text: 'RIFF' },
  { name: 'PDF',        at: 0, text: '%PDF-' },
  { name: 'Zip or Office file', at: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { name: 'gzip',       at: 0, bytes: [0x1f, 0x8b] },
];
// A readable text file is readable: its opening bytes are all printable. Ciphertext is not,
// and cannot be by accident — thirty-two printable bytes in a row occur in random data about
// once in twenty trillion files. This replaces a list of opening markers, which could not work:
// "{" is one byte, so one sealed file in every 256 starts with it, and a gate that fails on a
// healthy build of 800 files three times a run is a gate that gets switched off.
const TEXT_RUN = 32;
const printable = (b) => (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;
// Long enough that random bytes will not produce them within the age of this repository.
const ANYWHERE = ['WEBVTT', '<!doctype html', '<!DOCTYPE html', '</html>', '-----BEGIN'];

const dir = process.argv[2];
const extra = [];
for (let i = 3; i < process.argv.length; i++) if (process.argv[i] === '--extra') extra.push(process.argv[++i]);
if (!dir) { console.error('usage: refuse-plaintext.mjs <dir> [--extra <marker>]...'); process.exit(2); }
if (!existsSync(dir)) { console.log(`${dir} does not exist; nothing to check`); process.exit(0); }

const files = [];
(function walk(d) {
  for (const e of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, e.name);
    e.isDirectory() ? walk(p) : files.push(p);
  }
})(dir);

const ALLOWED = /(\.bin|\.params\.json)$/;      // ciphertext, and the derivation parameters
const problems = [];
let scanned = 0;

for (const f of files) {
  if (!ALLOWED.test(f)) { problems.push(`${f}: not sealed — this file would be published as it is`); continue; }
  if (f.endsWith('.params.json')) continue;     // salt and iteration count, public by design
  scanned++;
  const buf = readFileSync(f);

  for (const s of SIGNATURES) {
    const want = s.bytes ?? [...Buffer.from(s.text, 'latin1')];
    if (want.every((b, i) => buf[s.at + i] === b)) problems.push(`${f}: begins as a ${s.name}`);
  }
  if (buf.length >= TEXT_RUN && [...buf.slice(0, TEXT_RUN)].every(printable)) {
    problems.push(`${f}: opens with ${TEXT_RUN} bytes of readable text: `
      + `"${buf.slice(0, 48).toString('latin1').replace(/\s+/g, ' ')}"`);
  }

  const whole = buf.toString('latin1');
  for (const m of [...ANYWHERE, ...extra]) {
    const at = whole.indexOf(m);
    if (at >= 0) problems.push(`${f}: contains "${m}" at offset ${at}`);
  }
}

if (problems.length) {
  console.error(`${problems.length} problem(s); this build must not be published:`);
  for (const p of problems.slice(0, 40)) console.error('  ' + p);
  process.exit(1);
}
const bytes = files.filter((f) => f.endsWith('.bin')).reduce((s, f) => s + statSync(f).size, 0);
console.log(`${scanned} sealed files (${(bytes / 1048576).toFixed(1)} MB) carry no signature and open as bytes, not text`);
