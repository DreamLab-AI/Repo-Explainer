// Decrypt an explainer pack in the browser and serve it from memory.
//
// The host serves ciphertext and nothing else. Everything a reader sees is decrypted here,
// including the video: a clip is fetched as bytes, decrypted, and handed to the player as a
// blob, so the player never requests a path that a passer-by could request too.
//
// What this protects against: anyone who finds the repository. What it does not protect
// against: someone who has the passphrase, and an attacker willing to grind the ciphertext
// offline — which is why the passphrase is long and the derivation slow.

const KEY_STORE = 'explainer.key.v1';   // sessionStorage: gone when the tab closes
const state = { key: null, manifest: null, pack: null, params: null, urls: new Map() };

const $ = (sel) => document.querySelector(sel);
const bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

async function deriveKey(passphrase, params) {
  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytes(params.salt), iterations: params.iterations, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

// Sealed as iv ‖ ciphertext ‖ tag; WebCrypto wants the tag left on the end and the iv apart.
async function open(sealed, key, ivBytes) {
  const buf = new Uint8Array(sealed);
  const iv = buf.slice(0, ivBytes);
  const body = buf.slice(ivBytes);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, body));
}

async function fetchSealed(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.arrayBuffer();
}

async function unlock(pack, passphrase) {
  const params = await (await fetch(`enc/${pack}.params.json`, { cache: 'no-store' })).json();
  const key = await deriveKey(passphrase, params);
  let manifest;
  try {
    const raw = await open(await fetchSealed(`enc/${pack}.manifest.bin`), key, params.ivBytes);
    manifest = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    // A wrong passphrase fails the authentication tag; there is nothing else it could be.
    throw new Error('That passphrase does not open this pack.');
  }
  Object.assign(state, { key, manifest, pack, params });
  sessionStorage.setItem(KEY_STORE, JSON.stringify({ pack, passphrase }));
  return manifest;
}

function entryFor(path) {
  const clean = path.replace(/^\.\//, '').split('#')[0].split('?')[0];
  return state.manifest.entries.find((e) => e.path === clean)
      || state.manifest.entries.find((e) => e.path.endsWith('/' + clean));
}

// One decryption per file per session; a clip opened twice plays from the same blob.
async function urlFor(path) {
  const entry = entryFor(path);
  if (!entry) return null;
  if (state.urls.has(entry.blob)) return state.urls.get(entry.blob);
  const plain = await open(await fetchSealed(`enc/${state.pack}/${entry.blob}.bin`), state.key, state.params.ivBytes);
  const url = URL.createObjectURL(new Blob([plain], { type: entry.type }));
  state.urls.set(entry.blob, url);
  return url;
}

async function textOf(path) {
  const entry = entryFor(path);
  if (!entry) return null;
  const plain = await open(await fetchSealed(`enc/${state.pack}/${entry.blob}.bin`), state.key, state.params.ivBytes);
  return new TextDecoder().decode(plain);
}

// WebVTT, reduced to what a caption file from a narration step actually contains: an optional
// identifier, a timing line, and the lines of text under it. Settings after the timings are
// ignored rather than mis-parsed. Anything unrecognised is skipped, because one malformed cue
// should cost that cue and not the whole track.
function parseVtt(text) {
  const t = (s) => {
    const m = s.trim().match(/^(?:(\d+):)?(\d{1,2}):(\d{2})(?:[.,](\d{1,3}))?$/);
    if (!m) return null;
    return (+(m[1] ?? 0)) * 3600 + (+m[2]) * 60 + (+m[3]) + (+(m[4] ?? 0)) / 1000;
  };
  const cues = [];
  for (const block of text.replace(/\r\n?/g, '\n').split(/\n{2,}/)) {
    const lines = block.split('\n').filter((l) => l.trim() !== '');
    if (!lines.length || /^WEBVTT/.test(lines[0])) continue;
    const at = lines.findIndex((l) => l.includes('-->'));
    if (at < 0) continue;
    const [rawStart, rest] = lines[at].split('-->');
    const start = t(rawStart);
    const end = t((rest ?? '').trim().split(/\s+/)[0] ?? '');
    const body = lines.slice(at + 1).join('\n');
    if (start === null || end === null || end <= start || !body) continue;
    try { cues.push(new VTTCue(start, end, body)); } catch { /* skip a cue the browser rejects */ }
  }
  return cues;
}

// Rewrite a decrypted page so every reference points at a blob rather than at the host, and
// links between chapters stay inside the viewer.
async function render(path) {
  const html = await textOf(path);
  if (html === null) { $('#view').innerHTML = '<p class="miss">That page is not in this pack.</p>'; return; }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const base = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
  const resolve = (href) => (href.startsWith('/') || /^[a-z]+:/i.test(href) ? href
    : new URL(base + href, 'http://x/').pathname.slice(1));

  // A poster is a picture fetched like any other, but it arrives as its own attribute rather
  // than as src, so a loop over [src] walks straight past it and every clip opens on a broken
  // frame instead of the still someone chose.
  for (const el of doc.querySelectorAll('[poster]')) {
    const raw = el.getAttribute('poster');
    if (!raw || /^(https?:|data:|blob:)/i.test(raw)) continue;
    const url = await urlFor(resolve(raw));
    if (url) el.setAttribute('poster', url); else el.removeAttribute('poster');
  }
  // Everything with a src except a caption track, which is handled on its own further down:
  // this loop would otherwise give it a blob address here, in the parser's document, which is
  // precisely where a track cannot load one. Two loops both claiming the same element is how
  // the caption fix appeared to be running while doing nothing.
  for (const el of doc.querySelectorAll('[src]:not(track)')) {
    const raw = el.getAttribute('src');
    if (!raw || /^(https?:|data:|blob:)/i.test(raw)) continue;
    const url = await urlFor(resolve(raw));
    if (url) el.setAttribute('src', url); else el.removeAttribute('src');
  }
  // A pack's stylesheets live in its <head>, and only the body is inserted below, so rewriting
  // the links in the parsed document and stopping there throws the styling away: the pages then
  // inherit whatever this site's stylesheet happens to cover and lose their own layout. They
  // have to be adopted into the host document instead.
  //
  // All of them. A page linking two stylesheets is normal — one for the reading surface, one
  // for the source pane — and clearing the previous page's links inside the loop meant the
  // second adoption deleted the first, leaving a pack styled by half its own rules. So the set
  // for this page is gathered first, then what is no longer wanted goes, then what is missing
  // arrives.
  const wanted = new Map();
  for (const el of doc.querySelectorAll('link[rel="stylesheet"][href]')) {
    const target = resolve(el.getAttribute('href'));
    if (!wanted.has(target)) wanted.set(target, null);
  }
  for (const stale of document.querySelectorAll('link[data-pack-style]')) {
    if (!wanted.has(stale.dataset.packStyle)) stale.remove();
    else wanted.set(stale.dataset.packStyle, stale);
  }
  for (const [target, existing] of wanted) {
    if (existing) continue;
    const url = await urlFor(target);
    if (!url) continue;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    link.dataset.packStyle = target;
    document.head.append(link);
  }
  for (const el of doc.querySelectorAll('track[src], source[src]')) {
    const url = await urlFor(resolve(el.getAttribute('src')));
    if (!url) continue;
    // A source can carry its blob straight away. A track cannot: given a src while it still
    // belongs to the parser's document it starts loading there, fails, and stays failed after
    // adoption — readyState 3, no cues, captions quietly missing from every clip, and replacing
    // the element afterwards does not clear it. So the address is parked on the element and
    // attached below, once the element is somewhere a load can succeed.
    if (el.tagName === 'TRACK') { el.removeAttribute('src'); el.dataset.blobSrc = url; }
    else el.setAttribute('src', url);
  }
  // A link inside a pack usually goes to another page, and those stay in the viewer. Some go
  // to a file that is not a page at all — a transcript, a caption file, a clip — and rendering
  // one of those as HTML shows the reader its source. Those become ordinary links to a decrypted
  // blob, opened in a new tab, so the browser does what it would do with any file of that type.
  for (const a of doc.querySelectorAll('a[href]')) {
    const href = a.getAttribute('href');
    if (!href || /^(https?:|mailto:|#)/i.test(href)) continue;
    const target = resolve(href);
    const entry = entryFor(target.split('#')[0]);
    if (entry && entry.type !== 'text/html') {
      const url = await urlFor(target.split('#')[0]);
      if (url) { a.href = url; a.target = '_blank'; a.rel = 'noopener'; continue; }
    }
    // A citation points into the repository the pack was written from, which is not published
    // and cannot be: that is the whole reason the pack is sealed. Left as a link it is a dead
    // one. As text it still carries what it was for — the file and the lines a claim rests on,
    // which a reader with a checkout can open and a reader without one can at least name.
    if (!entry) {
      const span = document.createElement('span');
      span.className = 'unresolved';
      span.title = 'Cited from the repository, which is not published here';
      span.append(...a.childNodes);
      a.replaceWith(span);
      continue;
    }
    a.dataset.page = target;
    a.removeAttribute('href');
    a.setAttribute('role', 'link');
    a.setAttribute('tabindex', '0');
  }
  $('#view').replaceChildren(...doc.body.childNodes);
  // Captions, added as cues rather than fetched by the browser.
  //
  // Three ways of giving a track element a blob URL were tried and all three failed: in the
  // parser's document, after adoption, and on an element rebuilt here. readyState settles on 3
  // and the cues stay empty, so every clip plays with no captions and nothing says why. Rather
  // than keep guessing at what the element objects to, the text is decrypted here and the cues
  // are constructed directly, which depends on nothing but the WebVTT itself.
  for (const holder of $('#view').querySelectorAll('track[data-blob-src]')) {
    const url = holder.dataset.blobSrc;
    delete holder.dataset.blobSrc;
    const video = holder.closest('video');
    if (!video) continue;
    try {
      const vtt = await (await fetch(url)).text();
      // A track the video makes for itself is always writable. Reusing the element's own
      // TextTrack risks one already settled into an error state, which is the whole problem.
      const track = video.addTextTrack(holder.kind || 'captions', holder.label || 'English',
                                      holder.srclang || 'en');
      const cues = parseVtt(vtt);
      for (const cue of cues) track.addCue(cue);
      track.mode = cues.length && holder.hasAttribute('default') ? 'showing' : 'hidden';
      holder.remove();   // it would sit there failing to load, and show as a second empty track
    } catch { /* a clip without captions still plays; a broken page does not */ }
  }

  $('#view').querySelectorAll('[data-page]').forEach((a) => {
    const go = (e) => { e.preventDefault(); render(a.dataset.page); window.scrollTo(0, 0); };
    a.addEventListener('click', go);
    a.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(e); });
  });
  history.replaceState(null, '', `#${state.pack}/${path}`);
}

// What each collection is called in a sentence, so a gate reads "the documentation stack" and
// not "the docs pack". A name not listed here falls back to the slug, which is honest but plain.
const NAMES = {
  executive: 'executive and investor pack',
  user: 'pack for the people who use it',
  developer: 'pack for the engineer who inherits it',
  docs: 'documentation stack the repository carries',
};
const nameOf = (pack) => NAMES[pack] ?? `${pack} pack`;

async function start(pack, passphrase) {
  $('#gate-status').textContent = 'Deriving the key. This is deliberately slow.';
  try {
    const manifest = await unlock(pack, passphrase);
    // The gate leaves the document entirely rather than hiding, so its heading and its main
    // element cannot collide with the pack's own once the pack's stylesheet is in force.
    $('#gate').remove();
    $('#viewer').hidden = false;
    document.body.classList.add('reading');
    $('#leave').title = `Leave the ${nameOf(pack)}`;
    await render(manifest.entry);
  } catch (err) {
    $('#gate-status').textContent = err.message;
    $('#passphrase').select();
  }
}

// The browser only exposes its cryptography to a secure context, so over plain http there is
// nothing to derive a key with and every attempt fails deep inside with an unhelpful type error.
// Say what is wrong instead: the published site is https, and this is what a local preview hits.
function cryptoAvailable() {
  if (window.isSecureContext && window.crypto?.subtle) return true;
  $('#gate-status').textContent = 'This page needs a secure connection. Your browser only offers '
    + 'the cryptography that opens this over https, or from localhost.';
  $('#passphrase').disabled = true;
  $('#gate-form').querySelector('button').disabled = true;
  return false;
}

window.addEventListener('DOMContentLoaded', () => {
  const pack = new URLSearchParams(location.search).get('pack') || 'executive';
  $('#gate-pack').textContent = nameOf(pack);
  if (!cryptoAvailable()) return;
  $('#gate-form').addEventListener('submit', (e) => {
    e.preventDefault();
    start(pack, $('#passphrase').value.trim());
  });
  // Coming back to a tab that already unlocked should not ask again.
  const saved = sessionStorage.getItem(KEY_STORE);
  if (saved) {
    const { pack: p, passphrase } = JSON.parse(saved);
    if (p === pack) start(pack, passphrase);
  }
});
