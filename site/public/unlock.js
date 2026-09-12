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

// Rewrite a decrypted page so every reference points at a blob rather than at the host, and
// links between chapters stay inside the viewer.
async function render(path) {
  const html = await textOf(path);
  if (html === null) { $('#view').innerHTML = '<p class="miss">That page is not in this pack.</p>'; return; }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const base = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
  const resolve = (href) => (href.startsWith('/') || /^[a-z]+:/i.test(href) ? href
    : new URL(base + href, 'http://x/').pathname.slice(1));

  for (const el of doc.querySelectorAll('[src]')) {
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
    if (url) el.setAttribute('src', url);
  }
  for (const a of doc.querySelectorAll('a[href]')) {
    const href = a.getAttribute('href');
    if (!href || /^(https?:|mailto:|#)/i.test(href)) continue;
    a.dataset.page = resolve(href);
    a.removeAttribute('href');
    a.setAttribute('role', 'link');
    a.setAttribute('tabindex', '0');
  }
  $('#view').replaceChildren(...doc.body.childNodes);
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
