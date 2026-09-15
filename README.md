# Repo Explainer

One codebase, explained three times: to the engineer who inherits it, to the person who uses
the product to get a job done, and to the executive deciding whether to back it. Alongside them,
the working documentation the repository already carried, rendered so it can be read in a
browser.

The first edition of the packs published here was made entirely on local hardware: chapters,
diagrams, narration and clips from models running on a GPU in our own rack, reading a private
repository that never left it. The current edition was made differently and says so on the
landing page: the product was set up, deployed and used end to end on the client's own cloud
project on 14 September 2026 with a browser recording every screen, and the packs were rewritten
against that run by a frontier model working under the engagement's terms, with each pack's
build refusing any claim it cannot tie to a file and line and any figure without a caption.

## What is in this repository

- `site/public/` — the landing page, the stylesheet, the unlock script, and an abstract
  generated clip. This is everything that is readable.
- `site/enc/` — the packs, sealed. Every file is encrypted, and the manifest naming them is
  encrypted too, so the repository does not disclose what a pack contains.
- `tools/pack.mjs` — seals a collection. AES-256-GCM under a key derived from a passphrase by
  PBKDF2-SHA256 at 600,000 iterations.
- `tools/verify.mjs` — proves a build before it ships: that the key opens a file of every kind
  including video, and that a wrong key opens nothing.
- `tools/refuse-plaintext.mjs` — the check that nothing readable is being published, run both
  here and by the deploy workflow so the two cannot drift apart. It asks whether a file *is* a
  readable file of a known kind — a signature at its own offset, or an opening that is all
  printable text — rather than searching for short markers. Ciphertext produces "PNG" or a
  leading brace by chance often enough that a marker search fails a healthy build of eight
  hundred files most runs, and a gate that cries wolf is a gate that gets waved through.

The pages themselves are not built here. The packs come from the `explainer` skill in
[agentbox](https://github.com/DreamLab-AI/agentbox); the documentation stack is rendered by that
skill's `scripts/docs-stack.mjs`, which turns a repository's own `docs/` tree into this house
style, showing each diagram as drawn and keeping its mermaid source one click below.

## Why the content is encrypted rather than password-checked

A static host serves whatever path is asked for, so a password checked in JavaScript protects
nothing: the files sit next to the check. Here the host serves ciphertext. A reader's browser
derives the key from the passphrase and decrypts in memory, and a clip is handed to the player
as a blob rather than a URL, so no fetchable path to it exists.

This holds against anyone who finds the repository. It does not hold against someone who has
the passphrase, and ciphertext in public can be attacked offline by anyone patient, which is
why the passphrase is long and the derivation slow.

## Access

The passphrase is shared separately and is not in this repository.

## Building and sealing

```
node tools/pack.mjs   --pack <name> --src <directory> --out site --passphrase '<phrase>'
node tools/verify.mjs --site site --pack <name> --passphrase '<phrase>' [--marker <word>]
```

`--marker` refuses a build in which a given word appears anywhere in the ciphertext, for a name
that must not travel. It is an argument rather than a constant because this repository is
public, and a list of names you are trying not to publish is itself a disclosure.

Sealing happens on the machine that holds the source. The key never reaches a CI runner, and
the workflow refuses to publish a build in which anything under `site/enc` is readable.
