# Repo Explainer

One codebase, explained three times: to the engineer who inherits it, to the person who uses
the product to get a job done, and to the executive deciding whether to back it.

The packs published here were made entirely on local hardware. The chapters were written by a
27-billion-parameter model running on a GPU in our own rack, reading a private repository that
never left it and citing the file and lines behind every claim. The diagrams were drawn as
code by the same model. The narration came from a local speech model, the illustration from a
local image-to-video model, and the assembly from a deterministic compositor and FFmpeg on the
same machine. No hosted model saw the source, which is what makes the work possible on a
codebase under a confidentiality agreement.

## What is in this repository

- `site/public/` — the landing page, the stylesheet, the unlock script, and an abstract
  generated clip. This is everything that is readable.
- `site/enc/` — the packs, sealed. Every file is encrypted, and the manifest naming them is
  encrypted too, so the repository does not disclose what a pack contains.
- `tools/pack.mjs` — seals a pack. AES-256-GCM under a key derived from a passphrase by
  PBKDF2-SHA256 at 600,000 iterations.
- `tools/verify.mjs` — proves a build before it ships: that the key opens a file of every kind
  including video, that a wrong key opens nothing, and that no sealed file reveals its type.

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

## Building a pack

```
node tools/pack.mjs --pack <name> --src <pack directory> --out site --passphrase '<phrase>'
node tools/verify.mjs --site site --pack <name> --passphrase '<phrase>'
```

Sealing happens on the machine that holds the source. The key never reaches a CI runner, and
the workflow refuses to publish a build in which anything under `site/enc` is readable.
