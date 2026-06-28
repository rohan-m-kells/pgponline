# pgponline — OnlinePGP clone (client-side)

This repository contains a simple client-side PGP web app (index.html, script.js, style.css) that uses OpenPGP.js to generate keys, encrypt, decrypt, sign, and verify entirely in the browser. It is intended as a personal/local clone for convenience and learning.

Important notes:
- Keys and messages are handled locally in your browser. Nothing is sent to a server by the included files.
- Keep your private key and passphrase safe.

Files added:
- index.html — single-page UI
- script.js — OpenPGP.js integration (generate/encrypt/decrypt/sign/verify)
- style.css — minimal styling
- LICENSE — MIT

How to use:
- Open index.html in a modern browser (Chrome/Firefox/Edge/Safari).
- Generate a keypair, or paste existing armored keys into the key fields.
- Use the Encrypt / Decrypt / Sign / Verify buttons.

Want me to:
- Add GitHub Pages configuration to host this site?
- Add examples, localization, or a test suite?
