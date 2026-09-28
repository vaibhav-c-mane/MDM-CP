# Digital Signature Verifier (Discrete Mathematics Project)

A small online-style signature verifier, like the ones that check signed PDFs. Upload a signed **PDF**, a **.p7m** file, or **any file with its .p7s signature**, and it tells you:

1. **Is the document unchanged?** (hash comparison)
2. **Was it signed with the matching private key?** (RSA or ECDSA maths)
3. **Who is the signer, and do we trust them?** (certificate chain up to a trusted root, i.e. PKI)

Everything is built **from scratch** in Python with discrete mathematics: Euclid's algorithm, modular inverses, square-and-multiply, Miller–Rabin, Euler's theorem, the Chinese Remainder Theorem and elliptic-curve point addition. It also reads the real file formats (ASN.1 DER, X.509 certificates, CMS/PKCS#7, PDF signatures), so it verifies files signed by OpenSSL and PDF signing tools too, not only its own.

- **Backend:** Python standard library only, no installs.
- **Frontend:** plain HTML, CSS and JavaScript.
- **Samples:** 14 ready-made files (valid, tampered, untrusted, expired...) to click and try.
- **Tests:** 139 automated tests.

## Run it

Needs Python 3.8 or newer.

```bash
cd dm-signature-verifier
python run.py
```

Your browser opens **http://127.0.0.1:8000**. Press `Ctrl+C` in the terminal to stop.
(Use `py run.py` on Windows or `python3 run.py` on Mac/Linux if `python` is not found; `python run.py --port 9000` if port 8000 is busy.)

## The three pages

| Page | What it does |
|---|---|
| **Verify** | Drop a file and get a green / amber / red result, with each check explained and a "Show the maths" button for the hash, s^e mod n and the certificate chain |
| **Sign** | Pick a signer (or create one: you get a certificate from the demo CA), then write and sign a PDF or sign any file as `.p7s`. "Verify it now" checks it straight away |
| **How it works** | Hash → sign → verify → trust in four cards, RSA with small numbers, a Math Lab (gcd, inverse, modular power, primality, CRT) and two attacks |

## What the results mean

| Result | Meaning |
|---|---|
| **Signature is valid** (green) | Document unchanged, maths correct, certificate chain ends at a trusted root, certificates were valid |
| **Needs attention** (amber) | Document unchanged and maths correct, but the signer is not fully trusted: self-signed, unknown CA, expired certificate, weak SHA-1, or content added to the PDF after signing |
| **Signature is NOT valid** (red) | The document was changed, or the signature does not match the key |
| **No signature found** | The file carries no signature; for other files add the `.p7s` too |

## Sample files

On the Verify page, click any sample. The files are in `samples/`.

| Sample | Expected |
|---|---|
| Signed contract (PDF) | Valid |
| Amount changed after signing | Not valid |
| Corrupted signature value | Not valid |
| Content added after signing | Needs attention |
| Self-signed certificate | Needs attention |
| Certificate from an untrusted CA | Needs attention |
| Expired certificate | Needs attention |
| Weak hash (SHA-1) | Needs attention |
| Unsigned PDF | No signature |
| Text file + `.p7s` | Valid |
| Edited text file + `.p7s` | Not valid |
| Image + `.p7s` | Valid |
| Signature for a different file | Not valid |
| Signed message (`.p7m`) | Valid |

To make a fresh set: `python scripts/make_samples.py`.

## The demo PKI

```
DSV Demo Root CA   (trusted: trust/dsv-demo-root-ca.pem)
  └── DSV Demo Signing CA
        ├── Alice Sharma
        ├── Bob Verma
        └── signers you create on the Sign page
```

Only certificates in `trust/` are trusted, like the root list built into a browser or Adobe. Put another root `.pem` in `trust/` and restart to trust it too. To see the demo PDFs as trusted in Adobe Reader, import `trust/dsv-demo-root-ca.pem` there as a trusted certificate.

## Command line (optional)

```bash
python -m dsv verify samples/contract-signed.pdf
python -m dsv verify samples/invoice.txt --sig samples/invoice.txt.p7s
python -m dsv demo       # RSA step by step with p = 61, q = 53
python -m dsv attacks    # factoring a small key, textbook RSA forgery
```

## Run the tests

```bash
python -m unittest discover -s tests -t .
```

## Project layout

```
dsv/            the engine
  number_theory.py  gcd, extended Euclid, inverse, mod_pow, Miller–Rabin, CRT
  rsa.py            key generation, sign, verify
  ecc.py            elliptic curves P-256 / P-384 and ECDSA verification
  asn1.py           DER reader and writer
  x509.py           certificates, chain building, trust store
  cms.py            CMS / PKCS#7 signatures (.p7s, .p7m, inside PDFs)
  pdf.py            finding PDF signatures, making signed PDFs
  pubkey.py         PKCS#1 v1.5 RSA and ECDSA checks on real keys
  verifier.py       runs every check and builds the report
  pki.py            the demo CA and signers
  explain.py        step tables for the Math Lab
  attacks.py        factoring and forgery demos
backend/        HTTP server and JSON API
frontend/       index.html, style.css, app.js
pki/            demo CA and signer keys (plain JSON, for learning only)
trust/          trusted root certificates
samples/        the 14 sample files
tests/          automated tests (fixtures made with OpenSSL and pyHanko)
```

## Limitations (on purpose, to keep it simple)

- Revocation is not checked (no OCSP or CRL): the tool works offline.
- RSA-PSS and the P-521 curve are not supported; the result says "not supported" (amber).
- The Sign page creates new PDFs; to sign an existing file it makes a separate `.p7s`.
- Private keys are stored as plain JSON so they can be read while learning. Do not use this for real documents.
