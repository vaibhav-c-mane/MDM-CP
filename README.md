# Digital Signature Verifier (Discrete Mathematics Project)

A small online-style signature verifier, like the ones that check signed PDFs. Upload a signed **PDF** (with or without a **JPEG/PNG signature picture**), a **JPEG** or **PNG** image with its .p7s signature, a **.p7m** file, or **any file with its .p7s signature**, and it tells you:

1. **Is the document unchanged?** (hash comparison)
2. **Was it signed with the matching private key?** (RSA or ECDSA maths)
3. **Who is the signer, and do we trust them?** (certificate chain up to a trusted root, i.e. PKI)

Everything is built **from scratch** in Python with discrete mathematics: Euclid's algorithm, modular inverses, square-and-multiply, Miller–Rabin, Euler's theorem, the Chinese Remainder Theorem and elliptic-curve point addition. It also reads the real file formats (ASN.1 DER, X.509 certificates, CMS/PKCS#7, PDF signatures), so it verifies files signed by OpenSSL and PDF signing tools too, not only its own.

- **Backend:** Python standard library only, no installs.
- **Frontend:** plain HTML, CSS and JavaScript.
- **Samples:** 22 ready-made files (valid, tampered, untrusted, expired...) to click and try.
- **Tests:** 157 automated tests.

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
| **Sign** | Pick a signer (or create one: you get a certificate from the demo CA), then pick a format: **PDF**, **PDF + JPEG**, **PDF + PNG**, **JPEG**, **PNG**, **New PDF** or **Other file**. "Verify it now" checks it straight away |
| **How it works** | Hash → sign → verify → trust in four cards, RSA with small numbers, a Math Lab (gcd, inverse, modular power, primality, CRT) and two attacks |

## Formats

| Format | What you upload on Sign | What you get | How to verify |
|---|---|---|---|
| PDF | an existing .pdf | the same PDF with a signature inside | upload the signed PDF |
| PDF + JPEG | a .pdf and a .jpg picture of your signature | signed PDF, picture shown in the signature box | upload the signed PDF |
| PDF + PNG | a .pdf and a .png picture (transparent looks best) | signed PDF, picture shown in the signature box | upload the signed PDF |
| JPEG | a .jpg image | a .p7s signature file | upload the .jpg and the .p7s |
| PNG | a .png image | a .p7s signature file | upload the .png and the .p7s |
| New PDF | a title and text | a new signed PDF | upload the signed PDF |
| Other file | any file | a .p7s signature file | upload the file and the .p7s |

The signature picture only shows who signed; anyone could copy it. The proof is the digital signature (hash, RSA maths, certificate). An existing PDF is signed with an *incremental update*: the original bytes stay untouched and the signature, the box and the picture are appended, so earlier signatures in the file stay valid.

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
| PDF + PNG signature picture | Valid |
| PDF + JPEG signature picture | Valid |
| PDF + PNG, edited after signing | Not valid |
| Existing PDF signed (no picture) | Valid |
| JPEG photo + `.p7s` | Valid |
| JPEG photo edited after signing | Not valid |
| PNG photo + `.p7s` | Valid |
| PNG photo edited after signing | Not valid |
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
  pdfedit.py        reading existing PDFs and appending a signature (incremental update)
  images.py         reading JPEG and PNG signature pictures (PNG: zlib + row filters)
  pubkey.py         PKCS#1 v1.5 RSA and ECDSA checks on real keys
  verifier.py       runs every check and builds the report
  pki.py            the demo CA and signers
  explain.py        step tables for the Math Lab
  attacks.py        factoring and forgery demos
backend/        HTTP server and JSON API
frontend/       index.html, style.css, app.js
pki/            demo CA and signer keys (plain JSON, for learning only)
trust/          trusted root certificates
samples/        the 22 sample files (assets/ holds the signature pictures and photos)
tests/          automated tests (fixtures made with OpenSSL and pyHanko)
```

## Limitations (on purpose, to keep it simple)

- Revocation is not checked (no OCSP or CRL): the tool works offline.
- RSA-PSS and the P-521 curve are not supported; the result says "not supported" (amber).
- Encrypted (password-protected) PDFs and interlaced PNGs cannot be signed.
- Private keys are stored as plain JSON so they can be read while learning. Do not use this for real documents.
