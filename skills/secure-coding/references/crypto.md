# Cryptography, randomness & TLS

Parameter recommendations follow the [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) cheat sheets (CC BY-SA 4.0).

Rule zero: **use a high-level, vetted library and its defaults.** Never design a protocol, cipher mode, or padding scheme.

## Decision table
| Need | Use | Never |
|---|---|---|
| Store passwords | **argon2id** (m=19–64 MiB, t=2–3, p=1) · bcrypt cost ≥12 (72-byte limit) · scrypt | MD5, SHA-1, SHA-256 (even salted), encryption |
| Encrypt data | AES-256-GCM or ChaCha20-Poly1305 (AEAD), random 96-bit nonce per message; libsodium `secretbox`; Python `cryptography` `AESGCM`/`Fernet`; Google Tink | ECB, CBC without MAC, DES/3DES, RC4, static/zero IV, reusing nonces |
| Sign/verify | Ed25519; ECDSA P-256; RSA-PSS ≥3072 | RSA PKCS#1 v1.5 for new designs, DSA |
| Message integrity | HMAC-SHA-256 with constant-time compare | plain hash of `secret + message` |
| Random tokens/IDs/OTP | `secrets.token_urlsafe(32)` · `crypto.randomBytes(32)` / `crypto.randomUUID()` · Go `crypto/rand` · Java `SecureRandom` · Rust `rand::rngs::OsRng` | `random`, `Math.random`, `rand()`, `java.util.Random`, timestamps, sequential IDs as secrets |
| Key derivation from password | Argon2id / scrypt / PBKDF2-HMAC-SHA256 ≥600k iterations | single hash |
| Hash for non-security use | SHA-256 / BLAKE2/3 | MD5/SHA-1 where collisions matter (signatures, dedupe of untrusted input) |
| Transport | TLS 1.2+ (prefer 1.3), library default cert verification, HSTS | `verify=False`, custom trust-all managers, TLS 1.0/1.1, SSLv3 |

## Snippets

**Python passwords** (`argon2-cffi`)
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
ph = PasswordHasher()  # argon2id defaults
hashed = ph.hash(password)
def verify(hashed: str, password: str) -> bool:
    try:
        ok = ph.verify(hashed, password)
    except VerifyMismatchError:
        return False
    return ok  # optionally: if ph.check_needs_rehash(hashed): rehash and store
```

**Node passwords**: `argon2` package `await argon2.hash(pw, { type: argon2.argon2id })` / `argon2.verify(hash, pw)`, or `bcrypt` with cost 12.

**Go passwords**: `golang.org/x/crypto/argon2` (IDKey) or `golang.org/x/crypto/bcrypt` (`bcrypt.GenerateFromPassword(pw, 12)`).

**Python AEAD**
```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)    # store in a KMS/secret manager
nonce = os.urandom(12)                        # unique per message
ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
blob = nonce + ct
```

**Node AEAD**
```ts
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
const iv = randomBytes(12);
const c = createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([c.update(plain), c.final()]);
const tag = c.getAuthTag(); // store iv + tag + ct; on decrypt call setAuthTag(tag) before final()
```

**Constant-time compare**: Python `hmac.compare_digest(a, b)`, Node `crypto.timingSafeEqual(a, b)` (equal-length buffers), Go `subtle.ConstantTimeCompare`.

**Webhook signature verification** (Stripe/GitHub style): compute HMAC over the *raw* request body, compare in constant time, reject if the timestamp is older than 5 minutes (replay).

## Key management
- Keys live in a KMS or secret manager, never next to the data they protect.
- Plan for rotation: store a key ID with each ciphertext.
- Encrypt PII and secrets at rest when the threat model includes DB leaks. Use envelope encryption via KMS.

## Post-quantum note (2026)
For new long-lived key exchange, prefer hybrid X25519+ML-KEM-768 where the TLS library supports it (it is on by default in modern OpenSSL, BoringSSL, and Go). Do not hand-roll PQC.
