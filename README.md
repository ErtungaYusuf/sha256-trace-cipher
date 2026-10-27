# Single-Register Message Recovery in SHA-256

**and a Message-Locked Encryption Scheme Built from Its Compression Function**

**Full article:** <https://ertungayusuf.github.io/sha256-trace-cipher/>

> **Disclaimer.** This repository is intended for study and research. The implementation has not been independently audited and, being written in pure Python, is slow. It must not be used to protect real data.

## Abstract

We study the evolution of the internal state of the SHA-256 compression function and show that the per-round values of any single one of the eight working variables *a, …, h*, together with the final digest, uniquely determine the input message. The result follows from the fact that each round computes only two new words, *a* and *e*, while the remaining six are delayed copies; consequently, each message schedule word *W<sub>t</sub>* can be recovered from one register by modular subtraction. We provide a reference implementation and verify recovery for all eight registers on messages of 0 to 1000 bytes. We then show that such a round trace does not constitute a ciphertext, since the digest enters only the final three rounds and the message words are recoverable without it. Finally, we describe two constructions that use no cryptographic primitive other than SHA-256: SHACAL-2 in an authenticated CBC mode, and a message-locked encryption scheme in which the key is the SHA-256 digest of the message and the ciphertext is the round trace masked by the compression function keyed through its chaining input. We discuss the underlying assumptions and the inherent limitations of message-locked encryption.

## Summary of results

1. **Single-register recovery.** In each round, only *a* and *e* are newly computed. The other six variables are delayed copies: *b<sub>t</sub> = a<sub>t−1</sub>*, …, *h<sub>t</sub> = e<sub>t−3</sub>*. Given the full state *S<sub>t</sub>*, the next value of *a* or *e* determines *W<sub>t</sub>* uniquely, and the procedure is applied inductively from the IV. For the delayed variables, the final one to three values of each block follow from the feed-forward *H<sup>(i)</sup> = H<sup>(i−1)</sup> + S<sub>64</sub>*.
2. **The trace is not a ciphertext.** The digest is used only for *W<sub>61</sub>, …, W<sub>63</sub>*, which are not message words. The message is therefore recoverable from the trace alone (`attack_no_key.py`).
3. **SHACAL-2.** Removing the feed-forward turns the compression function into a 256-bit block cipher with a 512-bit key. Decryption runs the rounds in reverse.
4. **Message-locked encryption.** The key is *K = SHA-256(s)*. The ciphertext is the trace of *h*, masked word by word modulo 2<sup>32</sup> with *f(K, D ‖ j)*, where *f* is the compression function with *K* in the chaining-input position. Integrity follows from the requirement that the recovered string hash to *K*.

The article discusses the security assumptions and the inherent limitations of the last construction: exhaustive search over predictable messages (mitigated by an optional salt), per-message keys, determinism without salt, and ciphertext expansion.

## Usage

The implementation requires Python 3 and no external packages. On Windows, replace `python` with `py`. Program output and source comments are in Turkish.

```bash
# Single-register recovery
python encoder.py "Hello, world" -r h -o trace.json
python decoder.py trace.json
python attack_no_key.py trace.json

# SHACAL-2 with HMAC-SHA256
python sha256_cipher.py keygen -o master.key
python sha256_cipher.py enc "Secret message" -k master.key -o message.s2c
python sha256_cipher.py dec message.s2c -k master.key

# Message-locked encryption (key = digest)
python sha256_mle.py enc "Secret message" -o message.mle --key-out message.key
python sha256_mle.py enc "yes" --tuz -o message.mle --key-out message.key
python sha256_mle.py dec message.mle -k message.key
```

Test suite:

```bash
python test_roundtrip.py && python test_attack.py && python test_sha256_cipher.py && python test_sha256_mle.py
```

The modules `hashlib` and `hmac` are used only in the test suite, to validate the implementation against the Python standard library.

## Repository contents

| File | Contents |
|---|---|
| `sha256_core.py` | SHA-256 from scratch: round function, inverse round, message schedule, trace recording |
| `encoder.py`, `decoder.py` | Single-register trace generation and message recovery |
| `attack_no_key.py` | Recovery of a plain trace without the digest |
| `sha256_cipher.py` | SHACAL-2 in CBC mode with HMAC-SHA256 |
| `sha256_mle.py` | Message-locked encryption with the digest as key |
| `test_*.py` | Validation tests |
| `docs/index.html` | The article, published with GitHub Pages |

## References

1. National Institute of Standards and Technology. *Secure Hash Standard (SHS)*. FIPS PUB 180-4, 2015.
2. H. Handschuh and D. Naccache. *SHACAL*. Submission to the NESSIE project, 2000–2001.
3. R. McEvoy, M. Tunstall, C. C. Murphy and W. P. Marnane. Differential power analysis of HMAC based on SHA-2, and countermeasures. In *WISA 2007*.
4. S. Belaïd, L. Bettale, E. Dottax, L. Genelle and F. Rondepierre. Differential power analysis of HMAC SHA-2 in the Hamming weight model. In *SECRYPT 2013*.
5. F. Mendel, T. Nad and M. Schläffer. Improving local collisions: new attacks on reduced SHA-256. In *EUROCRYPT 2013*.
6. M. Bellare. New proofs for NMAC and HMAC: security without collision-resistance. In *CRYPTO 2006*.
7. J. R. Douceur, A. Adya, W. J. Bolosky, D. Simon and M. Theimer. Reclaiming space from duplicate files in a serverless distributed file system. In *ICDCS 2002*.
8. M. Bellare, S. Keelveedhi and T. Ristenpart. Message-locked encryption and secure deduplication. In *EUROCRYPT 2013*.
9. H. Krawczyk, M. Bellare and R. Canetti. *HMAC: Keyed-Hashing for Message Authentication*. RFC 2104, 1997.
