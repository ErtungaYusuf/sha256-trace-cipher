"""
Yalnızca SHA-256 ve iç bileşenleriyle doğrulamalı şifreleme:
    SHACAL-2 blok şifresi (CBC modu) + HMAC-SHA256 (encrypt-then-MAC)
Parola yok, başka kripto modülü yok: tüm kriptografi sha256_core.py üzerinde.

Fikir — trace şemasının TERSİ:
  SHA-256 sıkıştırmasında 512 bitlik blok, message_schedule ile W[0..63]'e genişler ve
  a..h durumunu 64 tur karıştırır; sonda H_yeni = H_eski + durum eklenir.
  Bu son eklemeyi kaldırınca elde kalan 256 bitlik bir BLOK ŞİFREDİR (SHACAL-2,
  Handschuh & Naccache; NESSIE 2003):
      anahtar   = 512 bit  -> message_schedule -> 64 tur anahtarı W[t]
      düz metin = başlangıç durumu a..h (32 bayt)
      şifreli   = 64. tur sonrası a..h
  Trace şemasında W (mesaj) saklanmak isteniyordu ama durum herkesin bildiği IV'den
  başlıyor ve her tur sızıyordu -> W geri çıkıyordu. Burada roller ters:
  W gizli ANAHTAR, a..h VERİ, ve dışarıya yalnızca 64. turun sonucu çıkar.
  Çözme = turları geriye çalıştırmak (inverse_round_step) — decoder'daki tersine
  çevirmenin aynısı, ama bu sefer W'yi yalnızca anahtar sahibi bilir.

Anahtar:
  keygen ile bir kez üretilen 32 baytlık rastgele ana anahtar (hex olarak dosyada).
  Rastgelelik işletim sisteminden (os.urandom) gelir; SHA-256 deterministik olduğu
  için rastgeleliği kendisi üretemez.
  enc_key = HMAC(ana, "enc"|1) || HMAC(ana, "enc"|2)   -> 512 bit SHACAL-2 anahtarı
  mac_key = HMAC(ana, "mac"|1)

Çıktı formatı: MAGIC(4) | iv(32) | şifreli(32*n) | etiket(32)

Kullanım:
    py sha256_cipher.py keygen -o anahtar.key
    py sha256_cipher.py enc "gizli mesaj" -k anahtar.key -o mesaj.s2c
    py sha256_cipher.py dec mesaj.s2c -k anahtar.key
"""
import argparse
import os
import sys

from sha256_core import K, inverse_round_step, message_schedule, round_step, sha256

MAGIC = b"SHC3"
BLOCK = 32  # SHACAL-2 blok boyu = a..h = 8 x 32 bit
KEY_LEN, TAG_LEN = 32, 32


class AuthenticationError(Exception):
    pass


def _words(data: bytes):
    return [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]


def _bytes(words):
    return b"".join(x.to_bytes(4, "big") for x in words)


def _xor(x: bytes, y: bytes) -> bytes:
    return bytes(p ^ q for p, q in zip(x, y))


def _equal(x: bytes, y: bytes) -> bool:
    """Sabit zamanlı karşılaştırma (etiketi bayt bayt sızdırmamak için)."""
    if len(x) != len(y):
        return False
    diff = 0
    for p, q in zip(x, y):
        diff |= p ^ q
    return diff == 0


# --- SHACAL-2: SHA-256 turları, feed-forward olmadan ---

def shacal2_encrypt_block(round_keys, block: bytes) -> bytes:
    state = _words(block)
    for t in range(64):
        state = round_step(state, K[t], round_keys[t])
    return _bytes(state)


def shacal2_decrypt_block(round_keys, block: bytes) -> bytes:
    state = _words(block)
    for t in reversed(range(64)):
        state = inverse_round_step(state, K[t], round_keys[t])
    return _bytes(state)


# --- HMAC-SHA256 (RFC 2104), kendi SHA-256'mız üzerinde ---

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if len(key) > 64:
        key = sha256(key)
    key = key.ljust(64, b"\x00")
    inner = sha256(bytes(x ^ 0x36 for x in key) + message)
    return sha256(bytes(x ^ 0x5C for x in key) + inner)


def generate_key() -> bytes:
    return os.urandom(KEY_LEN)


def _expand_keys(master: bytes):
    if len(master) != KEY_LEN:
        raise ValueError(f"Anahtar {KEY_LEN} bayt olmalı")
    enc_key = hmac_sha256(master, b"enc\x01") + hmac_sha256(master, b"enc\x02")
    mac_key = hmac_sha256(master, b"mac\x01")
    return message_schedule(enc_key), mac_key


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    round_keys, mac_key = _expand_keys(key)
    iv = os.urandom(BLOCK)

    n = BLOCK - len(plaintext) % BLOCK
    data = plaintext + bytes([n]) * n

    prev, out = iv, bytearray()
    for i in range(0, len(data), BLOCK):
        prev = shacal2_encrypt_block(round_keys, _xor(data[i:i + BLOCK], prev))
        out += prev

    header = MAGIC + iv
    ciphertext = bytes(out)
    return header + ciphertext + hmac_sha256(mac_key, header + ciphertext)


def decrypt(blob: bytes, key: bytes) -> bytes:
    header_len = len(MAGIC) + BLOCK
    body_len = len(blob) - header_len - TAG_LEN
    if not blob.startswith(MAGIC) or body_len < BLOCK or body_len % BLOCK:
        raise AuthenticationError("Geçersiz format")
    header, ciphertext, tag = blob[:header_len], blob[header_len:-TAG_LEN], blob[-TAG_LEN:]
    iv = header[len(MAGIC):]

    round_keys, mac_key = _expand_keys(key)
    # Önce doğrula, sonra çöz (padding oracle vb. saldırıları kapatır)
    if not _equal(tag, hmac_sha256(mac_key, header + ciphertext)):
        raise AuthenticationError("Yanlış anahtar ya da veri değiştirilmiş")

    prev, out = iv, bytearray()
    for i in range(0, len(ciphertext), BLOCK):
        block = ciphertext[i:i + BLOCK]
        out += _xor(shacal2_decrypt_block(round_keys, block), prev)
        prev = block

    n = out[-1]
    if not 1 <= n <= BLOCK or out[-n:] != bytes([n]) * n:
        raise AuthenticationError("Geçersiz padding")
    return bytes(out[:-n])


def _read_key(path: str) -> bytes:
    with open(path, encoding="ascii") as f:
        return bytes.fromhex(f.read().strip())


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="SHA-256 bileşenleriyle şifreleme (SHACAL-2 + HMAC)")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen", help="Rastgele anahtar dosyası üret")
    g.add_argument("-o", "--output", default="anahtar.key")
    e = sub.add_parser("enc", help="Şifrele")
    e.add_argument("message", nargs="?")
    e.add_argument("--file")
    e.add_argument("-k", "--key", default="anahtar.key")
    e.add_argument("-o", "--output", default="mesaj.s2c")
    d = sub.add_parser("dec", help="Çöz")
    d.add_argument("input")
    d.add_argument("-k", "--key", default="anahtar.key")
    d.add_argument("-o", "--output")
    args = p.parse_args()

    if args.cmd == "keygen":
        if os.path.exists(args.output):
            raise SystemExit(f"HATA: {args.output} zaten var, üzerine yazılmadı")
        with open(args.output, "w", encoding="ascii") as f:
            f.write(generate_key().hex())
        print(f"Anahtar üretildi: {args.output} (256 bit). Alıcıya güvenli bir yoldan ilet.")
    elif args.cmd == "enc":
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            data = (args.message or "").encode("utf-8")
        blob = encrypt(data, _read_key(args.key))
        with open(args.output, "wb") as f:
            f.write(blob)
        print(f"Şifrelendi: {args.output} ({len(blob)} bayt)")
        print(f"Hex       : {blob.hex()}")
    else:
        with open(args.input, "rb") as f:
            blob = f.read()
        try:
            data = decrypt(blob, _read_key(args.key))
        except AuthenticationError as ex:
            raise SystemExit(f"HATA: {ex}")
        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            print(f"Çözüldü: {args.output}")
        else:
            print("Mesaj:", data.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
