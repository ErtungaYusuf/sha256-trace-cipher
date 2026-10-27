"""
SHA-256 ile "mesaja kilitli" şifreleme (message-locked / convergent encryption).

Kurallar:
  anahtar        = string'in SHA-256 sonuç hash'i
  şifreli metin  = string SHA-256'ya atılırken her turda bir register'ın değeri (trace)
  çözme          = şifreli metin + sonuç hash -> string
  Başka kripto modülü yok: her şey sha256_core.py üzerinde.

Çıplak trace neden yetmiyor, ne ekliyoruz:
  SHA-256'da her şey IV'den ileri doğru hesaplanır ve standart IV herkese açıktır.
  Bu yüzden çıplak trace anahtar olmadan da ileri yönde çözülür (attack_no_key.py).
  SHA-256'nın iç yapısında gizli bir değerin girebileceği tek yer zincir değeridir (IV).
  Sonuç hash zaten bir zincir değeridir: mesaj devam etseydi sonraki bloğun IV'si olurdu.
  Bu yüzden anahtarı IV'nin yerine koyup sıkıştırma fonksiyonunu çalıştırıyoruz:
      maske_j = compress(anahtar, sayaç_j)        (çağrı başına 8 kelime)
  Zincir değeri gizliyken sıkıştırma fonksiyonunun sözde-rastgele (PRF) olması,
  HMAC/NMAC güvenlik ispatlarının da dayandığı temel varsayımdır.
      şifreli kelime = trace kelimesi + maske   (mod 2^32, SHA-256'nın kendi toplaması)

Doğrulama bedava gelir: çözülen string'in SHA-256'sı anahtara eşit olmalı.
Şifreli metni değiştiren biri, aynı hash'i veren başka bir string (çarpışma) bulmak zorunda.

Bilinen sınırlar (bu sınıftaki tüm şemalarda vardır):
  - Anahtar mesaja bağlı: her mesajın anahtarı alıcıya ayrıca ve gizlice iletilmeli.
  - Tahmin edilebilir mesajlar ("evet", PIN, tarih) denemeyle çözülür: saldırgan
    tahmininin SHA-256'sını anahtar olarak dener. --tuz bunu kapatır: string'in sonuna
    16 rastgele bayt eklenir; anahtar yine SHA-256'ya atılan o string'in sonuç hash'idir.
  - Tuz yoksa aynı mesaj her zaman aynı şifreli metni verir.
  - Mesaj uzunluğu 64 bayt hassasiyetinde görünür; şifreli metin mesajın ~4 katıdır.

Format: MAGIC(4) | register(1) | bayraklar(1) | maskelenmiş trace (blok başına 64 x 4 bayt)

Kullanım:
    py sha256_mle.py enc "gizli mesaj" -o mesaj.mle --key-out mesaj.key
    py sha256_mle.py enc "evet" --tuz -o mesaj.mle --key-out mesaj.key
    py sha256_mle.py dec mesaj.mle -k mesaj.key        (ya da -k <64 hex karakter>)
"""
import argparse
import os
import sys

from decoder import decode
from sha256_core import IV, MASK, REGISTERS, blocks_of, compress, pad

MAGIC = b"MLE1"
HEADER_LEN = len(MAGIC) + 2
FLAG_SALT = 0x01
SALT_LEN = 16
MASK_DOMAIN = b"sha256-mle maske"


def _words(data: bytes):
    return [int.from_bytes(data[i:i + 4], "big") for i in range(0, len(data), 4)]


def _bytes(words):
    return b"".join(x.to_bytes(4, "big") for x in words)


def _mask_words(key_words, count):
    """Anahtar zincir değeri (IV) olarak -> compress ile sözde-rastgele maske kelimeleri."""
    out, j = [], 0
    while len(out) < count:
        block = MASK_DOMAIN.ljust(56, b"\x00") + j.to_bytes(8, "big")
        out += compress(key_words, block)
        j += 1
    return out[:count]


def _trace(data: bytes, register: str):
    """data SHA-256'ya atılırken register'ın tur 1..64 değerleri (tüm bloklar) + sonuç hash."""
    idx = REGISTERS.index(register)
    h, words = list(IV), []
    for block in blocks_of(pad(data)):
        states = []
        h = compress(h, block, trace=states)
        words += [s[idx] for s in states]
    return words, h


def encrypt(message: bytes, register="h", salt=False):
    """-> (şifreli metin, anahtar). Anahtar = SHA-256(string), string = mesaj [+ tuz]."""
    data = message + (os.urandom(SALT_LEN) if salt else b"")
    trace, h = _trace(data, register)
    masked = [(t + m) & MASK for t, m in zip(trace, _mask_words(h, len(trace)))]
    header = MAGIC + register.encode("ascii") + bytes([FLAG_SALT if salt else 0])
    return header + _bytes(masked), _bytes(h)


def decrypt(blob: bytes, key: bytes) -> bytes:
    body = blob[HEADER_LEN:]
    if (not blob.startswith(MAGIC) or len(key) != 32 or not body or len(body) % 256
            or chr(blob[4]) not in REGISTERS):
        raise ValueError("Geçersiz format")
    register, flags = chr(blob[4]), blob[5]

    key_words = _words(key)
    masked = _words(body)
    trace = [(c - m) & MASK for c, m in zip(masked, _mask_words(key_words, len(masked)))]
    try:
        # decode, çözülen string'in SHA-256'sının anahtara eşit olduğunu da doğrular
        data = decode({"register": register, "digest": key.hex(),
                       "blocks": [[f"{v:08x}" for v in trace[i:i + 64]]
                                  for i in range(0, len(trace), 64)]})
    except ValueError:
        raise ValueError("Yanlış anahtar ya da şifreli metin değiştirilmiş") from None
    # Trace'in decoder'ın kullanmadığı kelimeleri dahil tamamı tutmalı (şifreli metin tek olsun)
    if _trace(data, register) != (trace, key_words):
        raise ValueError("Yanlış anahtar ya da şifreli metin değiştirilmiş")

    if flags & FLAG_SALT:
        if len(data) < SALT_LEN:
            raise ValueError("Geçersiz format")
        data = data[:-SALT_LEN]
    return data


def _read_key(arg: str) -> bytes:
    if os.path.exists(arg):
        with open(arg, encoding="ascii") as f:
            arg = f.read()
    return bytes.fromhex(arg.strip())


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Anahtar = SHA-256 sonuç hash, şifreli metin = trace")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enc", help="Şifrele")
    e.add_argument("message", nargs="?")
    e.add_argument("--file")
    e.add_argument("-r", "--register", default="h", choices=list(REGISTERS))
    e.add_argument("--tuz", action="store_true", help="Tahmin edilebilir mesajlar için 16 rastgele bayt ekle")
    e.add_argument("-o", "--output", default="mesaj.mle")
    e.add_argument("--key-out", help="Anahtarı (hex) bu dosyaya da yaz")
    d = sub.add_parser("dec", help="Çöz")
    d.add_argument("input")
    d.add_argument("-k", "--key", required=True, help="Anahtar: 64 hex karakter ya da dosya yolu")
    d.add_argument("-o", "--output")
    args = p.parse_args()

    if args.cmd == "enc":
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            data = (args.message or "").encode("utf-8")
        blob, key = encrypt(data, args.register, args.tuz)
        with open(args.output, "wb") as f:
            f.write(blob)
        if args.key_out:
            with open(args.key_out, "w", encoding="ascii") as f:
                f.write(key.hex())
        print(f"Şifreli metin : {args.output} ({len(blob)} bayt, register {args.register}"
              f"{', tuzlu' if args.tuz else ''})")
        print(f"Anahtar       : {key.hex()}   (= SHA-256 sonuç hash)")
    else:
        with open(args.input, "rb") as f:
            blob = f.read()
        try:
            data = decrypt(blob, _read_key(args.key))
        except ValueError as ex:
            raise SystemExit(f"HATA: {ex}")
        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            print(f"Çözüldü: {args.output}")
        else:
            print("Mesaj:", data.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
