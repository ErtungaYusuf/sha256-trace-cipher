import hashlib
import hmac
import os

# hashlib/hmac yalnızca TESTTE, kendi uygulamamızı doğrulamak için kullanılıyor
from sha256_cipher import (AuthenticationError, _bytes, _words, decrypt, encrypt, generate_key,
                           hmac_sha256, shacal2_decrypt_block, shacal2_encrypt_block)
from sha256_core import IV, MASK, compress, message_schedule

# 1) SHACAL-2 + feed-forward == SHA-256 sıkıştırması (uygulamanın doğruluğu)
for _ in range(50):
    block, h_prev = os.urandom(64), _words(os.urandom(32))
    for start in (IV, h_prev):
        enc = _words(shacal2_encrypt_block(message_schedule(block), _bytes(start)))
        assert [(x + y) & MASK for x, y in zip(enc, start)] == compress(start, block)
print("SHACAL-2 + feed-forward == SHA-256 sıkıştırması: OK")

# 2) Turları geriye çalıştırmak şifrelemeyi tam tersine çeviriyor
for _ in range(50):
    rk, pt = message_schedule(os.urandom(64)), os.urandom(32)
    assert shacal2_decrypt_block(rk, shacal2_encrypt_block(rk, pt)) == pt
print("SHACAL-2 çözme (ters turlar): OK")

# 3) Kendi HMAC'imiz == Python hmac
for klen in (0, 16, 32, 64, 65, 200):
    k, m = os.urandom(klen), os.urandom(100)
    assert hmac_sha256(k, m) == hmac.new(k, m, hashlib.sha256).digest()
print("Kendi HMAC-SHA256 == stdlib hmac: OK")

# 4) Çığ etkisi: düz metinde 1 bit -> şifreli blokta ~128 bit değişim
rk = message_schedule(os.urandom(64))
diffs = []
for _ in range(200):
    pt = bytearray(os.urandom(32))
    c1 = shacal2_encrypt_block(rk, bytes(pt))
    bit = int.from_bytes(os.urandom(1), "big")
    pt[bit // 8] ^= 1 << (bit % 8)
    c2 = shacal2_encrypt_block(rk, bytes(pt))
    diffs.append(bin(int.from_bytes(c1, "big") ^ int.from_bytes(c2, "big")).count("1"))
print(f"Çığ etkisi: 1 bit değişim -> ortalama {sum(diffs) / len(diffs):.1f}/256 bit değişti")

# 5) Uçtan uca
key = generate_key()
for n in [0, 1, 31, 32, 33, 100, 1000]:
    msg = os.urandom(n)
    assert decrypt(encrypt(msg, key), key) == msg
print("Gidiş-dönüş: OK")

msg = "Gizli mesaj: saat 21:00'de buluşalım".encode()
c1, c2 = encrypt(msg, key), encrypt(msg, key)
assert c1 != c2
print("Aynı mesaj iki kez -> farklı şifreli metin: OK")

for bad, name in [(lambda: decrypt(c1, generate_key()), "Yanlış anahtar"),
                  (lambda: decrypt(c1[:60] + bytes([c1[60] ^ 1]) + c1[61:], key), "Değiştirilmiş veri")]:
    try:
        bad()
        raise SystemExit(f"HATA: {name} kabul edildi")
    except AuthenticationError:
        print(f"{name} reddedildi: OK")
print("Tüm testler geçti.")
