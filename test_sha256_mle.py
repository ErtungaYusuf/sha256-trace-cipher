import hashlib  # yalnızca TESTTE: anahtarın gerçekten SHA-256(mesaj) olduğunu doğrulamak için
import os

from attack_no_key import attack
from sha256_core import REGISTERS, sha256
from sha256_mle import HEADER_LEN, decrypt, encrypt

# 1) Gidiş-dönüş
for reg in REGISTERS:
    for n in [0, 1, 55, 56, 64, 65, 200, 1000]:
        msg = os.urandom(n)
        for salt in (False, True):
            c, k = encrypt(msg, reg, salt)
            assert decrypt(c, k) == msg, (reg, n, salt)
print("Gidiş-dönüş (8 register, tuzlu/tuzsuz): OK")

# 2) Anahtar gerçekten SHA-256 sonuç hash'i
msg = "Gizli mesaj: saat 21:00'de buluşalım".encode()
c, k = encrypt(msg)
assert k == hashlib.sha256(msg).digest()
print("Anahtar == SHA-256(mesaj): OK")

# 3) Çıplak trace'i kıran anahtarsız saldırı artık çalışmıyor
words = [c[i:i + 4].hex() for i in range(HEADER_LEN, len(c), 4)]
try:
    recovered = attack({"register": "h", "blocks": [words[i:i + 64] for i in range(0, len(words), 64)]})
except ValueError:
    recovered = None
assert recovered != msg
print("Anahtarsız saldırı (attack_no_key) başarısız: OK")

# 4) Yanlış anahtar / değiştirilmiş şifreli metin
for i in range(HEADER_LEN, len(c)):
    bad = c[:i] + bytes([c[i] ^ 1]) + c[i + 1:]
    try:
        decrypt(bad, k)
        raise SystemExit(f"HATA: bayt {i} değiştirildi ama kabul edildi")
    except ValueError:
        pass
print(f"Şifreli metnin her baytında 1 bit değişim reddedildi ({len(c) - HEADER_LEN} bayt): OK")
try:
    decrypt(c, os.urandom(32))
    raise SystemExit("HATA: yanlış anahtar kabul edildi")
except ValueError:
    print("Yanlış anahtar reddedildi: OK")

# 5) Tuzsuz deterministik, tuzlu her seferinde farklı
assert encrypt(msg)[0] == encrypt(msg)[0]
assert encrypt(msg, salt=True)[0] != encrypt(msg, salt=True)[0]
print("Tuzsuz: aynı mesaj -> aynı şifreli metin; tuzlu: her seferinde farklı: OK")


# 6) Bilinen sınır: tahmin edilebilir mesaj denemeyle çözülür, tuz bunu kapatır
def brute_force(blob, candidates):
    for g in candidates:
        try:
            return decrypt(blob, sha256(g))
        except ValueError:
            pass
    return None


candidates = [b"evet", "hayır".encode(), b"belki"]
assert brute_force(encrypt(b"evet")[0], candidates) == b"evet"
assert brute_force(encrypt(b"evet", salt=True)[0], candidates) is None
print("Tahmin edilebilir mesaj: tuzsuz denemeyle çözüldü, tuzlu çözülemedi: OK")
print("Tüm testler geçti.")
