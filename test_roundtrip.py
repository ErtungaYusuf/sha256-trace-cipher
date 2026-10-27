"""Tüm register'lar ve farklı uzunluklar için encode -> decode testi."""
import os
import random

from decoder import decode
from encoder import encode
from sha256_core import REGISTERS

random.seed(1)
lengths = [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 128, 300, 1000]
messages = [os.urandom(n) for n in lengths] + ["Merhaba dünya, SHA-256 çözüldü mü?".encode()]

for reg in REGISTERS:
    for msg in messages:
        assert decode(encode(msg, reg)) == msg, (reg, len(msg))
    print(f"register {reg}: {len(messages)} mesaj OK")

# Bozuk trace yakalanmalı
t = encode(b"test mesaji", "e")
t["blocks"][0][10] = f"{int(t['blocks'][0][10], 16) ^ 1:08x}"
try:
    decode(t)
    raise SystemExit("HATA: bozuk trace fark edilmedi")
except ValueError as e:
    print("Bozuk trace yakalandı:", e)
print("Tüm testler geçti.")
