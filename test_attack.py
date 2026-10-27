import os

from attack_no_key import attack
from encoder import encode
from sha256_core import REGISTERS

for reg in REGISTERS:
    for n in [0, 5, 55, 64, 65, 200, 1000]:
        msg = os.urandom(n)
        t = encode(msg, reg)
        del t["digest"]
        assert attack(t) == msg, (reg, n)
    print(f"register {reg}: anahtarsız çözüldü")
