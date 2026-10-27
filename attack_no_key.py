"""
SALDIRI: "Şifreli metin = tur trace'i, anahtar = final hash" şemasını
anahtarı (digest'i) HİÇ kullanmadan çözer.

Neden: Decoder digest'i yalnızca son bloğun son 1-3 turunda (W[61..63]) kullanır.
Mesaj kelimeleri W[0..15] ise ilk 16+gecikme turdan tamamen belirlenir.
Bu yüzden digest yerine sıfır koysak bile mesaj bozulmadan çıkar.
"""
import json
import sys

from decoder import _chaining_from_next, recover_block
from sha256_core import IV, REGISTERS, unpad


def attack(trace: dict) -> bytes:
    idx = REGISTERS.index(trace["register"])
    family, delay = (0, idx) if idx < 4 else (4, idx - 4)
    blocks = [[int(v, 16) for v in blk] for blk in trace["blocks"]]

    h = list(IV)
    padded = b""
    for i, leaked in enumerate(blocks):
        if i == len(blocks) - 1:
            h_out_known = {family + m: 0 for m in range(delay)}  # anahtar yok -> uydurma değer
        else:
            h_out_known = _chaining_from_next(blocks[i + 1], family, delay)
        block, h, _ = recover_block(h, leaked, family, delay, h_out_known)
        padded += block
    return unpad(padded)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    with open(sys.argv[1], encoding="utf-8") as f:
        trace = json.load(f)
    trace.pop("digest", None)  # saldırganda anahtar yok
    print("Anahtarsız çözülen mesaj:", attack(trace).decode("utf-8", errors="replace"))
