"""
DECODER: Final hash + her turda TEK bir register'ın değeri verildiğinde
orijinal mesajı baştan inşa eder.

Neden çalışıyor?
  Bir turda sadece iki register YENİ hesaplanır:
      a' = T1 + T2          e' = d + T1
      T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
  Diğerleri kaydırmadır: b'=a, c'=b, d'=c, f'=e, g'=f, h'=g.
  Dolayısıyla her register bir "kaynak" dizinin (a ya da e) gecikmeli kopyasıdır:
      b_t = a_{t-1},  c_t = a_{t-2},  d_t = a_{t-3}   (f,g,h için aynısı e ile)
  Durum ileriye doğru tam bilindiğinde, sıradaki a (veya e) değeri W[t]'yi
  mod 2^32 toplama ile TEK şekilde belirler:
      W[t] = (a' - T2) - (h + Σ1(e) + Ch + K[t])        (a ailesi)
      W[t] = (e' - d)  - (h + Σ1(e) + Ch + K[t])        (e ailesi)
  W[0..15] = 512 bitlik mesaj bloğudur. Gecikmeli register'larda (b,c,d,f,g,h)
  bloğun son 1-3 tur değeri trace'te yoktur; bunlar H_i = H_{i-1} + state_64
  ilişkisinden, yani final hash'ten (veya sonraki bloğun IV'sinden) gelir.

Kullanım:
    py decoder.py trace.json
    py decoder.py trace.json -o cikti.bin
"""
import argparse
import json
import sys

from sha256_core import (IV, K, MASK, REGISTERS, big_sigma0, big_sigma1, ch, maj,
                         message_schedule, round_step, unpad)


def _chaining_from_next(next_leaked, family, delay):
    """Sonraki bloğun ilk 'delay' tur değerinden bu bloğun çıkış H değerlerini çıkarır.
    Sonraki blokta tur t'deki değer = src'_{t-delay}, ve src'_{-m} = IV'[family+m] = H_i[family+m]."""
    return {family + m: next_leaked[delay - m - 1] for m in range(delay)}


def recover_block(h_prev, leaked, family, delay, h_out_known):
    """
    h_prev      : bu bloğun giriş zincir değeri (8 kelime)
    leaked      : tur 1..64 sonrasında sızdırılan register değerleri
    family      : 0 -> a ailesi (a,b,c,d), 4 -> e ailesi (e,f,g,h)
    delay       : register'ın kaynaktan gecikmesi (a/e=0, b/f=1, c/g=2, d/h=3)
    h_out_known : {indeks: değer} — bu bloğun çıkış H kelimelerinden gerekli olanlar
    """
    # src[j] = tur j sonrasındaki a (veya e) değeri, j = 1..64
    src = [None] * 65
    for j in range(1, 65 - delay):
        src[j] = leaked[j + delay - 1]
    for j in range(65 - delay, 65):
        m = 64 - j  # state_64[family+m] = src_{64-m}
        src[j] = (h_out_known[family + m] - h_prev[family + m]) & MASK

    state = list(h_prev)
    w = []
    for t in range(64):
        a, b, c, d, e, f, g, h = state
        partial_t1 = (h + big_sigma1(e) + ch(e, f, g) + K[t]) & MASK
        if family == 0:
            t1 = (src[t + 1] - (big_sigma0(a) + maj(a, b, c))) & MASK
        else:
            t1 = (src[t + 1] - d) & MASK
        wt = (t1 - partial_t1) & MASK
        w.append(wt)
        state = round_step(state, K[t], wt)

    block = b"".join(x.to_bytes(4, "big") for x in w[:16])
    # Tutarlılık: W[16..63] mesaj genişletmesiyle uyuşmalı (trace bozuk değilse)
    consistent = message_schedule(block) == w
    h_out = [(x + y) & MASK for x, y in zip(h_prev, state)]
    return block, h_out, consistent


def decode(trace: dict) -> bytes:
    register = trace["register"]
    idx = REGISTERS.index(register)
    family, delay = (0, idx) if idx < 4 else (4, idx - 4)

    digest = bytes.fromhex(trace["digest"])
    final_h = [int.from_bytes(digest[i:i + 4], "big") for i in range(0, 32, 4)]
    blocks = [[int(v, 16) for v in blk] for blk in trace["blocks"]]

    h = list(IV)
    padded = b""
    for i, leaked in enumerate(blocks):
        if i == len(blocks) - 1:
            h_out_known = {family + m: final_h[family + m] for m in range(delay)}
        else:
            h_out_known = _chaining_from_next(blocks[i + 1], family, delay)

        block, h, consistent = recover_block(h, leaked, family, delay, h_out_known)
        if not consistent:
            raise ValueError(f"Blok {i}: W[16..63] mesaj genişletmesiyle uyuşmuyor — trace bozuk/yanlış")
        padded += block

    if h != final_h:
        raise ValueError("Yeniden inşa edilen mesajın hash'i verilen digest ile uyuşmuyor")
    return unpad(padded)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Hash + tek register trace'inden mesajı geri kurar")
    p.add_argument("trace", help="encoder.py çıktısı (JSON)")
    p.add_argument("-o", "--output", help="Kurtarılan mesajı ham bayt olarak yaz")
    args = p.parse_args()

    with open(args.trace, encoding="utf-8") as f:
        trace = json.load(f)

    message = decode(trace)
    print(f"Register : {trace['register']}")
    print(f"Digest   : {trace['digest']}  (doğrulandı ✓)")
    print(f"Uzunluk  : {len(message)} bayt")
    try:
        print(f"Mesaj    : {message.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"Mesaj(hex): {message.hex()}")
    if args.output:
        with open(args.output, "wb") as f:
            f.write(message)
        print(f"Yazıldı  : {args.output}")


if __name__ == "__main__":
    main()
