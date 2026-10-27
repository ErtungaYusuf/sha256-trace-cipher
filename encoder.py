"""
ENCODER: Mesajın SHA-256 özetini hesaplar ve seçilen TEK bir register'ın
(a..h) her turdaki değerini sızdırır (trace).

Kullanım:
    py encoder.py "merhaba dünya" -r e -o trace.json
    py encoder.py --file girdi.bin -r h -o trace.json
"""
import argparse
import hashlib
import json
import sys

from sha256_core import IV, REGISTERS, blocks_of, compress, pad


def encode(message: bytes, register: str):
    idx = REGISTERS.index(register)
    h = list(IV)
    leaked_blocks = []
    for block in blocks_of(pad(message)):
        states = []
        h = compress(h, block, trace=states)
        leaked_blocks.append([s[idx] for s in states])  # tur 1..64 sonrası değerler
    digest = b"".join(x.to_bytes(4, "big") for x in h)
    assert digest == hashlib.sha256(message).digest(), "Kendi SHA-256'mız hashlib ile uyuşmuyor!"
    return {
        "register": register,
        "digest": digest.hex(),
        "blocks": [[f"{v:08x}" for v in blk] for blk in leaked_blocks],
    }


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="SHA-256 + tek register sızıntısı üretir")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("message", nargs="?", help="UTF-8 mesaj")
    src.add_argument("--file", help="Mesajı dosyadan oku (ham bayt)")
    p.add_argument("-r", "--register", default="e", choices=list(REGISTERS),
                   help="Her turda sızdırılan register (varsayılan: e)")
    p.add_argument("-o", "--output", default="trace.json")
    args = p.parse_args()

    if args.file:
        with open(args.file, "rb") as f:
            message = f.read()
    else:
        message = args.message.encode("utf-8")

    result = encode(message, args.register)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)

    print(f"SHA-256      : {result['digest']}")
    print(f"Register     : {args.register}")
    print(f"Blok sayısı  : {len(result['blocks'])} (blok başına 64 tur)")
    print(f"Trace yazıldı: {args.output}")


if __name__ == "__main__":
    main()
