"""
Sıfırdan SHA-256 (FIPS 180-4) — her turun iç durumunu (a..h) kaydedebilen sürüm.
"""

MASK = 0xFFFFFFFF
REGISTERS = "abcdefgh"

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def big_sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small_sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def pad(message: bytes) -> bytes:
    bit_len = len(message) * 8
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    return padded + bit_len.to_bytes(8, "big")


def unpad(padded: bytes) -> bytes:
    bit_len = int.from_bytes(padded[-8:], "big")
    if bit_len % 8 or bit_len // 8 > len(padded) - 9:
        raise ValueError("Geçersiz padding: uzunluk alanı tutarsız")
    return padded[: bit_len // 8]


def blocks_of(padded: bytes):
    return [padded[i:i + 64] for i in range(0, len(padded), 64)]


def message_schedule(block: bytes):
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        w.append((small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) + w[t - 16]) & MASK)
    return w


def round_step(state, k, w):
    """Tek tur. state = [a,b,c,d,e,f,g,h] -> yeni state."""
    a, b, c, d, e, f, g, h = state
    t1 = (h + big_sigma1(e) + ch(e, f, g) + k + w) & MASK
    t2 = (big_sigma0(a) + maj(a, b, c)) & MASK
    return [(t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g]


def inverse_round_step(state, k, w):
    """round_step'in tersi: tur SONRASI durum + W[t] -> tur ÖNCESİ durum."""
    a1, b1, c1, d1, e1, f1, g1, h1 = state
    a, b, c, e, f, g = b1, c1, d1, f1, g1, h1
    t2 = (big_sigma0(a) + maj(a, b, c)) & MASK
    t1 = (a1 - t2) & MASK
    d = (e1 - t1) & MASK
    h = (t1 - big_sigma1(e) - ch(e, f, g) - k - w) & MASK
    return [a, b, c, d, e, f, g, h]


def compress(h_prev, block: bytes, trace=None):
    """Bir bloğu sıkıştırır. trace verilirse her turdan SONRAKİ durum (1..64) eklenir."""
    w = message_schedule(block)
    state = list(h_prev)
    for t in range(64):
        state = round_step(state, K[t], w[t])
        if trace is not None:
            trace.append(list(state))
    return [(x + y) & MASK for x, y in zip(h_prev, state)]


def sha256(message: bytes) -> bytes:
    h = list(IV)
    for block in blocks_of(pad(message)):
        h = compress(h, block)
    return b"".join(x.to_bytes(4, "big") for x in h)
