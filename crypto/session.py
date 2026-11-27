"""Demonstrasi pemakaian kunci sesi Diffie-Hellman pada kriptografi simetri.

Materi menyebut bahwa kunci sesi K dipakai pada algoritma kunci-simetri.
Di sini dipakai cipher aliran XOR sederhana dengan keystream yang dibangkitkan
dari K lewat generator kongruen linear (LCG) buatan sendiri.

PERINGATAN: ini murni untuk demonstrasi pembelajaran, TIDAK aman untuk dunia
nyata (gunakan AES-GCM / ChaCha20 pada sistem sungguhan).
"""


def _keystream(key, length):
    """Keystream dari LCG (parameter Numerical Recipes) dengan seed = K."""
    # Seed hanya memakai 32 bit terbawah dari K -> ruang kunci efektif cuma
    # 2^32 (bisa di-brute force); inilah salah satu alasan cipher ini tidak aman.
    state = key % (2 ** 32)
    out = bytearray()
    for _ in range(length):
        state = (1664525 * state + 1013904223) % (2 ** 32)
        out.append((state >> 24) & 0xFF)   # ambil 8 bit teratas (lebih acak)
    return bytes(out)


def xor_cipher(data, key):
    """Enkripsi = dekripsi: data XOR keystream(key)."""
    # XOR dua kali dengan keystream yang sama mengembalikan data semula:
    #   (d ^ k) ^ k = d   -> fungsi yang sama dipakai untuk enkripsi & dekripsi.
    ks = _keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))
