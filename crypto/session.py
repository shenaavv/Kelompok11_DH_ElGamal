"""Demonstrasi pemakaian kunci sesi Diffie-Hellman pada kriptografi simetri.

Materi menyebut bahwa kunci sesi K dipakai pada algoritma kunci-simetri.
Di sini dipakai cipher aliran XOR sederhana dengan keystream yang dibangkitkan
dari K lewat generator kongruen linear (LCG) buatan sendiri.

PERINGATAN: ini murni untuk demonstrasi pembelajaran, TIDAK aman untuk dunia
nyata (gunakan AES-GCM / ChaCha20 pada sistem sungguhan).
"""


def _keystream(key, length):
    """Keystream dari LCG (parameter Numerical Recipes) dengan seed = K."""
    state = key % (2 ** 32)
    out = bytearray()
    for _ in range(length):
        state = (1664525 * state + 1013904223) % (2 ** 32)
        out.append((state >> 24) & 0xFF)
    return bytes(out)


def xor_cipher(data, key):
    """Enkripsi = dekripsi: data XOR keystream(key)."""
    ks = _keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))
