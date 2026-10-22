"""Algoritma ElGamal (ditulis manual).

Tahapan (sesuai materi Pertemuan 9):
  1. Pembangkitan kunci
       - pilih bilangan prima p dan akar primitif g dari p
       - pilih kunci privat x, 1 < x < p-1
       - kunci publik y = g^x mod p      -> publik (y, g, p), privat (x, p)
  2. Enkripsi blok m (0 <= m <= p-1)
       - pilih k acak, 1 <= k <= p-2
       - a = g^k mod p ,  b = y^k * m mod p      -> cipherteks (a, b)
  3. Dekripsi
       - m = b * (a^x)^-1 mod p = b * a^(p-1-x) mod p
"""
from collections import namedtuple

from . import encoding
from .math_utils import (find_primitive_root, generate_safe_prime,
                         is_probable_prime, is_primitive_root, mod_exp,
                         mod_inverse, random_between)
from .trace import SILENT, fmt

PublicKey = namedtuple("PublicKey", "p g y")
PrivateKey = namedtuple("PrivateKey", "p g x")
# blocks: list[(a, b)], length: panjang data asli (byte atau digit)
Ciphertext = namedtuple("Ciphertext", "blocks block_size length mode")


# ------------------------------------------------------ 1. pembangkitan kunci
def generate_keypair(p=None, g=None, x=None, bits=256, tr=SILENT):
    """Membangkitkan pasangan kunci ElGamal.

    Jika p/g/x tidak diberikan, dibangkitkan otomatis (p prima aman `bits` bit).
    """
    tr.title("TAHAP 1 - Pembangkitan kunci ElGamal")
    factors = None          # faktor prima dari p-1 (diketahui untuk prima aman)
    if p is None:
        p, q = generate_safe_prime(bits)
        factors = [2, q]
        tr.step(f"Bangkitkan prima aman p ({bits} bit): p = {fmt(p)}")
    else:
        if not is_probable_prime(p):
            raise ValueError("p harus bilangan prima")
        tr.step(f"Bilangan prima p = {p}")
    if g is None:
        g = find_primitive_root(p, factors=factors)
    elif not is_primitive_root(g, p, factors):
        raise ValueError("g bukan akar primitif dari p")
    tr.step(f"Akar primitif g = {g}")

    if x is None:
        x = random_between(2, p - 2)
    elif not (1 < x < p - 1):
        raise ValueError("kunci privat x harus memenuhi 1 < x < p-1")
    tr.step(f"Kunci privat x = {fmt(x)} (1 < x < p-1)")

    y = mod_exp(g, x, p)
    tr.step("Kunci publik y = g^x mod p")
    tr.line(f"y = {g}^{fmt(x)} mod {fmt(p)} = {fmt(y)}")
    tr.step(f"Kunci publik  : (y, g, p) = ({fmt(y)}, {g}, {fmt(p)})")
    tr.step(f"Kunci privat  : (x, p)    = ({fmt(x)}, {fmt(p)})")
    return PublicKey(p, g, y), PrivateKey(p, g, x)


# ------------------------------------------------------------ 2. enkripsi
def encrypt_block(m, pub, k=None, tr=SILENT):
    """Enkripsi satu blok bilangan m -> (a, b)."""
    p, g, y = pub
    if not (0 <= m <= p - 1):
        raise ValueError(f"blok m={m} di luar rentang [0, p-1]")
    if k is None:
        k = random_between(1, p - 2)
    elif not (1 <= k <= p - 2):
        raise ValueError("k harus pada rentang [1, p-2]")
    a = mod_exp(g, k, p)
    b = (mod_exp(y, k, p) * m) % p
    tr.step(f"Enkripsi m = {fmt(m)} dengan k = {fmt(k)}")
    tr.line(f"a = g^k mod p     = {g}^{fmt(k)} mod {fmt(p)} = {fmt(a)}")
    tr.line(f"b = y^k * m mod p = {fmt(y)}^{fmt(k)} * {fmt(m)} mod {fmt(p)} = {fmt(b)}")
    tr.line(f"cipherteks blok = (a, b) = ({fmt(a)}, {fmt(b)})")
    return a, b


# ------------------------------------------------------------ 3. dekripsi
def decrypt_block(a, b, priv, tr=SILENT):
    """Dekripsi satu pasangan (a, b) -> m.

    Memakai (a^x)^-1 = a^(p-1-x) mod p (teorema Fermat), sesuai materi, lalu
    diverifikasi dengan invers modular dari extended Euclid.
    """
    p, _, x = priv
    inv_fermat = mod_exp(a, p - 1 - x, p)
    m = (b * inv_fermat) % p
    # verifikasi silang dengan extended Euclid
    ax = mod_exp(a, x, p)
    inv_euclid = mod_inverse(ax, p)
    assert inv_fermat == inv_euclid, "invers Fermat != invers Euclid"
    tr.step(f"Dekripsi (a, b) = ({fmt(a)}, {fmt(b)})")
    tr.line(f"(a^x)^-1 = a^(p-1-x) mod p = {fmt(a)}^{fmt(p - 1 - x)} mod {fmt(p)} = {fmt(inv_fermat)}")
    tr.line(f"m = b * (a^x)^-1 mod p = {fmt(b)} * {fmt(inv_fermat)} mod {fmt(p)} = {fmt(m)}")
    return m


# --------------------------------------------- pesan penuh (teks / file byte)
def encrypt_bytes(data, pub, tr=SILENT):
    """Enkripsi data byte (teks UTF-8 atau isi file) -> Ciphertext."""
    size = encoding.block_size_for(pub.p)
    blocks = encoding.bytes_to_blocks(data, size)
    tr.step(f"{len(data)} byte dipecah menjadi {len(blocks)} blok @ {size} byte")
    enc = [encrypt_block(m, pub, tr=tr) for m in blocks]
    return Ciphertext(enc, size, len(data), "byte")


def decrypt_bytes(ct, priv, tr=SILENT):
    """Dekripsi Ciphertext mode byte -> bytes."""
    blocks = [decrypt_block(a, b, priv, tr=tr) for a, b in ct.blocks]
    return encoding.blocks_to_bytes(blocks, ct.block_size, ct.length)


def encrypt_text_slide(text, pub, ks=None, tr=SILENT):
    """Enkripsi teks huruf A-Z dengan skema materi (A=00..Z=25, blok 4 digit).

    `ks` (opsional): daftar k per blok untuk mereproduksi contoh materi.
    """
    digits = encoding.text_to_digits(text)
    blocks = encoding.digits_to_blocks(digits, 4)
    tr.step(f"Pesan '{text.upper()}' -> {digits} -> blok {blocks}")
    enc = []
    for i, m in enumerate(blocks):
        enc.append(encrypt_block(m, pub, k=(ks[i] if ks else None), tr=tr))
    return Ciphertext(enc, 4, len(digits), "slide")


def decrypt_text_slide(ct, priv, tr=SILENT):
    """Dekripsi Ciphertext mode slide -> teks."""
    blocks = [decrypt_block(a, b, priv, tr=tr) for a, b in ct.blocks]
    digits = encoding.blocks_to_digits(blocks, ct.length, ct.block_size)
    tr.step(f"Blok {blocks} -> {digits}")
    return encoding.digits_to_text(digits)
