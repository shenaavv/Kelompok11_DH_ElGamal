"""Pertukaran kunci Diffie-Hellman (ditulis manual).

Tahapan (sesuai materi Pertemuan 9):
  1. Alice & Bob menyepakati bilangan prima n dan akar primitif g (publik).
  2. Alice memilih x acak (rahasia), mengirim X = g^x mod n kepada Bob.
  3. Bob memilih y acak (rahasia), mengirim Y = g^y mod n kepada Alice.
  4. Alice menghitung K  = Y^x mod n.
  5. Bob   menghitung K' = X^y mod n.   Hasilnya K = K' = g^(xy) mod n.
"""
from .math_utils import (generate_safe_prime, find_primitive_root,
                         is_probable_prime, is_primitive_root, mod_exp,
                         random_between)
from .trace import SILENT, fmt


def generate_parameters(bits=256, tr=SILENT):
    """Tahap 1: membangkitkan parameter publik (n, g)."""
    tr.title("TAHAP 1 - Parameter publik Diffie-Hellman")
    n, q = generate_safe_prime(bits)
    tr.step(f"Bangkitkan prima aman n = 2q+1 ({bits} bit): n = {fmt(n)}")
    g = find_primitive_root(n, factors=[2, q])
    tr.step(f"Cari akar primitif g dari n: g = {g}")
    return n, g


def validate_parameters(n, g):
    """Memeriksa n prima dan g akar primitif dari n."""
    if not is_probable_prime(n):
        raise ValueError("n harus bilangan prima")
    if not is_primitive_root(g, n):
        raise ValueError("g bukan akar primitif dari n")


def generate_private_key(n):
    """Tahap 2/3a: bilangan rahasia acak 1 < x < n-1."""
    return random_between(2, n - 2)


def compute_public_value(g, private, n):
    """Tahap 2/3b: nilai publik = g^private mod n."""
    return mod_exp(g, private, n)


def compute_shared_secret(other_public, own_private, n):
    """Tahap 4/5: kunci sesi = other_public^own_private mod n."""
    if not (1 < other_public < n - 1):
        raise ValueError("nilai publik pihak lain tidak valid")
    return mod_exp(other_public, own_private, n)


def run_exchange(n, g, x=None, y=None, tr=SILENT, validate=True):
    """Menjalankan seluruh protokol dan mengembalikan hasilnya (dict).

    x dan y boleh diberikan (untuk mereproduksi contoh); jika tidak, acak.
    `validate=False` melewati uji g akar primitif (berguna untuk n besar
    yang faktorisasi n-1 nya tidak mudah dihitung ulang).
    """
    if validate:
        validate_parameters(n, g)
    tr.title("DIFFIE-HELLMAN KEY EXCHANGE")
    tr.step(f"Parameter publik: n = {fmt(n)}, g = {g}")

    x = x if x is not None else generate_private_key(n)
    X = compute_public_value(g, x, n)
    tr.step(f"Alice memilih x = {fmt(x)} (rahasia)")
    tr.line(f"X = g^x mod n = {g}^{fmt(x)} mod {fmt(n)} = {fmt(X)}   --> dikirim ke Bob")

    y = y if y is not None else generate_private_key(n)
    Y = compute_public_value(g, y, n)
    tr.step(f"Bob memilih y = {fmt(y)} (rahasia)")
    tr.line(f"Y = g^y mod n = {g}^{fmt(y)} mod {fmt(n)} = {fmt(Y)}   --> dikirim ke Alice")

    K = compute_shared_secret(Y, x, n)
    tr.step("Alice menghitung kunci sesi")
    tr.line(f"K  = Y^x mod n = {fmt(Y)}^{fmt(x)} mod {fmt(n)} = {fmt(K)}")
    K2 = compute_shared_secret(X, y, n)
    tr.step("Bob menghitung kunci sesi")
    tr.line(f"K' = X^y mod n = {fmt(X)}^{fmt(y)} mod {fmt(n)} = {fmt(K2)}")

    tr.step(f"K == K' ? {K == K2}")
    return {"n": n, "g": g, "x": x, "y": y, "X": X, "Y": Y, "K": K, "K2": K2,
            "ok": K == K2}
