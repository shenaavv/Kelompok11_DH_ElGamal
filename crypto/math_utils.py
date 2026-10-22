"""Fungsi matematika dasar yang dibutuhkan Diffie-Hellman dan ElGamal.

Semua ditulis manual:
  - eksponensiasi modular (square-and-multiply)
  - gcd & extended Euclid, invers modular
  - uji keprimaan Miller-Rabin, pembangkit bilangan prima & prima aman
  - faktorisasi prima (trial division), uji & pencarian akar primitif
  - logaritma diskrit brute force (untuk demonstrasi serangan)
"""
import random

_rng = random.SystemRandom()

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def random_between(low, high):
    """Bilangan bulat acak pada rentang [low, high] (inklusif)."""
    return _rng.randint(low, high)


# ---------------------------------------------------------------- eksponen
def mod_exp(base, exp, mod):
    """Menghitung base^exp mod `mod` dengan metode square-and-multiply.

    Menelusuri bit eksponen dari paling kanan: jika bit = 1 kalikan hasil
    dengan base saat ini, lalu kuadratkan base.
    """
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("eksponen harus >= 0")
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


# ------------------------------------------------------------ gcd & invers
def gcd(a, b):
    """Faktor persekutuan terbesar (algoritma Euclid)."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a, b):
    """Mengembalikan (g, x, y) sehingga a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


def mod_inverse(a, m):
    """Invers perkalian a terhadap modulo m (a * a^-1 = 1 mod m)."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} tidak memiliki invers modulo {m}")
    return x % m


# ------------------------------------------------------------- keprimaan
def is_probable_prime(n, rounds=40):
    """Uji keprimaan Miller-Rabin (probabilistik).

    Tulis n-1 = 2^s * d (d ganjil). Untuk tiap basis a, n lolos jika
    a^d = 1 (mod n) atau a^(d*2^r) = -1 (mod n) untuk suatu 0 <= r < s.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random_between(2, n - 2)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Membangkitkan bilangan prima acak dengan panjang `bits` bit."""
    if bits < 2:
        raise ValueError("bits minimal 2")
    while True:
        cand = random_between(1 << (bits - 1), (1 << bits) - 1) | 1
        if is_probable_prime(cand):
            return cand


def generate_safe_prime(bits):
    """Membangkitkan prima aman p = 2q + 1 (q juga prima).

    Dengan prima aman, faktor prima dari p-1 hanyalah {2, q}, sehingga uji
    akar primitif menjadi sangat efisien.  Mengembalikan (p, q).
    """
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and is_probable_prime(p):
            return p, q


# ------------------------------------------------------ akar primitif
def prime_factors(n):
    """Himpunan faktor prima dari n (trial division; untuk n kecil)."""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return sorted(factors)


def is_primitive_root(g, p, factors=None):
    """Apakah g akar primitif modulo prima p?

    g adalah akar primitif jika g^((p-1)/q) != 1 (mod p) untuk setiap faktor
    prima q dari p-1.  `factors` boleh diberikan bila faktorisasi p-1 sudah
    diketahui (mis. prima aman); bila tidak, dihitung dengan trial division.
    """
    if g <= 1 or g >= p:
        return False
    if factors is None:
        factors = prime_factors(p - 1)
    return all(mod_exp(g, (p - 1) // q, p) != 1 for q in factors)


def find_primitive_root(p, factors=None, start=2):
    """Mencari akar primitif terkecil modulo p mulai dari `start`."""
    if factors is None:
        factors = prime_factors(p - 1)
    for g in range(start, p):
        if is_primitive_root(g, p, factors):
            return g
    raise ValueError("akar primitif tidak ditemukan")


# ------------------------------------------------------ logaritma diskrit
def discrete_log_bruteforce(g, y, p, limit=None):
    """Mencari x dengan g^x = y (mod p) secara brute force.

    Hanya layak untuk p kecil; dipakai untuk memperlihatkan bahwa keamanan
    Diffie-Hellman/ElGamal bergantung pada sulitnya masalah logaritma diskrit.
    Mengembalikan (x, jumlah_percobaan) atau (None, jumlah_percobaan).
    """
    limit = limit if limit is not None else p - 1
    cur = 1
    for x in range(limit + 1):
        if cur == y % p:
            return x, x + 1
        cur = (cur * g) % p
    return None, limit + 1
