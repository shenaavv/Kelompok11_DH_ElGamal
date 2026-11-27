"""Fungsi matematika dasar yang dibutuhkan Diffie-Hellman dan ElGamal.

Semua ditulis manual:
  - eksponensiasi modular (square-and-multiply)
  - gcd & extended Euclid, invers modular
  - uji keprimaan Miller-Rabin, pembangkit bilangan prima & prima aman
  - faktorisasi prima (trial division), uji & pencarian akar primitif
  - logaritma diskrit brute force (untuk demonstrasi serangan)
"""
import random

# SystemRandom mengambil bilangan acak dari sumber acak sistem operasi
# (/dev/urandom di Linux), sehingga tidak bisa ditebak. Modul `random` biasa
# (Mersenne Twister) TIDAK aman untuk kunci: keadaannya bisa direkonstruksi
# dari beberapa keluaran sebelumnya.
_rng = random.SystemRandom()

# Prima kecil untuk menyaring kandidat sebelum Miller-Rabin (lebih cepat).
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

    Kenapa tidak langsung (base ** exp) % mod?  Eksponen kunci berukuran
    ~256 bit; base ** exp akan menjadi bilangan dengan jumlah digit yang
    astronomis. Square-and-multiply hanya butuh ~256 kuadrat + <=256 perkalian,
    dan setiap langkah langsung di-mod sehingga angkanya tetap kecil (< mod^2).

    Contoh 3^13 mod 7, dengan 13 = 1101 (biner), dibaca dari bit kanan:
      bit 1 -> result = 1*3 = 3     ; base = 3^2 = 9 mod 7 = 2   (= 3^2)
      bit 0 -> (lewati)             ; base = 2^2 = 4           (= 3^4)
      bit 1 -> result = 3*4 = 12 = 5; base = 4^2 = 16 mod 7 = 2 (= 3^8)
      bit 1 -> result = 5*2 = 10 = 3                          -> 3^13 mod 7 = 3
    """
    if mod == 1:
        return 0                     # apa pun mod 1 = 0
    if exp < 0:
        raise ValueError("eksponen harus >= 0")
    result = 1
    base %= mod                      # kecilkan base dulu
    while exp > 0:
        if exp & 1:                  # bit paling kanan = 1?
            result = (result * base) % mod   # masukkan base^(2^i) ke hasil
        base = (base * base) % mod   # base^(2^i) -> base^(2^(i+1))
        exp >>= 1                    # geser ke bit berikutnya
    return result


# ------------------------------------------------------------ gcd & invers
def gcd(a, b):
    """Faktor persekutuan terbesar (algoritma Euclid)."""
    # gcd(a, b) = gcd(b, a mod b), diulang sampai sisa = 0.
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a, b):
    """Mengembalikan (g, x, y) sehingga a*x + b*y = g = gcd(a, b)."""
    # Sama seperti Euclid biasa, tetapi sambil mencatat koefisien x dan y.
    # Invariannya:  a*old_x + b*old_y = old_r   dan   a*x + b*y = r
    # Ketika r = 0, old_r adalah gcd dan (old_x, old_y) koefisiennya.
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
    # Dari extended Euclid: a*x + m*y = 1. Jika di-mod m, suku m*y hilang:
    #   a*x = 1 (mod m)  ->  x adalah invers a.
    # Contoh: mod_inverse(3, 7) = 5 karena 3*5 = 15 = 1 (mod 7).
    # Invers hanya ada jika gcd(a, m) = 1 (selalu benar bila m prima dan
    # a bukan kelipatan m).
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} tidak memiliki invers modulo {m}")
    return x % m                     # x bisa negatif -> jadikan positif


# ------------------------------------------------------------- keprimaan
def is_probable_prime(n, rounds=40):
    """Uji keprimaan Miller-Rabin (probabilistik).

    Tulis n-1 = 2^s * d (d ganjil). Untuk tiap basis a, n lolos jika
    a^d = 1 (mod n) atau a^(d*2^r) = -1 (mod n) untuk suatu 0 <= r < s.

    Bilangan komposit lolos satu putaran dengan peluang <= 1/4, sehingga
    dengan 40 putaran peluang salah <= 4^-40 (praktis nol).
    """
    if n < 2:
        return False
    # Saring cepat dengan prima kecil.
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Tulis n-1 = 2^s * d dengan d ganjil.
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random_between(2, n - 2)          # basis acak (saksi)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue                          # lolos putaran ini
        for _ in range(s - 1):
            x = (x * x) % n                   # a^(d*2^r) untuk r = 1..s-1
            if x == n - 1:
                break                         # lolos putaran ini
        else:
            return False                      # a membuktikan n PASTI komposit
    return True                               # (hampir pasti) prima


def generate_prime(bits):
    """Membangkitkan bilangan prima acak dengan panjang `bits` bit."""
    if bits < 2:
        raise ValueError("bits minimal 2")
    while True:
        # Rentang [2^(bits-1), 2^bits - 1] menjamin bit teratas = 1 (panjang
        # tepat `bits` bit); "| 1" menjadikannya ganjil (genap pasti bukan prima).
        cand = random_between(1 << (bits - 1), (1 << bits) - 1) | 1
        if is_probable_prime(cand):
            return cand


def generate_safe_prime(bits):
    """Membangkitkan prima aman p = 2q + 1 (q juga prima).

    Dengan prima aman, faktor prima dari p-1 hanyalah {2, q}, sehingga uji
    akar primitif menjadi sangat efisien.  Mengembalikan (p, q).
    """
    # Coba-coba: ambil prima q, cek apakah 2q+1 juga prima. Ini bagian yang
    # paling lama saat membangkitkan kunci besar (butuh banyak percobaan).
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
        factors.add(n)               # sisa > 1 pasti prima
    return sorted(factors)


def is_primitive_root(g, p, factors=None):
    """Apakah g akar primitif modulo prima p?

    g adalah akar primitif jika g^((p-1)/q) != 1 (mod p) untuk setiap faktor
    prima q dari p-1.  `factors` boleh diberikan bila faktorisasi p-1 sudah
    diketahui (mis. prima aman); bila tidak, dihitung dengan trial division.
    """
    # Kenapa cukup cek (p-1)/q?  "Orde" g (pangkat terkecil e dengan g^e = 1)
    # selalu membagi p-1. Jika orde g < p-1, orde itu pasti membagi (p-1)/q
    # untuk suatu faktor prima q, sehingga g^((p-1)/q) = 1. Jadi bila semua
    # pengecekan != 1, orde g = p-1, artinya g membangkitkan semua 1..p-1.
    # Contoh p = 7 (p-1 = 6, faktor {2, 3}):
    #   g = 3: 3^3 mod 7 = 6, 3^2 mod 7 = 2  -> keduanya != 1 -> akar primitif
    #   g = 2: 2^3 mod 7 = 1                 -> bukan (2 hanya membangkitkan {1,2,4})
    if g <= 1 or g >= p:
        return False
    if factors is None:
        factors = prime_factors(p - 1)
    return all(mod_exp(g, (p - 1) // q, p) != 1 for q in factors)


def find_primitive_root(p, factors=None, start=2):
    """Mencari akar primitif terkecil modulo p mulai dari `start`."""
    if factors is None:
        factors = prime_factors(p - 1)
    # Akar primitif cukup banyak, sehingga biasanya ditemukan dalam beberapa
    # percobaan pertama (mis. 2, 3, 5, ...).
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
    # Coba x = 0, 1, 2, ... sambil menghitung g^x secara bertahap. Untuk p
    # 256 bit, jumlah percobaannya bisa ~2^256 -> mustahil diselesaikan.
    limit = limit if limit is not None else p - 1
    cur = 1                          # cur = g^x mod p untuk x saat ini
    for x in range(limit + 1):
        if cur == y % p:
            return x, x + 1
        cur = (cur * g) % p
    return None, limit + 1
