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

Gambaran besar: kenapa ElGamal bisa bekerja?
--------------------------------------------
ElGamal pada dasarnya adalah "Diffie-Hellman sekali pakai" + perkalian:
  * Penerima (Alice) punya rahasia x dan mempublikasikan y = g^x mod p.
  * Pengirim (Bob) memilih rahasia sementara k dan mengirim a = g^k mod p.
  * Keduanya bisa menghitung "kunci bersama" s yang SAMA tanpa bertukar rahasia:
        Bob   : s = y^k = (g^x)^k = g^(x*k) mod p
        Alice : s = a^x = (g^k)^x = g^(k*x) mod p
  * Bob menyamarkan pesan dengan mengalikan  : b = s * m mod p
  * Alice membuka samaran dengan "membagi"   : m = b * s^-1 mod p
Penyadap hanya melihat (p, g, y, a, b). Untuk mendapatkan s ia harus tahu x
atau k, artinya harus memecahkan logaritma diskrit (mencari x dari g^x mod p)
yang sangat sulit untuk p besar (mis. 256 bit ke atas).

Contoh angka (materi, direproduksi di demo/demo_slide.py):
  Kunci   : p = 2273, g = 3, x = 243  ->  y = 3^243 mod 2273 = 461
  Pesan   : 'HALO' -> '07001114' -> blok m1 = 700, m2 = 1114
  Enkripsi m1 dengan k = 1463:
            a = 3^1463 mod 2273            = 1439
            s = 461^1463 mod 2273          = 1825   (kunci bersama)
            b = 1825 * 700 mod 2273        = 74     -> cipherteks (1439, 74)
  Dekripsi (Alice hanya tahu x = 243):
            s = 1439^243 mod 2273          = 1825   (sama dengan milik Bob!)
            s^-1 = 1439^(2273-1-243) mod 2273 = 1439^2029 mod 2273 = 1791
            m = 74 * 1791 mod 2273         = 700    -> pesan asli kembali
"""
from collections import namedtuple

from . import encoding
from .math_utils import (find_primitive_root, generate_safe_prime,
                         is_probable_prime, is_primitive_root, mod_exp,
                         mod_inverse, random_between)
from .trace import SILENT, fmt

# ------------------------------------------------- struktur data kunci/cipher
# namedtuple = tuple biasa yang field-nya bisa diakses dengan nama (pub.p,
# pub.y, ...) dan tetap bisa di-unpack seperti tuple:  p, g, y = pub
#
# PublicKey  : boleh dibagikan ke siapa saja (dipakai untuk ENKRIPSI).
PublicKey = namedtuple("PublicKey", "p g y")
# PrivateKey : RAHASIA, hanya disimpan pemilik kunci (dipakai untuk DEKRIPSI).
#              g ikut disimpan hanya untuk kelengkapan; dekripsi cukup p dan x.
PrivateKey = namedtuple("PrivateKey", "p g x")
# Ciphertext : seluruh hasil enkripsi satu pesan.
#   blocks     : list pasangan (a, b), satu pasangan per blok pesan
#   block_size : ukuran tiap blok (byte untuk mode "byte", digit untuk "slide")
#   length     : panjang data asli (byte atau digit). Dipakai saat dekripsi
#                agar blok terakhir dan nol di depan blok kembali persis.
#   mode       : "byte" (teks/file apa pun) atau "slide" (huruf A-Z, skema materi)
Ciphertext = namedtuple("Ciphertext", "blocks block_size length mode")


# ------------------------------------------------------ 1. pembangkitan kunci
def generate_keypair(p=None, g=None, x=None, bits=256, tr=SILENT):
    """Membangkitkan pasangan kunci ElGamal.

    Jika p/g/x tidak diberikan, dibangkitkan otomatis (p prima aman `bits` bit).

    Parameter:
      p, g, x : boleh diisi manual (mis. untuk mereproduksi contoh materi);
                bila None, nilainya dibangkitkan otomatis.
      bits    : panjang p dalam bit bila p dibangkitkan otomatis.
      tr      : tracer untuk mencetak langkah perhitungan (SILENT = tanpa output).
    Mengembalikan (PublicKey(p, g, y), PrivateKey(p, g, x)).
    """
    tr.title("TAHAP 1 - Pembangkitan kunci ElGamal")

    # --- 1a. Tentukan bilangan prima p -----------------------------------
    # Semua perhitungan ElGamal dilakukan "modulo p", sehingga ukuran p
    # menentukan keamanan: makin besar p, makin sulit logaritma diskritnya.
    factors = None          # faktor prima dari p-1 (diketahui untuk prima aman)
    if p is None:
        # Prima aman: p = 2q + 1 dengan q juga prima. Keuntungannya, faktor
        # prima dari p-1 = 2q sudah pasti {2, q}, jadi pengecekan akar
        # primitif (langkah 1b) cepat tanpa perlu memfaktorkan bilangan besar.
        p, q = generate_safe_prime(bits)
        factors = [2, q]
        tr.step(f"Bangkitkan prima aman p ({bits} bit): p = {fmt(p)}")
    else:
        # p diberikan pengguna -> pastikan benar-benar prima (uji Miller-Rabin).
        if not is_probable_prime(p):
            raise ValueError("p harus bilangan prima")
        tr.step(f"Bilangan prima p = {p}")

    # --- 1b. Tentukan akar primitif g -----------------------------------
    # g adalah akar primitif modulo p jika g^1, g^2, ..., g^(p-1) (mod p)
    # menghasilkan SEMUA bilangan 1..p-1. Dengan begitu y = g^x bisa bernilai
    # apa saja, sehingga x tidak bisa dipersempit/ditebak dari y.
    if g is None:
        g = find_primitive_root(p, factors=factors)   # cari g terkecil yang valid
    elif not is_primitive_root(g, p, factors):        # g dari pengguna -> divalidasi
        raise ValueError("g bukan akar primitif dari p")
    tr.step(f"Akar primitif g = {g}")

    # --- 1c. Pilih kunci privat x secara acak ----------------------------
    # Syarat 1 < x < p-1, yaitu x di [2, p-2]. Nilai x = 1 dan x = p-1
    # dihindari karena menghasilkan y = g dan y = g^(p-1) = 1 (langsung
    # ketahuan dari y). random_between memakai SystemRandom (acak dari OS),
    # bukan random biasa yang hasilnya bisa ditebak.
    if x is None:
        x = random_between(2, p - 2)
    elif not (1 < x < p - 1):
        raise ValueError("kunci privat x harus memenuhi 1 < x < p-1")
    tr.step(f"Kunci privat x = {fmt(x)} (1 < x < p-1)")

    # --- 1d. Hitung kunci publik y = g^x mod p ---------------------------
    # Menghitung y dari x itu mudah (square-and-multiply, lihat mod_exp),
    # tetapi kebalikannya -- mencari x dari y -- adalah masalah logaritma
    # diskrit yang sangat sulit. Inilah "fungsi satu arah" yang membuat x
    # tetap rahasia walaupun y disebarkan ke publik.
    y = mod_exp(g, x, p)
    tr.step("Kunci publik y = g^x mod p")
    tr.line(f"y = {g}^{fmt(x)} mod {fmt(p)} = {fmt(y)}")
    tr.step(f"Kunci publik  : (y, g, p) = ({fmt(y)}, {g}, {fmt(p)})")
    tr.step(f"Kunci privat  : (x, p)    = ({fmt(x)}, {fmt(p)})")
    # Kunci publik (p, g, y) dibagikan; kunci privat (p, g, x) disimpan rahasia.
    return PublicKey(p, g, y), PrivateKey(p, g, x)


# ------------------------------------------------------------ 2. enkripsi
def encrypt_block(m, pub, k=None, tr=SILENT):
    """Enkripsi satu blok bilangan m -> (a, b).

    Hanya membutuhkan KUNCI PUBLIK: siapa pun bisa mengenkripsi pesan untuk
    pemilik kunci, tetapi hanya pemegang kunci privat x yang bisa membukanya.
    """
    p, g, y = pub          # unpack kunci publik

    # m harus berada di [0, p-1] karena semua operasi dilakukan modulo p.
    # Bila m >= p, hasil dekripsi adalah m mod p (bukan m) -> pesan rusak.
    # Itulah sebabnya pesan panjang harus dipecah menjadi blok (encoding.py).
    if not (0 <= m <= p - 1):
        raise ValueError(f"blok m={m} di luar rentang [0, p-1]")

    # k = bilangan acak SEKALI PAKAI (ephemeral key) khusus untuk blok ini.
    #  - k baru di setiap pemanggilan membuat pesan yang sama menghasilkan
    #    cipherteks yang berbeda-beda (enkripsi probabilistik).
    #  - k TIDAK BOLEH dipakai ulang: jika dua blok memakai k yang sama, maka
    #    y^k-nya juga sama, dan penyerang yang tahu satu pasangan (m1, b1)
    #    bisa langsung menghitung m2 = b2 * b1^-1 * m1 mod p.
    #  - k harus dibuang setelah dipakai: siapa pun yang tahu k bisa
    #    menghitung y^k dan membuka b tanpa kunci privat.
    # Parameter k hanya diisi manual untuk mereproduksi contoh materi.
    if k is None:
        k = random_between(1, p - 2)
    elif not (1 <= k <= p - 2):
        raise ValueError("k harus pada rentang [1, p-2]")

    # a = g^k mod p
    #   "Petunjuk" untuk penerima. a ikut dikirim supaya penerima (yang tahu x)
    #   dapat menghitung ulang kunci bersama: a^x = g^(kx) = y^k.
    #   Dari a saja, k tidak bisa diketahui (lagi-lagi logaritma diskrit).
    a = mod_exp(g, k, p)

    # b = y^k * m mod p
    #   Pesan m "disamarkan" dengan mengalikannya dengan kunci bersama
    #   s = y^k = g^(xk). Tanpa mengetahui s, nilai b tampak acak.
    b = (mod_exp(y, k, p) * m) % p

    tr.step(f"Enkripsi m = {fmt(m)} dengan k = {fmt(k)}")
    tr.line(f"a = g^k mod p     = {g}^{fmt(k)} mod {fmt(p)} = {fmt(a)}")
    tr.line(f"b = y^k * m mod p = {fmt(y)}^{fmt(k)} * {fmt(m)} mod {fmt(p)} = {fmt(b)}")
    tr.line(f"cipherteks blok = (a, b) = ({fmt(a)}, {fmt(b)})")
    # Cipherteks satu blok = pasangan (a, b), jadi ukurannya 2x ukuran pesan.
    return a, b


# ------------------------------------------------------------ 3. dekripsi
def decrypt_block(a, b, priv, tr=SILENT):
    """Dekripsi satu pasangan (a, b) -> m.

    Memakai (a^x)^-1 = a^(p-1-x) mod p (teorema Fermat), sesuai materi, lalu
    diverifikasi dengan invers modular dari extended Euclid.
    """
    p, _, x = priv         # cukup p dan kunci privat x (g tidak diperlukan)

    # Ide dekripsi: hitung ulang kunci bersama s, lalu "bagi" b dengan s.
    #   s = a^x = (g^k)^x = g^(kx) = (g^x)^k = y^k   <- sama seperti saat enkripsi
    #   b = s * m   ==>   m = b * s^-1 mod p
    # "Membagi" dalam aritmetika modular = mengalikan dengan invers modular.
    #
    # Cara 1 (sesuai materi) - Teorema Fermat kecil:
    #   Untuk p prima dan a tidak habis dibagi p berlaku  a^(p-1) = 1 (mod p).
    #   Karena a^x * a^(p-1-x) = a^(p-1) = 1, maka (a^x)^-1 = a^(p-1-x) mod p.
    #   Jadi invers cukup dihitung dengan SATU kali mod_exp (x < p-1 sehingga
    #   eksponen p-1-x selalu positif).
    inv_fermat = mod_exp(a, p - 1 - x, p)

    # m = b * (a^x)^-1 mod p  -> pesan asli kembali
    m = (b * inv_fermat) % p

    # Cara 2 (verifikasi silang) - Extended Euclid:
    #   Hitung s = a^x mod p, lalu cari s^-1 dengan extended Euclid.
    #   Kedua cara harus menghasilkan invers yang sama; assert ini memastikan
    #   implementasi matematika kita konsisten. Langkah ini TIDAK wajib untuk
    #   dekripsi, hanya pengecekan (dan bahan pembelajaran).
    ax = mod_exp(a, x, p)
    inv_euclid = mod_inverse(ax, p)
    assert inv_fermat == inv_euclid, "invers Fermat != invers Euclid"

    tr.step(f"Dekripsi (a, b) = ({fmt(a)}, {fmt(b)})")
    tr.line(f"(a^x)^-1 = a^(p-1-x) mod p = {fmt(a)}^{fmt(p - 1 - x)} mod {fmt(p)} = {fmt(inv_fermat)}")
    tr.line(f"m = b * (a^x)^-1 mod p = {fmt(b)} * {fmt(inv_fermat)} mod {fmt(p)} = {fmt(m)}")
    # Catatan: dengan kunci privat yang SALAH tidak ada error di sini; hasilnya
    # hanya bilangan acak. Kesalahan baru terdeteksi saat blok dikonversi
    # kembali menjadi byte/teks (lihat encoding.blocks_to_bytes).
    return m


# --------------------------------------------- pesan penuh (teks / file byte)
def encrypt_bytes(data, pub, tr=SILENT):
    """Enkripsi data byte (teks UTF-8 atau isi file) -> Ciphertext."""
    # 1) Tentukan ukuran blok (byte) agar nilai setiap blok PASTI < p.
    #    Contoh: p 256 bit -> (256 - 1) // 8 = 31 byte per blok.
    size = encoding.block_size_for(pub.p)
    # 2) Pecah data menjadi blok-blok bilangan bulat (big-endian).
    #    Contoh: b"Hi" -> 0x4869 = 18537 (jika muat dalam satu blok).
    blocks = encoding.bytes_to_blocks(data, size)
    tr.step(f"{len(data)} byte dipecah menjadi {len(blocks)} blok @ {size} byte")
    # 3) Enkripsi setiap blok secara terpisah. k tidak diberikan, sehingga
    #    setiap blok otomatis mendapat k acak baru (lihat encrypt_block).
    enc = [encrypt_block(m, pub, tr=tr) for m in blocks]
    # 4) Simpan juga ukuran blok dan panjang data asli: keduanya dibutuhkan
    #    saat dekripsi untuk menyusun ulang byte dengan tepat.
    return Ciphertext(enc, size, len(data), "byte")


def decrypt_bytes(ct, priv, tr=SILENT):
    """Dekripsi Ciphertext mode byte -> bytes."""
    # Dekripsi setiap pasangan (a, b) menjadi blok bilangan m ...
    blocks = [decrypt_block(a, b, priv, tr=tr) for a, b in ct.blocks]
    # ... lalu ubah kembali menjadi byte. Jika kunci privat salah, m berupa
    # bilangan acak yang biasanya terlalu besar untuk ukuran bloknya, sehingga
    # blocks_to_bytes melempar ValueError ("kunci salah atau data rusak").
    return encoding.blocks_to_bytes(blocks, ct.block_size, ct.length)


def encrypt_text_slide(text, pub, ks=None, tr=SILENT):
    """Enkripsi teks huruf A-Z dengan skema materi (A=00..Z=25, blok 4 digit).

    `ks` (opsional): daftar k per blok untuk mereproduksi contoh materi.
    """
    # 'HALO' -> '07001114'   (H=07, A=00, L=11, O=14)
    digits = encoding.text_to_digits(text)
    # '07001114' -> [700, 1114]   (setiap 4 digit = 2 huruf = 1 blok)
    # Catatan: setiap blok tetap harus < p. Dengan p = 2273 (contoh materi),
    # pasangan huruf yang diawali X/Y/Z (nilai >= 2300) akan ditolak oleh
    # encrypt_block. Untuk p besar (mis. 256 bit) hal ini tidak masalah.
    blocks = encoding.digits_to_blocks(digits, 4)
    tr.step(f"Pesan '{text.upper()}' -> {digits} -> blok {blocks}")
    enc = []
    for i, m in enumerate(blocks):
        # Pakai k dari `ks` bila diberikan (reproduksi materi), selain itu acak.
        enc.append(encrypt_block(m, pub, k=(ks[i] if ks else None), tr=tr))
    # length = jumlah digit; penting bila jumlah huruf ganjil, mis. 'HAL' ->
    # '070011' -> [700, 11]: blok terakhir harus dikembalikan sebagai '11'
    # (2 digit), bukan '0011' (4 digit -> 'AL') yang membuat hasilnya 'HAAL'.
    return Ciphertext(enc, 4, len(digits), "slide")


def decrypt_text_slide(ct, priv, tr=SILENT):
    """Dekripsi Ciphertext mode slide -> teks."""
    # (a, b) -> blok bilangan, mis. [(1439, 74), (1220, 1682)] -> [700, 1114]
    blocks = [decrypt_block(a, b, priv, tr=tr) for a, b in ct.blocks]
    # [700, 1114] -> '07001114'  (nol di depan dikembalikan dengan zfill)
    digits = encoding.blocks_to_digits(blocks, ct.length, ct.block_size)
    tr.step(f"Blok {blocks} -> {digits}")
    # '07001114' -> 'HALO'
    return encoding.digits_to_text(digits)
