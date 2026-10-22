"""Demo otomatis end-to-end dengan parameter besar (tanpa input pengguna).

Jalankan dari folder root project:
    python demo/demo_lengkap.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from crypto import diffie_hellman as dh      # noqa: E402
from crypto import elgamal as eg             # noqa: E402
from crypto.math_utils import discrete_log_bruteforce, mod_exp  # noqa: E402
from crypto.session import xor_cipher        # noqa: E402
from crypto.trace import Tracer, fmt         # noqa: E402

tr = Tracer(True)
quiet = Tracer(False)

print("#" * 70)
print("# A. Diffie-Hellman dengan parameter 256 bit")
print("#" * 70)
n, g = dh.generate_parameters(256, tr=tr)
r = dh.run_exchange(n, g, tr=tr, validate=False)
assert r["ok"]

print("\n" + "#" * 70)
print("# B. Kunci sesi DH dipakai untuk cipher simetri (demo XOR-LCG)")
print("#" * 70)
pesan = "Pesan rahasia Kelompok 11".encode()
cipher = xor_cipher(pesan, r["K"])
print(f"  Alice mengenkripsi : {pesan!r}")
print(f"  Cipherteks (hex)   : {cipher.hex()}")
print(f"  Bob mendekripsi    : {xor_cipher(cipher, r['K2'])!r}")
assert xor_cipher(cipher, r["K2"]) == pesan

print("\n" + "#" * 70)
print("# C. ElGamal 256 bit: kunci, enkripsi & dekripsi teks UTF-8")
print("#" * 70)
pub, priv = eg.generate_keypair(bits=256, tr=tr)
teks = "Halo Dunia! Kriptografi ITS 2026"
ct = eg.encrypt_bytes(teks.encode("utf-8"), pub, tr=quiet)
print(f"\n  Plainteks   : {teks}")
print(f"  Jumlah blok : {len(ct.blocks)} (tiap blok {ct.block_size} byte)")
for i, (a, b) in enumerate(ct.blocks[:2], 1):
    print(f"  Blok {i}: a = {fmt(a)}")
    print(f"          b = {fmt(b)}")
out = eg.decrypt_bytes(ct, priv, tr=quiet).decode("utf-8")
print(f"  Hasil dekripsi : {out}")
assert out == teks

print("\n  Enkripsi yang sama dua kali menghasilkan cipherteks berbeda (k acak):")
ct2 = eg.encrypt_bytes(teks.encode("utf-8"), pub, tr=quiet)
print(f"  Blok-1 sama? {ct.blocks[0] == ct2.blocks[0]}")

print("\n" + "#" * 70)
print("# D. Serangan logaritma diskrit pada parameter KECIL vs BESAR")
print("#" * 70)
p_kecil, g_kecil = 2273, 3
y = mod_exp(g_kecil, 243, p_kecil)
t = time.time()
x_found, tries = discrete_log_bruteforce(g_kecil, y, p_kecil)
print(f"  p=2273  : x ditemukan = {x_found} setelah {tries} percobaan "
      f"({time.time() - t:.4f} dtk)")
print(f"  p 256 bit: ruang kunci ~ 2^255 = {fmt(2 ** 255)} kemungkinan")
print("  -> brute force tidak layak; keamanan bertumpu pada masalah logaritma diskrit.")
