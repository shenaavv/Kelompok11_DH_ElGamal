"""Mereproduksi contoh perhitungan pada materi Pertemuan 9.

Jalankan dari folder root project:
    python demo/demo_slide.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from crypto import diffie_hellman as dh      # noqa: E402
from crypto import elgamal as eg             # noqa: E402
from crypto.trace import Tracer              # noqa: E402

tr = Tracer(True)

print("#" * 70)
print("# CONTOH 1 - Diffie-Hellman (slide 11): n=251, g=6, x=124, y=158")
print("#" * 70)
r = dh.run_exchange(251, 6, x=124, y=158, tr=tr)
assert (r["X"], r["Y"], r["K"], r["K2"]) == (209, 197, 79, 79)
print("\n>> Sesuai materi: X=209, Y=197, K=K'=79  [OK]")

print("\n" + "#" * 70)
print("# CONTOH 2 - ElGamal (slide 15, 17, 18, 20): p=2273, g=3, x=243")
print("#" * 70)
pub, priv = eg.generate_keypair(p=2273, g=3, x=243, tr=tr)
assert pub.y == 461

tr.title("TAHAP 2 - Enkripsi 'HALO' (Bob -> Alice), k1=1463, k2=2001")
ct = eg.encrypt_text_slide("HALO", pub, ks=[1463, 2001], tr=tr)
assert ct.blocks == [(1439, 74), (1220, 1682)]

tr.title("TAHAP 3 - Dekripsi (Alice)")
plain = eg.decrypt_text_slide(ct, priv, tr=tr)
assert plain == "HALO"
print(f"\n>> Cipherteks {ct.blocks} -> plainteks '{plain}'  [OK, sesuai materi]")
