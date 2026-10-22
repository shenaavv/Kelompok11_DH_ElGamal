"""Program utama Kelompok 11 - Diffie-Hellman & ElGamal (menu interaktif).

Jalankan:  python main.py
Semua algoritma ada di paket `crypto/` dan ditulis manual tanpa library jadi.
"""
import os
import sys

from crypto import diffie_hellman as dh
from crypto import elgamal as eg
from crypto import storage
from crypto.math_utils import discrete_log_bruteforce, is_probable_prime
from crypto.session import xor_cipher
from crypto.trace import Tracer

tr = Tracer(True)
quiet = Tracer(False)
KEY_DIR = "contoh"


def ask_int(prompt, default=None):
    """Minta bilangan bulat; kosong -> default (None = acak/otomatis)."""
    raw = input(prompt).strip()
    if raw == "":
        return default
    return int(raw)


def ask_path(prompt, default):
    raw = input(f"{prompt} [{default}]: ").strip()
    return raw or default


# ------------------------------------------------------------- Diffie-Hellman
def menu_dh():
    print("\n--- Diffie-Hellman Key Exchange ---")
    print("Kosongkan input untuk membangkitkan otomatis/acak.")
    n = ask_int("Bilangan prima n (kosong = otomatis): ")
    if n is None:
        bits = ask_int("Panjang bit n [256]: ", 256)
        n, g = dh.generate_parameters(bits, tr=tr)
        validate = False
    else:
        if not is_probable_prime(n):
            print("n bukan bilangan prima.")
            return
        g = ask_int("Akar primitif g (kosong = cari otomatis): ")
        if g is None:
            from crypto.math_utils import find_primitive_root
            g = find_primitive_root(n)
            print(f"  g (akar primitif terkecil) = {g}")
        validate = True
    x = ask_int("Kunci rahasia Alice x (kosong = acak): ")
    y = ask_int("Kunci rahasia Bob y (kosong = acak): ")
    try:
        r = dh.run_exchange(n, g, x, y, tr=tr, validate=validate)
    except ValueError as e:
        print(f"Kesalahan: {e}")
        return
    if input("\nPakai K sebagai kunci cipher simetri (demo XOR)? [y/N]: ").lower() == "y":
        msg = input("Pesan: ").encode("utf-8")
        c = xor_cipher(msg, r["K"])
        print(f"  Alice -> Bob (hex) : {c.hex()}")
        print(f"  Bob mendekripsi    : {xor_cipher(c, r['K2']).decode('utf-8', 'replace')}")


# -------------------------------------------------------------------- ElGamal
def menu_generate_keys():
    print("\n--- Pembangkitan Kunci ElGamal ---")
    p = ask_int("Bilangan prima p (kosong = otomatis): ")
    g = x = None
    bits = 256
    if p is None:
        bits = ask_int("Panjang bit p [256]: ", 256)
    else:
        g = ask_int("Akar primitif g (kosong = otomatis): ")
    x = ask_int("Kunci privat x (kosong = acak): ")
    try:
        pub, priv = eg.generate_keypair(p=p, g=g, x=x, bits=bits, tr=tr)
    except ValueError as e:
        print(f"Kesalahan: {e}")
        return
    os.makedirs(KEY_DIR, exist_ok=True)
    pub_path = ask_path("Simpan kunci publik ke", f"{KEY_DIR}/public.key")
    priv_path = ask_path("Simpan kunci privat ke", f"{KEY_DIR}/private.key")
    storage.save_public_key(pub_path, pub)
    storage.save_private_key(priv_path, priv)
    print("Kunci tersimpan.")


def menu_encrypt_text():
    print("\n--- Enkripsi Teks ElGamal ---")
    pub = storage.load_public_key(ask_path("Berkas kunci publik", f"{KEY_DIR}/public.key"))
    teks = input("Plainteks: ")
    mode = input("Mode [1] byte UTF-8 (umum)  [2] huruf A-Z skema slide: ").strip() or "1"
    try:
        if mode == "2":
            ct = eg.encrypt_text_slide(teks.replace(" ", ""), pub, tr=tr)
        else:
            ct = eg.encrypt_bytes(teks.encode("utf-8"), pub, tr=tr)
    except ValueError as e:
        print(f"Kesalahan: {e}")
        return
    out = ask_path("Simpan cipherteks ke", f"{KEY_DIR}/pesan.enc")
    storage.save_ciphertext(out, ct)
    print(f"Cipherteks tersimpan di {out}")


def menu_decrypt_text():
    print("\n--- Dekripsi Teks ElGamal ---")
    priv = storage.load_private_key(ask_path("Berkas kunci privat", f"{KEY_DIR}/private.key"))
    ct = storage.load_ciphertext(ask_path("Berkas cipherteks", f"{KEY_DIR}/pesan.enc"))
    if ct.mode == "slide":
        print(f"\nPlainteks: {eg.decrypt_text_slide(ct, priv, tr=tr)}")
    else:
        data = eg.decrypt_bytes(ct, priv, tr=tr)
        print(f"\nPlainteks: {data.decode('utf-8', 'replace')}")


def menu_encrypt_file():
    print("\n--- Enkripsi File ElGamal ---")
    pub = storage.load_public_key(ask_path("Berkas kunci publik", f"{KEY_DIR}/public.key"))
    src = input("Path file yang dienkripsi: ").strip()
    with open(src, "rb") as f:
        data = f.read()
    print(f"Mengenkripsi {len(data)} byte ... (pure Python, file besar akan lambat)")
    ct = eg.encrypt_bytes(data, pub, tr=quiet)
    out = ask_path("Simpan hasil ke", src + ".enc")
    storage.save_ciphertext(out, ct)
    print(f"Selesai: {len(ct.blocks)} blok -> {out}")


def menu_decrypt_file():
    print("\n--- Dekripsi File ElGamal ---")
    priv = storage.load_private_key(ask_path("Berkas kunci privat", f"{KEY_DIR}/private.key"))
    src = input("Path file .enc: ").strip()
    ct = storage.load_ciphertext(src)
    data = eg.decrypt_bytes(ct, priv, tr=quiet)
    default = src[:-4] + ".dec" if src.endswith(".enc") else src + ".dec"
    out = ask_path("Simpan hasil ke", default)
    with open(out, "wb") as f:
        f.write(data)
    print(f"Selesai: {len(data)} byte -> {out}")


def menu_attack():
    print("\n--- Demo Serangan Logaritma Diskrit (parameter kecil) ---")
    p = ask_int("p [2273]: ", 2273)
    g = ask_int("g [3]: ", 3)
    x = ask_int("x rahasia [243]: ", 243)
    from crypto.math_utils import mod_exp
    y = mod_exp(g, x, p)
    print(f"Penyadap melihat y = {g}^x mod {p} = {y}")
    found, tries = discrete_log_bruteforce(g, y, p)
    print(f"Brute force menemukan x = {found} setelah {tries} percobaan")


def menu_demo_slide():
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "demo", "demo_slide.py"))


MENU = [
    ("Diffie-Hellman: pertukaran kunci (tahap demi tahap)", menu_dh),
    ("ElGamal: bangkitkan kunci publik & privat", menu_generate_keys),
    ("ElGamal: enkripsi teks", menu_encrypt_text),
    ("ElGamal: dekripsi teks", menu_decrypt_text),
    ("ElGamal: enkripsi file", menu_encrypt_file),
    ("ElGamal: dekripsi file", menu_decrypt_file),
    ("Demo contoh materi (K=79 dan 'HALO')", menu_demo_slide),
    ("Demo serangan logaritma diskrit", menu_attack),
]


def main():
    while True:
        print("\n" + "=" * 60)
        print(" KELOMPOK 11 - Diffie-Hellman & ElGamal (tanpa library)")
        print("=" * 60)
        for i, (label, _) in enumerate(MENU, 1):
            print(f" {i}. {label}")
        print(" 0. Keluar")
        pilih = input("Pilih menu: ").strip()
        if pilih == "0":
            print("Sampai jumpa!")
            return
        if pilih.isdigit() and 1 <= int(pilih) <= len(MENU):
            try:
                MENU[int(pilih) - 1][1]()
            except (ValueError, OSError) as e:
                print(f"Kesalahan: {e}")
        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nKeluar.")
        sys.exit(0)
