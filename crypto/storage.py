"""Penyimpanan kunci dan cipherteks ke berkas teks sederhana (tanpa JSON/pickle).

Format kunci   : baris "nama=nilai" (bilangan desimal).
Format cipher  : header "ELGAMAL-v1", metadata, lalu satu baris "a:b" per blok.
"""
from .elgamal import Ciphertext, PrivateKey, PublicKey


def _write_kv(path, header, values):
    with open(path, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        for k, v in values:
            f.write(f"{k}={v}\n")


def _read_kv(path, header):
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    if not lines or lines[0] != header:
        raise ValueError(f"{path}: bukan berkas {header}")
    return {k: v for k, v in (ln.split("=", 1) for ln in lines[1:])}


def save_public_key(path, pub):
    _write_kv(path, "ELGAMAL-PUBLIC-KEY", [("p", pub.p), ("g", pub.g), ("y", pub.y)])


def save_private_key(path, priv):
    _write_kv(path, "ELGAMAL-PRIVATE-KEY", [("p", priv.p), ("g", priv.g), ("x", priv.x)])


def load_public_key(path):
    d = _read_kv(path, "ELGAMAL-PUBLIC-KEY")
    return PublicKey(int(d["p"]), int(d["g"]), int(d["y"]))


def load_private_key(path):
    d = _read_kv(path, "ELGAMAL-PRIVATE-KEY")
    return PrivateKey(int(d["p"]), int(d["g"]), int(d["x"]))


def save_ciphertext(path, ct):
    with open(path, "w", encoding="utf-8") as f:
        f.write("ELGAMAL-v1\n")
        f.write(f"mode={ct.mode}\n")
        f.write(f"block_size={ct.block_size}\n")
        f.write(f"length={ct.length}\n")
        f.write("---\n")
        for a, b in ct.blocks:
            f.write(f"{a}:{b}\n")


def load_ciphertext(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    if not lines or lines[0] != "ELGAMAL-v1":
        raise ValueError(f"{path}: bukan berkas cipherteks ElGamal")
    meta, i = {}, 1
    while lines[i] != "---":
        k, v = lines[i].split("=", 1)
        meta[k] = v
        i += 1
    blocks = []
    for ln in lines[i + 1:]:
        a, b = ln.split(":")
        blocks.append((int(a), int(b)))
    return Ciphertext(blocks, int(meta["block_size"]), int(meta["length"]), meta["mode"])
