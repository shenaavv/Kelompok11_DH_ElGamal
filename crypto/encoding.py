"""Konversi pesan <-> bilangan bulat blok (m_i harus berada pada [0, p-1]).

Dua mode:
  1. Mode SLIDE  : A=00, B=01, ..., Z=25; digit dipecah per 4 digit
                   (contoh materi: 'HALO' -> 07001114 -> 0700, 1114).
  2. Mode BYTE   : data apa pun (teks UTF-8 / file) dipecah per blok byte
                   dengan ukuran sehingga setiap blok < p.
"""


# ------------------------------------------------------------- mode SLIDE
def text_to_digits(text):
    """'HALO' -> '07001114' (huruf A-Z saja, A=00 ... Z=25)."""
    digits = []
    for ch in text.upper():
        if not ("A" <= ch <= "Z"):
            raise ValueError(f"mode slide hanya mendukung huruf A-Z (ditemukan {ch!r})")
        digits.append(f"{ord(ch) - ord('A'):02d}")
    return "".join(digits)


def digits_to_text(digits):
    """'07001114' -> 'HALO'."""
    if len(digits) % 2:
        raise ValueError("jumlah digit harus genap")
    return "".join(chr(int(digits[i:i + 2]) + ord("A"))
                   for i in range(0, len(digits), 2))


def digits_to_blocks(digits, width=4):
    """'07001114' -> [700, 1114] (blok `width` digit)."""
    return [int(digits[i:i + width]) for i in range(0, len(digits), width)]


def blocks_to_digits(blocks, total_digits, width=4):
    """[700, 1114] -> '07001114'; blok terakhir menyesuaikan sisa digit."""
    out = []
    remaining = total_digits
    for b in blocks:
        w = min(width, remaining)
        out.append(str(b).zfill(w))
        remaining -= w
    return "".join(out)


# -------------------------------------------------------------- mode BYTE
def block_size_for(p):
    """Jumlah byte per blok agar nilai blok selalu < p."""
    size = (p.bit_length() - 1) // 8
    if size < 1:
        raise ValueError("p terlalu kecil untuk mode byte (minimal 9 bit)")
    return size


def bytes_to_blocks(data, block_size):
    """Pecah byte menjadi blok bilangan bulat (big-endian)."""
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        blocks.append(int.from_bytes(chunk, "big"))
    return blocks


def blocks_to_bytes(blocks, block_size, length):
    """Kebalikan bytes_to_blocks; `length` = panjang data asli (byte)."""
    out = bytearray()
    remaining = length
    for b in blocks:
        w = min(block_size, remaining)
        try:
            out += b.to_bytes(w, "big")
        except OverflowError:
            raise ValueError("hasil dekripsi tidak valid (kunci salah atau data rusak)")
        remaining -= w
    return bytes(out)
