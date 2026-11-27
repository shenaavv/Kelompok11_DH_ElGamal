# Diffie-Hellman & ElGamal — Kelompok 11 (Kriptografi)

Implementasi **pertukaran kunci Diffie-Hellman** dan **algoritma ElGamal**
sepenuhnya manual: **tanpa library atau framework kriptografi jadi**. Seluruh
operasi (eksponensiasi modular, Euclid, invers modular, Miller-Rabin, akar
primitif, pemecahan blok pesan) ditulis sendiri. Satu-satunya modul standar
untuk logika inti adalah `random.SystemRandom` (sumber bilangan acak).

## Anggota:

| Nama                   | NRP        |
|------------------------|------------|
| Kanafira Vanesha Putri | 5027241010 |
| Fika Arka Nuriyah      | 5027241071 |
| S. Farhan Baig         | 5027241097 |

## Struktur project

```
kelompok11_dh_elgamal/
├── main.py                  # menu interaktif (semua tahapan, tampilkan langkah)
├── README.md
├── crypto/
│   ├── __init__.py
│   ├── math_utils.py        # mod_exp, gcd, extended Euclid, invers, Miller-Rabin,
│   │                        # prima aman, akar primitif, logaritma diskrit brute force
│   ├── diffie_hellman.py    # parameter, nilai publik, kunci sesi, run_exchange
│   ├── elgamal.py           # generate_keypair, encrypt/decrypt blok, teks, byte/file
│   ├── encoding.py          # teks <-> blok bilangan (mode slide A=00..Z=25 & mode byte)
│   ├── storage.py           # simpan/baca kunci dan cipherteks (format teks)
│   ├── session.py           # demo kunci sesi DH + cipher simetri XOR (edukasi)
│   └── trace.py             # pencetak langkah-langkah perhitungan
├── demo/
│   ├── demo_slide.py        # mereproduksi contoh materi (K=79, 'HALO')
│   └── demo_lengkap.py      # demo otomatis 256 bit end-to-end
├── tests/
│   └── test_all.py          # 18 unit test (unittest bawaan Python)
├── contoh/                  # contoh kunci, pesan, dan hasil enkripsi
└── Laporan_Kelompok11.pdf
```

## Cara menjalankan

Kebutuhan: **Python 3.8+** saja (tanpa `pip install`).

```bash
python main.py                              # menu interaktif
python3 ui.py                               # antarmuka web lokal
python demo/demo_slide.py                   # contoh perhitungan dari materi
python demo/demo_lengkap.py                 # demo otomatis parameter 256 bit
python -m unittest discover -s tests -v     # jalankan semua unit test
```

Antarmuka web dapat dibuka di `http://127.0.0.1:8000` setelah menjalankan
`python3 ui.py`. Hentikan server dengan `Ctrl+C`. Kunci dan cipherteks UI hanya
disimpan di memori proses selama server berjalan; UI ini ditujukan untuk demo
pembelajaran, bukan untuk melindungi data sungguhan. UI mendukung enkripsi teks
maupun upload file dan dekripsi file `.enc`; ukuran file dibatasi 32 KB agar
demo tetap responsif.

## Tahapan algoritma dan lokasinya di kode

| Tahap | Fungsi | Penjelasan |
|-------|--------|------------|
| DH 1 — parameter publik (n, g) | `diffie_hellman.generate_parameters`, `validate_parameters` | [lihat](#dh-1-parameter-publik-n-dan-g) |
| DH 2/3 — nilai rahasia & publik (X, Y) | `generate_private_key`, `compute_public_value` | [lihat](#dh-2-dan-3-nilai-rahasia-dan-nilai-publik) |
| DH 4/5 — kunci sesi K = K' | `compute_shared_secret`, `run_exchange` | [lihat](#dh-4-dan-5-kunci-sesi-k) |
| ElGamal 1 — pembangkitan kunci | `elgamal.generate_keypair` | [lihat](#elgamal-1-pembangkitan-kunci) |
| ElGamal 2 — enkripsi (a, b) | `encrypt_block`, `encrypt_text_slide`, `encrypt_bytes` | [lihat](#elgamal-2-enkripsi) |
| ElGamal 3 — dekripsi | `decrypt_block`, `decrypt_text_slide`, `decrypt_bytes` | [lihat](#elgamal-3-dekripsi) |
| Fungsi matematika pendukung | `math_utils.*` | [lihat](#lampiran-fungsi-matematika-pendukung) |

## Penjelasan kode per tahap

Setiap tahap di bawah berisi empat bagian:

1. **Kode**: potongan kode asli dari folder `crypto/`. Baris `tr.*` (pencetak
   langkah) dan komentar panjang tidak ditampilkan agar ringkas.
2. **Penjelasan kode**: apa yang dilakukan setiap baris.
3. **Matematika**: rumus di balik kode dan alasan rumus itu bekerja.
4. **Contoh**: perhitungan dengan angka dari materi Pertemuan 9. Semua angka
   bisa dicek ulang dengan `python demo/demo_slide.py`.

Notasi: `a^b` artinya a pangkat b, dan `mod n` artinya sisa bagi n.

---

### DH 1: Parameter publik n dan g

Kode: [crypto/diffie_hellman.py](crypto/diffie_hellman.py#L26)

```python
def generate_parameters(bits=256, tr=SILENT):
    n, q = generate_safe_prime(bits)              # n = 2q + 1, n dan q prima
    g = find_primitive_root(n, factors=[2, q])    # akar primitif terkecil dari n
    return n, g


def validate_parameters(n, g):
    if not is_probable_prime(n):
        raise ValueError("n harus bilangan prima")
    if not is_primitive_root(g, n):
        raise ValueError("g bukan akar primitif dari n")
```

**Penjelasan kode**

- `generate_safe_prime(bits)` membangkitkan **prima aman** `n = 2q + 1`
  (n dan q sama-sama prima). Fungsi ini mengembalikan `n` dan `q`.
- Untuk prima aman, faktor prima dari `n - 1 = 2q` pasti hanya `{2, q}`. Karena
  itu `find_primitive_root` cukup diberi `factors=[2, q]` dan tidak perlu
  memfaktorkan bilangan 256 bit, yang akan sangat lambat.
- `validate_parameters` dipakai ketika n dan g diisi manual (misalnya angka
  dari materi). Fungsi ini memastikan n prima (uji Miller-Rabin) dan g akar
  primitif. Jika tidak, program berhenti dengan `ValueError`.
- `n` dan `g` bersifat **publik**: boleh diketahui siapa saja, termasuk penyadap.

**Matematika**

```math
n = 2q + 1, \quad n \text{ dan } q \text{ prima}
```

`g` disebut **akar primitif** modulo n jika `g^1, g^2, ..., g^(n-1) mod n`
menghasilkan **semua** bilangan `1, 2, ..., n-1`. Cara mengujinya:

```math
g \text{ akar primitif} \iff g^{(n-1)/q_i} \not\equiv 1 \pmod{n} \text{ untuk setiap faktor prima } q_i \text{ dari } n-1
```

Akar primitif dibutuhkan supaya nilai publik `g^x mod n` bisa bernilai apa saja.
Dengan begitu rahasia `x` tidak bisa dipersempit dari nilai publiknya.

**Contoh** (materi: n = 251, g = 6)

```text
n = 251 (prima)
n - 1 = 250 = 2 · 5^3   ->  faktor prima {2, 5}
eksponen uji: 250/2 = 125  dan  250/5 = 50

g = 2 : 2^125 mod 251 = 250,  2^50 mod 251 = 1     -> GAGAL
g = 3 : 3^125 mod 251 = 1                          -> GAGAL
g = 4 : 4^125 mod 251 = 1                          -> GAGAL
g = 5 : 5^125 mod 251 = 1                          -> GAGAL
g = 6 : 6^125 mod 251 = 250,  6^50 mod 251 = 219   -> LOLOS  =>  g = 6
```

Jadi `find_primitive_root(251)` menghasilkan `6`, sama dengan materi.
(251 bukan prima aman karena 125 bukan prima, sehingga faktor `n - 1` dicari
dengan trial division.)

Contoh prima aman kecil (8 bit) dari `generate_parameters`:
`q = 83` maka `n = 2·83 + 1 = 167`, dan faktor prima `n - 1` adalah `{2, 83}`.
Nilai g = 2, 3, 4 gagal karena `g^83 mod 167 = 1`. Untuk g = 5,
`5^83 mod 167 = 166` dan `5^2 mod 167 = 25`, keduanya bukan 1, jadi `g = 5`.

---

### DH 2 dan 3: Nilai rahasia dan nilai publik

Kode: [crypto/diffie_hellman.py](crypto/diffie_hellman.py#L46)

```python
def generate_private_key(n):
    return random_between(2, n - 2)       # rahasia acak, 1 < x < n-1


def compute_public_value(g, private, n):
    return mod_exp(g, private, n)         # nilai publik = g^private mod n
```

**Penjelasan kode**

- `generate_private_key` memilih angka acak di rentang `[2, n-2]` memakai
  `random.SystemRandom`, yaitu sumber acak dari sistem operasi yang tidak bisa
  ditebak. Angka ini **tidak pernah dikirim**.
- `compute_public_value` menghitung `g^private mod n` dengan
  [`mod_exp`](#mod_exp-eksponensiasi-modular) (square-and-multiply). Hasilnya
  boleh dikirim lewat jalur terbuka.
- Alice dan Bob masing-masing memanggil kedua fungsi ini: Alice mendapat `x`
  dan `X`, Bob mendapat `y` dan `Y`.

**Matematika**

```math
X = g^{x} \bmod n, \qquad Y = g^{y} \bmod n
```

Menghitung `X` dari `x` itu cepat. Sebaliknya, mencari `x` dari `X` disebut
**masalah logaritma diskrit**, dan tidak ada cara cepat untuk n yang besar.
Inilah "fungsi satu arah" yang menjadi dasar keamanan DH dan ElGamal.

Nilai `x = 1` dan `x = n-1` dihindari karena `g^1 = g` dan `g^(n-1) = 1`
(Teorema Fermat). Keduanya langsung ketahuan dari nilai publiknya.

**Contoh** (materi: x = 124, y = 158)

```text
Alice: x = 124 (rahasia)  ->  X = 6^124 mod 251 = 209   --> dikirim ke Bob
Bob  : y = 158 (rahasia)  ->  Y = 6^158 mod 251 = 197   --> dikirim ke Alice
```

---

### DH 4 dan 5: Kunci sesi K

Kode: [crypto/diffie_hellman.py](crypto/diffie_hellman.py#L59)

```python
def compute_shared_secret(other_public, own_private, n):
    if not (1 < other_public < n - 1):
        raise ValueError("nilai publik pihak lain tidak valid")
    return mod_exp(other_public, own_private, n)   # (nilai publik lawan)^(rahasia sendiri)


def run_exchange(n, g, x=None, y=None, tr=SILENT, validate=True):
    if validate:
        validate_parameters(n, g)
    x = x if x is not None else generate_private_key(n)   # Alice
    X = compute_public_value(g, x, n)
    y = y if y is not None else generate_private_key(n)   # Bob
    Y = compute_public_value(g, y, n)
    K = compute_shared_secret(Y, x, n)                    # Alice: Y^x
    K2 = compute_shared_secret(X, y, n)                   # Bob  : X^y
    return {"n": n, "g": g, "x": x, "y": y, "X": X, "Y": Y, "K": K, "K2": K2,
            "ok": K == K2}
```

**Penjelasan kode**

- `compute_shared_secret` memangkatkan **nilai publik milik lawan** dengan
  **rahasia milik sendiri**.
- Pengecekan `1 < other_public < n - 1` menolak nilai "jebakan". Jika penyerang
  di tengah jalan mengganti nilai publik menjadi `1` atau `n-1`, kunci sesi
  pasti `1` atau `n-1` dan mudah ditebak.
- `run_exchange` menjalankan seluruh protokol dari dua sisi. `x` dan `y` boleh
  diisi manual untuk mereproduksi contoh materi; jika kosong, nilainya acak.
- Hasilnya berupa `dict`. `ok` bernilai `True` jika kunci Alice (`K`) sama
  dengan kunci Bob (`K2`).

**Matematika**

```math
K = Y^{x} = (g^{y})^{x} = g^{xy} = (g^{x})^{y} = X^{y} = K' \pmod{n}
```

Alice dan Bob mendapat kunci yang sama karena urutan pemangkatan bisa ditukar
(`(g^y)^x = (g^x)^y`). Kunci itu tidak pernah dikirim. Penyadap hanya melihat
`n, g, X, Y`. Untuk mendapatkan `K`, penyadap harus menemukan `x` atau `y`
terlebih dahulu (logaritma diskrit).

**Contoh** (materi)

```text
        Alice                       publik                          Bob
  x = 124 (rahasia)            n = 251, g = 6                y = 158 (rahasia)
  X = 6^124 mod 251 = 209  ------- X = 209 ------->
                           <------ Y = 197 --------   Y = 6^158 mod 251 = 197

  K  = Y^x mod n = 197^124 mod 251 = 79
                                                      K' = X^y mod n = 209^158 mod 251 = 79

Cek: g^(x·y) = 6^(124·158) = 6^19592 mod 251 = 79   ->  K = K' = 79
```

Kenapa n harus besar? Penyadap bisa mencoba semua kemungkinan x dengan
[`discrete_log_bruteforce`](#discrete_log_bruteforce-serangan-coba-semua):
`discrete_log_bruteforce(6, 209, 251)` menemukan `x = 124` setelah hanya **125
percobaan**. Untuk n 256 bit, jumlah percobaannya bisa mencapai sekitar
`2^255 ≈ 5,8 × 10^76`, sehingga mustahil diselesaikan.

Kunci sesi `K` kemudian dipakai untuk kriptografi simetri. Contoh edukatifnya
ada di [crypto/session.py](crypto/session.py) (cipher XOR, **tidak aman** untuk
dunia nyata).

---

### ElGamal 1: Pembangkitan kunci

Kode: [crypto/elgamal.py](crypto/elgamal.py#L67)

```python
PublicKey = namedtuple("PublicKey", "p g y")     # dibagikan
PrivateKey = namedtuple("PrivateKey", "p g x")   # dirahasiakan


def generate_keypair(p=None, g=None, x=None, bits=256, tr=SILENT):
    factors = None
    if p is None:
        p, q = generate_safe_prime(bits)         # p = 2q + 1
        factors = [2, q]
    else:
        if not is_probable_prime(p):
            raise ValueError("p harus bilangan prima")

    if g is None:
        g = find_primitive_root(p, factors=factors)
    elif not is_primitive_root(g, p, factors):
        raise ValueError("g bukan akar primitif dari p")

    if x is None:
        x = random_between(2, p - 2)
    elif not (1 < x < p - 1):
        raise ValueError("kunci privat x harus memenuhi 1 < x < p-1")

    y = mod_exp(g, x, p)                         # kunci publik
    return PublicKey(p, g, y), PrivateKey(p, g, x)
```

**Penjelasan kode**

- `p`, `g`, dan `x` boleh diisi manual (untuk contoh materi). Jika `None`, nilainya
  dibangkitkan otomatis dengan ukuran `bits` (default 256 bit).
- **Langkah p**: jika dibangkitkan otomatis, p adalah prima aman. Jika diisi
  pengguna, p dicek keprimaannya.
- **Langkah g**: dicari akar primitif terkecil, atau g dari pengguna divalidasi.
  Langkah ini sama seperti [DH 1](#dh-1-parameter-publik-n-dan-g).
- **Langkah x**: kunci privat diambil acak di `[2, p-2]`, sama seperti rahasia
  pada [DH 2/3](#dh-2-dan-3-nilai-rahasia-dan-nilai-publik).
- **Langkah y**: `y = g^x mod p` adalah kunci publik.
- `PublicKey` dan `PrivateKey` adalah `namedtuple`: isinya bisa diakses dengan
  nama (`pub.y`) atau di-unpack seperti tuple (`p, g, y = pub`).

**Matematika**

```math
y = g^{x} \bmod p
```

```math
\text{kunci publik} = (p,\ g,\ y), \qquad \text{kunci privat} = (p,\ x)
```

Kunci publik ElGamal sebenarnya adalah "nilai publik DH" milik penerima yang
diumumkan sekali untuk semua orang. Siapa pun yang ingin mengirim pesan
memakai `y` ini, seperti Bob memakai `X` milik Alice pada DH.

**Contoh** (materi: p = 2273, g = 3, x = 243)

```text
p = 2273 (prima)
p - 1 = 2272 = 2^5 · 71   ->  faktor prima {2, 71}
eksponen uji: 2272/2 = 1136  dan  2272/71 = 32

g = 2 : 2^1136 mod 2273 = 1                              -> GAGAL
g = 3 : 3^1136 mod 2273 = 2272,  3^32 mod 2273 = 377     -> LOLOS  =>  g = 3

x = 243 (rahasia)
y = g^x mod p = 3^243 mod 2273 = 461

Kunci publik  (p, g, y) = (2273, 3, 461)   -> dibagikan ke pengirim
Kunci privat  (p, g, x) = (2273, 3, 243)   -> disimpan sendiri
```

Saat disimpan dengan [crypto/storage.py](crypto/storage.py), kunci publik
menjadi berkas teks seperti ini:

```text
ELGAMAL-PUBLIC-KEY
p=2273
g=3
y=461
```

---

### ElGamal 2: Enkripsi

Enkripsi dilakukan dalam tiga langkah: pesan diubah menjadi blok bilangan
(2a), setiap blok dienkripsi (2b), lalu semua hasilnya dikumpulkan (2c).

#### 2a. Mengubah pesan menjadi blok bilangan

Kode: [crypto/encoding.py](crypto/encoding.py)

```python
# ---- mode SLIDE (huruf A-Z, sesuai materi) ----
def text_to_digits(text):
    digits = []
    for ch in text.upper():
        if not ("A" <= ch <= "Z"):
            raise ValueError(...)
        digits.append(f"{ord(ch) - ord('A'):02d}")   # A=00, B=01, ..., Z=25
    return "".join(digits)


def digits_to_blocks(digits, width=4):
    return [int(digits[i:i + width]) for i in range(0, len(digits), width)]


# ---- mode BYTE (teks UTF-8 atau file apa pun) ----
def block_size_for(p):
    size = (p.bit_length() - 1) // 8
    if size < 1:
        raise ValueError("p terlalu kecil untuk mode byte (minimal 9 bit)")
    return size


def bytes_to_blocks(data, block_size):
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        blocks.append(int.from_bytes(chunk, "big"))
    return blocks
```

**Penjelasan kode**

- ElGamal hanya bisa mengenkripsi **bilangan** `m` dengan `0 <= m <= p-1`. Karena
  itu pesan harus diubah menjadi bilangan dan dipotong-potong menjadi blok.
- **Mode slide**: setiap huruf diubah menjadi 2 digit (`ord(ch) - ord('A')`),
  lalu setiap 4 digit (2 huruf) menjadi satu blok.
- **Mode byte**: data dipotong per `size` byte, lalu setiap potongan dibaca
  sebagai satu bilangan besar (`int.from_bytes`, big-endian).
- `block_size_for` memilih ukuran blok sehingga nilai blok **pasti** lebih kecil
  dari p.

**Matematika**

Jika p punya L bit, maka `p >= 2^(L-1)`. Blok berukuran `size` byte bernilai
paling besar `2^(8·size) - 1`. Dengan memilih:

```math
\text{size} = \left\lfloor \frac{L-1}{8} \right\rfloor \quad\Rightarrow\quad m \le 2^{8\cdot\text{size}} - 1 < 2^{L-1} \le p
```

Syarat `m < p` dibutuhkan karena semua operasi dilakukan modulo p. Jika
`m >= p`, hasil dekripsi menjadi `m mod p`, bukan `m`, sehingga pesan rusak.

**Contoh**

```text
Mode slide:
  'HALO'  ->  H=07, A=00, L=11, O=14  ->  '07001114'
          ->  blok [0700, 1114]  =  [700, 1114]      (keduanya < p = 2273)

Mode byte (p 256 bit):
  size = (256 - 1) // 8 = 31 byte per blok
  b"Hi" = 0x48 0x69  ->  0x4869 = 72·256 + 105 = 18537
  contoh/pesan_contoh.txt (82 byte)  ->  3 blok: 31 + 31 + 20 byte
```

Catatan: dengan p = 2273, pasangan huruf yang diawali X, Y, atau Z gagal
dienkripsi. Contohnya `'XA'` menjadi blok 2300, padahal blok harus kurang dari
2273. Untuk p 256 bit hal ini tidak menjadi masalah.

#### 2b. Enkripsi satu blok

Kode: [crypto/elgamal.py](crypto/elgamal.py#L134)

```python
def encrypt_block(m, pub, k=None, tr=SILENT):
    p, g, y = pub                                # hanya butuh kunci PUBLIK
    if not (0 <= m <= p - 1):
        raise ValueError(f"blok m={m} di luar rentang [0, p-1]")
    if k is None:
        k = random_between(1, p - 2)             # k acak, sekali pakai
    elif not (1 <= k <= p - 2):
        raise ValueError("k harus pada rentang [1, p-2]")
    a = mod_exp(g, k, p)                         # a = g^k mod p
    b = (mod_exp(y, k, p) * m) % p               # b = y^k * m mod p
    return a, b
```

**Penjelasan kode**

- Enkripsi hanya memakai **kunci publik** `(p, g, y)`. Siapa pun bisa
  mengenkripsi untuk pemilik kunci, tetapi hanya pemilik kunci privat yang bisa
  membukanya.
- `k` adalah bilangan acak **sekali pakai** yang dibuat baru untuk setiap blok.
  Parameter `k` hanya diisi manual untuk mereproduksi contoh materi.
- `a = g^k mod p` adalah "petunjuk" untuk penerima. Nilai ini ikut dikirim supaya
  penerima bisa menghitung ulang kunci penyamar.
- `b = y^k · m mod p` adalah pesan yang sudah disamarkan.
- Hasilnya pasangan `(a, b)`, sehingga ukuran cipherteks 2 kali ukuran pesan.

**Matematika**

```math
a = g^{k} \bmod p, \qquad b = y^{k} \cdot m \bmod p
```

Nilai `s = y^k = (g^x)^k = g^(xk) mod p` adalah **kunci bersama sekali pakai**,
sama seperti kunci sesi pada DH (`k` berperan seperti rahasia Bob, `a` seperti
nilai publik Bob). Pesan disamarkan dengan cara dikalikan dengan `s`.

Kenapa `k` harus acak dan tidak boleh dipakai ulang?

- Karena k acak, pesan yang sama menghasilkan cipherteks yang berbeda setiap kali
  dienkripsi.
- Jika dua blok memakai k yang sama, nilai `s`-nya juga sama:
  `b1 = s·m1` dan `b2 = s·m2`. Penyerang yang tahu `m1` bisa langsung menghitung
  `m2 = b2 · b1^(-1) · m1 mod p`.

**Contoh** (materi: kunci publik (2273, 3, 461), pesan 'HALO')

```text
Blok 1: m = 700,  k = 1463
  a = g^k mod p      = 3^1463 mod 2273          = 1439
  s = y^k mod p      = 461^1463 mod 2273        = 1825
  b = s · m mod p    = 1825 · 700 mod 2273      = 74
  cipherteks blok 1  = (1439, 74)

Blok 2: m = 1114, k = 2001
  a = g^k mod p      = 3^2001 mod 2273          = 1220
  s = y^k mod p      = 461^2001 mod 2273        = 1087
  b = s · m mod p    = 1087 · 1114 mod 2273     = 1682
  cipherteks blok 2  = (1220, 1682)
```

#### 2c. Enkripsi pesan utuh

Kode: [crypto/elgamal.py](crypto/elgamal.py#L224)

```python
def encrypt_bytes(data, pub, tr=SILENT):
    size = encoding.block_size_for(pub.p)                 # 1. ukuran blok
    blocks = encoding.bytes_to_blocks(data, size)         # 2. data -> blok
    enc = [encrypt_block(m, pub, tr=tr) for m in blocks]  # 3. enkripsi tiap blok
    return Ciphertext(enc, size, len(data), "byte")       # 4. kumpulkan hasil


def encrypt_text_slide(text, pub, ks=None, tr=SILENT):
    digits = encoding.text_to_digits(text)                # 'HALO' -> '07001114'
    blocks = encoding.digits_to_blocks(digits, 4)         # -> [700, 1114]
    enc = []
    for i, m in enumerate(blocks):
        enc.append(encrypt_block(m, pub, k=(ks[i] if ks else None), tr=tr))
    return Ciphertext(enc, 4, len(digits), "slide")
```

**Penjelasan kode**

- Kedua fungsi mengikuti pola yang sama: pesan diubah menjadi blok, setiap blok
  dienkripsi dengan `encrypt_block`, lalu hasilnya dibungkus `Ciphertext`.
- `encrypt_bytes` tidak memberi `k`, sehingga setiap blok otomatis mendapat k
  acak yang baru.
- `ks` di `encrypt_text_slide` hanya dipakai untuk mereproduksi materi
  (`ks=[1463, 2001]`).
- `Ciphertext` menyimpan `block_size` dan `length` (panjang data asli). Keduanya
  wajib ada untuk dekripsi. Contohnya `'HAL'` menjadi blok `[700, 11]`: tanpa
  `length`, blok terakhir akan dikembalikan sebagai `'0011'` (4 digit) sehingga
  hasilnya `'HAAL'`.

**Contoh**

```text
encrypt_text_slide('HALO', pub, ks=[1463, 2001])
  -> Ciphertext(blocks=[(1439, 74), (1220, 1682)], block_size=4, length=8, mode='slide')
```

Jika disimpan dengan `storage.save_ciphertext`, hasilnya menjadi berkas berikut:

```text
ELGAMAL-v1
mode=slide
block_size=4
length=8
---
1439:74
1220:1682
```

---

### ElGamal 3: Dekripsi

#### 3a. Dekripsi satu blok

Kode: [crypto/elgamal.py](crypto/elgamal.py#L182)

```python
def decrypt_block(a, b, priv, tr=SILENT):
    p, _, x = priv                                # hanya butuh p dan kunci privat x
    inv_fermat = mod_exp(a, p - 1 - x, p)         # (a^x)^-1 = a^(p-1-x) mod p
    m = (b * inv_fermat) % p                      # m = b * (a^x)^-1 mod p
    # verifikasi silang dengan extended Euclid
    ax = mod_exp(a, x, p)
    inv_euclid = mod_inverse(ax, p)
    assert inv_fermat == inv_euclid, "invers Fermat != invers Euclid"
    return m
```

**Penjelasan kode**

- Dekripsi memakai **kunci privat** `x`. Nilai `g` tidak dibutuhkan, sehingga
  di-unpack ke `_`.
- `inv_fermat` adalah invers dari `a^x` yang dihitung dengan **satu** kali
  `mod_exp` memakai Teorema Fermat (sesuai materi).
- `m = b · inv_fermat mod p` mengembalikan pesan asli.
- Tiga baris terakhir menghitung invers yang sama dengan cara lain
  ([extended Euclid](#extended_gcd-dan-mod_inverse-invers-modular)) sebagai
  pengecekan bahwa implementasi matematikanya benar. Bagian ini tidak wajib
  untuk dekripsi.
- Jika kunci privat salah, fungsi ini **tidak** error, tetapi `m` yang dihasilkan
  berupa angka acak. Kesalahan baru terdeteksi saat blok diubah kembali
  menjadi byte (lihat 3b).

**Matematika**

Penerima menghitung ulang kunci bersama `s` dari `a` dan kunci privatnya:

```math
a^{x} = (g^{k})^{x} = (g^{x})^{k} = y^{k} = s \pmod{p}
```

Lalu pesan dikembalikan dengan "membagi" b dengan s, yaitu mengalikan dengan
invers modular `s^(-1)`:

```math
b \cdot (a^{x})^{-1} = (s \cdot m) \cdot s^{-1} = m \pmod{p}
```

Invers dihitung dengan **Teorema Fermat kecil**: untuk p prima dan a yang
tidak habis dibagi p, berlaku `a^(p-1) = 1 mod p`. Akibatnya:

```math
a^{x} \cdot a^{p-1-x} = a^{p-1} \equiv 1 \pmod{p} \quad\Rightarrow\quad (a^{x})^{-1} \equiv a^{p-1-x} \pmod{p}
```

**Contoh** (materi: kunci privat x = 243, p = 2273)

```text
Blok 1: (a, b) = (1439, 74)
  s       = a^x mod p           = 1439^243 mod 2273   = 1825   (sama dengan s milik pengirim!)
  p-1-x   = 2273 - 1 - 243      = 2029
  s^(-1)  = a^(p-1-x) mod p     = 1439^2029 mod 2273  = 1791
  cek     : 1825 · 1791 mod 2273 = 1                           (benar invers)
  m       = b · s^(-1) mod p    = 74 · 1791 mod 2273  = 700

Blok 2: (a, b) = (1220, 1682)
  s       = 1220^243 mod 2273   = 1087
  s^(-1)  = 1220^2029 mod 2273  = 1125
  m       = 1682 · 1125 mod 2273 = 1114
```

#### 3b. Dekripsi pesan utuh

Kode: [crypto/elgamal.py](crypto/elgamal.py#L241) dan
[crypto/encoding.py](crypto/encoding.py#L38)

```python
def decrypt_text_slide(ct, priv, tr=SILENT):
    blocks = [decrypt_block(a, b, priv, tr=tr) for a, b in ct.blocks]
    digits = encoding.blocks_to_digits(blocks, ct.length, ct.block_size)
    return encoding.digits_to_text(digits)


def decrypt_bytes(ct, priv, tr=SILENT):
    blocks = [decrypt_block(a, b, priv, tr=tr) for a, b in ct.blocks]
    return encoding.blocks_to_bytes(blocks, ct.block_size, ct.length)


# encoding.py
def blocks_to_digits(blocks, total_digits, width=4):
    out = []
    remaining = total_digits
    for b in blocks:
        w = min(width, remaining)          # blok terakhir bisa < 4 digit
        out.append(str(b).zfill(w))        # 700 -> '0700'
        remaining -= w
    return "".join(out)


def blocks_to_bytes(blocks, block_size, length):
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
```

**Penjelasan kode**

- Setiap pasangan `(a, b)` didekripsi menjadi blok bilangan, lalu blok-blok
  itu diubah kembali menjadi teks atau byte. Ini kebalikan dari langkah 2a.
- `zfill(w)` dan `to_bytes(w, ...)` mengembalikan **nol di depan** yang hilang
  saat blok diubah menjadi `int`, misalnya `'0700'` yang tersimpan sebagai `700`.
- `length` dari `Ciphertext` dipakai untuk menentukan panjang blok terakhir.
- Jika kunci privat salah, blok hasil dekripsi berupa angka acak yang biasanya
  terlalu besar untuk `w` byte. Akibatnya `to_bytes` gagal dan muncul pesan
  error "kunci salah atau data rusak".

**Contoh**

```text
decrypt_text_slide(Ciphertext([(1439, 74), (1220, 1682)], 4, 8, 'slide'), priv)
  decrypt_block         ->  [700, 1114]
  blocks_to_digits      ->  '0700' + '1114' = '07001114'
  digits_to_text        ->  07=H, 00=A, 11=L, 14=O  =  'HALO'
```

---

## Lampiran: fungsi matematika pendukung

Semua fungsi ini ada di [crypto/math_utils.py](crypto/math_utils.py) dan dipakai
oleh DH maupun ElGamal.

### mod_exp: eksponensiasi modular

Kode: [crypto/math_utils.py](crypto/math_utils.py#L29)

```python
def mod_exp(base, exp, mod):
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("eksponen harus >= 0")
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:                         # bit paling kanan = 1?
            result = (result * base) % mod
        base = (base * base) % mod          # kuadratkan base
        exp >>= 1                           # geser ke bit berikutnya
    return result
```

**Penjelasan kode**: metode **square-and-multiply**. Eksponen dibaca bit demi
bit dari kanan. Di setiap langkah base dikuadratkan. Jika bitnya 1, base saat
itu dikalikan ke `result`. Setiap perkalian langsung di-`mod`, sehingga angkanya
tidak pernah membesar.

**Matematika**: eksponen ditulis dalam biner, `e = sum(b_i · 2^i)`, sehingga:

```math
g^{e} = \prod_{b_i = 1} g^{2^{i}} \pmod{n}
```

Untuk eksponen 256 bit hanya dibutuhkan sekitar 256 kuadrat dan paling banyak
256 perkalian. Menghitung `g**x` secara langsung akan menghasilkan angka yang
terlalu besar untuk disimpan komputer.

**Contoh**: `3^13 mod 7`, dengan 13 = `1101` dalam biner

| exp (biner) | bit kanan | result | base untuk langkah berikutnya |
|-------------|-----------|--------|-------------------------------|
| 1101 | 1 | 1·3 = **3** | 3² = 9 mod 7 = 2 (= 3^2) |
| 110  | 0 | 3 (tetap) | 2² = 4 (= 3^4) |
| 11   | 1 | 3·4 = 12 mod 7 = **5** | 4² = 16 mod 7 = 2 (= 3^8) |
| 1    | 1 | 5·2 = 10 mod 7 = **3** | selesai |

Hasilnya `3^13 mod 7 = 3`. Cek: `3^13 = 1.594.323 = 7 · 227.760 + 3`.

### extended_gcd dan mod_inverse: invers modular

Kode: [crypto/math_utils.py](crypto/math_utils.py#L69)

```python
def extended_gcd(a, b):
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y           # gcd, x, y  dengan  a*x + b*y = gcd


def mod_inverse(a, m):
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} tidak memiliki invers modulo {m}")
    return x % m
```

**Penjelasan kode**: fungsi ini menjalankan algoritma Euclid (bagi terus sampai
sisanya 0) sambil mencatat koefisien `x` dan `y`. `mod_inverse` mengambil `x`
lalu menjadikannya positif dengan `% m`.

**Matematika** (identitas Bezout):

```math
a \cdot x + m \cdot y = \gcd(a, m) = 1 \quad\Rightarrow\quad a \cdot x \equiv 1 \pmod{m} \quad\Rightarrow\quad a^{-1} \equiv x \pmod{m}
```

**Contoh**: invers `1825` modulo `2273` (nilai `s` pada dekripsi blok 1)

| q | old_r | r | old_x | x |
|---|-------|---|-------|---|
| – | 1825 | 2273 | 1 | 0 |
| 0 | 2273 | 1825 | 0 | 1 |
| 1 | 1825 | 448 | 1 | -1 |
| 4 | 448 | 33 | -1 | 5 |
| 13 | 33 | 19 | 5 | -66 |
| 1 | 19 | 14 | -66 | 71 |
| 1 | 14 | 5 | 71 | -137 |
| 2 | 5 | 4 | -137 | 345 |
| 1 | 4 | 1 | 345 | **-482** |
| 4 | 1 | 0 | -482 | 2273 |

Hasilnya gcd = 1 dan x = -482, sehingga invers = `-482 mod 2273 = 1791`. Nilai
ini sama dengan hasil cara Fermat (`1439^2029 mod 2273 = 1791`), dan inilah yang
dicek oleh `assert` di `decrypt_block`.

### is_probable_prime: uji Miller-Rabin

Kode: [crypto/math_utils.py](crypto/math_utils.py#L99)

```python
def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:                # saring cepat dengan prima < 100
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:                      # tulis n-1 = 2^s * d (d ganjil)
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random_between(2, n - 2)       # basis acak
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue                       # lolos putaran ini
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break                      # lolos putaran ini
        else:
            return False                   # PASTI komposit
    return True                            # hampir pasti prima
```

**Penjelasan kode**: kandidat disaring dulu dengan prima kecil. Setelah itu
`n - 1` ditulis sebagai `2^s · d`. Untuk setiap basis acak `a`, barisan
`a^d, a^(2d), a^(4d), ...` dicek: n lolos putaran itu jika barisan dimulai dari
1 atau memuat `n - 1`.

**Matematika**: jika n prima, `a^(n-1) = 1 mod n` (Fermat), dan satu-satunya
akar kuadrat dari 1 modulo prima adalah `±1`. Jadi barisan di atas pasti berisi
1 di awal atau `-1` (= `n-1`) di tengah jalan. Bilangan komposit lolos satu
putaran dengan peluang paling besar 1/4, sehingga peluang lolos 40 putaran
paling besar `4^(-40)`.

**Contoh** (basis a = 2)

```text
n = 2273 :  n-1 = 2272 = 2^5 · 71  ->  s = 5, d = 71
            2^71 mod n = 1530 -> kuadrat 1983 -> kuadrat 2272 (= n-1)  -> LOLOS
n = 10403:  (= 101 · 103, lolos saringan prima kecil)
            n-1 = 10402 = 2^1 · 5201  ->  s = 1, d = 5201
            2^5201 mod n = 7880, bukan 1 dan bukan n-1, tidak ada kuadrat lagi -> KOMPOSIT
```

### generate_prime dan generate_safe_prime: membangkitkan prima

Kode: [crypto/math_utils.py](crypto/math_utils.py#L135)

```python
def generate_prime(bits):
    while True:
        cand = random_between(1 << (bits - 1), (1 << bits) - 1) | 1
        if is_probable_prime(cand):
            return cand


def generate_safe_prime(bits):
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and is_probable_prime(p):
            return p, q
```

**Penjelasan kode**: `generate_prime` mengambil angka acak yang bit teratasnya 1
(supaya panjangnya tepat `bits` bit), memaksanya ganjil dengan `| 1`, lalu
mengujinya dengan Miller-Rabin. Proses diulang sampai ketemu prima.
`generate_safe_prime` mencari prima `q`, lalu mengecek apakah `2q + 1` juga
prima. Proses inilah yang paling lama saat membangkitkan kunci 256 bit.

**Matematika**: untuk prima aman `p = 2q + 1`, `p - 1 = 2q`, sehingga faktor
primanya hanya `{2, q}`. Uji akar primitif cukup menghitung dua pangkat:
`g^q` dan `g^2`.

**Contoh** (8 bit): `q = 83` (7 bit, prima) memberi `p = 167` (8 bit, prima),
jadi 167 adalah prima aman. Prima aman 8 bit lainnya adalah 179 (q = 89) dan
227 (q = 113).

### is_primitive_root dan find_primitive_root: akar primitif

Kode: [crypto/math_utils.py](crypto/math_utils.py#L177)

```python
def is_primitive_root(g, p, factors=None):
    if g <= 1 or g >= p:
        return False
    if factors is None:
        factors = prime_factors(p - 1)            # trial division
    return all(mod_exp(g, (p - 1) // q, p) != 1 for q in factors)


def find_primitive_root(p, factors=None, start=2):
    if factors is None:
        factors = prime_factors(p - 1)
    for g in range(start, p):
        if is_primitive_root(g, p, factors):
            return g
    raise ValueError("akar primitif tidak ditemukan")
```

**Penjelasan kode**: `is_primitive_root` mengecek `g^((p-1)/q) mod p` untuk setiap
faktor prima q dari `p - 1`. Jika tidak ada yang bernilai 1, g adalah akar
primitif. `find_primitive_root` mencoba g = 2, 3, 4, ... sampai ketemu.

**Matematika**: **orde** g adalah pangkat terkecil `e` sehingga `g^e = 1 mod p`.
Orde selalu membagi `p - 1`. Jika orde g lebih kecil dari `p - 1`, orde itu
pasti membagi `(p-1)/q` untuk suatu faktor prima q, sehingga
`g^((p-1)/q) = 1`. Jadi jika semua pengecekan menghasilkan nilai selain 1, orde
g sama dengan `p - 1`, artinya g membangkitkan semua bilangan `1 .. p-1`.

**Contoh** (p = 7, `p - 1 = 6`, faktor prima {2, 3})

| pangkat e | 1 | 2 | 3 | 4 | 5 | 6 |
|-----------|---|---|---|---|---|---|
| `2^e mod 7` | 2 | 4 | **1** | 2 | 4 | 1 |
| `3^e mod 7` | 3 | 2 | 6 | 4 | 5 | **1** |

- g = 2: `2^(6/2) = 2^3 mod 7 = 1`, jadi **bukan** akar primitif. Pangkatnya
  hanya menghasilkan {1, 2, 4}.
- g = 3: `3^3 mod 7 = 6` dan `3^2 mod 7 = 2`, keduanya bukan 1, jadi **akar
  primitif**. Pangkatnya menghasilkan semua {1, 2, 3, 4, 5, 6}.

### discrete_log_bruteforce: serangan coba semua

Kode: [crypto/math_utils.py](crypto/math_utils.py#L211)

```python
def discrete_log_bruteforce(g, y, p, limit=None):
    limit = limit if limit is not None else p - 1
    cur = 1                                 # cur = g^x mod p
    for x in range(limit + 1):
        if cur == y % p:
            return x, x + 1                 # (x ditemukan, jumlah percobaan)
        cur = (cur * g) % p
    return None, limit + 1
```

**Penjelasan kode**: fungsi ini mencoba x = 0, 1, 2, ... sambil menghitung
`g^x` bertahap (dikali g setiap langkah) sampai sama dengan nilai publik `y`.
Fungsi ini dipakai pada menu "serangan" untuk menunjukkan bahwa p kecil tidak
aman.

**Contoh**: `discrete_log_bruteforce(6, 209, 251)` menghasilkan `(124, 125)`.
Rahasia Alice pada contoh DH ditemukan dalam 125 percobaan. Untuk p 256 bit,
jumlah percobaannya bisa mencapai sekitar `5,8 × 10^76`.

## Catatan

* Program ditujukan untuk **pembelajaran**. ElGamal di sini tanpa padding
  (tidak CCA-secure) dan `session.py` memakai cipher XOR-LCG yang tidak aman.
* Implementasi pure Python lambat untuk file besar (tiap blok = 2 eksponensiasi
  modular 256 bit).
* Berkas `contoh/private.key` hanya contoh; jangan dipakai untuk data nyata.
