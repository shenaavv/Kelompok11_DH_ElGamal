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
│   └── test_all.py          # 16 unit test (unittest bawaan Python)
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

| Tahap | Fungsi |
|-------|--------|
| DH 1 — parameter publik (n, g) | `diffie_hellman.generate_parameters`, `validate_parameters` |
| DH 2/3 — nilai rahasia & publik (X, Y) | `generate_private_key`, `compute_public_value` |
| DH 4/5 — kunci sesi K = K' | `compute_shared_secret`, `run_exchange` |
| ElGamal 1 — pembangkitan kunci | `elgamal.generate_keypair` |
| ElGamal 2 — enkripsi (a, b) | `encrypt_block`, `encrypt_text_slide`, `encrypt_bytes` |
| ElGamal 3 — dekripsi | `decrypt_block`, `decrypt_text_slide`, `decrypt_bytes` |

## Catatan

* Program ditujukan untuk **pembelajaran**. ElGamal di sini tanpa padding
  (tidak CCA-secure) dan `session.py` memakai cipher XOR-LCG yang tidak aman.
* Implementasi pure Python lambat untuk file besar (tiap blok = 2 eksponensiasi
  modular 256 bit).
* Berkas `contoh/private.key` hanya contoh; jangan dipakai untuk data nyata.
