"""Unit test (unittest bawaan Python).

Jalankan dari root project:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from crypto import diffie_hellman as dh, elgamal as eg, encoding, storage  # noqa: E402
from crypto.math_utils import (discrete_log_bruteforce, extended_gcd, gcd,  # noqa: E402
                               find_primitive_root, is_primitive_root,
                               is_probable_prime, mod_exp, mod_inverse,
                               prime_factors)
from crypto.session import xor_cipher  # noqa: E402
from ui import parse_file_ciphertext, serialize_file_ciphertext  # noqa: E402


class TestMath(unittest.TestCase):
    def test_mod_exp_matches_builtin(self):
        for b, e, m in [(6, 124, 251), (3, 243, 2273), (7, 0, 13), (2, 10**6, 10**9 + 7)]:
            self.assertEqual(mod_exp(b, e, m), pow(b, e, m))

    def test_gcd_and_inverse(self):
        self.assertEqual(gcd(48, 18), 6)
        g, x, y = extended_gcd(240, 46)
        self.assertEqual(240 * x + 46 * y, g)
        self.assertEqual((mod_inverse(3, 11) * 3) % 11, 1)
        with self.assertRaises(ValueError):
            mod_inverse(6, 9)

    def test_primality(self):
        self.assertTrue(all(is_probable_prime(p) for p in [2, 251, 2273, 104729]))
        self.assertFalse(any(is_probable_prime(c) for c in [1, 4, 91, 561, 2271]))

    def test_primitive_root(self):
        self.assertEqual(prime_factors(250), [2, 5])
        self.assertTrue(is_primitive_root(6, 251))
        self.assertTrue(is_primitive_root(3, 2273))
        self.assertFalse(is_primitive_root(1, 251))
        g = find_primitive_root(2273)
        self.assertTrue(is_primitive_root(g, 2273))

    def test_discrete_log(self):
        x, _ = discrete_log_bruteforce(3, 461, 2273)
        self.assertEqual(mod_exp(3, x, 2273), 461)


class TestDiffieHellman(unittest.TestCase):
    def test_slide_example(self):
        r = dh.run_exchange(251, 6, 124, 158)
        self.assertEqual((r["X"], r["Y"], r["K"], r["K2"]), (209, 197, 79, 79))

    def test_random_parameters(self):
        n, g = dh.generate_parameters(64)
        r = dh.run_exchange(n, g, validate=False)
        self.assertTrue(r["ok"])

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            dh.validate_parameters(250, 6)       # n bukan prima
        with self.assertRaises(ValueError):
            dh.validate_parameters(251, 1)       # 1 bukan akar primitif


class TestElGamal(unittest.TestCase):
    def test_slide_example(self):
        pub, priv = eg.generate_keypair(p=2273, g=3, x=243)
        self.assertEqual(pub.y, 461)
        ct = eg.encrypt_text_slide("HALO", pub, ks=[1463, 2001])
        self.assertEqual(ct.blocks, [(1439, 74), (1220, 1682)])
        self.assertEqual(eg.decrypt_text_slide(ct, priv), "HALO")

    def test_bytes_roundtrip(self):
        pub, priv = eg.generate_keypair(bits=128)
        for data in [b"", b"A", "Halo \u2603 dunia".encode(), bytes(range(256)), b"\x00\x00ab"]:
            ct = eg.encrypt_bytes(data, pub)
            self.assertEqual(eg.decrypt_bytes(ct, priv), data)

    def test_probabilistic(self):
        pub, _ = eg.generate_keypair(bits=64)
        self.assertNotEqual(eg.encrypt_block(5, pub), eg.encrypt_block(5, pub))

    def test_wrong_key_fails(self):
        pub, priv = eg.generate_keypair(bits=64)
        wrong = eg.PrivateKey(priv.p, priv.g, priv.x - 1)
        ct = eg.encrypt_bytes(b"rahasia", pub)
        try:
            self.assertNotEqual(eg.decrypt_bytes(ct, wrong), b"rahasia")
        except ValueError:
            pass   # hasil sampah di luar rentang blok juga dianggap gagal

    def test_invalid_inputs(self):
        pub, _ = eg.generate_keypair(p=2273, g=3, x=243)
        with self.assertRaises(ValueError):
            eg.encrypt_block(2273, pub)           # m >= p
        with self.assertRaises(ValueError):
            eg.generate_keypair(p=2273, g=3, x=1)  # x di luar rentang
        with self.assertRaises(ValueError):
            eg.generate_keypair(p=2274, g=3, x=5)  # p bukan prima


class TestEncodingAndStorage(unittest.TestCase):
    def test_slide_encoding(self):
        self.assertEqual(encoding.text_to_digits("HALO"), "07001114")
        self.assertEqual(encoding.digits_to_blocks("07001114"), [700, 1114])
        self.assertEqual(encoding.digits_to_text("07001114"), "HALO")
        with self.assertRaises(ValueError):
            encoding.text_to_digits("HAL0")

    def test_storage_roundtrip(self):
        pub, priv = eg.generate_keypair(bits=64)
        ct = eg.encrypt_bytes(b"uji simpan", pub)
        with tempfile.TemporaryDirectory() as d:
            storage.save_public_key(f"{d}/pub", pub)
            storage.save_private_key(f"{d}/priv", priv)
            storage.save_ciphertext(f"{d}/ct", ct)
            self.assertEqual(storage.load_public_key(f"{d}/pub"), pub)
            self.assertEqual(storage.load_private_key(f"{d}/priv"), priv)
            ct2 = storage.load_ciphertext(f"{d}/ct")
            self.assertEqual(eg.decrypt_bytes(ct2, storage.load_private_key(f"{d}/priv")),
                             b"uji simpan")

    def test_file_ciphertext_roundtrip(self):
        pub, priv = eg.generate_keypair(bits=64)
        original = b"\x00binary file\xff"
        encrypted = eg.encrypt_bytes(original, pub)
        serialized = serialize_file_ciphertext(encrypted, "sample.bin")
        restored, filename = parse_file_ciphertext(serialized, priv)
        self.assertEqual(filename, "sample.bin")
        self.assertEqual(eg.decrypt_bytes(restored, priv), original)

    def test_invalid_file_ciphertext_metadata(self):
        pub, priv = eg.generate_keypair(bits=64)
        encrypted = eg.encrypt_bytes(b"file", pub)
        serialized = serialize_file_ciphertext(encrypted, "sample.bin")
        corrupted = serialized.replace(b"length=4", b"length=999")
        with self.assertRaises(ValueError):
            parse_file_ciphertext(corrupted, priv)


class TestSession(unittest.TestCase):
    def test_xor_symmetric(self):
        msg = b"kunci sesi"
        self.assertEqual(xor_cipher(xor_cipher(msg, 79), 79), msg)
        self.assertNotEqual(xor_cipher(msg, 79), msg)


if __name__ == "__main__":
    unittest.main()
