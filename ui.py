"""Antarmuka web lokal untuk demo Diffie-Hellman dan ElGamal.

Jalankan dari folder proyek: python3 ui.py
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import urlparse

from crypto import diffie_hellman as dh
from crypto import elgamal as eg
from crypto.math_utils import find_primitive_root
from crypto.trace import SILENT


ROOT = os.path.dirname(os.path.abspath(__file__))
MAX_BODY_SIZE = 64 * 1024
MAX_TEXT_SIZE = 10_000
state = {"public_key": None, "private_key": None, "ciphertext": None}
state_lock = Lock()


def parse_optional_int(value, label):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} harus berupa bilangan bulat") from None


def run_dh(data):
    n = parse_optional_int(data.get("n"), "n")
    g = parse_optional_int(data.get("g"), "g")
    x = parse_optional_int(data.get("x"), "Kunci rahasia Alice")
    y = parse_optional_int(data.get("y"), "Kunci rahasia Bob")
    if n is None:
        bits = parse_optional_int(data.get("bits", 64), "Panjang bit")
        if bits is None or not 32 <= bits <= 512:
            raise ValueError("Panjang bit harus di antara 32 dan 512")
        n, g = dh.generate_parameters(bits, tr=SILENT)
        validate = False
    else:
        if g is None:
            g = find_primitive_root(n)
        validate = True
    result = dh.run_exchange(n, g, x, y, tr=SILENT, validate=validate)
    return {key: str(value) if isinstance(value, int) and not isinstance(value, bool) else value
            for key, value in result.items()}


def generate_keys(data):
    p = parse_optional_int(data.get("p"), "p")
    g = parse_optional_int(data.get("g"), "g")
    x = parse_optional_int(data.get("x"), "Kunci privat")
    bits = parse_optional_int(data.get("bits", 128), "Panjang bit")
    if bits is None or not 32 <= bits <= 512:
        raise ValueError("Panjang bit harus di antara 32 dan 512")
    public_key, private_key = eg.generate_keypair(
        p=p, g=g, x=x, bits=bits, tr=SILENT
    )
    with state_lock:
        state["public_key"] = public_key
        state["private_key"] = private_key
        state["ciphertext"] = None
    return {
        "public": {"p": str(public_key.p), "g": str(public_key.g),
                   "y": str(public_key.y)},
        "private": {"p": str(private_key.p), "x": str(private_key.x)},
    }


def encrypt_text(data):
    text = data.get("text", "")
    mode = data.get("mode", "byte")
    if not isinstance(text, str):
        raise ValueError("Pesan harus berupa teks")
    if len(text) > MAX_TEXT_SIZE:
        raise ValueError(f"Pesan maksimal {MAX_TEXT_SIZE} karakter")
    with state_lock:
        public_key = state["public_key"]
        if public_key is None:
            raise ValueError("Buat kunci ElGamal terlebih dahulu")
        if mode == "slide":
            ciphertext = eg.encrypt_text_slide(text.replace(" ", ""), public_key)
        elif mode == "byte":
            ciphertext = eg.encrypt_bytes(text.encode("utf-8"), public_key)
        else:
            raise ValueError("Mode enkripsi tidak dikenal")
        state["ciphertext"] = ciphertext
    return {
        "mode": ciphertext.mode,
        "block_size": ciphertext.block_size,
        "length": ciphertext.length,
        "blocks": [[str(a), str(b)] for a, b in ciphertext.blocks],
    }


def decrypt_text():
    with state_lock:
        private_key = state["private_key"]
        ciphertext = state["ciphertext"]
        if private_key is None:
            raise ValueError("Buat kunci ElGamal terlebih dahulu")
        if ciphertext is None:
            raise ValueError("Enkripsi pesan terlebih dahulu")
        if ciphertext.mode == "slide":
            plaintext = eg.decrypt_text_slide(ciphertext, private_key)
        else:
            plaintext = eg.decrypt_bytes(ciphertext, private_key).decode(
                "utf-8", "replace"
            )
    return {"text": plaintext}


class Handler(BaseHTTPRequestHandler):
    server_version = "CryptoDemoUI/1.0"

    def _valid_local_host(self):
        host = self.headers.get("Host", "")
        return host in (f"127.0.0.1:{self.server.server_port}",
                        f"localhost:{self.server.server_port}")

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._valid_local_host():
            self.send_error(403)
            return
        if urlparse(self.path).path == "/api/status":
            with state_lock:
                status = {"has_keys": state["public_key"] is not None,
                          "has_ciphertext": state["ciphertext"] is not None}
            self._send_json(status)
            return
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return
        try:
            with open(os.path.join(ROOT, "web", "index.html"), "rb") as page:
                body = page.read()
        except OSError as error:
            self.send_error(500, str(error))
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._valid_local_host():
            self.send_error(403)
            return
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if (parsed_origin.scheme != "http"
                    or parsed_origin.netloc != self.headers.get("Host")):
                self.send_error(403)
                return
        if self.headers.get_content_type() != "application/json":
            self._send_json({"error": "Content-Type harus application/json"}, 415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_BODY_SIZE:
                raise ValueError("Ukuran permintaan tidak valid")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Format permintaan tidak valid")
            route = urlparse(self.path).path
            actions = {
                "/api/dh": lambda: run_dh(data),
                "/api/keys": lambda: generate_keys(data),
                "/api/encrypt": lambda: encrypt_text(data),
                "/api/decrypt": decrypt_text,
            }
            action = actions.get(route)
            if action is None:
                self._send_json({"error": "Endpoint tidak ditemukan"}, 404)
                return
            self._send_json(action())
        except (ValueError, OSError, json.JSONDecodeError) as error:
            self._send_json({"error": str(error)}, 400)

    def log_message(self, format_string, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("UI Kriptografi berjalan di http://127.0.0.1:8000")
    print("Tekan Ctrl+C untuk menghentikan server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
