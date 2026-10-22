"""Pencatat langkah (tracer) agar setiap tahapan algoritma dapat ditampilkan."""


def fmt(n, limit=40):
    """Format bilangan besar agar ringkas saat ditampilkan."""
    s = str(n)
    if len(s) <= limit:
        return s
    return f"{s[:14]}...{s[-8:]} ({n.bit_length()} bit)"


class Tracer:
    """Mencetak langkah-langkah perhitungan bila `enabled=True`."""

    def __init__(self, enabled=True):
        self.enabled = enabled

    def title(self, text):
        if self.enabled:
            print(f"\n=== {text} ===")

    def step(self, text):
        if self.enabled:
            print(f"  * {text}")

    def line(self, text):
        if self.enabled:
            print(f"      {text}")


# Tracer "diam" untuk pemanggilan tanpa output.
SILENT = Tracer(False)
