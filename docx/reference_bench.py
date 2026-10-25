"""
Script đo số liệu THAM CHIẾU (Python + thư viện cryptography/OpenSSL), mô phỏng đúng
thuật toán của CryptoCore (.NET) để đối chiếu:
  - AES-256-CBC + PKCS7, header "AES1" + IV 16 byte, xử lý luồng với bộ đệm 4 MB
  - So sánh file theo từng byte
  - RSA OAEP-SHA256 (public) vs giải mã (private, CRT), ModPow thô e / d / CRT
  - Chữ ký PKCS#1 v1.5 (tất định) vs PSS (ngẫu nhiên) vs nonce+timestamp
  - Ký "thủ công" EM^d mod n trùng với thư viện

Chạy:  python reference_bench.py --dir /đường/dẫn --sizes 100 1024 2048 4096
"""
import argparse, os, time, secrets, hashlib, struct, statistics, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

BUF = 4 * 1024 * 1024
MAGIC = b"AES1"


def create_random_file(path, size):
    with open(path, "wb") as f:
        left = size
        while left:
            n = min(BUF, left)
            f.write(os.urandom(n))
            left -= n


def encrypt_file(src, dst, key):
    t = time.perf_counter()
    iv = secrets.token_bytes(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    pad = sympad.PKCS7(128).padder()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(MAGIC + iv)
        while chunk := fi.read(BUF):
            fo.write(enc.update(pad.update(chunk)))
        fo.write(enc.update(pad.finalize()) + enc.finalize())
    return time.perf_counter() - t


def decrypt_file(src, dst, key):
    t = time.perf_counter()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        head = fi.read(20)
        assert head[:4] == MAGIC
        dec = Cipher(algorithms.AES(key), modes.CBC(head[4:])).decryptor()
        unpad = sympad.PKCS7(128).unpadder()
        while chunk := fi.read(BUF):
            fo.write(unpad.update(dec.update(chunk)))
        fo.write(unpad.update(dec.finalize()) + unpad.finalize())
    return time.perf_counter() - t


def compare_files(a, b):
    t = time.perf_counter()
    if os.path.getsize(a) != os.path.getsize(b):
        return False, time.perf_counter() - t
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(BUF), fb.read(BUF)
            if x != y:
                return False, time.perf_counter() - t
            if not x:
                return True, time.perf_counter() - t


def bench_aes(directory, sizes_mb):
    key = secrets.token_bytes(32)
    print("| Kích thước | Mã hoá (s) | MB/s | Giải mã (s) | MB/s | So sánh byte | T. so sánh (s) | Δ kích thước |")
    print("|---:|---:|---:|---:|---:|:---:|---:|---:|")
    for mb in sizes_mb:
        src = os.path.join(directory, f"test_{mb}MB.bin")
        enc, dec = src + ".aes", os.path.join(directory, f"decrypted_test_{mb}MB.bin")
        if not os.path.exists(src):
            create_random_file(src, mb * 1024 * 1024)
        te = encrypt_file(src, enc, key)
        td = decrypt_file(enc, dec, key)
        eq, tc = compare_files(src, dec)
        delta = os.path.getsize(enc) - os.path.getsize(src)
        size = f"{mb} MB" if mb < 1024 else f"{mb/1024:g} GB"
        print(f"| {size} | {te:.3f} | {mb/te:.1f} | {td:.3f} | {mb/td:.1f} | {'GIỐNG 100%' if eq else 'KHÁC'} | {tc:.3f} | +{delta} B |", flush=True)
        for p in (enc, dec, src):
            os.remove(p)


def timeit(fn, n):
    fn()
    t = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t) * 1000 / n


def bench_rsa(iterations):
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    data = secrets.token_bytes(32)
    print("| Khoá | Phép toán | Khoá dùng | Số mũ (bit) | ms/lần | lần/giây |")
    print("|---|---|---|---:|---:|---:|")
    for bits in (1024, 2048, 3072, 4096):
        k = rsa.generate_private_key(65537, bits)
        pub = k.public_key()
        pn, n = k.private_numbers(), k.public_key().public_numbers().n
        e, d, p, q = pn.public_numbers.e, pn.d, pn.p, pn.q
        dp, dq, qi = pn.dmp1, pn.dmq1, pn.iqmp
        c = pub.encrypt(data, oaep)
        sig = k.sign(data, padding.PKCS1v15(), hashes.SHA256())
        m = int.from_bytes(secrets.token_bytes(bits // 8 - 1), "big")
        cm = pow(m, e, n)

        def crt():
            m1, m2 = pow(cm, dp, p), pow(cm, dq, q)
            return m2 + ((qi * (m1 - m2)) % p) * q

        assert crt() == m
        heavy = max(5, iterations // (bits // 512))
        rows = [
            ("Mã hoá OAEP-SHA256", "Public (n,e)", e.bit_length(), timeit(lambda: pub.encrypt(data, oaep), iterations)),
            ("Giải mã OAEP-SHA256", "Private (CRT)", d.bit_length(), timeit(lambda: k.decrypt(c, oaep), iterations)),
            ("Xác minh chữ ký PKCS#1", "Public (n,e)", e.bit_length(), timeit(lambda: pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256()), iterations)),
            ("Ký PKCS#1 v1.5", "Private (CRT)", d.bit_length(), timeit(lambda: k.sign(data, padding.PKCS1v15(), hashes.SHA256()), iterations)),
            ("ModPow thô: m^e mod n", "Public (n,e)", e.bit_length(), timeit(lambda: pow(m, e, n), iterations)),
            ("ModPow thô: c^d mod n (không CRT)", "Private (n,d)", d.bit_length(), timeit(lambda: pow(cm, d, n), heavy)),
            ("ModPow thô: c^d mod n (có CRT)", "Private (p,q,dP,dQ,qInv)", d.bit_length(), timeit(crt, heavy)),
        ]
        for op, used, eb, ms in rows:
            print(f"| RSA-{bits} | {op} | {used} | {eb} | {ms:.4f} | {1000/ms:,.0f} |", flush=True)


DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def manual_pkcs1_sign(k, data):
    pn = k.private_numbers()
    n = pn.public_numbers.n
    kb = (n.bit_length() + 7) // 8
    t = DIGESTINFO_SHA256 + hashlib.sha256(data).digest()
    em = b"\x00\x01" + b"\xff" * (kb - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), pn.d, n).to_bytes(kb, "big")


def bench_sign():
    k = rsa.generate_private_key(65537, 2048)
    pub = k.public_key()
    data = "Cung mot du lieu, cung mot nguoi ky".encode()
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def nonce_sign():
        nonce, ts = secrets.token_bytes(16), int(time.time() * 1000)
        h = hashlib.sha256(nonce + struct.pack(">q", ts) + data).digest()
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        return nonce + k.sign(h, padding.PKCS1v15(), Prehashed(hashes.SHA256()))

    for name, fn in [
        ("Pkcs1v15", lambda: k.sign(data, padding.PKCS1v15(), hashes.SHA256())),
        ("Pss", lambda: k.sign(data, pss, hashes.SHA256())),
        ("NonceTimestamp", nonce_sign),
    ]:
        sigs = [fn() for _ in range(5)]
        print(f"- {name}: {len(set(sigs))}/5 chữ ký khác nhau")
    lib = k.sign(data, padding.PKCS1v15(), hashes.SHA256())
    print(f"- Ký thủ công EM^d mod n trùng với thư viện PKCS#1: {manual_pkcs1_sign(k, data) == lib}")
    s1 = k.sign(data, padding.PKCS1v15(), hashes.SHA256())
    s2 = k.sign(data + b".", padding.PKCS1v15(), hashes.SHA256())
    diff = sum(bin(a ^ b).count("1") for a, b in zip(s1, s2))
    print(f"- Dữ liệu thêm 1 dấu '.': chữ ký khác {diff}/2048 bit")


def bench_hash(trials=10000):
    diffs = []
    for _ in range(trials):
        msg = bytearray(random.randbytes(64))
        h1 = hashlib.sha256(msg).digest()
        bit = random.randrange(512)
        msg[bit // 8] ^= 1 << (bit % 8)
        h2 = hashlib.sha256(msg).digest()
        diffs.append(sum(bin(a ^ b).count("1") for a, b in zip(h1, h2)))
    print(f"{trials} lần đảo 1 bit: trung bình {statistics.mean(diffs):.2f}/256 bit ({statistics.mean(diffs)/2.56:.2f}%), "
          f"min {min(diffs)}, max {max(diffs)}, độ lệch chuẩn {statistics.pstdev(diffs):.2f}")
    a, b = "An toan va bao mat thong tin", "An toan va bao mat thong tim"
    ha, hb = hashlib.sha256(a.encode()).hexdigest(), hashlib.sha256(b.encode()).hexdigest()
    bits = sum(bin(x ^ y).count("1") for x, y in zip(bytes.fromhex(ha), bytes.fromhex(hb)))
    print(f'"{a}" → {ha}\n"{b}" → {hb}\n→ đổi 1 ký tự: {bits}/256 bit khác, {sum(x != y for x, y in zip(ha, hb))}/64 ký tự hex khác')


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--sizes", type=int, nargs="*", default=[100, 1024])
    ap.add_argument("--iter", type=int, default=200)
    ap.add_argument("--only", choices=["aes", "rsa", "sign", "hash"])
    a = ap.parse_args()
    if a.only in (None, "aes"): print("## AES-256-CBC\n"); bench_aes(a.dir, a.sizes); print()
    if a.only in (None, "rsa"): print("## RSA\n"); bench_rsa(a.iter); print()
    if a.only in (None, "sign"): print("## Chữ ký số\n"); bench_sign(); print()
    if a.only in (None, "hash"): print("## SHA-256\n"); bench_hash()
