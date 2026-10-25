using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace CryptoCore;

public enum PemFormat
{
    /// <summary>PKCS#1: "BEGIN RSA PUBLIC KEY" / "BEGIN RSA PRIVATE KEY" (chỉ dành cho RSA).</summary>
    Pkcs1,
    /// <summary>X.509 SubjectPublicKeyInfo ("BEGIN PUBLIC KEY") / PKCS#8 ("BEGIN PRIVATE KEY") – định dạng chung, phổ biến nhất.</summary>
    SpkiPkcs8
}

/// <summary>Một thành phần của khoá RSA (n, e, d, p, q, ...).</summary>
public sealed class RsaComponent
{
    public string Name { get; init; }
    public string Meaning { get; init; }
    public byte[] Value { get; init; }

    public BigInteger AsBigInteger => new BigInteger(Value, isUnsigned: true, isBigEndian: true);
    public long BitLength => (long)AsBigInteger.GetBitLength();
    public string Hex => Convert.ToHexString(Value);
    public string Decimal => AsBigInteger.ToString();
}

/// <summary>
/// Mã hoá bất đối xứng RSA: mã hoá bằng một khoá, giải mã bằng khoá còn lại.
/// Padding mã hoá: OAEP-SHA256  =>  dữ liệu tối đa = k - 2*32 - 2 byte (k = độ dài modulus theo byte).
/// Với RSA-2048: 256 - 66 = 190 byte (đúng giới hạn "không quá 190 byte" của đề bài).
/// </summary>
public static class RsaService
{
    public const int OaepSha256Overhead = 2 * 32 + 2;

    // ------------------------------------------------------------------ 1. Sinh cặp khoá
    public static RSA GenerateKeyPair(int keySizeBits = 2048) => RSA.Create(keySizeBits);

    // ------------------------------------------------------------------ 2. Xuất PEM
    public static string ExportPublicPem(RSA rsa, PemFormat format) =>
        format == PemFormat.Pkcs1 ? rsa.ExportRSAPublicKeyPem() : rsa.ExportSubjectPublicKeyInfoPem();

    public static string ExportPrivatePem(RSA rsa, PemFormat format) =>
        format == PemFormat.Pkcs1 ? rsa.ExportRSAPrivateKeyPem() : rsa.ExportPkcs8PrivateKeyPem();

    // ------------------------------------------------------------------ 4. Nhập PEM
    /// <summary>Nạp khoá từ chuỗi PEM (hỗ trợ cả 4 loại: RSA PUBLIC/PRIVATE KEY, PUBLIC KEY, PRIVATE KEY).</summary>
    public static RSA ImportPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    public static bool HasPrivateKey(RSA rsa)
    {
        try { rsa.ExportParameters(true); return true; }
        catch (CryptographicException) { return false; }
    }

    /// <summary>Lấy các thành phần của khoá. Khoá công khai: n, e. Khoá bí mật: n, e, d, p, q, dP, dQ, qInv.</summary>
    public static List<RsaComponent> GetComponents(RSA rsa)
    {
        bool isPrivate = HasPrivateKey(rsa);
        RSAParameters p = rsa.ExportParameters(isPrivate);
        var list = new List<RsaComponent>
        {
            new() { Name = "n (Modulus)", Meaning = "n = p·q, dùng chung cho cả khoá công khai và bí mật", Value = p.Modulus },
            new() { Name = "e (PublicExponent)", Meaning = "Số mũ công khai (thường 65537 = 0x010001, rất nhỏ)", Value = p.Exponent },
        };
        if (isPrivate)
        {
            list.Add(new() { Name = "d (PrivateExponent)", Meaning = "Số mũ bí mật: e·d ≡ 1 (mod λ(n)), dài gần bằng n", Value = p.D });
            list.Add(new() { Name = "p (Prime1)", Meaning = "Số nguyên tố thứ nhất", Value = p.P });
            list.Add(new() { Name = "q (Prime2)", Meaning = "Số nguyên tố thứ hai", Value = p.Q });
            list.Add(new() { Name = "dP (Exponent1)", Meaning = "d mod (p-1) – dùng cho CRT", Value = p.DP });
            list.Add(new() { Name = "dQ (Exponent2)", Meaning = "d mod (q-1) – dùng cho CRT", Value = p.DQ });
            list.Add(new() { Name = "qInv (Coefficient)", Meaning = "q^-1 mod p – dùng cho CRT", Value = p.InverseQ });
        }
        return list;
    }

    public static string DescribeKey(RSA rsa)
    {
        var sb = new StringBuilder();
        bool isPrivate = HasPrivateKey(rsa);
        sb.AppendLine($"Loại khoá : {(isPrivate ? "KHOÁ BÍ MẬT (private key)" : "KHOÁ CÔNG KHAI (public key)")}");
        sb.AppendLine($"Độ dài    : {rsa.KeySize} bit  =>  dữ liệu tối đa OAEP-SHA256 = {MaxOaepSha256DataLength(rsa)} byte");
        sb.AppendLine();
        foreach (var c in GetComponents(rsa))
        {
            sb.AppendLine($"== {c.Name}  [{c.Value.Length} byte, {c.BitLength} bit]");
            sb.AppendLine($"   {c.Meaning}");
            if (c.Value.Length <= 8) sb.AppendLine($"   Thập phân: {c.Decimal}");
            sb.AppendLine($"   Hex: {Wrap(c.Hex, 64, "        ")}");
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static string Wrap(string s, int width, string indent)
    {
        if (s.Length <= width) return s;
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length; i += width)
        {
            if (i > 0) sb.AppendLine().Append(indent);
            sb.Append(s, i, Math.Min(width, s.Length - i));
        }
        return sb.ToString();
    }

    // ------------------------------------------------------------------ 5, 6. Mã hoá / giải mã
    public static int MaxOaepSha256DataLength(RSA rsa) => rsa.KeySize / 8 - OaepSha256Overhead;

    /// <summary>Mã hoá bằng khoá công khai (n, e) với padding OAEP-SHA256.</summary>
    public static byte[] Encrypt(RSA rsa, byte[] data)
    {
        int max = MaxOaepSha256DataLength(rsa);
        if (data.Length > max)
            throw new ArgumentException($"Dữ liệu dài {data.Length} byte, vượt quá giới hạn {max} byte của RSA-{rsa.KeySize} OAEP-SHA256.");
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>Giải mã bằng khoá bí mật (d hoặc p, q, dP, dQ, qInv).</summary>
    public static byte[] Decrypt(RSA rsa, byte[] cipher) => rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

    // ------------------------------------------------------------------ 7. Đánh giá tốc độ
    public sealed class BenchRow
    {
        public int KeyBits { get; init; }
        public string Operation { get; init; }
        public string KeyUsed { get; init; }
        public int ExponentBits { get; init; }
        public int Iterations { get; init; }
        public double TotalMs { get; init; }
        public double AvgMs => TotalMs / Iterations;
        public double OpsPerSecond => Iterations / (TotalMs / 1000.0);
    }

    /// <summary>
    /// Đo tốc độ các phép toán RSA với từng kích thước khoá.
    ///  - Mã hoá OAEP / Xác minh chữ ký: dùng khoá công khai (e = 65537, chỉ 17 bit).
    ///  - Giải mã OAEP / Ký: dùng khoá bí mật (d ~ kích thước n), thư viện dùng CRT để tăng tốc.
    ///  - ModPow "thô" (BigInteger): so sánh trực tiếp m^e mod n với c^d mod n, và c^d có/không dùng CRT.
    /// </summary>
    public static List<BenchRow> Benchmark(int[] keySizes, int iterations, IProgress<string> log = null, CancellationToken ct = default)
    {
        var rows = new List<BenchRow>();
        byte[] data = RandomNumberGenerator.GetBytes(32); // ví dụ: 1 khoá AES-256
        byte[] hash = SHA256.HashData(data);

        foreach (int bits in keySizes)
        {
            log?.Report($"Sinh khoá RSA-{bits}...");
            using RSA rsa = RSA.Create(bits);
            RSAParameters p = rsa.ExportParameters(true);
            var n = ToBig(p.Modulus); var e = ToBig(p.Exponent); var d = ToBig(p.D);
            var P = ToBig(p.P); var Q = ToBig(p.Q); var dp = ToBig(p.DP); var dq = ToBig(p.DQ); var qInv = ToBig(p.InverseQ);
            int eBits = (int)e.GetBitLength(), dBits = (int)d.GetBitLength();

            byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            byte[] sig = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            BigInteger m = ToBig(RandomNumberGenerator.GetBytes(bits / 8 - 1));
            BigInteger c = BigInteger.ModPow(m, e, n);

            // ModPow thô với d (không CRT) rất chậm ở khoá lớn → giảm số lần lặp cho 2 phép này.
            int heavyIterations = Math.Max(5, iterations / Math.Max(1, bits / 512));

            void Run(string op, string keyUsed, int expBits, Action action, int count = 0)
            {
                ct.ThrowIfCancellationRequested();
                if (count <= 0) count = iterations;
                action(); // warm-up
                var sw = Stopwatch.StartNew();
                for (int i = 0; i < count; i++) action();
                sw.Stop();
                var row = new BenchRow
                {
                    KeyBits = bits, Operation = op, KeyUsed = keyUsed, ExponentBits = expBits,
                    Iterations = count, TotalMs = sw.Elapsed.TotalMilliseconds
                };
                rows.Add(row);
                log?.Report($"RSA-{bits} | {op,-34} | {row.AvgMs,10:F4} ms/lần | {row.OpsPerSecond,10:F0} lần/s");
            }

            Run("Mã hoá OAEP-SHA256", "Public (n,e)", eBits, () => rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256));
            Run("Giải mã OAEP-SHA256", "Private (CRT)", dBits, () => rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256));
            Run("Xác minh chữ ký PKCS#1", "Public (n,e)", eBits, () => rsa.VerifyHash(hash, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Run("Ký PKCS#1 v1.5", "Private (CRT)", dBits, () => rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            Run("ModPow thô: m^e mod n", "Public (n,e)", eBits, () => BigInteger.ModPow(m, e, n));
            Run("ModPow thô: c^d mod n (không CRT)", "Private (n,d)", dBits, () => BigInteger.ModPow(c, d, n), heavyIterations);
            Run("ModPow thô: c^d mod n (có CRT)", "Private (p,q,dP,dQ,qInv)", dBits, () => CrtDecrypt(c, P, Q, dp, dq, qInv), heavyIterations);
        }
        return rows;
    }

    /// <summary>Giải mã RSA bằng Định lý số dư Trung Hoa (CRT): nhanh hơn ~3-4 lần so với c^d mod n.</summary>
    public static BigInteger CrtDecrypt(BigInteger c, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qInv)
    {
        BigInteger m1 = BigInteger.ModPow(c % p, dp, p);
        BigInteger m2 = BigInteger.ModPow(c % q, dq, q);
        BigInteger h = (qInv * (m1 - m2)) % p;
        if (h.Sign < 0) h += p;
        return m2 + h * q;
    }

    public static BigInteger ToBig(byte[] bigEndianUnsigned) => new BigInteger(bigEndianUnsigned, isUnsigned: true, isBigEndian: true);

    /// <summary>Đổi BigInteger thành mảng byte big-endian dài đúng 'length' byte (thêm 0 ở đầu nếu thiếu).</summary>
    public static byte[] ToFixedBytes(BigInteger value, int length)
    {
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == length) return raw;
        if (raw.Length > length) throw new ArgumentException("Giá trị lớn hơn độ dài cho phép.");
        byte[] result = new byte[length];
        Buffer.BlockCopy(raw, 0, result, length - raw.Length, raw.Length);
        return result;
    }
}
