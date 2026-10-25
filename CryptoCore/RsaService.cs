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
