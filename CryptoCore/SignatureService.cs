using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoCore;

public enum SignScheme
{
    /// <summary>RSASSA-PKCS1-v1_5: TẤT ĐỊNH – cùng dữ liệu + cùng khoá => luôn ra cùng chữ ký.</summary>
    Pkcs1v15,
    /// <summary>RSASSA-PSS: XÁC SUẤT – mỗi lần ký sinh "salt" ngẫu nhiên => chữ ký khác nhau. (ĐỀ XUẤT)</summary>
    Pss,
    /// <summary>Tự thiết kế: ký SHA256(nonce ngẫu nhiên || thời điểm ký || dữ liệu); nonce + thời điểm gửi kèm chữ ký.</summary>
    NonceTimestamp
}

/// <summary>Kết quả ký: chữ ký và (nếu có) các tham số ngẫu nhiên cần gửi kèm để xác minh.</summary>
public sealed class SignatureResult
{
    public SignScheme Scheme { get; init; }
    public byte[] Signature { get; init; }
    public byte[] Nonce { get; init; }          // chỉ dùng với NonceTimestamp
    public long TimestampUnixMs { get; init; }  // chỉ dùng với NonceTimestamp

    /// <summary>Dạng chuỗi để lưu/gửi đi. NonceTimestamp: "nonceBase64.timestamp.signatureBase64".</summary>
    public string ToPortableString() => Scheme == SignScheme.NonceTimestamp
        ? $"{Convert.ToBase64String(Nonce)}.{TimestampUnixMs}.{Convert.ToBase64String(Signature)}"
        : Convert.ToBase64String(Signature);

    public static SignatureResult FromPortableString(string s, SignScheme scheme)
    {
        s = s.Trim();
        if (scheme != SignScheme.NonceTimestamp)
            return new SignatureResult { Scheme = scheme, Signature = Convert.FromBase64String(s) };
        string[] parts = s.Split('.');
        if (parts.Length != 3) throw new FormatException("Chữ ký dạng nonce phải có 3 phần: nonce.timestamp.signature");
        return new SignatureResult
        {
            Scheme = scheme,
            Nonce = Convert.FromBase64String(parts[0]),
            TimestampUnixMs = long.Parse(parts[1]),
            Signature = Convert.FromBase64String(parts[2])
        };
    }
}

/// <summary>
/// CHỮ KÝ SỐ = dùng khoá BÍ MẬT RSA "mã hoá" giá trị băm của dữ liệu.
/// Người nhận dùng khoá CÔNG KHAI để kiểm tra.
/// </summary>
public static class SignatureService
{
    public const int NonceSize = 16;

    public static SignatureResult Sign(RSA rsa, byte[] data, SignScheme scheme)
    {
        switch (scheme)
        {
            case SignScheme.Pkcs1v15:
                return new SignatureResult { Scheme = scheme, Signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) };

            case SignScheme.Pss:
                // .NET dùng salt dài bằng độ dài hash (32 byte) sinh ngẫu nhiên cho MỖI lần ký.
                return new SignatureResult { Scheme = scheme, Signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) };

            case SignScheme.NonceTimestamp:
            {
                byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
                long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                byte[] hash = NonceHash(nonce, ts, data);
                byte[] sig = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return new SignatureResult { Scheme = scheme, Signature = sig, Nonce = nonce, TimestampUnixMs = ts };
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(scheme));
        }
    }

    public static bool Verify(RSA rsa, byte[] data, SignatureResult sig)
    {
        switch (sig.Scheme)
        {
            case SignScheme.Pkcs1v15:
                return rsa.VerifyData(data, sig.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            case SignScheme.Pss:
                return rsa.VerifyData(data, sig.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            case SignScheme.NonceTimestamp:
                byte[] hash = NonceHash(sig.Nonce, sig.TimestampUnixMs, data);
                return rsa.VerifyHash(hash, sig.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            default:
                return false;
        }
    }

    /// <summary>SHA256( nonce || timestamp (8 byte big-endian) || data ).</summary>
    public static byte[] NonceHash(byte[] nonce, long timestampUnixMs, byte[] data)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData(nonce);
        Span<byte> ts = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(ts, timestampUnixMs);
        h.AppendData(ts);
        h.AppendData(data);
        return h.GetHashAndReset();
    }

    // ------------------------------------------------------------------ Minh hoạ "thủ công"
    /// <summary>Tiền tố DigestInfo (ASN.1) của SHA-256 theo PKCS#1 v1.5 (RFC 8017, mục 9.2).</summary>
    public static readonly byte[] Sha256DigestInfoPrefix = Convert.FromHexString("3031300d060960864801650304020105000420");

    /// <summary>
    /// Ký "bằng tay" để minh hoạ bản chất: s = EM^d mod n,
    /// với EM = 00 01 FF..FF 00 || DigestInfo(SHA-256) || H(data).
    /// Kết quả phải TRÙNG KHỚP với rsa.SignData(..., Pkcs1).
    /// </summary>
    public static byte[] ManualSignPkcs1(RSAParameters priv, byte[] data, out byte[] encodedMessage)
    {
        int k = priv.Modulus.Length;
        encodedMessage = EncodePkcs1(SHA256.HashData(data), k);
        BigInteger m = RsaService.ToBig(encodedMessage);
        BigInteger s = BigInteger.ModPow(m, RsaService.ToBig(priv.D), RsaService.ToBig(priv.Modulus));
        return RsaService.ToFixedBytes(s, k);
    }

    /// <summary>Xác minh "bằng tay": EM' = s^e mod n, so sánh với EM tính lại từ dữ liệu.</summary>
    public static bool ManualVerifyPkcs1(RSAParameters pub, byte[] data, byte[] signature, out byte[] recovered)
    {
        int k = pub.Modulus.Length;
        BigInteger s = RsaService.ToBig(signature);
        BigInteger m = BigInteger.ModPow(s, RsaService.ToBig(pub.Exponent), RsaService.ToBig(pub.Modulus));
        recovered = RsaService.ToFixedBytes(m, k);
        return recovered.AsSpan().SequenceEqual(EncodePkcs1(SHA256.HashData(data), k));
    }

    private static byte[] EncodePkcs1(byte[] hash, int k)
    {
        int tLen = Sha256DigestInfoPrefix.Length + hash.Length;
        if (k < tLen + 11) throw new ArgumentException("Khoá quá ngắn.");
        byte[] em = new byte[k];
        em[0] = 0x00;
        em[1] = 0x01;
        for (int i = 2; i < k - tLen - 1; i++) em[i] = 0xFF;
        em[k - tLen - 1] = 0x00;
        Buffer.BlockCopy(Sha256DigestInfoPrefix, 0, em, k - tLen, Sha256DigestInfoPrefix.Length);
        Buffer.BlockCopy(hash, 0, em, k - hash.Length, hash.Length);
        return em;
    }
}
