using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace CryptoCore;

/// <summary>Kết quả của một thao tác mã hoá / giải mã file.</summary>
public sealed class FileOpResult
{
    public long InputBytes { get; init; }
    public long OutputBytes { get; init; }
    public TimeSpan Elapsed { get; init; }

    /// <summary>Tốc độ xử lý tính theo MB/s (1 MB = 1024*1024 byte) dựa trên kích thước file nguồn.</summary>
    public double MBps => Elapsed.TotalSeconds <= 0 ? 0 : InputBytes / 1048576.0 / Elapsed.TotalSeconds;

    public override string ToString() =>
        $"{ByteFormat.Bytes(InputBytes)} -> {ByteFormat.Bytes(OutputBytes)} | {Elapsed.TotalSeconds:F3} s | {MBps:F1} MB/s";
}

/// <summary>Kết quả so sánh 2 file theo từng byte.</summary>
public sealed class CompareResult
{
    public bool Equal { get; init; }
    public long LengthA { get; init; }
    public long LengthB { get; init; }
    /// <summary>-1 nếu giống nhau hoàn toàn, ngược lại là vị trí byte đầu tiên khác nhau.</summary>
    public long FirstDifferenceOffset { get; init; }
    public TimeSpan Elapsed { get; init; }

    public override string ToString()
    {
        if (Equal)
            return $"GIỐNG NHAU 100% ({LengthA:N0} byte đã so sánh) - {Elapsed.TotalSeconds:F3} s";
        if (LengthA != LengthB && FirstDifferenceOffset == Math.Min(LengthA, LengthB))
            return $"KHÁC NHAU: kích thước khác ({LengthA:N0} vs {LengthB:N0} byte)";
        return $"KHÁC NHAU tại byte thứ {FirstDifferenceOffset:N0} (kích thước {LengthA:N0} vs {LengthB:N0})";
    }
}

/// <summary>
/// Mã hoá đối xứng AES (cùng một khoá cho mã hoá và giải mã).
/// Chế độ: AES-CBC + PKCS7 padding, IV ngẫu nhiên 16 byte cho mỗi lần mã hoá.
///
/// Định dạng file mã hoá:  [4 byte "AES1"] [16 byte IV] [ciphertext ...]
/// Định dạng văn bản mã hoá: Base64( IV(16 byte) || ciphertext )
///
/// File được xử lý dạng luồng (stream) với bộ đệm 4 MB nên mã hoá được file nhiều GB
/// mà không cần nạp cả file vào RAM.
/// </summary>
public static class AesService
{
    public const int IvSize = 16;
    public const int DefaultBufferSize = 4 * 1024 * 1024; // 4 MB
    private static readonly byte[] FileMagic = "AES1"u8.ToArray();

    // ------------------------------------------------------------------ 1. Sinh khoá
    /// <summary>Sinh khoá AES ngẫu nhiên bằng bộ sinh số ngẫu nhiên an toàn mật mã (CSPRNG).</summary>
    public static byte[] GenerateKey(int keySizeBits = 256)
    {
        if (keySizeBits is not (128 or 192 or 256))
            throw new ArgumentException("Kích thước khoá AES phải là 128, 192 hoặc 256 bit.");
        return RandomNumberGenerator.GetBytes(keySizeBits / 8);
    }

    // ------------------------------------------------------------------ 2. Lưu khoá ra file
    /// <summary>Lưu khoá ra file văn bản dạng Base64 (1 dòng).</summary>
    public static void SaveKey(string path, byte[] key)
    {
        ValidateKey(key);
        File.WriteAllText(path, Convert.ToBase64String(key), Encoding.ASCII);
    }

    // ------------------------------------------------------------------ 3. Import khoá từ file
    /// <summary>
    /// Đọc khoá từ file. Hỗ trợ file Base64 (do SaveKey tạo ra), file Hex,
    /// hoặc file nhị phân thô dài đúng 16/24/32 byte.
    /// </summary>
    public static byte[] LoadKey(string path)
    {
        byte[] raw = File.ReadAllBytes(path);
        string text = Encoding.ASCII.GetString(raw).Trim();

        byte[] key = null;
        try { key = Convert.FromBase64String(text); } catch (FormatException) { }

        if (key is null || !IsValidKeyLength(key.Length))
        {
            try { key = Convert.FromHexString(text); } catch (FormatException) { key = null; }
        }
        if (key is null || !IsValidKeyLength(key.Length))
        {
            key = IsValidKeyLength(raw.Length) ? raw : null;
        }
        if (key is null)
            throw new CryptographicException("File không chứa khoá AES hợp lệ (cần 16/24/32 byte, dạng Base64, Hex hoặc nhị phân).");
        return key;
    }

    public static bool IsValidKeyLength(int bytes) => bytes is 16 or 24 or 32;

    private static void ValidateKey(byte[] key)
    {
        if (key is null || !IsValidKeyLength(key.Length))
            throw new ArgumentException("Khoá AES phải dài 16, 24 hoặc 32 byte.");
    }

    private static Aes CreateAes(byte[] key)
    {
        ValidateKey(key);
        var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        return aes;
    }

    // ------------------------------------------------------------------ 4. Mã hoá đoạn văn bản
    /// <summary>Mã hoá chuỗi UTF-8, trả về Base64(IV || ciphertext).</summary>
    public static string EncryptText(string plainText, byte[] key)
    {
        using Aes aes = CreateAes(key);
        byte[] iv = RandomNumberGenerator.GetBytes(IvSize);
        byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plainText ?? ""), iv, PaddingMode.PKCS7);

        byte[] packed = new byte[IvSize + cipher.Length];
        Buffer.BlockCopy(iv, 0, packed, 0, IvSize);
        Buffer.BlockCopy(cipher, 0, packed, IvSize, cipher.Length);
        return Convert.ToBase64String(packed);
    }

    /// <summary>Giải mã chuỗi Base64(IV || ciphertext) về văn bản UTF-8.</summary>
    public static string DecryptText(string base64, byte[] key)
    {
        byte[] packed = Convert.FromBase64String(base64.Trim());
        if (packed.Length < IvSize + 16 || (packed.Length - IvSize) % 16 != 0)
            throw new CryptographicException("Dữ liệu mã hoá không hợp lệ.");

        using Aes aes = CreateAes(key);
        byte[] plain = aes.DecryptCbc(packed.AsSpan(IvSize), packed.AsSpan(0, IvSize), PaddingMode.PKCS7);
        return Encoding.UTF8.GetString(plain);
    }

    // ------------------------------------------------------------------ 5. Mã hoá file -> file
    /// <summary>Mã hoá file nguồn và lưu vào file đích. Đo thời gian bằng Stopwatch.</summary>
    public static FileOpResult EncryptFile(string sourcePath, string destPath, byte[] key,
        IProgress<double> progress = null, CancellationToken ct = default, int bufferSize = DefaultBufferSize)
    {
        var sw = Stopwatch.StartNew();
        using Aes aes = CreateAes(key);
        byte[] iv = RandomNumberGenerator.GetBytes(IvSize);
        aes.IV = iv;

        long inLen;
        using (var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, FileOptions.SequentialScan))
        using (var output = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize))
        {
            inLen = input.Length;
            output.Write(FileMagic);
            output.Write(iv);

            using ICryptoTransform enc = aes.CreateEncryptor();
            using var crypto = new CryptoStream(output, enc, CryptoStreamMode.Write, leaveOpen: true);
            Pump(input, crypto, inLen, () => input.Position, progress, ct, bufferSize);
            crypto.FlushFinalBlock();
        }
        sw.Stop();
        progress?.Report(1.0);
        return new FileOpResult { InputBytes = inLen, OutputBytes = new FileInfo(destPath).Length, Elapsed = sw.Elapsed };
    }

    /// <summary>Giải mã file đã mã hoá bằng EncryptFile.</summary>
    public static FileOpResult DecryptFile(string encryptedPath, string destPath, byte[] key,
        IProgress<double> progress = null, CancellationToken ct = default, int bufferSize = DefaultBufferSize)
    {
        var sw = Stopwatch.StartNew();
        using Aes aes = CreateAes(key);

        long inLen;
        using (var input = new FileStream(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, FileOptions.SequentialScan))
        using (var output = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize))
        {
            inLen = input.Length;
            byte[] header = new byte[FileMagic.Length + IvSize];
            if (input.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) != header.Length
                || !header.AsSpan(0, FileMagic.Length).SequenceEqual(FileMagic))
                throw new CryptographicException("File không đúng định dạng mã hoá của chương trình (thiếu header AES1).");

            aes.IV = header.AsSpan(FileMagic.Length, IvSize).ToArray();
            using ICryptoTransform dec = aes.CreateDecryptor();
            using var crypto = new CryptoStream(input, dec, CryptoStreamMode.Read, leaveOpen: true);
            Pump(crypto, output, inLen, () => input.Position, progress, ct, bufferSize);
        }
        sw.Stop();
        progress?.Report(1.0);
        return new FileOpResult { InputBytes = inLen, OutputBytes = new FileInfo(destPath).Length, Elapsed = sw.Elapsed };
    }

    private static void Pump(Stream from, Stream to, long total, Func<long> position,
        IProgress<double> progress, CancellationToken ct, int bufferSize)
    {
        byte[] buffer = new byte[bufferSize];
        int lastPercent = -1;
        int n;
        while ((n = from.Read(buffer, 0, buffer.Length)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            to.Write(buffer, 0, n);
            if (progress != null && total > 0)
            {
                int percent = (int)(position() * 100 / total);
                if (percent != lastPercent) { lastPercent = percent; progress.Report(percent / 100.0); }
            }
        }
    }

    // ------------------------------------------------------------------ So sánh theo byte
    /// <summary>So sánh 2 file theo từng byte (đọc theo khối 4 MB).</summary>
    public static CompareResult CompareFiles(string pathA, string pathB,
        IProgress<double> progress = null, CancellationToken ct = default, int bufferSize = DefaultBufferSize)
    {
        var sw = Stopwatch.StartNew();
        using var a = new FileStream(pathA, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, FileOptions.SequentialScan);
        using var b = new FileStream(pathB, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, FileOptions.SequentialScan);
        long lenA = a.Length, lenB = b.Length;
        long common = Math.Min(lenA, lenB);

        byte[] bufA = new byte[bufferSize];
        byte[] bufB = new byte[bufferSize];
        long offset = 0;
        int lastPercent = -1;
        while (offset < common)
        {
            ct.ThrowIfCancellationRequested();
            int want = (int)Math.Min(bufferSize, common - offset);
            a.ReadExactly(bufA, 0, want);
            b.ReadExactly(bufB, 0, want);

            var sa = bufA.AsSpan(0, want);
            var sb = bufB.AsSpan(0, want);
            if (!sa.SequenceEqual(sb))
            {
                int idx = sa.CommonPrefixLength(sb);
                sw.Stop();
                return new CompareResult { Equal = false, LengthA = lenA, LengthB = lenB, FirstDifferenceOffset = offset + idx, Elapsed = sw.Elapsed };
            }
            offset += want;
            if (progress != null && common > 0)
            {
                int percent = (int)(offset * 100 / common);
                if (percent != lastPercent) { lastPercent = percent; progress.Report(percent / 100.0); }
            }
        }
        sw.Stop();
        bool equal = lenA == lenB;
        return new CompareResult { Equal = equal, LengthA = lenA, LengthB = lenB, FirstDifferenceOffset = equal ? -1 : common, Elapsed = sw.Elapsed };
    }

    // ------------------------------------------------------------------ Tạo file thử nghiệm
    /// <summary>Tạo file dữ liệu ngẫu nhiên có kích thước cho trước (phục vụ thử nghiệm file hàng GB).</summary>
    public static TimeSpan CreateRandomFile(string path, long sizeBytes,
        IProgress<double> progress = null, CancellationToken ct = default, int bufferSize = DefaultBufferSize)
    {
        var sw = Stopwatch.StartNew();
        var rnd = new Random();
        byte[] buffer = new byte[bufferSize];
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize);
        long written = 0;
        int lastPercent = -1;
        while (written < sizeBytes)
        {
            ct.ThrowIfCancellationRequested();
            int n = (int)Math.Min(bufferSize, sizeBytes - written);
            rnd.NextBytes(buffer.AsSpan(0, n));
            fs.Write(buffer, 0, n);
            written += n;
            int percent = (int)(written * 100 / Math.Max(1, sizeBytes));
            if (progress != null && percent != lastPercent) { lastPercent = percent; progress.Report(percent / 100.0); }
        }
        sw.Stop();
        return sw.Elapsed;
    }

    /// <summary>Tính SHA-256 của file (dùng làm bằng chứng phụ cho việc so sánh).</summary>
    public static string Sha256OfFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, DefaultBufferSize, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(fs));
    }
}

public static class ByteFormat
{
    public static string Bytes(long n)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = n;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{n} B" : $"{v:F2} {units[u]}";
    }
}
