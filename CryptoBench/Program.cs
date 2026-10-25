using System.Text;
using CryptoCore;

// Ứng dụng CONSOLE chạy thử nghiệm tự động và in bảng số liệu (Markdown) để đưa vào báo cáo.
//   dotnet run -c Release --project CryptoBench -- aes 100 1024 2048 4096 --dir D:\test
//   dotnet run -c Release --project CryptoBench -- rsa 200
//   dotnet run -c Release --project CryptoBench -- sign
//   dotnet run -c Release --project CryptoBench -- all
Console.OutputEncoding = Encoding.UTF8;

string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "all";
string dir = GetOption("--dir") ?? Path.Combine(Path.GetTempPath(), "aes_bench");
bool keep = args.Contains("--keep");

switch (mode)
{
    case "aes":
        RunAes(ParseNumbers(args.Skip(1)).DefaultIfEmpty(100).ToArray());
        break;
    case "rsa":
        RunRsa((int)ParseNumbers(args.Skip(1)).DefaultIfEmpty(200).First());
        break;
    case "sign":
        RunSign();
        break;
    default:
        RunAes(new long[] { 100, 1024 });
        RunRsa(200);
        RunSign();
        break;
}

string GetOption(string name)
{
    int i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static IEnumerable<long> ParseNumbers(IEnumerable<string> items)
{
    foreach (var s in items)
    {
        if (s.StartsWith("--")) yield break;
        if (long.TryParse(s, out long v)) yield return v;
    }
}

void RunAes(long[] sizesMb)
{
    Directory.CreateDirectory(dir);
    byte[] key = AesService.GenerateKey(256);
    Console.WriteLine($"## AES-256-CBC – thư mục thử nghiệm: {dir}");
    Console.WriteLine();
    Console.WriteLine("| Kích thước | Mã hoá (s) | MB/s | Giải mã (s) | MB/s | So sánh byte | T. so sánh (s) | Δ kích thước |");
    Console.WriteLine("|---:|---:|---:|---:|---:|:---:|---:|---:|");
    foreach (long mb in sizesMb)
    {
        string src = Path.Combine(dir, $"test_{mb}MB.bin");
        string enc = src + ".aes";
        string dec = Path.Combine(dir, $"decrypted_test_{mb}MB.bin");
        if (!File.Exists(src) || new FileInfo(src).Length != mb * 1024 * 1024)
        {
            Console.Error.WriteLine($"  tạo file {mb} MB...");
            AesService.CreateRandomFile(src, mb * 1024 * 1024);
        }
        var r1 = AesService.EncryptFile(src, enc, key);
        var r2 = AesService.DecryptFile(enc, dec, key);
        var r3 = AesService.CompareFiles(src, dec);
        Console.WriteLine($"| {ByteFormat.Bytes(r1.InputBytes)} | {r1.Elapsed.TotalSeconds:F3} | {r1.MBps:F1} | {r2.Elapsed.TotalSeconds:F3} | {r2.MBps:F1} | " +
                          $"{(r3.Equal ? "GIỐNG 100%" : "KHÁC @" + r3.FirstDifferenceOffset)} | {r3.Elapsed.TotalSeconds:F3} | +{r1.OutputBytes - r1.InputBytes} B |");
        if (!keep) { File.Delete(enc); File.Delete(dec); }
    }
    Console.WriteLine();
}

void RunRsa(int iterations)
{
    Console.WriteLine($"## RSA – {iterations} lần lặp mỗi phép");
    Console.WriteLine();
    var rows = RsaService.Benchmark(new[] { 1024, 2048, 3072, 4096 }, iterations, new Progress<string>(s => Console.Error.WriteLine("  " + s)));
    Thread.Sleep(200); // chờ Progress in hết log
    Console.WriteLine("| Khoá | Phép toán | Khoá dùng | Số mũ (bit) | ms/lần | lần/giây |");
    Console.WriteLine("|---|---|---|---:|---:|---:|");
    foreach (var r in rows)
        Console.WriteLine($"| RSA-{r.KeyBits} | {r.Operation} | {r.KeyUsed} | {r.ExponentBits} | {r.AvgMs:F4} | {r.OpsPerSecond:N0} |");
    Console.WriteLine();
}

void RunSign()
{
    Console.WriteLine("## Chữ ký số – ký 5 lần cùng dữ liệu, cùng khoá");
    Console.WriteLine();
    using var rsa = RsaService.GenerateKeyPair(2048);
    byte[] data = Encoding.UTF8.GetBytes("Cung mot du lieu, cung mot nguoi ky");
    foreach (SignScheme scheme in Enum.GetValues<SignScheme>())
    {
        var sigs = Enumerable.Range(0, 5).Select(_ => SignatureService.Sign(rsa, data, scheme)).ToList();
        int distinct = sigs.Select(s => Convert.ToBase64String(s.Signature)).Distinct().Count();
        bool allOk = sigs.All(s => SignatureService.Verify(rsa, data, s));
        Console.WriteLine($"- {scheme}: {distinct}/5 chữ ký khác nhau, tất cả xác minh đúng: {allOk}");
    }
    byte[] manual = SignatureService.ManualSignPkcs1(rsa.ExportParameters(true), data, out _);
    byte[] lib = rsa.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
    Console.WriteLine($"- Ký thủ công EM^d mod n trùng với .NET PKCS#1: {manual.AsSpan().SequenceEqual(lib)}");
    Console.WriteLine();
    Console.WriteLine("## SHA-256 – hiệu ứng thác lũ");
    Console.WriteLine();
    Console.WriteLine(HashService.AvalancheTest(10000, 64).ToString());
}
