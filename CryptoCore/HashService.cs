using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace CryptoCore;

/// <summary>Băm SHA-256 (256 bit = 32 byte) và đo "hiệu ứng thác lũ" (avalanche effect).</summary>
public static class HashService
{
    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);
    public static byte[] Sha256(string text) => SHA256.HashData(Encoding.UTF8.GetBytes(text ?? ""));

    /// <summary>Số bit khác nhau giữa 2 mảng cùng độ dài (khoảng cách Hamming).</summary>
    public static int BitDifference(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("Hai mảng phải cùng độ dài.");
        int count = 0;
        for (int i = 0; i < a.Length; i++) count += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return count;
    }

    /// <summary>Số ký tự hex khác nhau (tối đa 64 với SHA-256).</summary>
    public static int HexCharDifference(string hexA, string hexB)
    {
        int n = Math.Min(hexA.Length, hexB.Length), diff = Math.Abs(hexA.Length - hexB.Length);
        for (int i = 0; i < n; i++) if (hexA[i] != hexB[i]) diff++;
        return diff;
    }

    /// <summary>Chuỗi đánh dấu '^' dưới các ký tự hex bị thay đổi.</summary>
    public static string DiffMarker(string hexA, string hexB)
    {
        var sb = new StringBuilder();
        int n = Math.Min(hexA.Length, hexB.Length);
        for (int i = 0; i < n; i++) sb.Append(hexA[i] == hexB[i] ? ' ' : '^');
        return sb.ToString();
    }

    /// <summary>Chuỗi nhị phân 256 bit, mỗi byte cách nhau một khoảng trắng.</summary>
    public static string ToBinary(byte[] data)
    {
        var sb = new StringBuilder();
        foreach (byte b in data) sb.Append(Convert.ToString(b, 2).PadLeft(8, '0')).Append(' ');
        return sb.ToString().TrimEnd();
    }

    public sealed class AvalancheResult
    {
        public int Trials { get; init; }
        public int MessageLength { get; init; }
        public double AverageBits { get; init; }
        public int MinBits { get; init; }
        public int MaxBits { get; init; }
        public double StdDev { get; init; }
        public double AveragePercent => AverageBits / 256.0 * 100.0;

        public override string ToString() =>
            $"{Trials:N0} lần thử, thông điệp {MessageLength} byte, mỗi lần chỉ đảo 1 bit đầu vào:\r\n" +
            $"  Số bit thay đổi ở đầu ra: trung bình {AverageBits:F2}/256 ({AveragePercent:F2}%), " +
            $"nhỏ nhất {MinBits}, lớn nhất {MaxBits}, độ lệch chuẩn {StdDev:F2}\r\n" +
            $"  Lý thuyết (hàm băm lý tưởng): trung bình 128 bit (50%), độ lệch chuẩn 8.";
    }

    /// <summary>Thử nghiệm: đảo đúng 1 bit ngẫu nhiên của thông điệp ngẫu nhiên, đếm số bit thay đổi của SHA-256.</summary>
    public static AvalancheResult AvalancheTest(int trials = 10000, int messageLength = 64)
    {
        var rnd = new Random();
        byte[] msg = new byte[messageLength];
        long sum = 0, sumSq = 0;
        int min = int.MaxValue, max = 0;
        for (int t = 0; t < trials; t++)
        {
            rnd.NextBytes(msg);
            byte[] h1 = SHA256.HashData(msg);
            int bit = rnd.Next(messageLength * 8);
            msg[bit / 8] ^= (byte)(1 << (bit % 8));
            byte[] h2 = SHA256.HashData(msg);
            int d = BitDifference(h1, h2);
            sum += d; sumSq += (long)d * d;
            if (d < min) min = d;
            if (d > max) max = d;
        }
        double avg = (double)sum / trials;
        double variance = (double)sumSq / trials - avg * avg;
        return new AvalancheResult
        {
            Trials = trials, MessageLength = messageLength, AverageBits = avg,
            MinBits = min, MaxBits = max, StdDev = Math.Sqrt(Math.Max(0, variance))
        };
    }
}
