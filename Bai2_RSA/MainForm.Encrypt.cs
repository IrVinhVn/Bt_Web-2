using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using CryptoCore;

namespace Bai2_RSA;

// TAB 5-6: MÃ HOÁ (public key) / GIẢI MÃ (private key) – OAEP-SHA256, dữ liệu ≤ 190 byte với RSA-2048
public sealed partial class MainForm
{
    private readonly RadioButton rdoDataText = new() { Text = "Văn bản (UTF-8)", AutoSize = true };
    private readonly RadioButton rdoDataB64 = new() { Text = "Mảng byte (nhập dạng Base64)", AutoSize = true, Checked = true };
    private readonly TextBox txtData = MonoBox(readOnly: false, wrap: true);
    private readonly Label lblDataLen = new() { AutoSize = true, Margin = new Padding(3, 8, 3, 3) };
    private readonly TextBox txtCipherB64 = MonoBox(readOnly: false, wrap: true);
    private readonly TextBox txtEncLog = MonoBox(wrap: true);
    private byte[] _lastDecrypted;

    private TabPage BuildEncryptTab()
    {
        txtData.TextChanged += (_, _) => UpdateDataLength();
        rdoDataText.CheckedChanged += (_, _) => UpdateDataLength();

        var srcBar = Flow(Lbl("Kiểu dữ liệu:"), rdoDataB64, rdoDataText,
            Btn("Sinh khoá AES-256 (32 byte) làm dữ liệu", OnRandomAesKeyAsData),
            Btn("Nạp dữ liệu từ file...", OnLoadDataFile),
            Btn("Lưu dữ liệu gốc (.bin)...", OnSaveOriginal),
            lblDataLen);

        var encBar = Flow(Btn("5. MÃ HOÁ bằng public key  ▼", OnEncrypt),
            Btn("Lưu bản mã ra file (.b64)...", OnSaveCipher),
            Lbl("(OAEP có yếu tố ngẫu nhiên: mã hoá cùng dữ liệu nhiều lần cho bản mã khác nhau)"));

        var decBar = Flow(Btn("6. GIẢI MÃ: chọn private .pem + file bản mã...", OnDecryptFromFiles),
            Btn("Giải mã bản mã đang hiển thị (khoá bí mật hiện tại)", OnDecryptCurrent),
            Btn("So sánh kết quả giải mã với file gốc (.bin)...", OnCompareWithFile));

        var page = new TabPage("5-6. Mã hoá / Giải mã");
        page.Controls.Add(Rows(
            (srcBar, 0),
            (Group("Dữ liệu nguồn", txtData), 22),
            (encBar, 0),
            (Group("Bản mã (Base64) – có thể dán vào để giải mã", txtCipherB64), 22),
            (decBar, 0),
            (Group("Kết quả", txtEncLog), 56)));
        return page;
    }

    private byte[] GetSourceBytes()
    {
        if (rdoDataText.Checked) return Encoding.UTF8.GetBytes(txtData.Text);
        return Convert.FromBase64String(txtData.Text.Trim());
    }

    private void UpdateDataLength()
    {
        RSA key = PublicKey;
        int max = key == null ? 190 : RsaService.MaxOaepSha256DataLength(key);
        try
        {
            int len = GetSourceBytes().Length;
            lblDataLen.Text = $"{len} / {max} byte";
            lblDataLen.ForeColor = len <= max ? Color.DarkGreen : Color.Red;
        }
        catch (FormatException)
        {
            lblDataLen.Text = "Base64 không hợp lệ";
            lblDataLen.ForeColor = Color.Red;
        }
    }

    private void OnRandomAesKeyAsData(object sender, EventArgs e)
    {
        rdoDataB64.Checked = true;
        txtData.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        EncLog("Đã sinh khoá AES-256 ngẫu nhiên (32 byte) làm dữ liệu cần mã hoá – đây là kịch bản thực tế: RSA dùng để 'bọc' khoá AES.");
    }

    private void OnLoadDataFile(object sender, EventArgs e)
    {
        using var dlg = new OpenFileDialog { Filter = "Tất cả (*.*)|*.*" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        byte[] data = File.ReadAllBytes(dlg.FileName);
        if (data.Length > 4096) { MessageBox.Show(this, "File quá lớn để mã hoá trực tiếp bằng RSA."); return; }
        rdoDataB64.Checked = true;
        txtData.Text = Convert.ToBase64String(data);
        EncLog($"Đã nạp {data.Length} byte từ {dlg.FileName}");
    }

    private void OnSaveOriginal(object sender, EventArgs e)
    {
        try
        {
            byte[] data = GetSourceBytes();
            using var dlg = new SaveFileDialog { Filter = "Binary (*.bin)|*.bin", FileName = "original.bin" };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            File.WriteAllBytes(dlg.FileName, data);
            EncLog($"Đã lưu dữ liệu gốc ({data.Length} byte) vào {dlg.FileName} – dùng để so sánh sau khi giải mã.");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void OnEncrypt(object sender, EventArgs e)
    {
        RSA key = PublicKey;
        if (!Require(key, "khoá công khai")) return;
        try
        {
            byte[] data = GetSourceBytes();
            var sw = Stopwatch.StartNew();
            byte[] cipher = RsaService.Encrypt(key, data);
            sw.Stop();
            txtCipherB64.Text = Convert.ToBase64String(cipher);
            EncLog($"MÃ HOÁ bằng {KeySource(key)}: {data.Length} byte → {cipher.Length} byte bản mã (= độ dài modulus), {sw.Elapsed.TotalMilliseconds:F3} ms.");
        }
        catch (Exception ex) { ShowError(ex, "Không mã hoá được"); }
    }

    private void OnSaveCipher(object sender, EventArgs e)
    {
        if (string.IsNullOrWhiteSpace(txtCipherB64.Text)) { MessageBox.Show(this, "Chưa có bản mã."); return; }
        using var dlg = new SaveFileDialog { Filter = "Base64 (*.b64)|*.b64|Text (*.txt)|*.txt", FileName = "cipher.b64" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, txtCipherB64.Text.Trim());
        EncLog($"Đã lưu bản mã (Base64) vào {dlg.FileName}");
    }

    /// <summary>Đầu vào: file PEM (private key) + file chứa dữ liệu đã mã hoá (Base64).</summary>
    private void OnDecryptFromFiles(object sender, EventArgs e)
    {
        string pem = ReadTextFile(this, "Chọn file PEM PRIVATE KEY", PemFilter, out string pemPath);
        if (pem == null) return;
        string b64 = ReadTextFile(this, "Chọn file bản mã (Base64)", "Base64 (*.b64;*.txt)|*.b64;*.txt|Tất cả (*.*)|*.*", out string cipherPath);
        if (b64 == null) return;
        try
        {
            using RSA rsa = RsaService.ImportPem(pem);
            if (!RsaService.HasPrivateKey(rsa)) throw new InvalidOperationException("File PEM không chứa private key.");
            txtCipherB64.Text = b64.Trim();
            DecryptAndCompare(rsa, Convert.FromBase64String(b64.Trim()), $"private key {Path.GetFileName(pemPath)}, bản mã {Path.GetFileName(cipherPath)}");
        }
        catch (Exception ex) { ShowError(ex, "Giải mã thất bại"); }
    }

    private void OnDecryptCurrent(object sender, EventArgs e)
    {
        RSA key = PrivateKey;
        if (!Require(key, "khoá bí mật")) return;
        try { DecryptAndCompare(key, Convert.FromBase64String(txtCipherB64.Text.Trim()), KeySource(key)); }
        catch (Exception ex) { ShowError(ex, "Giải mã thất bại (sai khoá hoặc bản mã bị sửa)"); }
    }

    private void DecryptAndCompare(RSA rsa, byte[] cipher, string source)
    {
        var sw = Stopwatch.StartNew();
        byte[] plain = RsaService.Decrypt(rsa, cipher);
        sw.Stop();
        _lastDecrypted = plain;

        var sb = new StringBuilder();
        sb.AppendLine($"GIẢI MÃ bằng {source}: {cipher.Length} byte → {plain.Length} byte, {sw.Elapsed.TotalMilliseconds:F3} ms.");
        sb.AppendLine($"   Kết quả (Base64): {Convert.ToBase64String(plain)}");
        sb.AppendLine($"   Kết quả (Hex)   : {Convert.ToHexString(plain)}");
        if (rdoDataText.Checked) sb.AppendLine($"   Kết quả (UTF-8) : {Encoding.UTF8.GetString(plain)}");
        try
        {
            byte[] src = GetSourceBytes();
            bool same = src.AsSpan().SequenceEqual(plain);
            sb.AppendLine(same
                ? $"   SO SÁNH với dữ liệu nguồn trên màn hình: GIỐNG NHAU 100% ({src.Length} byte)."
                : $"   SO SÁNH với dữ liệu nguồn trên màn hình: KHÁC NHAU (nguồn {src.Length} byte).");
        }
        catch (FormatException) { }
        EncLog(sb.ToString().TrimEnd());
    }

    private void OnCompareWithFile(object sender, EventArgs e)
    {
        if (_lastDecrypted == null) { MessageBox.Show(this, "Hãy giải mã trước."); return; }
        using var dlg = new OpenFileDialog { Title = "Chọn file dữ liệu gốc (.bin)", Filter = "Binary (*.bin)|*.bin|Tất cả (*.*)|*.*" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        byte[] original = File.ReadAllBytes(dlg.FileName);
        bool same = original.AsSpan().SequenceEqual(_lastDecrypted);
        int firstDiff = same ? -1 : original.AsSpan().CommonPrefixLength(_lastDecrypted);
        EncLog(same
            ? $"SO SÁNH với {dlg.FileName}: GIỐNG NHAU 100% ({original.Length} byte)."
            : $"SO SÁNH với {dlg.FileName}: KHÁC NHAU từ byte {firstDiff} (gốc {original.Length} byte, giải mã {_lastDecrypted.Length} byte).");
    }

    private void EncLog(string s) => txtEncLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {Crlf(s)}\r\n");
}
