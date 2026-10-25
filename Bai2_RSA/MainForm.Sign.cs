using System.Security.Cryptography;
using System.Text;
using CryptoCore;

namespace Bai2_RSA;

// TAB 9: CHỮ KÝ SỐ – cùng dữ liệu, cùng người ký nhưng mỗi lần ký ra chữ ký KHÁC NHAU
public sealed partial class MainForm
{
    private readonly TextBox txtSignData = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Text = "Hop dong so 2026/10: Ben A chuyen cho ben B 100.000.000 VND." };
    private readonly ComboBox cboScheme = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 380 };
    private readonly NumericUpDown numSignTimes = new() { Minimum = 1, Maximum = 100, Value = 5, Width = 60 };
    private readonly DataGridView gridSign = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, Font = Mono
    };
    private readonly TextBox txtSignLog = MonoBox(wrap: true);
    private SignatureResult _lastSignature;

    private static readonly (SignScheme scheme, string name)[] Schemes =
    {
        (SignScheme.Pkcs1v15, "RSA PKCS#1 v1.5 + SHA-256 (tất định – KHÔNG đạt)"),
        (SignScheme.Pss, "RSA-PSS + SHA-256, salt ngẫu nhiên (ĐỀ XUẤT 1 – chuẩn)"),
        (SignScheme.NonceTimestamp, "Nonce + Timestamp + PKCS#1 (ĐỀ XUẤT 2 – tự thiết kế)"),
    };

    private SignScheme SelectedScheme => Schemes[Math.Max(0, cboScheme.SelectedIndex)].scheme;

    private TabPage BuildSignTab()
    {
        foreach (var s in Schemes) cboScheme.Items.Add(s.name);
        cboScheme.SelectedIndex = 0;

        gridSign.Columns.Add("no", "#");
        gridSign.Columns.Add("scheme", "Phương pháp");
        gridSign.Columns.Add("sig", "Chữ ký (hex, 48 ký tự đầu)");
        gridSign.Columns.Add("extra", "Nonce / thời điểm");
        gridSign.Columns.Add("ok", "Xác minh");
        gridSign.Columns["no"].FillWeight = 20;
        gridSign.Columns["scheme"].FillWeight = 60;
        gridSign.Columns["sig"].FillWeight = 260;
        gridSign.Columns["extra"].FillWeight = 120;
        gridSign.Columns["ok"].FillWeight = 40;

        var bar1 = Flow(Lbl("Phương pháp:"), cboScheme, Lbl("Số lần ký:"), numSignTimes,
            Btn("9. Ký N lần CÙNG dữ liệu, CÙNG khoá", OnSignMany),
            Btn("So sánh cả 3 phương pháp", OnCompareSchemes));
        var bar2 = Flow(
            Btn("Ký dữ liệu KHÁC (thêm 1 dấu '.')", OnSignDifferentData),
            Btn("Xác minh chữ ký cuối với dữ liệu BỊ SỬA", OnVerifyTampered),
            Btn("Minh hoạ: s = EM^d mod n (tự tính bằng BigInteger)", OnManualSign),
            Btn("Lưu chữ ký...", OnSaveSignature),
            Btn("Xác minh chữ ký từ file...", OnVerifyFromFile),
            Btn("Xoá", (_, _) => { gridSign.Rows.Clear(); txtSignLog.Clear(); }));

        var proposal = MonoBox(wrap: true);
        proposal.Text = Crlf(ProposalText);

        var lower = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        lower.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        lower.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        lower.Controls.Add(Group("Nhật ký", txtSignLog), 0, 0);
        lower.Controls.Add(Group("ĐỀ XUẤT PHƯƠNG PHÁP", proposal), 1, 0);

        var page = new TabPage("9. Chữ ký số");
        page.Controls.Add(Rows(
            (Lbl("Dữ liệu cần ký:", bold: true), 0),
            (txtSignData, 12),
            (bar1, 0),
            (bar2, 0),
            (gridSign, 38),
            (lower, 50)));
        return page;
    }

    private byte[] SignInput => Encoding.UTF8.GetBytes(txtSignData.Text);

    private void AddSignRow(int no, SignatureResult r, bool ok)
    {
        string hex = Convert.ToHexString(r.Signature);
        string extra = r.Scheme == SignScheme.NonceTimestamp
            ? $"{Convert.ToHexString(r.Nonce)[..12]}… / {DateTimeOffset.FromUnixTimeMilliseconds(r.TimestampUnixMs).ToLocalTime():HH:mm:ss.fff}"
            : "";
        gridSign.Rows.Add(no, r.Scheme.ToString(), hex[..48] + "…", extra, ok ? "ĐÚNG" : "SAI");
    }

    private List<SignatureResult> SignMany(RSA key, byte[] data, SignScheme scheme, int times, bool addRows)
    {
        var list = new List<SignatureResult>();
        for (int i = 0; i < times; i++)
        {
            var r = SignatureService.Sign(key, data, scheme);
            bool ok = SignatureService.Verify(key, data, r);
            if (addRows) AddSignRow(i + 1, r, ok);
            list.Add(r);
        }
        _lastSignature = list[^1];
        return list;
    }

    private static int DistinctCount(List<SignatureResult> list) =>
        list.Select(r => Convert.ToBase64String(r.Signature)).Distinct().Count();

    private void OnSignMany(object sender, EventArgs e)
    {
        RSA key = PrivateKey;
        if (!Require(key, "khoá bí mật")) return;
        int n = (int)numSignTimes.Value;
        gridSign.Rows.Clear();
        var list = SignMany(key, SignInput, SelectedScheme, n, true);
        int distinct = DistinctCount(list);
        SignLog($"{SelectedScheme}: ký {n} lần cùng dữ liệu, cùng khoá ({KeySource(key)}) → {distinct} chữ ký khác nhau. " +
                (distinct == n ? "ĐẠT yêu cầu: mỗi lần ký cho một chữ ký mới, và tất cả đều xác minh ĐÚNG."
                               : "KHÔNG đạt: chữ ký lặp lại (thuật toán tất định)."));
    }

    private void OnCompareSchemes(object sender, EventArgs e)
    {
        RSA key = PrivateKey;
        if (!Require(key, "khoá bí mật")) return;
        int n = (int)numSignTimes.Value;
        gridSign.Rows.Clear();
        var sb = new StringBuilder("SO SÁNH (cùng dữ liệu, cùng khoá, ký " + n + " lần):\n");
        foreach (var (scheme, name) in Schemes)
        {
            var list = SignMany(key, SignInput, scheme, n, true);
            sb.AppendLine($"  {name}: {DistinctCount(list)}/{n} chữ ký khác nhau");
        }
        SignLog(sb.ToString().TrimEnd());
    }

    private void OnSignDifferentData(object sender, EventArgs e)
    {
        RSA key = PrivateKey;
        if (!Require(key, "khoá bí mật")) return;
        byte[] d1 = SignInput;
        byte[] d2 = Encoding.UTF8.GetBytes(txtSignData.Text + ".");
        var s1 = SignatureService.Sign(key, d1, SignScheme.Pkcs1v15);
        var s2 = SignatureService.Sign(key, d2, SignScheme.Pkcs1v15);
        int bits = HashService.BitDifference(s1.Signature, s2.Signature);
        SignLog($"Dữ liệu khác nhau 1 ký tự (PKCS#1 v1.5):\n  s1 = {Convert.ToHexString(s1.Signature)[..48]}…\n  s2 = {Convert.ToHexString(s2.Signature)[..48]}…\n" +
                $"  → chữ ký KHÁC NHAU ({bits}/{s1.Signature.Length * 8} bit khác). Dữ liệu khác → H(m) khác → chữ ký khác.");
    }

    private void OnVerifyTampered(object sender, EventArgs e)
    {
        RSA key = PublicKey;
        if (_lastSignature == null) { MessageBox.Show(this, "Hãy ký trước."); return; }
        if (!Require(key, "khoá công khai")) return;
        byte[] original = SignInput;
        byte[] tampered = Encoding.UTF8.GetBytes(txtSignData.Text.Replace("100.000.000", "900.000.000") + (txtSignData.Text.Contains("100.000.000") ? "" : "!"));
        bool okOriginal = SignatureService.Verify(key, original, _lastSignature);
        bool okTampered = SignatureService.Verify(key, tampered, _lastSignature);
        SignLog($"Xác minh bằng khoá CÔNG KHAI ({_lastSignature.Scheme}):\n  dữ liệu gốc  → {(okOriginal ? "ĐÚNG" : "SAI")}\n  dữ liệu bị sửa → {(okTampered ? "ĐÚNG" : "SAI (phát hiện giả mạo)")}");
    }

    private void OnManualSign(object sender, EventArgs e)
    {
        RSA key = PrivateKey;
        if (!Require(key, "khoá bí mật")) return;
        byte[] data = SignInput;
        RSAParameters priv = key.ExportParameters(true);
        byte[] manual = SignatureService.ManualSignPkcs1(priv, data, out byte[] em);
        byte[] lib = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        bool verified = SignatureService.ManualVerifyPkcs1(key.ExportParameters(false), data, manual, out byte[] recovered);

        string emHex = Convert.ToHexString(em);
        SignLog("MINH HOẠ BẢN CHẤT CHỮ KÝ SỐ RSA (PKCS#1 v1.5):\n" +
                $"  1) H = SHA256(m) = {Convert.ToHexString(SHA256.HashData(data))}\n" +
                $"  2) EM = 00 01 FF…FF 00 || DigestInfo || H  ({em.Length} byte)\n" +
                $"     = {emHex[..12]}…{emHex[^((19 + 32) * 2)..]}\n" +
                "  3) s = EM^d mod n  (dùng khoá BÍ MẬT)\n" +
                $"     s (tự tính) = {Convert.ToHexString(manual)[..48]}…\n" +
                $"     s (.NET)    = {Convert.ToHexString(lib)[..48]}…\n" +
                $"     → trùng khớp: {manual.AsSpan().SequenceEqual(lib)}\n" +
                $"  4) Xác minh: s^e mod n (khoá CÔNG KHAI) = EM ? → {verified}\n" +
                "  Vì EM chỉ phụ thuộc H(m) nên PKCS#1 v1.5 là TẤT ĐỊNH: cùng m + cùng d ⇒ cùng s.");
    }

    private void OnSaveSignature(object sender, EventArgs e)
    {
        if (_lastSignature == null) { MessageBox.Show(this, "Hãy ký trước."); return; }
        using var dlg = new SaveFileDialog { Filter = "Signature (*.sig)|*.sig", FileName = $"chuky_{_lastSignature.Scheme}.sig" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, _lastSignature.ToPortableString());
        SignLog($"Đã lưu chữ ký ({_lastSignature.Scheme}) vào {dlg.FileName}");
    }

    private void OnVerifyFromFile(object sender, EventArgs e)
    {
        RSA key = PublicKey;
        if (!Require(key, "khoá công khai")) return;
        string text = ReadTextFile(this, "Chọn file chữ ký (.sig)", "Signature (*.sig)|*.sig|Tất cả (*.*)|*.*", out string path);
        if (text == null) return;
        try
        {
            var sig = SignatureResult.FromPortableString(text, SelectedScheme);
            bool ok = SignatureService.Verify(key, SignInput, sig);
            SignLog($"Xác minh {Path.GetFileName(path)} ({SelectedScheme}) với dữ liệu hiện tại bằng {KeySource(key)} → {(ok ? "ĐÚNG" : "SAI")}");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void SignLog(string s) => txtSignLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {Crlf(s)}\r\n\r\n");

    private const string ProposalText =
@"VẤN ĐỀ
Chữ ký RSA ""cơ bản"" s = EM^d mod n với EM = PAD(H(m)) cố định (PKCS#1 v1.5)
→ cùng dữ liệu m + cùng khoá d ⇒ LUÔN ra cùng chữ ký s (tất định).

Ý TƯỞNG CHUNG
Đưa một giá trị NGẪU NHIÊN r (sinh mới mỗi lần ký) vào phép băm/đệm:
   s = PAD(H(m), r)^d mod n
Người xác minh phải khôi phục hoặc được gửi kèm r để kiểm tra.

ĐỀ XUẤT 1 (khuyến nghị) – RSA-PSS (RFC 8017, mục 8.1 / 9.1)
 1. mHash = SHA256(m)
 2. salt = 32 byte ngẫu nhiên (CSPRNG), mới mỗi lần ký
 3. H = SHA256(0x00×8 || mHash || salt)
 4. DB = PS(0x00…) || 0x01 || salt
 5. maskedDB = DB XOR MGF1(H)
 6. EM = maskedDB || H || 0xBC ;  s = EM^d mod n
 Xác minh: EM = s^e mod n → gỡ mặt nạ lấy lại salt → tính lại H và so sánh.
 Salt nằm ẨN trong chữ ký, không cần gửi kèm, độ dài chữ ký không đổi.
 Ưu điểm: chuẩn quốc tế, có chứng minh an toàn, .NET hỗ trợ sẵn
 (RSASignaturePadding.Pss). Khuyến nghị dùng thay PKCS#1 v1.5.

ĐỀ XUẤT 2 – Nonce + dấu thời gian (tự thiết kế trên PKCS#1 v1.5)
 1. nonce = 16 byte ngẫu nhiên, t = thời điểm ký
 2. h = SHA256(nonce || t || m)
 3. s = PKCS1(h)^d mod n
 4. Gửi đi: (m, nonce, t, s)
 Xác minh: tính lại h từ (nonce, t, m) rồi kiểm tra s bằng khoá công khai.
 Ưu điểm: dễ hiểu, biết thời điểm ký, chống phát lại (replay)
 nếu bên nhận lưu nonce đã dùng / giới hạn thời gian.
 Nhược điểm: phải gửi kèm nonce, t; không phải chuẩn.

(Khác: ECDSA/DSA vốn ngẫu nhiên theo k – nhưng k phải tuyệt đối
 không lặp lại, nếu lặp sẽ lộ khoá bí mật; RFC 6979 lại làm k tất định.)

KẾT LUẬN: dùng RSA-PSS – cùng dữ liệu, cùng người ký, mỗi lần ký cho chữ ký
khác nhau, mọi chữ ký đều xác minh đúng bằng cùng một khoá công khai.";
}
