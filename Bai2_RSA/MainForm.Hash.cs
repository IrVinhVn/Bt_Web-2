using System.Text;
using CryptoCore;

namespace Bai2_RSA;

// TAB 8: SHA-256 – thay đổi rất nhỏ ở đầu vào làm kết quả băm thay đổi ~50% số bit (hiệu ứng thác lũ)
public sealed partial class MainForm
{
    private readonly TextBox txtHashInput = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Text = "An toan va bao mat thong tin" };
    private readonly TextBox txtHashOut = MonoBox(wrap: true);
    private readonly TextBox txtHashHistory = MonoBox();
    private readonly NumericUpDown numAvalanche = new() { Minimum = 100, Maximum = 1000000, Value = 10000, Increment = 1000, Width = 90 };
    private byte[] _prevHash;
    private string _prevInput;
    private int _hashChanges;

    private TabPage BuildHashTab()
    {
        txtHashInput.TextChanged += (_, _) => RecomputeHash();

        var bar = Flow(
            Btn("Đổi 1 ký tự cuối (+1 mã ký tự)", (_, _) => TweakLastChar()),
            Btn("Thêm dấu cách", (_, _) => txtHashInput.AppendText(" ")),
            Btn("Đổi hoa/thường ký tự đầu", (_, _) => ToggleFirstCase()),
            Lbl("   Thử nghiệm thác lũ: số lần"), numAvalanche,
            Btn("Chạy (mỗi lần đảo đúng 1 bit)", OnAvalanche),
            Btn("Xoá lịch sử", (_, _) => { txtHashHistory.Clear(); _hashChanges = 0; }));

        var page = new TabPage("8. SHA-256");
        page.Controls.Add(Rows(
            (Lbl("Nhập dữ liệu – chuỗi băm được tính lại NGAY khi gõ:", bold: true), 0),
            (txtHashInput, 15),
            (bar, 0),
            (Group("Kết quả băm hiện tại và so sánh với lần trước", txtHashOut), 35),
            (Group("Lịch sử các lần thay đổi", txtHashHistory), 50)));
        page.Enter += (_, _) => { if (_prevHash == null) RecomputeHash(); };
        return page;
    }

    private void RecomputeHash()
    {
        string input = txtHashInput.Text;
        byte[] h = HashService.Sha256(input);
        string hex = Convert.ToHexString(h).ToLowerInvariant();

        var sb = new StringBuilder();
        sb.AppendLine($"Đầu vào : {Encoding.UTF8.GetByteCount(input)} byte (UTF-8)");
        sb.AppendLine($"SHA-256 : {hex}");
        if (_prevHash != null)
        {
            string prevHex = Convert.ToHexString(_prevHash).ToLowerInvariant();
            int bits = HashService.BitDifference(_prevHash, h);
            int hexDiff = HashService.HexCharDifference(prevHex, hex);
            sb.AppendLine($"Lần trước: {prevHex}");
            sb.AppendLine($"Khác ở   : {HashService.DiffMarker(prevHex, hex)}");
            sb.AppendLine();
            sb.AppendLine($"Số bit thay đổi       : {bits}/256 = {bits / 2.56:F2}%   (lý tưởng ≈ 128 = 50%)");
            sb.AppendLine($"Số ký tự hex thay đổi : {hexDiff}/64 = {hexDiff / 0.64:F2}%   (lý tưởng ≈ 60/64 = 93.75%)");
            sb.AppendLine();
            sb.AppendLine("Nhị phân (lần này):");
            sb.AppendLine(HashService.ToBinary(h));

            if (input != _prevInput)
            {
                _hashChanges++;
                txtHashHistory.AppendText(
                    $"#{_hashChanges,3}  \"{Shorten(_prevInput)}\" → \"{Shorten(input)}\"\r\n" +
                    $"      {prevHex}\r\n      {hex}\r\n      bit đổi: {bits}/256 ({bits / 2.56:F1}%), hex đổi: {hexDiff}/64\r\n");
            }
        }
        txtHashOut.Text = Crlf(sb.ToString());
        _prevHash = h;
        _prevInput = input;
    }

    private static string Shorten(string s) => s == null ? "" : s.Length <= 40 ? s : s[..37] + "...";

    private void TweakLastChar()
    {
        string s = txtHashInput.Text;
        if (s.Length == 0) { txtHashInput.Text = "a"; return; }
        txtHashInput.Text = s[..^1] + (char)(s[^1] + 1);
    }

    private void ToggleFirstCase()
    {
        string s = txtHashInput.Text;
        if (s.Length == 0) return;
        char c = s[0];
        char t = char.IsUpper(c) ? char.ToLowerInvariant(c) : char.ToUpperInvariant(c);
        txtHashInput.Text = t + s[1..];
    }

    private async void OnAvalanche(object sender, EventArgs e)
    {
        int n = (int)numAvalanche.Value;
        var btn = (Button)sender;
        btn.Enabled = false;
        try
        {
            var r = await Task.Run(() => HashService.AvalancheTest(n, 64));
            txtHashHistory.AppendText("\r\n=== THỬ NGHIỆM HIỆU ỨNG THÁC LŨ ===\r\n" + Crlf(r.ToString()) + "\r\n" +
                "  ⇒ Thay đổi chỉ 1 bit đầu vào làm ~50% bit đầu ra thay đổi, không đoán được bit nào đổi.\r\n" +
                "    Đây là tính chất cần thiết để chữ ký số trên H(m) an toàn: không thể sửa m mà giữ nguyên H(m).\r\n\r\n");
        }
        finally { btn.Enabled = true; }
    }
}
