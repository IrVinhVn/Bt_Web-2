using System.Diagnostics;
using CryptoCore;

namespace Bai2_RSA;

// TAB 1-2: SINH CẶP KHOÁ VÀ XUẤT RA FILE PEM
public sealed partial class MainForm
{
    private readonly ComboBox cboGenSize = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90 };
    private readonly RadioButton rdoPkcs1 = new() { Text = "PKCS#1 (BEGIN RSA PUBLIC/PRIVATE KEY)", AutoSize = true, Checked = true };
    private readonly RadioButton rdoPkcs8 = new() { Text = "X.509 SPKI / PKCS#8 (BEGIN PUBLIC/PRIVATE KEY)", AutoSize = true };
    private readonly TextBox txtGenPublic = MonoBox();
    private readonly TextBox txtGenPrivate = MonoBox();
    private readonly Label lblGenInfo = new() { AutoSize = true, ForeColor = Color.DarkGreen };

    private TabPage BuildKeysTab()
    {
        cboGenSize.Items.AddRange(new object[] { 1024, 2048, 3072, 4096 });
        cboGenSize.SelectedItem = 2048;
        rdoPkcs1.CheckedChanged += (_, _) => RefreshGeneratedPem();

        var top = Flow(Lbl("Độ dài khoá (bit):"), cboGenSize, Btn("1. Sinh cặp khoá", OnGenerate), Lbl("Định dạng PEM:"), rdoPkcs1, rdoPkcs8);
        var save = Flow(Btn("2. Lưu public key (.pem)...", (_, _) => SavePem(txtGenPublic.Text, "public.pem")),
                        Btn("2. Lưu private key (.pem)...", (_, _) => SavePem(txtGenPrivate.Text, "private.pem")),
                        Btn("Lưu cả 2 vào thư mục...", OnSaveBoth),
                        lblGenInfo);

        var split = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55));
        split.Controls.Add(Group("Public key (n, e) – được phép công khai", txtGenPublic), 0, 0);
        split.Controls.Add(Group("Private key (n, e, d, p, q, dP, dQ, qInv) – PHẢI GIỮ BÍ MẬT", txtGenPrivate), 1, 0);

        var page = new TabPage("1-2. Sinh & xuất khoá");
        page.Controls.Add(Rows((top, 0), (save, 0), (split, 100)));
        return page;
    }

    private PemFormat SelectedPemFormat => rdoPkcs1.Checked ? PemFormat.Pkcs1 : PemFormat.SpkiPkcs8;

    private void OnGenerate(object sender, EventArgs e)
    {
        int bits = (int)cboGenSize.SelectedItem;
        Cursor = Cursors.WaitCursor;
        try
        {
            var sw = Stopwatch.StartNew();
            var rsa = RsaService.GenerateKeyPair(bits);
            sw.Stop();
            _generated?.Dispose();
            _generated = rsa;
            RefreshGeneratedPem();
            lblGenInfo.Text = $"Đã sinh RSA-{bits} trong {sw.Elapsed.TotalMilliseconds:F0} ms. Dữ liệu mã hoá tối đa (OAEP-SHA256): {RsaService.MaxOaepSha256DataLength(rsa)} byte.";
            UpdateKeyStatus();
        }
        finally { Cursor = Cursors.Default; }
    }

    private void RefreshGeneratedPem()
    {
        if (_generated == null) return;
        txtGenPublic.Text = RsaService.ExportPublicPem(_generated, SelectedPemFormat).Replace("\n", "\r\n");
        txtGenPrivate.Text = RsaService.ExportPrivatePem(_generated, SelectedPemFormat).Replace("\n", "\r\n");
    }

    private void SavePem(string pem, string defaultName)
    {
        if (string.IsNullOrWhiteSpace(pem)) { Require(null, "cặp khoá"); return; }
        using var dlg = new SaveFileDialog { Filter = PemFilter, FileName = defaultName };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, pem.Replace("\r\n", "\n") + "\n");
        lblGenInfo.Text = "Đã lưu: " + dlg.FileName;
    }

    private void OnSaveBoth(object sender, EventArgs e)
    {
        if (!Require(_generated, "cặp khoá")) return;
        using var dlg = new FolderBrowserDialog { Description = "Chọn thư mục lưu public.pem và private.pem" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(Path.Combine(dlg.SelectedPath, "public.pem"), txtGenPublic.Text.Replace("\r\n", "\n") + "\n");
        File.WriteAllText(Path.Combine(dlg.SelectedPath, "private.pem"), txtGenPrivate.Text.Replace("\r\n", "\n") + "\n");
        lblGenInfo.Text = "Đã lưu public.pem và private.pem vào " + dlg.SelectedPath;
    }
}
