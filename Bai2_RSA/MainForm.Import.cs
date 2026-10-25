using CryptoCore;

namespace Bai2_RSA;

// TAB 4: NHẬP FILE PEM – public key → (n, e); private key → (n, e, d, p, q, dP, dQ, qInv)
public sealed partial class MainForm
{
    private readonly TextBox txtImportPublic = MonoBox();
    private readonly TextBox txtImportPrivate = MonoBox();
    private readonly Label lblImportInfo = new() { AutoSize = true, ForeColor = Color.DarkGreen };

    private TabPage BuildImportTab()
    {
        var bar = Flow(
            Btn("Nhập PUBLIC key (.pem)...", OnImportPublic),
            Btn("Nhập PRIVATE key (.pem)...", OnImportPrivate),
            Btn("Bỏ khoá đã nhập (dùng lại khoá vừa sinh)", (_, _) =>
            {
                _importedPublic?.Dispose(); _importedPublic = null;
                _importedPrivate?.Dispose(); _importedPrivate = null;
                txtImportPublic.Clear(); txtImportPrivate.Clear();
                lblImportInfo.Text = "Đã bỏ khoá import.";
                UpdateKeyStatus();
            }),
            lblImportInfo);

        var split = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        split.Controls.Add(Group("Public key: n, e", txtImportPublic), 0, 0);
        split.Controls.Add(Group("Private key: n, e, d, p, q, dP, dQ, qInv", txtImportPrivate), 1, 0);

        var page = new TabPage("4. Nhập PEM (n, e, d...)");
        page.Controls.Add(Rows((bar, 0), (split, 100)));
        return page;
    }

    private void OnImportPublic(object sender, EventArgs e)
    {
        string pem = ReadTextFile(this, "Chọn file PEM chứa PUBLIC key", PemFilter, out string path);
        if (pem == null) return;
        try
        {
            var rsa = RsaService.ImportPem(pem);
            if (RsaService.HasPrivateKey(rsa))
            {
                // Người dùng chọn nhầm file private: chỉ giữ phần công khai (n, e).
                var pub = System.Security.Cryptography.RSA.Create();
                pub.ImportParameters(rsa.ExportParameters(false));
                rsa.Dispose();
                rsa = pub;
                lblImportInfo.Text = "File là private key – chỉ lấy phần công khai (n, e).";
            }
            _importedPublic?.Dispose();
            _importedPublic = rsa;
            txtImportPublic.Text = $"File: {path}\r\n\r\n" + Crlf(RsaService.DescribeKey(rsa));
            lblImportInfo.Text = $"Đã nhập public key RSA-{rsa.KeySize}.";
            UpdateKeyStatus();
        }
        catch (Exception ex) { ShowError(ex, "PEM không hợp lệ"); }
    }

    private void OnImportPrivate(object sender, EventArgs e)
    {
        string pem = ReadTextFile(this, "Chọn file PEM chứa PRIVATE key", PemFilter, out string path);
        if (pem == null) return;
        try
        {
            var rsa = RsaService.ImportPem(pem);
            if (!RsaService.HasPrivateKey(rsa))
            {
                rsa.Dispose();
                throw new InvalidOperationException("File này chỉ chứa public key, không có d, p, q...");
            }
            _importedPrivate?.Dispose();
            _importedPrivate = rsa;
            txtImportPrivate.Text = $"File: {path}\r\n\r\n" + Crlf(RsaService.DescribeKey(rsa));
            lblImportInfo.Text = $"Đã nhập private key RSA-{rsa.KeySize}.";
            UpdateKeyStatus();
        }
        catch (Exception ex) { ShowError(ex, "PEM không hợp lệ"); }
    }

    internal static string Crlf(string s) => s.Replace("\r\n", "\n").Replace("\n", "\r\n");
}
