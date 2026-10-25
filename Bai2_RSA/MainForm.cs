using System.Security.Cryptography;
using CryptoCore;

namespace Bai2_RSA;

/// <summary>
/// BÀI 2 – MÃ HOÁ BẤT ĐỐI XỨNG RSA, SHA-256 VÀ CHỮ KÝ SỐ.
/// Mỗi yêu cầu của đề bài nằm trong một tab (xem các file MainForm.*.cs).
/// </summary>
public sealed partial class MainForm : Form
{
    internal static readonly Font Mono = new("Consolas", 9.5f);

    /// <summary>Cặp khoá vừa sinh ở tab 1.</summary>
    private RSA _generated;
    /// <summary>Khoá công khai import từ PEM ở tab 4.</summary>
    private RSA _importedPublic;
    /// <summary>Khoá bí mật import từ PEM ở tab 4.</summary>
    private RSA _importedPrivate;

    private readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    private readonly ToolStripStatusLabel statusKey = new() { Text = "Chưa có khoá." };

    public MainForm()
    {
        Text = "Bài 2 – RSA (PEM, mã hoá OAEP), SHA-256 và Chữ ký số";
        Font = new Font("Segoe UI", 9.5f);
        AutoScaleMode = AutoScaleMode.Font;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1200, 840);
        MinimumSize = new Size(950, 700);

        tabs.TabPages.Add(BuildKeysTab());
        tabs.TabPages.Add(BuildPemTab());
        tabs.TabPages.Add(BuildImportTab());
        tabs.TabPages.Add(BuildEncryptTab());
        tabs.TabPages.Add(BuildBenchTab());
        tabs.TabPages.Add(BuildHashTab());
        tabs.TabPages.Add(BuildSignTab());

        var status = new StatusStrip();
        status.Items.Add(statusKey);
        Controls.Add(tabs);
        Controls.Add(status);
    }

    // =====================================================================================
    // Khoá đang dùng: ưu tiên khoá import từ PEM, nếu không có thì dùng khoá vừa sinh.
    // =====================================================================================
    private RSA PublicKey => _importedPublic ?? _importedPrivate ?? _generated;
    private RSA PrivateKey => _importedPrivate ?? _generated;

    private string KeySource(RSA k) =>
        k == null ? "(chưa có)" :
        ReferenceEquals(k, _importedPublic) ? $"public key import từ PEM (RSA-{k.KeySize})" :
        ReferenceEquals(k, _importedPrivate) ? $"private key import từ PEM (RSA-{k.KeySize})" :
        $"cặp khoá vừa sinh (RSA-{k.KeySize})";

    private void UpdateKeyStatus()
    {
        statusKey.Text = $"Khoá công khai đang dùng: {KeySource(PublicKey)}   |   Khoá bí mật đang dùng: {KeySource(PrivateKey)}";
    }

    private bool Require(RSA key, string what)
    {
        if (key != null) return true;
        MessageBox.Show(this, $"Chưa có {what}. Hãy sinh khoá (tab 1) hoặc import PEM (tab 4).", "Thiếu khoá",
            MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return false;
    }

    // =====================================================================================
    // Tiện ích dựng giao diện
    // =====================================================================================
    internal static Button Btn(string text, EventHandler onClick)
    {
        var b = new Button { Text = text, AutoSize = true, Margin = new Padding(3) };
        b.Click += onClick;
        return b;
    }

    internal static Label Lbl(string text, bool bold = false)
    {
        var l = new Label { Text = text, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 3, 3) };
        if (bold) l.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
        return l;
    }

    internal static TextBox MonoBox(bool readOnly = true, bool wrap = false) => new()
    {
        Multiline = true,
        ReadOnly = readOnly,
        ScrollBars = wrap ? ScrollBars.Vertical : ScrollBars.Both,
        WordWrap = wrap,
        Dock = DockStyle.Fill,
        Font = Mono,
        BackColor = readOnly ? Color.WhiteSmoke : SystemColors.Window
    };

    internal static FlowLayoutPanel Flow(params Control[] controls)
    {
        var f = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        f.Controls.AddRange(controls);
        return f;
    }

    /// <summary>Bảng 1 cột, các hàng AutoSize trừ những hàng chỉ định theo phần trăm.</summary>
    internal static TableLayoutPanel Rows(params (Control control, float percent)[] rows)
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = rows.Length };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < rows.Length; i++)
        {
            t.RowStyles.Add(rows[i].percent > 0 ? new RowStyle(SizeType.Percent, rows[i].percent) : new RowStyle(SizeType.AutoSize));
            t.Controls.Add(rows[i].control, 0, i);
        }
        return t;
    }

    internal static GroupBox Group(string title, Control content)
    {
        var g = new GroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(6) };
        g.Controls.Add(content);
        return g;
    }

    private void ShowError(Exception ex, string title = "Lỗi") =>
        MessageBox.Show(this, ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);

    internal static string ReadTextFile(IWin32Window owner, string title, string filter, out string path)
    {
        path = null;
        using var dlg = new OpenFileDialog { Title = title, Filter = filter };
        if (dlg.ShowDialog(owner) != DialogResult.OK) return null;
        path = dlg.FileName;
        return File.ReadAllText(path);
    }

    internal const string PemFilter = "PEM (*.pem)|*.pem|Tất cả (*.*)|*.*";
}
