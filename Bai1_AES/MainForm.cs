using System.Diagnostics;
using System.Text;
using CryptoCore;

namespace Bai1_AES;

/// <summary>
/// BÀI 1 – MÃ HOÁ ĐỐI XỨNG AES (mã hoá và giải mã dùng chung 1 khoá).
/// 1. Sinh khoá  2. Lưu khoá ra file  3. Import khoá từ file
/// 4. Mã hoá đoạn văn bản -> hiển thị  5. Mã hoá file -> lưu file
/// + Thử nghiệm file lớn (GB): đo thời gian mã hoá / giải mã, so sánh từng byte file nguồn và file giải mã.
/// </summary>
public sealed class MainForm : Form
{
    private static readonly Font Mono = new("Consolas", 9.5f);

    private byte[] _key;
    private CancellationTokenSource _cts;

    // Khoá
    private readonly ComboBox cboKeySize = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
    private readonly TextBox txtKey = new() { ReadOnly = true, Font = Mono, Dock = DockStyle.Fill };
    private readonly Label lblKeyInfo = new() { AutoSize = true, ForeColor = Color.DarkGreen, Text = "Chưa có khoá." };

    // Văn bản
    private readonly TextBox txtPlain = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Text = "Xin chào! Đây là bài tập An toàn và bảo mật thông tin – mã hoá AES." };
    private readonly TextBox txtCipher = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = Mono };

    // File
    private readonly TextBox txtSource = new() { Dock = DockStyle.Fill };
    private readonly NumericUpDown numSizeMb = new() { Minimum = 1, Maximum = 20480, Value = 1024, Increment = 256, Width = 80 };
    private readonly ProgressBar progress = new() { Dock = DockStyle.Fill, Maximum = 1000 };
    private readonly Label lblStatus = new() { AutoSize = true, Text = "Sẵn sàng." };
    private readonly DataGridView grid = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        AllowUserToAddRows = false,
        RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect
    };
    private readonly TextBox txtLog = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = Mono };
    private readonly List<Control> _busyControls = new();

    public MainForm()
    {
        Text = "Bài 1 – Mã hoá đối xứng AES (AES-CBC, PKCS7, IV ngẫu nhiên)";
        Font = new Font("Segoe UI", 9.5f);
        AutoScaleMode = AutoScaleMode.Font;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1100, 820);
        MinimumSize = new Size(900, 700);

        cboKeySize.Items.AddRange(new object[] { 128, 192, 256 });
        cboKeySize.SelectedItem = 256;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(8) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 70));
        root.Controls.Add(BuildKeyGroup(), 0, 0);
        root.Controls.Add(BuildTextGroup(), 0, 1);
        root.Controls.Add(BuildFileGroup(), 0, 2);
        Controls.Add(root);

        SetupGrid();
        FormClosing += (_, _) => _cts?.Cancel();
    }

    // =====================================================================================
    // GIAO DIỆN
    // =====================================================================================
    private Button Btn(string text, EventHandler onClick, bool busyAware = true)
    {
        var b = new Button { Text = text, AutoSize = true, Margin = new Padding(3) };
        b.Click += onClick;
        if (busyAware) _busyControls.Add(b);
        return b;
    }

    private static Label Lbl(string text) => new() { Text = text, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 3, 3) };

    private Control BuildKeyGroup()
    {
        var g = new GroupBox { Text = "1-3. Khoá AES", Dock = DockStyle.Fill, AutoSize = true };
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
        buttons.Controls.Add(Lbl("Độ dài khoá (bit):"));
        buttons.Controls.Add(cboKeySize);
        buttons.Controls.Add(Btn("1. Sinh khoá", OnGenerateKey));
        buttons.Controls.Add(Btn("2. Lưu khoá ra file...", OnSaveKey));
        buttons.Controls.Add(Btn("3. Import khoá từ file...", OnLoadKey));
        buttons.Controls.Add(lblKeyInfo);

        t.Controls.Add(buttons, 0, 0);
        t.SetColumnSpan(buttons, 2);
        t.Controls.Add(Lbl("Khoá (Base64):"), 0, 1);
        t.Controls.Add(txtKey, 1, 1);
        g.Controls.Add(t);
        return g;
    }

    private Control BuildTextGroup()
    {
        var g = new GroupBox { Text = "4. Mã hoá đoạn văn bản (kết quả = Base64(IV || ciphertext))", Dock = DockStyle.Fill };
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2 };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        t.Controls.Add(Lbl("Văn bản gốc (UTF-8):"), 0, 0);
        t.Controls.Add(Lbl("Bản mã (Base64):"), 2, 0);
        t.Controls.Add(txtPlain, 0, 1);

        var mid = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Anchor = AnchorStyles.None };
        mid.Controls.Add(Btn("Mã hoá  →", OnEncryptText, false));
        mid.Controls.Add(Btn("←  Giải mã", OnDecryptText, false));
        t.Controls.Add(mid, 1, 1);
        t.Controls.Add(txtCipher, 2, 1);
        g.Controls.Add(t);
        return g;
    }

    private Control BuildFileGroup()
    {
        var g = new GroupBox { Text = "5. Mã hoá file -> lưu vào file  +  Thử nghiệm file lớn (đo thời gian, so sánh byte)", Dock = DockStyle.Fill };
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6 };
        t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 45));

        // Hàng 1: chọn file nguồn
        var r1 = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, AutoSize = true };
        r1.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        r1.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        r1.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        r1.Controls.Add(Lbl("File nguồn:"), 0, 0);
        r1.Controls.Add(txtSource, 1, 0);
        r1.Controls.Add(Btn("Chọn file...", OnBrowseSource), 2, 0);
        t.Controls.Add(r1, 0, 0);

        // Hàng 2: tạo file test
        var r2 = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        r2.Controls.Add(Lbl("Tạo file dữ liệu ngẫu nhiên kích thước (MB):"));
        r2.Controls.Add(numSizeMb);
        r2.Controls.Add(Btn("Tạo file test...", OnCreateTestFile));
        r2.Controls.Add(Lbl("(1024 MB = 1 GB; nên thử 100 MB, 1 GB, 2 GB, 4 GB)"));
        t.Controls.Add(r2, 0, 1);

        // Hàng 3: các thao tác
        var r3 = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        r3.Controls.Add(Btn("Mã hoá file...", OnEncryptFile));
        r3.Controls.Add(Btn("Giải mã file...", OnDecryptFile));
        r3.Controls.Add(Btn("So sánh 2 file theo byte...", OnCompareFiles));
        var full = Btn("▶ Thử nghiệm đầy đủ (mã hoá → giải mã → so sánh)", OnFullTest);
        full.Font = new Font(Font, FontStyle.Bold);
        r3.Controls.Add(full);
        r3.Controls.Add(Btn("Huỷ", (_, _) => _cts?.Cancel(), false));
        r3.Controls.Add(Btn("Xuất kết quả CSV...", OnExportCsv, false));
        t.Controls.Add(r3, 0, 2);

        // Hàng 4: tiến trình
        var r4 = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
        r4.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
        r4.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
        r4.Controls.Add(progress, 0, 0);
        r4.Controls.Add(lblStatus, 1, 0);
        t.Controls.Add(r4, 0, 3);

        t.Controls.Add(grid, 0, 4);
        t.Controls.Add(txtLog, 0, 5);
        g.Controls.Add(t);
        return g;
    }

    private void SetupGrid()
    {
        grid.Columns.Add("file", "File nguồn");
        grid.Columns.Add("size", "Kích thước");
        grid.Columns.Add("key", "Khoá");
        grid.Columns.Add("encT", "T. mã hoá (s)");
        grid.Columns.Add("encS", "Tốc độ MH (MB/s)");
        grid.Columns.Add("decT", "T. giải mã (s)");
        grid.Columns.Add("decS", "Tốc độ GM (MB/s)");
        grid.Columns.Add("cmp", "So sánh byte");
        grid.Columns.Add("cmpT", "T. so sánh (s)");
        grid.Columns["file"].FillWeight = 180;
        grid.Columns["cmp"].FillWeight = 140;
    }

    // =====================================================================================
    // 1-3. KHOÁ
    // =====================================================================================
    private void OnGenerateKey(object sender, EventArgs e)
    {
        SetKey(AesService.GenerateKey((int)cboKeySize.SelectedItem), "Đã sinh khoá mới bằng RandomNumberGenerator (CSPRNG).");
    }

    private void OnSaveKey(object sender, EventArgs e)
    {
        if (!EnsureKey()) return;
        using var dlg = new SaveFileDialog { Filter = "AES key (*.key)|*.key|Tất cả (*.*)|*.*", FileName = $"aes{_key.Length * 8}.key" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        AesService.SaveKey(dlg.FileName, _key);
        Log($"Đã lưu khoá ({_key.Length * 8} bit, Base64) vào: {dlg.FileName}");
    }

    private void OnLoadKey(object sender, EventArgs e)
    {
        using var dlg = new OpenFileDialog { Filter = "AES key (*.key)|*.key|Tất cả (*.*)|*.*" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            SetKey(AesService.LoadKey(dlg.FileName), $"Đã import khoá từ: {dlg.FileName}");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void SetKey(byte[] key, string message)
    {
        _key = key;
        txtKey.Text = Convert.ToBase64String(key);
        cboKeySize.SelectedItem = key.Length * 8;
        lblKeyInfo.Text = $"AES-{key.Length * 8}  |  {key.Length} byte  |  Hex: {Convert.ToHexString(key)[..Math.Min(16, key.Length * 2)]}...";
        Log(message);
    }

    private bool EnsureKey()
    {
        if (_key != null) return true;
        MessageBox.Show(this, "Hãy sinh khoá hoặc import khoá trước.", "Chưa có khoá", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return false;
    }

    // =====================================================================================
    // 4. VĂN BẢN
    // =====================================================================================
    private void OnEncryptText(object sender, EventArgs e)
    {
        if (!EnsureKey()) return;
        try
        {
            var sw = Stopwatch.StartNew();
            txtCipher.Text = AesService.EncryptText(txtPlain.Text, _key);
            sw.Stop();
            Log($"Mã hoá văn bản {Encoding.UTF8.GetByteCount(txtPlain.Text)} byte -> {txtCipher.Text.Length} ký tự Base64 trong {sw.Elapsed.TotalMilliseconds:F3} ms. (Mỗi lần mã hoá có IV mới nên bản mã khác nhau.)");
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void OnDecryptText(object sender, EventArgs e)
    {
        if (!EnsureKey()) return;
        try
        {
            txtPlain.Text = AesService.DecryptText(txtCipher.Text, _key);
            Log("Giải mã văn bản thành công.");
        }
        catch (Exception ex) { ShowError(ex, "Giải mã thất bại (sai khoá hoặc dữ liệu bị sửa)"); }
    }

    // =====================================================================================
    // 5. FILE
    // =====================================================================================
    private void OnBrowseSource(object sender, EventArgs e)
    {
        using var dlg = new OpenFileDialog { Filter = "Tất cả (*.*)|*.*" };
        if (dlg.ShowDialog(this) == DialogResult.OK) txtSource.Text = dlg.FileName;
    }

    private async void OnCreateTestFile(object sender, EventArgs e)
    {
        long mb = (long)numSizeMb.Value;
        using var dlg = new SaveFileDialog { Filter = "Binary (*.bin)|*.bin", FileName = $"test_{mb}MB.bin" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        string path = dlg.FileName;
        await RunBusy($"Đang tạo file {mb} MB...", async (prog, ct) =>
        {
            TimeSpan t = await Task.Run(() => AesService.CreateRandomFile(path, mb * 1024 * 1024, prog, ct), ct);
            txtSource.Text = path;
            Log($"Đã tạo {path} ({ByteFormat.Bytes(mb * 1024 * 1024)}) trong {t.TotalSeconds:F2} s.");
        });
    }

    private async void OnEncryptFile(object sender, EventArgs e)
    {
        if (!EnsureKey() || !EnsureSource()) return;
        string src = txtSource.Text;
        using var dlg = new SaveFileDialog { Filter = "Encrypted (*.aes)|*.aes|Tất cả (*.*)|*.*", FileName = Path.GetFileName(src) + ".aes", InitialDirectory = Path.GetDirectoryName(src) };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        string dst = dlg.FileName;
        byte[] key = _key;
        await RunBusy("Đang mã hoá...", async (prog, ct) =>
        {
            FileOpResult r = await Task.Run(() => AesService.EncryptFile(src, dst, key, prog, ct), ct);
            Log($"MÃ HOÁ: {src} -> {dst}\r\n   {r}");
        });
    }

    private async void OnDecryptFile(object sender, EventArgs e)
    {
        if (!EnsureKey()) return;
        using var open = new OpenFileDialog { Filter = "Encrypted (*.aes)|*.aes|Tất cả (*.*)|*.*" };
        if (open.ShowDialog(this) != DialogResult.OK) return;
        string src = open.FileName;
        string suggested = src.EndsWith(".aes", StringComparison.OrdinalIgnoreCase) ? Path.GetFileNameWithoutExtension(src) : Path.GetFileName(src);
        using var dlg = new SaveFileDialog { Filter = "Tất cả (*.*)|*.*", FileName = "decrypted_" + suggested, InitialDirectory = Path.GetDirectoryName(src) };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        string dst = dlg.FileName;
        byte[] key = _key;
        await RunBusy("Đang giải mã...", async (prog, ct) =>
        {
            FileOpResult r = await Task.Run(() => AesService.DecryptFile(src, dst, key, prog, ct), ct);
            Log($"GIẢI MÃ: {src} -> {dst}\r\n   {r}");
        });
    }

    private async void OnCompareFiles(object sender, EventArgs e)
    {
        using var a = new OpenFileDialog { Title = "Chọn file NGUỒN" };
        if (a.ShowDialog(this) != DialogResult.OK) return;
        using var b = new OpenFileDialog { Title = "Chọn file ĐÃ GIẢI MÃ", InitialDirectory = Path.GetDirectoryName(a.FileName) };
        if (b.ShowDialog(this) != DialogResult.OK) return;
        string pa = a.FileName, pb = b.FileName;
        await RunBusy("Đang so sánh từng byte...", async (prog, ct) =>
        {
            CompareResult r = await Task.Run(() => AesService.CompareFiles(pa, pb, prog, ct), ct);
            Log($"SO SÁNH: {pa}\r\n      vs {pb}\r\n   => {r}");
        });
    }

    /// <summary>Quy trình thử nghiệm: mã hoá -> giải mã -> so sánh byte. Ghi 1 dòng vào bảng kết quả.</summary>
    private async void OnFullTest(object sender, EventArgs e)
    {
        if (!EnsureKey() || !EnsureSource()) return;
        string src = txtSource.Text;
        string enc = src + ".aes";
        string dec = Path.Combine(Path.GetDirectoryName(src) ?? "", "decrypted_" + Path.GetFileName(src));
        byte[] key = _key;
        long size = new FileInfo(src).Length;

        await RunBusy("Thử nghiệm...", async (prog, ct) =>
        {
            Log($"===== THỬ NGHIỆM: {src} ({ByteFormat.Bytes(size)}), AES-{key.Length * 8} =====");
            SetStatus("1/3 Đang mã hoá...");
            FileOpResult r1 = await Task.Run(() => AesService.EncryptFile(src, enc, key, prog, ct), ct);
            Log($"   Mã hoá : {r1}");

            SetStatus("2/3 Đang giải mã...");
            FileOpResult r2 = await Task.Run(() => AesService.DecryptFile(enc, dec, key, prog, ct), ct);
            Log($"   Giải mã: {r2}");

            SetStatus("3/3 Đang so sánh từng byte...");
            CompareResult r3 = await Task.Run(() => AesService.CompareFiles(src, dec, prog, ct), ct);
            Log($"   So sánh: {r3}");

            grid.Rows.Add(Path.GetFileName(src), ByteFormat.Bytes(size), $"AES-{key.Length * 8}",
                r1.Elapsed.TotalSeconds.ToString("F3"), r1.MBps.ToString("F1"),
                r2.Elapsed.TotalSeconds.ToString("F3"), r2.MBps.ToString("F1"),
                r3.Equal ? "GIỐNG 100%" : r3.ToString(), r3.Elapsed.TotalSeconds.ToString("F3"));
            Log($"   File mã hoá lớn hơn file gốc {r1.OutputBytes - r1.InputBytes} byte (4 byte header + 16 byte IV + padding PKCS7).");
        });
    }

    private void OnExportCsv(object sender, EventArgs e)
    {
        using var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "ket_qua_aes.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", grid.Columns.Cast<DataGridViewColumn>().Select(c => $"\"{c.HeaderText}\"")));
        foreach (DataGridViewRow row in grid.Rows)
            sb.AppendLine(string.Join(",", row.Cells.Cast<DataGridViewCell>().Select(c => $"\"{c.Value}\"")));
        File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
        Log($"Đã xuất kết quả: {dlg.FileName}");
    }

    private bool EnsureSource()
    {
        if (File.Exists(txtSource.Text)) return true;
        MessageBox.Show(this, "Hãy chọn file nguồn (hoặc tạo file test).", "Thiếu file nguồn", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return false;
    }

    // =====================================================================================
    // TIỆN ÍCH
    // =====================================================================================
    private async Task RunBusy(string status, Func<IProgress<double>, CancellationToken, Task> work)
    {
        _cts = new CancellationTokenSource();
        foreach (var c in _busyControls) c.Enabled = false;
        progress.Value = 0;
        SetStatus(status);
        var prog = new Progress<double>(v => progress.Value = Math.Clamp((int)(v * 1000), 0, 1000));
        try
        {
            await work(prog, _cts.Token);
            SetStatus("Hoàn tất.");
        }
        catch (OperationCanceledException) { SetStatus("Đã huỷ."); Log("Đã huỷ thao tác."); }
        catch (Exception ex) { SetStatus("Lỗi."); ShowError(ex); }
        finally
        {
            foreach (var c in _busyControls) c.Enabled = true;
            _cts.Dispose();
            _cts = null;
        }
    }

    private void SetStatus(string s) => lblStatus.Text = s;

    private void Log(string s)
    {
        txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {s}\r\n");
    }

    private void ShowError(Exception ex, string title = "Lỗi")
    {
        Log($"LỖI: {ex.Message}");
        MessageBox.Show(this, ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
