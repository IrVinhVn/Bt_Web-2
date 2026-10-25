using System.Text;
using CryptoCore;

namespace Bai2_RSA;

// TAB 7: ĐÁNH GIÁ TỐC ĐỘ – khoá công khai (n, e nhỏ) vs khoá bí mật (n, d rất lớn)
public sealed partial class MainForm
{
    private readonly CheckedListBox clbBenchSizes = new() { CheckOnClick = true, Height = 70, Width = 110, IntegralHeight = false };
    private readonly NumericUpDown numBenchIter = new() { Minimum = 10, Maximum = 100000, Value = 200, Increment = 50, Width = 80 };
    private readonly DataGridView gridBench = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
    };
    private readonly TextBox txtBenchLog = MonoBox(wrap: true);
    private Button btnBench;
    private List<RsaService.BenchRow> _benchRows;

    private TabPage BuildBenchTab()
    {
        clbBenchSizes.Items.AddRange(new object[] { 1024, 2048, 3072, 4096 });
        clbBenchSizes.SetItemChecked(0, true);
        clbBenchSizes.SetItemChecked(1, true);
        clbBenchSizes.SetItemChecked(2, true);

        btnBench = Btn("7. Chạy đánh giá tốc độ", OnRunBench);
        var bar = Flow(Lbl("Kích thước khoá:"), clbBenchSizes, Lbl("Số lần lặp mỗi phép:"), numBenchIter, btnBench,
                       Btn("Xuất CSV...", OnExportBench));

        gridBench.Columns.Add("bits", "Khoá");
        gridBench.Columns.Add("op", "Phép toán");
        gridBench.Columns.Add("key", "Khoá dùng");
        gridBench.Columns.Add("exp", "Số mũ (bit)");
        gridBench.Columns.Add("avg", "TB (ms/lần)");
        gridBench.Columns.Add("ops", "Lần/giây");
        gridBench.Columns.Add("ratio", "Chậm hơn public ×");
        gridBench.Columns["op"].FillWeight = 220;
        gridBench.Columns["key"].FillWeight = 160;

        var page = new TabPage("7. Tốc độ public vs private");
        page.Controls.Add(Rows((bar, 0), (gridBench, 60), (Group("Nhật ký & nhận xét", txtBenchLog), 40)));
        return page;
    }

    private async void OnRunBench(object sender, EventArgs e)
    {
        int[] sizes = clbBenchSizes.CheckedItems.Cast<int>().ToArray();
        if (sizes.Length == 0) return;
        int iter = (int)numBenchIter.Value;
        btnBench.Enabled = false;
        gridBench.Rows.Clear();
        txtBenchLog.Clear();
        var log = new Progress<string>(s => txtBenchLog.AppendText(s + "\r\n"));
        try
        {
            _benchRows = await Task.Run(() => RsaService.Benchmark(sizes, iter, log));
            FillBenchGrid(_benchRows);
            txtBenchLog.AppendText("\r\n" + Crlf(BenchConclusion(_benchRows)));
        }
        catch (Exception ex) { ShowError(ex); }
        finally { btnBench.Enabled = true; }
    }

    private void FillBenchGrid(List<RsaService.BenchRow> rows)
    {
        foreach (var g in rows.GroupBy(r => r.KeyBits))
        {
            // Mốc so sánh: phép toán cùng loại dùng khoá công khai
            double encAvg = g.First(r => r.Operation.StartsWith("Mã hoá")).AvgMs;
            double verAvg = g.First(r => r.Operation.StartsWith("Xác minh")).AvgMs;
            double rawPub = g.First(r => r.Operation.Contains("m^e")).AvgMs;
            foreach (var r in g)
            {
                double baseline = r.Operation.StartsWith("Giải mã") ? encAvg
                                : r.Operation.StartsWith("Ký") ? verAvg
                                : r.Operation.Contains("c^d") ? rawPub : r.AvgMs;
                gridBench.Rows.Add($"RSA-{r.KeyBits}", r.Operation, r.KeyUsed, r.ExponentBits,
                    r.AvgMs.ToString("F4"), r.OpsPerSecond.ToString("N0"), (r.AvgMs / baseline).ToString("F1"));
            }
        }
    }

    internal static string BenchConclusion(List<RsaService.BenchRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("NHẬN XÉT (tự động từ số liệu đo được):");
        foreach (var g in rows.GroupBy(r => r.KeyBits))
        {
            double enc = g.First(r => r.Operation.StartsWith("Mã hoá")).AvgMs;
            double dec = g.First(r => r.Operation.StartsWith("Giải mã")).AvgMs;
            double rawE = g.First(r => r.Operation.Contains("m^e")).AvgMs;
            double rawD = g.First(r => r.Operation.Contains("không CRT")).AvgMs;
            double rawCrt = g.First(r => r.Operation.Contains("có CRT")).AvgMs;
            sb.AppendLine($" • RSA-{g.Key}: giải mã (private) chậm hơn mã hoá (public) {dec / enc:F1} lần; " +
                          $"ModPow thô với d chậm hơn với e {rawD / rawE:F0} lần; CRT nhanh hơn không CRT {rawD / rawCrt:F1} lần.");
        }
        sb.AppendLine(" • Lý do: e = 65537 chỉ có 17 bit (2 bit 1) → ~17 phép bình phương + 1 phép nhân.");
        sb.AppendLine("   d dài xấp xỉ n (vd 2048 bit) → ~2048 bình phương + ~1024 phép nhân: nhiều hơn hàng trăm lần.");
        sb.AppendLine(" • Lý thuyết: khoá dài gấp đôi → thao tác public chậm ~4 lần (O(k²)), private chậm ~8 lần (O(k³)); thực đo thường thấp hơn do chi phí cố định.");
        sb.AppendLine(" • Hệ quả thực tế: mã hoá / xác minh chữ ký (public) rất nhanh; giải mã / ký (private) chậm hơn nhiều.");
        return sb.ToString();
    }

    private void OnExportBench(object sender, EventArgs e)
    {
        if (_benchRows == null) return;
        using var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "rsa_benchmark.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var sb = new StringBuilder("KeyBits,Operation,KeyUsed,ExponentBits,Iterations,AvgMs,OpsPerSecond\n");
        foreach (var r in _benchRows)
            sb.AppendLine($"{r.KeyBits},\"{r.Operation}\",\"{r.KeyUsed}\",{r.ExponentBits},{r.Iterations},{r.AvgMs:F4},{r.OpsPerSecond:F0}");
        File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
    }
}
