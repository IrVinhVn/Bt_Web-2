using CryptoCore;

namespace Bai2_RSA;

// TAB 3: XEM PEM – GIẢI THÍCH Ý NGHĨA CÁC BYTE (ASN.1 DER)
public sealed partial class MainForm
{
    private readonly TreeView treePem = new() { Dock = DockStyle.Fill, Font = Mono, HideSelection = false };
    private readonly TextBox txtPemNode = MonoBox();
    private readonly TextBox txtPemReport = MonoBox();
    private readonly TextBox txtPemSource = MonoBox(readOnly: false);
    private readonly Label lblPemInfo = new() { AutoSize = true, ForeColor = Color.DarkBlue };
    private PemInspector _inspector;

    private TabPage BuildPemTab()
    {
        var bar = Flow(
            Btn("Mở file PEM...", OnOpenPemToView),
            Btn("Xem public key vừa sinh", (_, _) => { txtPemSource.Text = txtGenPublic.Text; AnalyzePem(); }),
            Btn("Xem private key vừa sinh", (_, _) => { txtPemSource.Text = txtGenPrivate.Text; AnalyzePem(); }),
            Btn("Phân tích nội dung bên dưới", (_, _) => AnalyzePem()),
            lblPemInfo);

        var left = Rows((Lbl("Cây ASN.1 (chọn 1 nút để xem chi tiết byte):"), 0), (treePem, 100));
        var right = Rows((Lbl("Chi tiết nút: Tag – Length – Value"), 0), (txtPemNode, 100));
        var upper = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
        upper.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        upper.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        upper.Controls.Add(left, 0, 0);
        upper.Controls.Add(right, 1, 0);

        var lowerTabs = new TabControl { Dock = DockStyle.Fill };
        var pReport = new TabPage("Báo cáo đầy đủ + hex dump");
        pReport.Controls.Add(txtPemReport);
        var pSrc = new TabPage("Nội dung PEM (có thể dán vào)");
        pSrc.Controls.Add(txtPemSource);
        lowerTabs.TabPages.Add(pReport);
        lowerTabs.TabPages.Add(pSrc);

        treePem.AfterSelect += (_, ev) =>
        {
            if (ev.Node?.Tag is Asn1Node n && _inspector != null) txtPemNode.Text = _inspector.NodeDetails(n).Replace("\n", "\r\n").Replace("\r\r\n", "\r\n");
        };

        var page = new TabPage("3. Xem PEM (ý nghĩa byte)");
        page.Controls.Add(Rows((bar, 0), (upper, 50), (lowerTabs, 50)));
        return page;
    }

    private void OnOpenPemToView(object sender, EventArgs e)
    {
        string text = ReadTextFile(this, "Chọn file PEM", PemFilter, out string path);
        if (text == null) return;
        txtPemSource.Text = text.Replace("\r\n", "\n").Replace("\n", "\r\n");
        AnalyzePem();
        lblPemInfo.Text += "   (" + path + ")";
    }

    private void AnalyzePem()
    {
        try
        {
            _inspector = PemInspector.Parse(txtPemSource.Text);
            treePem.BeginUpdate();
            treePem.Nodes.Clear();
            treePem.Nodes.Add(BuildTree(_inspector.Root));
            treePem.ExpandAll();
            treePem.EndUpdate();
            treePem.SelectedNode = treePem.Nodes[0];
            txtPemReport.Text = _inspector.FullReport().Replace("\r\n", "\n").Replace("\n", "\r\n");
            lblPemInfo.Text = $"Nhãn: {_inspector.Label}  |  Base64: {_inspector.Base64Body.Length} ký tự  |  DER: {_inspector.Der.Length} byte";
        }
        catch (Exception ex) { ShowError(ex, "Không phân tích được PEM"); }
    }

    private static TreeNode BuildTree(Asn1Node n)
    {
        string summary = n.ValueSummary();
        string text = $"[{n.Offset:D4}] {PemInspector.Hex(n.HeaderBytes)} {n.TagName} ({n.ContentLength} B)"
                      + (string.IsNullOrEmpty(n.Meaning) ? "" : "  ← " + n.Meaning)
                      + (n.Tag == 0x02 && n.ContentLength <= 8 ? "  " + summary : "");
        var t = new TreeNode(text) { Tag = n };
        foreach (var c in n.Children) t.Nodes.Add(BuildTree(c));
        return t;
    }
}
