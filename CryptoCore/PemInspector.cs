using System.Numerics;
using System.Text;

namespace CryptoCore;

/// <summary>Một nút trong cây ASN.1 DER (TLV = Tag - Length - Value).</summary>
public sealed class Asn1Node
{
    public int Offset { get; init; }          // vị trí byte Tag trong DER
    public int HeaderLength { get; init; }    // số byte Tag + Length
    public int ContentLength { get; init; }   // số byte Value
    public byte Tag { get; init; }
    public int Depth { get; init; }
    public byte[] Der { get; init; }
    public List<Asn1Node> Children { get; } = new();
    /// <summary>Với BIT STRING / OCTET STRING bọc dữ liệu DER bên trong.</summary>
    public bool Encapsulates { get; set; }
    public string Meaning { get; set; } = "";

    public int ContentOffset => Offset + HeaderLength;
    public int TotalLength => HeaderLength + ContentLength;
    public bool IsConstructed => (Tag & 0x20) != 0;
    public ReadOnlySpan<byte> Content => Der.AsSpan(ContentOffset, ContentLength);
    public ReadOnlySpan<byte> HeaderBytes => Der.AsSpan(Offset, HeaderLength);

    public string TagName => Tag switch
    {
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0x30 => "SEQUENCE",
        0x31 => "SET",
        0xA0 => "[0] (context)",
        0xA1 => "[1] (context)",
        _ => $"TAG 0x{Tag:X2}"
    };

    /// <summary>Mô tả ngắn giá trị (số nguyên, OID, ...).</summary>
    public string ValueSummary()
    {
        switch (Tag)
        {
            case 0x02:
            {
                var v = new BigInteger(Content, isUnsigned: false, isBigEndian: true);
                long bits = (long)v.GetBitLength();
                string lead = ContentLength > 1 && Content[0] == 0x00
                    ? " (byte 00 đầu tiên chỉ để đánh dấu số dương vì bit cao nhất của byte kế tiếp = 1)" : "";
                return ContentLength <= 8 ? $"= {v} ({bits} bit){lead}" : $"số {bits} bit{lead}";
            }
            case 0x06:
                string oid = PemInspector.DecodeOid(Content);
                return PemInspector.OidName(oid) is { } name ? $"{oid} = {name}" : oid;
            case 0x05:
                return "(không có giá trị – tham số thuật toán rỗng)";
            case 0x03:
                return $"unused bits = {(ContentLength > 0 ? Content[0] : 0)}" + (Encapsulates ? ", bên trong chứa cấu trúc DER" : "");
            case 0x04:
                return Encapsulates ? "bên trong chứa cấu trúc DER" : $"{ContentLength} byte";
            default:
                return IsConstructed ? $"{Children.Count} phần tử" : "";
        }
    }

    public override string ToString() =>
        $"[{Offset:D4}] {TagName} (len {ContentLength}) {(string.IsNullOrEmpty(Meaning) ? "" : "– " + Meaning)}";
}

/// <summary>
/// Phân tích file PEM và giải thích ý nghĩa từng byte.
/// PEM = "-----BEGIN &lt;LABEL&gt;-----" + Base64(DER) + "-----END &lt;LABEL&gt;-----".
/// DER là mã hoá nhị phân của cấu trúc ASN.1, mỗi phần tử gồm: Tag (1 byte) | Length (1..n byte) | Value.
/// </summary>
public sealed class PemInspector
{
    public string Label { get; private set; }
    public string Base64Body { get; private set; }
    public byte[] Der { get; private set; }
    public Asn1Node Root { get; private set; }

    public static PemInspector Parse(string pem)
    {
        const string begin = "-----BEGIN ";
        int b = pem.IndexOf(begin, StringComparison.Ordinal);
        if (b < 0) throw new FormatException("Không tìm thấy dòng -----BEGIN ...-----");
        int labelStart = b + begin.Length;
        int labelEnd = pem.IndexOf("-----", labelStart, StringComparison.Ordinal);
        string label = pem.Substring(labelStart, labelEnd - labelStart);
        string endMarker = "-----END " + label + "-----";
        int bodyStart = labelEnd + 5;
        int e = pem.IndexOf(endMarker, bodyStart, StringComparison.Ordinal);
        if (e < 0) throw new FormatException("Không tìm thấy dòng " + endMarker);

        string body = new string(pem.Substring(bodyStart, e - bodyStart).Where(ch => !char.IsWhiteSpace(ch)).ToArray());
        byte[] der = Convert.FromBase64String(body);

        var insp = new PemInspector { Label = label, Base64Body = body, Der = der };
        insp.Root = ParseNode(der, 0, der.Length, 0, out int consumed);
        if (consumed != der.Length) throw new FormatException("Dữ liệu DER thừa byte ở cuối.");
        insp.AssignMeanings();
        return insp;
    }

    // ------------------------------------------------------------------ Bộ phân tích DER
    private static Asn1Node ParseNode(byte[] der, int offset, int limit, int depth, out int consumed)
    {
        if (offset + 2 > limit) throw new FormatException($"DER bị cắt cụt tại offset {offset}.");
        byte tag = der[offset];
        if ((tag & 0x1F) == 0x1F) throw new FormatException("Không hỗ trợ tag dạng nhiều byte.");
        int pos = offset + 1;
        int lenByte = der[pos++];
        int length;
        if (lenByte < 0x80)
        {
            length = lenByte;                         // dạng ngắn: 1 byte
        }
        else
        {
            int count = lenByte & 0x7F;               // dạng dài: 0x8N + N byte độ dài
            if (count == 0 || count > 4 || pos + count > limit) throw new FormatException($"Độ dài không hợp lệ tại offset {offset}.");
            length = 0;
            for (int i = 0; i < count; i++) length = (length << 8) | der[pos++];
        }
        int header = pos - offset;
        if (pos + length > limit) throw new FormatException($"Độ dài vượt quá dữ liệu tại offset {offset}.");

        var node = new Asn1Node { Offset = offset, HeaderLength = header, ContentLength = length, Tag = tag, Depth = depth, Der = der };

        if (node.IsConstructed)
        {
            int p = pos, end = pos + length;
            while (p < end)
            {
                node.Children.Add(ParseNode(der, p, end, depth + 1, out int used));
                p += used;
            }
        }
        else if (tag == 0x03 && length > 1 && der[pos] == 0x00 && der[pos + 1] == 0x30)
        {
            TryEncapsulated(node, der, pos + 1, pos + length, depth);
        }
        else if (tag == 0x04 && length > 0 && der[pos] == 0x30)
        {
            TryEncapsulated(node, der, pos, pos + length, depth);
        }

        consumed = header + length;
        return node;
    }

    private static void TryEncapsulated(Asn1Node node, byte[] der, int start, int end, int depth)
    {
        try
        {
            var inner = ParseNode(der, start, end, depth + 1, out int used);
            if (start + used == end) { node.Children.Add(inner); node.Encapsulates = true; }
        }
        catch (FormatException) { /* không phải DER lồng – coi như dữ liệu thô */ }
    }

    // ------------------------------------------------------------------ Gán ý nghĩa theo chuẩn
    private void AssignMeanings()
    {
        switch (Label)
        {
            case "RSA PUBLIC KEY":
                Root.Meaning = "RSAPublicKey (PKCS#1, RFC 8017 A.1.1)";
                LabelRsaPublic(Root);
                break;
            case "RSA PRIVATE KEY":
                Root.Meaning = "RSAPrivateKey (PKCS#1, RFC 8017 A.1.2)";
                LabelRsaPrivate(Root);
                break;
            case "PUBLIC KEY":
                Root.Meaning = "SubjectPublicKeyInfo (X.509, RFC 5280)";
                if (Root.Children.Count >= 2)
                {
                    LabelAlgId(Root.Children[0]);
                    var bitStr = Root.Children[1];
                    bitStr.Meaning = "subjectPublicKey – BIT STRING chứa RSAPublicKey";
                    if (bitStr.Children.Count == 1)
                    {
                        bitStr.Children[0].Meaning = "RSAPublicKey (PKCS#1)";
                        LabelRsaPublic(bitStr.Children[0]);
                    }
                }
                break;
            case "PRIVATE KEY":
                Root.Meaning = "PrivateKeyInfo (PKCS#8, RFC 5208)";
                if (Root.Children.Count >= 3)
                {
                    Root.Children[0].Meaning = "version = 0";
                    LabelAlgId(Root.Children[1]);
                    var oct = Root.Children[2];
                    oct.Meaning = "privateKey – OCTET STRING chứa RSAPrivateKey";
                    if (oct.Children.Count == 1)
                    {
                        oct.Children[0].Meaning = "RSAPrivateKey (PKCS#1)";
                        LabelRsaPrivate(oct.Children[0]);
                    }
                }
                break;
            default:
                Root.Meaning = "Cấu trúc không phải khoá RSA đã biết";
                break;
        }
    }

    private static void LabelAlgId(Asn1Node algId)
    {
        algId.Meaning = "AlgorithmIdentifier – cho biết loại khoá";
        if (algId.Children.Count > 0) algId.Children[0].Meaning = "algorithm (OID)";
        if (algId.Children.Count > 1) algId.Children[1].Meaning = "parameters = NULL";
    }

    private static void LabelRsaPublic(Asn1Node seq)
    {
        string[] names = { "n – modulus", "e – publicExponent" };
        for (int i = 0; i < seq.Children.Count && i < names.Length; i++) seq.Children[i].Meaning = names[i];
    }

    private static void LabelRsaPrivate(Asn1Node seq)
    {
        string[] names =
        {
            "version (0 = two-prime)", "n – modulus", "e – publicExponent", "d – privateExponent",
            "p – prime1", "q – prime2", "dP = d mod (p-1) – exponent1", "dQ = d mod (q-1) – exponent2",
            "qInv = q^-1 mod p – coefficient"
        };
        for (int i = 0; i < seq.Children.Count && i < names.Length; i++) seq.Children[i].Meaning = names[i];
    }

    // ------------------------------------------------------------------ OID
    public static string DecodeOid(ReadOnlySpan<byte> content)
    {
        if (content.Length == 0) return "";
        var parts = new List<string>();
        int first = content[0];
        parts.Add((first / 40).ToString());
        parts.Add((first % 40).ToString());
        long value = 0;
        for (int i = 1; i < content.Length; i++)
        {
            value = (value << 7) | (long)(content[i] & 0x7F);
            if ((content[i] & 0x80) == 0) { parts.Add(value.ToString()); value = 0; }
        }
        return string.Join(".", parts);
    }

    public static string OidName(string oid) => oid switch
    {
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        _ => null
    };

    // ------------------------------------------------------------------ Báo cáo dạng văn bản
    public IEnumerable<Asn1Node> Flatten()
    {
        var stack = new Stack<Asn1Node>();
        stack.Push(Root);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            yield return n;
            for (int i = n.Children.Count - 1; i >= 0; i--) stack.Push(n.Children[i]);
        }
    }

    public static string Hex(ReadOnlySpan<byte> bytes, int max = int.MaxValue)
    {
        var sb = new StringBuilder();
        int n = Math.Min(bytes.Length, max);
        for (int i = 0; i < n; i++) { if (i > 0) sb.Append(' '); sb.Append(bytes[i].ToString("X2")); }
        if (bytes.Length > max) sb.Append($" ... (+{bytes.Length - max} byte)");
        return sb.ToString();
    }

    public static string ExplainHeader(Asn1Node node)
    {
        var h = node.HeaderBytes;
        string tagExplain = $"{h[0]:X2} = {node.TagName}" + (node.IsConstructed ? " (constructed: bit 0x20 = 1 → chứa phần tử con)" : "");
        string lenExplain = h[1] < 0x80
            ? $"{h[1]:X2} = độ dài dạng ngắn: {node.ContentLength} byte"
            : $"{Hex(h.Slice(1))} = độ dài dạng dài: 0x{h[1]:X2} → {h[1] & 0x7F} byte độ dài tiếp theo = {node.ContentLength} byte";
        return $"Tag  : {tagExplain}\r\nLength: {lenExplain}";
    }

    public string NodeDetails(Asn1Node node)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{node.TagName}  –  {node.Meaning}");
        sb.AppendLine($"Offset {node.Offset} .. {node.Offset + node.TotalLength - 1}  (header {node.HeaderLength} byte + value {node.ContentLength} byte)");
        sb.AppendLine(ExplainHeader(node));
        string summary = node.ValueSummary();
        if (summary.Length > 0) sb.AppendLine($"Giá trị: {summary}");
        if (!node.IsConstructed)
        {
            sb.AppendLine("Value (hex):");
            sb.AppendLine(HexDump(node.Content, node.ContentOffset));
        }
        return sb.ToString();
    }

    public static string HexDump(ReadOnlySpan<byte> data, int baseOffset = 0, int perLine = 16)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += perLine)
        {
            int n = Math.Min(perLine, data.Length - i);
            sb.Append((baseOffset + i).ToString("X4")).Append(": ");
            sb.Append(Hex(data.Slice(i, n)).PadRight(perLine * 3));
            sb.Append(' ');
            for (int j = 0; j < n; j++) { byte c = data[i + j]; sb.Append(c >= 32 && c < 127 ? (char)c : '.'); }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public string FullReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine("================ CẤU TRÚC FILE PEM ================");
        sb.AppendLine($"Dòng đầu : -----BEGIN {Label}-----   (nhãn cho biết loại dữ liệu)");
        sb.AppendLine($"Thân     : {Base64Body.Length} ký tự Base64 (mỗi 4 ký tự = 3 byte) → {Der.Length} byte DER");
        sb.AppendLine($"Dòng cuối: -----END {Label}-----");
        sb.AppendLine();
        sb.AppendLine(Label switch
        {
            "RSA PUBLIC KEY" => "Định dạng PKCS#1 public key: SEQUENCE { n, e }",
            "PUBLIC KEY" => "Định dạng X.509 SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier{rsaEncryption, NULL}, BIT STRING{ SEQUENCE{n, e} } }",
            "RSA PRIVATE KEY" => "Định dạng PKCS#1 private key: SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }",
            "PRIVATE KEY" => "Định dạng PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING{ RSAPrivateKey } }",
            _ => ""
        });
        sb.AppendLine();
        sb.AppendLine("================ GIẢI THÍCH TỪNG PHẦN TỬ (TLV) ================");
        foreach (var node in Flatten())
        {
            string indent = new string(' ', node.Depth * 4);
            sb.AppendLine($"{indent}[offset {node.Offset,4}] {Hex(node.HeaderBytes)}  →  {node.TagName}, {node.ContentLength} byte  –  {node.Meaning}");
            string summary = node.ValueSummary();
            if (summary.Length > 0) sb.AppendLine($"{indent}      {summary}");
            if (!node.IsConstructed && !node.Encapsulates)
                sb.AppendLine($"{indent}      value: {Hex(node.Content, 24)}");
        }
        sb.AppendLine();
        sb.AppendLine("Ghi chú về Length: < 0x80 → 1 byte chứa trực tiếp độ dài; 0x81 → 1 byte độ dài theo sau; 0x82 → 2 byte độ dài theo sau.");
        sb.AppendLine("Ghi chú về INTEGER: DER dùng số có dấu (bù 2), nên nếu bit cao nhất = 1 phải thêm byte 0x00 ở đầu.");
        sb.AppendLine();
        sb.AppendLine("================ HEX DUMP TOÀN BỘ DER ================");
        sb.Append(HexDump(Der));
        return sb.ToString();
    }
}
