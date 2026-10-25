# Bài tập An toàn và Bảo mật Thông tin – Kết quả

## Bài 1 – Mã hoá AES (đối xứng: mã hoá và giải mã dùng chung 1 khoá)

| Yêu cầu | Cách làm trong app |
|---|---|
| 1. Sinh khoá AES | `RandomNumberGenerator` (CSPRNG), chọn 128/192/256 bit |
| 2. Lưu khoá ra file | File `.key` chứa khoá dạng Base64 |
| 3. Import khoá từ file | Đọc Base64 / Hex / nhị phân 16-24-32 byte |
| 4. Mã hoá đoạn văn bản → màn hình | `Base64(IV ‖ ciphertext)`, có nút giải mã ngược lại |
| 5. Mã hoá file → lưu file | Định dạng: `"AES1"` (4 byte) ‖ IV (16 byte) ‖ ciphertext |
| Thử nghiệm file lớn (GB) | Nút *Tạo file test* (MB tuỳ chọn) → *Thử nghiệm đầy đủ*: mã hoá → giải mã → so sánh từng byte (với cả 3 độ dài khoá 128/192/256 bit), ghi vào bảng, xuất CSV |

Thuật toán: **AES-CBC + PKCS7, IV ngẫu nhiên mỗi lần**, xử lý **dạng luồng** (`CryptoStream`, bộ đệm 4 MB) nên file nhiều GB vẫn chỉ tốn vài MB RAM. Thời gian đo bằng `Stopwatch`. So sánh byte đọc song song 2 file theo khối 4 MB, báo vị trí byte khác đầu tiên nếu có.

### Số liệu thử nghiệm

| File nguồn | Kích thước | Khoá | Mã hoá (s) | Tốc độ MH (MB/s) | Giải mã (s) | Tốc độ GM (MB/s) | So sánh byte | T. so sánh (s) | Δ kích thước |
|:---|---:|:---:|---:|---:|---:|---:|:---:|---:|---:|
| `test_100MB.bin` | 100,00 MB | AES-128 | 0,140 | 713,8 | 0,094 | 1059,8 | GIỐNG 100% | 0,058 | +36 B |
| `test_100MB.bin` | 100,00 MB | AES-192 | 0,196 | 509,4 | 0,167 | 600,0 | GIỐNG 100% | 0,095 | +36 B |
| `test_100MB.bin` | 100,00 MB | AES-256 | 0,183 | 546,6 | 0,143 | 700,3 | GIỐNG 100% | 0,054 | +36 B |
| `test_1024MB.bin` | 1,00 GB | AES-128 | 1,614 | 634,5 | 1,582 | 647,1 | GIỐNG 100% | 0,607 | +36 B |
| `test_1024MB.bin` | 1,00 GB | AES-192 | 1,951 | 524,8 | 1,309 | 782,1 | GIỐNG 100% | 0,616 | +36 B |
| `test_1024MB.bin` | 1,00 GB | AES-256 | 2,542 | 402,9 | 1,299 | 788,3 | GIỐNG 100% | 0,586 | +36 B |
| `test_2048MB.bin` | 2,00 GB | AES-128 | 3,485 | 587,7 | 3,417 | 599,4 | GIỐNG 100% | 1,449 | +36 B |
| `test_2048MB.bin` | 2,00 GB | AES-192 | 4,206 | 486,9 | 3,738 | 547,9 | GIỐNG 100% | 1,607 | +36 B |
| `test_2048MB.bin` | 2,00 GB | AES-256 | 4,093 | 500,4 | 3,618 | 566,0 | GIỐNG 100% | 1,561 | +36 B |
| `test_4096MB.bin` | 4,00 GB | AES-128 | 8,522 | 480,7 | 7,837 | 522,7 | GIỐNG 100% | 3,038 | +36 B |
| `test_4096MB.bin` | 4,00 GB | AES-192 | 9,294 | 440,7 | 8,654 | 473,3 | GIỐNG 100% | 3,057 | +36 B |
| `test_4096MB.bin` | 4,00 GB | AES-256 | 8,757 | 467,7 | 8,756 | 467,8 | GIỐNG 100% | 3,204 | +36 B |

### Kết luận Bài 1

1. **Đúng đắn:** Ở mọi kích thước (100 MB → 4 GB) và mọi độ dài khoá (128, 192, 256 bit), file giải mã **giống file nguồn 100% theo từng byte** ⇒ AES là phép biến đổi không mất mát; cùng một khoá vừa mã hoá vừa giải mã được.
2. **Thời gian tăng tuyến tính theo kích thước** (≈ 1,6–2,3 s/GB khi mã hoá, ≈ 1,3–2,1 s/GB khi giải mã trên máy đo): tốc độ duy trì quanh mức ~400–715 MB/s khi mã hoá và ~465–1060 MB/s khi giải mã ⇒ độ phức tạp O(n). Thời gian so sánh byte cũng tăng tuyến tính rất đều (~0,6 s cho 1 GB, ~1,5 s cho 2 GB và ~3,1 s cho 4 GB).
3. **Ảnh hưởng của độ dài khoá:** AES-128 (10 vòng lặp) luôn đạt tốc độ nhanh nhất ở mọi mức dung lượng (ví dụ ở 100 MB đạt 713,8 MB/s mã hoá và 1059,8 MB/s giải mã). AES-192 (12 vòng) và AES-256 (14 vòng) chậm hơn khoảng 10–30% do số vòng biến đổi nhiều hơn; riêng ở file lớn (2 GB, 4 GB), khoảng cách tốc độ giữa 3 loại khoá thu hẹp lại do bị giới hạn bởi tốc độ đọc/ghi ổ cứng.
4. **Giải mã nhanh hơn mã hoá** (nhất là ở file 100 MB – 1 GB, nhanh hơn tới ~1,3–1,9 lần): ở chế độ CBC, mã hoá khối i phải chờ kết quả của khối i-1 (xử lý tuần tự), còn khi giải mã các khối có thể tính toán độc lập nên tập lệnh phần cứng CPU (AES-NI) xử lý song song được nhiều khối cùng lúc.
5. **Kích thước tăng cố định 36 byte** dù file 100 MB hay 4 GB: 4 byte header + 16 byte IV + 16 byte padding PKCS7 (file test là bội số của 16 nên padding thêm nguyên 1 khối; nói chung padding 1–16 byte).
6. **Với file lớn, ổ đĩa mới là nút cổ chai:** Tốc độ giảm dần khi kích thước file tăng từ 100 MB lên 4 GB (ví dụ AES-128 giảm từ 713,8 MB/s xuống 480,7 MB/s, và ở 4 GB tốc độ mã hoá/giải mã của AES-256 xấp xỉ nhau ~467,7 MB/s) do bộ nhớ đệm (RAM cache) của hệ điều hành bị lấp đầy và chương trình phải chờ tốc độ ghi thực tế của ổ đĩa; nhờ xử lý dạng luồng (`CryptoStream`) nên dung lượng RAM tiêu thụ của app không tăng theo kích thước file.
7. **Đánh giá chung:** AES rất nhanh (hàng trăm MB/s đến hơn 1 GB/s) ⇒ cực kỳ phù hợp để mã hoá dữ liệu lớn. Hạn chế: chế độ CBC thuần tuý không phát hiện được dữ liệu bị sửa đổi trên đường truyền — thực tế nên dùng AES-GCM hoặc kết hợp thêm HMAC; và **vấn đề phân phối khoá đối xứng** → dẫn tới Bài 2 (dùng RSA để bọc khoá AES).

---

## Bài 2 – RSA, SHA-256 và Chữ ký số

| Yêu cầu | Tab trong app | Kết quả |
|---|---|---|
| 1-2. Sinh cặp khoá, xuất PEM | **1-2** | RSA 1024/2048/3072/4096 bit; PEM dạng PKCS#1 hoặc X.509 SPKI / PKCS#8 |
| 3. View PEM + ý nghĩa byte | **3** | Cây ASN.1/DER: Tag, Length (ngắn/dài), Value; gán nhãn n, e, d, p, q, dP, dQ, qInv, OID rsaEncryption |
| 4. Nhập PEM | **4** | Public → n, e; Private → n, e, d, p, q, dP, dQ, qInv |
| 5-6. Mã hoá ≤ 190 byte, giải mã, so sánh | **5-6** | OAEP-SHA256: RSA-2048 mã hoá tối đa 256 − 66 = **190 byte**, bản mã luôn 256 byte; giải mã **giống dữ liệu gốc 100%** |
| 7. Tốc độ public vs private | **7** | Bảng bên dưới |
| 8. SHA-256 | **8** | Bảng bên dưới |
| 9. Chữ ký số | **9** | Bảng bên dưới |

### Tốc độ: khoá công khai (e nhỏ) vs khoá bí mật (d lớn)

> Đo bằng `CryptoBench rsa` (giống tab 7), trung vị của 3 lần chạy (200/500/500 lần lặp mỗi phép).

| Khoá | Mã hoá (public) | Giải mã (private, CRT) | Chậm hơn | m^e mod n | c^d mod n (không CRT) | c^d (CRT) |
|---|---:|---:|---:|---:|---:|---:|
| RSA-1024 | 0,0051 ms | 0,096 ms | ×19 | 0,043 ms | 3,88 ms | 2,64 ms |
| RSA-2048 | 0,0163 ms | 0,730 ms | ×45 | 0,117 ms | 23,9 ms | 6,94 ms |
| RSA-3072 | 0,0333 ms | 1,829 ms | ×55 | 0,261 ms | 67,2 ms | 19,9 ms |
| RSA-4096 | 0,0568 ms | 3,795 ms | ×67 | 0,378 ms | 147,3 ms | 49,2 ms |

Kết luận:

1. **Khoá công khai nhanh hơn khoá bí mật rất nhiều**: e = 65537 chỉ 17 bit, còn d dài ≈ n (≈ 2048 bit với RSA-2048). Với phép lũy thừa thô, `c^d` chậm hơn `m^e` **~90–390 lần**; với thư viện .NET, giải mã chậm hơn mã hoá **19–67 lần**.
2. **CRT** (tính theo p, q nửa độ dài) giúp `c^d` nhanh hơn ~3–3,5 lần với khoá ≥ 2048 bit.
3. **Gấp đôi độ dài khoá**: thao tác public chậm ~3–3,5 lần, thao tác private chậm ~5–8 lần (lý thuyết ×4 và ×8).
4. Hệ quả: mã hoá và xác minh chữ ký (public) rẻ; giải mã và ký (private) đắt. RSA chỉ nên dùng cho dữ liệu nhỏ (bọc khoá AES 32 byte, ký giá trị băm 32 byte).

### SHA-256 – thay đổi rất nhỏ ở đầu vào

```
"An toan va bao mat thong tin" → 12b7ec56323f93e1c7ae163939d6e7f72da4c7fb8493052b0b3ddaab0fa6fd5f
"An toan va bao mat thong tim" → fcd1cc0e37447fe9676cdde717567bc974cc55441960de9e10c373844ba59707
→ đổi 1 ký tự: 128/256 bit khác (50%), 58/64 ký tự hex khác
```

| Thử nghiệm thác lũ (10 000 lần, đảo 1 bit đầu vào) | Kết quả | Lý thuyết |
|---|---:|---:|
| Số bit đầu ra thay đổi trung bình | 127,95/256 (49,98%) | 128 (50%) |
| Nhỏ nhất / lớn nhất | 96 / 164 | – |
| Độ lệch chuẩn | 7,94 | 8 |

Nhận xét: chỉ đổi 1 bit đầu vào, **khoảng một nửa số bit đầu ra thay đổi** (hiệu ứng thác lũ) ⇒ không thể sửa dữ liệu mà giữ nguyên giá trị băm.

### Chữ ký số – cùng dữ liệu, cùng người ký nhưng mỗi lần ký ra chữ ký khác nhau

Kết quả ký 5 lần cùng dữ liệu, cùng khoá RSA-2048:

| Phương pháp | Số chữ ký khác nhau | Xác minh |
|---|:---:|:---:|
| PKCS#1 v1.5 (tất định) | **1/5** | đúng |
| RSA-PSS (đề xuất 1) | **5/5** | tất cả đúng |
| Nonce + Timestamp (đề xuất 2) | **5/5** | tất cả đúng |

* Ký thủ công `s = EM^d mod n` bằng BigInteger **trùng khớp** với chữ ký PKCS#1 của .NET.
* Dữ liệu khác nhau 1 ký tự → chữ ký khác ~1000/2048 bit (≈ 50%); sửa dữ liệu sau khi ký → xác minh **SAI**.

**Đề xuất:**

1. **RSA-PSS (khuyến nghị, chuẩn RFC 8017):** mỗi lần ký sinh `salt` ngẫu nhiên 32 byte, `EM = maskedDB ‖ SHA256(0x00×8 ‖ SHA256(m) ‖ salt) ‖ 0xBC`, `s = EM^d mod n`. Salt nằm ẩn trong chữ ký, người xác minh tự khôi phục được, không cần gửi kèm.
2. **Nonce + dấu thời gian (tự thiết kế):** `h = SHA256(nonce ‖ t ‖ m)`, `s = Sign_PKCS1(h)`, gửi `(m, nonce, t, s)`. Dễ hiểu, chống phát lại, nhưng phải gửi kèm nonce, t và không phải chuẩn.

**Kết luận:** dùng **RSA-PSS** — cùng dữ liệu, cùng người ký, mỗi lần ký ra chữ ký khác nhau nhưng tất cả đều xác minh đúng bằng cùng một khoá công khai.