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