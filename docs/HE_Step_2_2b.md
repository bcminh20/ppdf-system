# Bước 2.2b — Trích xuất đặc trưng và mã hóa HE

Đầu vào là thư mục `Data Forensic lọc sạch` và `public_key.json` đã có trong repo. Chương trình `ppdf_extract_encrypt.py` xác minh SHA-256 theo manifest, tạo `V_i = [Số_từ_khóa, Điểm_ẩn_giấu]`, rồi áp dụng công thức Algorithm 2 trong paper (trang 142406). Module mã hóa không đọc `.env` và không tạo lại khóa.

## Kết quả chạy trên bộ bàn giao

Đã chạy ngày 15/11/2026 bằng môi trường conda `sage` (Python 3.11.11, SymPy 1.13.3), dùng public key hiện có và `n=8`:

| Hạng mục | Kết quả |
|---|---:|
| File trong manifest đã xác minh trước và sau xử lý | 203, toàn bộ khớp |
| Đối tượng có bảng điểm | 347 |
| Đối tượng khớp OR được mã hóa | 285 |
| Đối tượng 0 từ khóa, lưu trong audit | 62 |
| Đối tượng có byte được xuất cục bộ | 97 |
| Đối tượng chỉ có hit nguồn, chưa có byte cục bộ | 250 |
| Bản sao đổi đuôi/giữ nguyên tên đã gộp về bản xuất gốc | 81 |
| Ciphertext bit trong `Cr'_kwt` | 4.560 |

285 đối tượng mã hóa gồm PC 235, RM1 12 và RM2 38. Trong đó có đủ 271 đường dẫn nguồn từ bộ lọc Autopsy; phần bổ sung đến từ đường dẫn/nội dung bản xuất RM1 và PC. Đây là số đối tượng pháp chứng, bao gồm file slack và file tạm, không phải số tài liệu chính có nội dung khác nhau. Cả 17 tài liệu RM2 đổi đuôi có `V_i = [2, 5]`; ví dụ `proposal/landscape.png`.

Kết quả chi tiết nằm cục bộ tại `outputs/he_step_2_2b/`: bảng điểm `audit/features.csv`, bản mã `share/Cr_kwt_prime.json` và thống kê `audit/run_summary.json`. Dữ liệu gốc và kết quả chạy được Git bỏ qua; chạy lại chương trình sau khi đặt bộ bàn giao vào máy để tạo các file này. 14 kiểm thử đạt trong môi trường `sage`; đã kiểm tra lại checksum của 6 file kết quả, ID liên kết và miền giá trị của cả 4.560 ciphertext. Chưa thực hiện giải mã đầu cuối.

## Chạy lại

Yêu cầu Python 3.11+; thư viện Python dùng chung `requirements.txt` với bước tạo khóa. Không cần cài Office hoặc công cụ trích xuất bên ngoài.

```bash
python3 -m pip install -r requirements.txt
python3 ppdf_extract_encrypt.py \
  --input "Data Forensic lọc sạch" \
  --public-key public_key.json \
  --dimension 8 \
  --bit-width 8 \
  --output outputs/he_step_2_2b
```

Đường dẫn đầu ra phải mới, nằm ngoài thư mục chứng cứ. Nếu đã có kết quả, chọn một thư mục khác, chẳng hạn `outputs/he_step_2_2b_run2`. Không ghi đè kết quả cũ. Trong máy hiện tại đã có môi trường conda tên `sage` với SymPy. Có thể dùng:

```bash
conda activate sage
python ppdf_extract_encrypt.py --output outputs/he_step_2_2b_run2
```

## Một đối tượng được tính như thế nào?

- Gộp các dòng CSV Autopsy theo cặp `(nguồn PC/RM2, File Path)`. 631 dòng hit tạo thành 271 đối tượng nguồn: PC 233, RM2 38. Vị trí tham chiếu trong audit là **số bản ghi dữ liệu CSV, bắt đầu từ 1**, không phải số dòng văn bản vì một bản ghi có thể chứa xuống dòng.
- Ghép bản xuất `$OrphanFiles` với đường dẫn nguồn tương ứng; ghép OST theo đường dẫn nguồn. Đối tượng chỉ có CSV vẫn có vector dựa trên từ khóa đã được Autopsy báo cáo, với trạng thái `index_only_not_exported`.
- Đọc thêm các file chứng cứ đã xuất trong manifest, gồm tài liệu RM1, log và CSV email. `PC/emails.csv` được xử lý như một file chứa 14 email, không biến 14 email thành 14 file độc lập.
- Bản giữ tên cũ và bản đổi đuôi trên RM2 được kiểm tra hash rồi gộp vào `local_paths` của cùng đối tượng. Cùng nội dung trên RM1 và RM2 vẫn là hai vị trí chứng cứ, có SHA-256 để nhóm sau đối chiếu.
- Báo cáo bàn giao, cấu hình từ khóa, CSV hit, log đổi tên và ảnh Verify là tài liệu kiểm soát, không được cộng như file chứng cứ có từ khóa. Ảnh email vẫn là chứng cứ; chưa OCR.
- Mọi đối tượng trong phạm vi đều có hàng trong bảng điểm. Chỉ đối tượng có ít nhất một từ khóa được đưa vào `Cr'_kwt`; đối tượng 0 từ khóa vẫn được ghi trong audit để kiểm tra phạm vi và hạn chế parser.

## Quy tắc trích xuất và chấm điểm

`Số_từ_khóa` là **số từ khóa khác nhau quan sát được**, không phải số lần xuất hiện và không phải số dòng hit. Dùng bộ XML bàn giao: RM1/RM2 có 3 từ khóa dự án; PC có 11 từ khóa. Chuẩn hóa chữ hoa/thường; so khớp literal với biên từ. `secret_project` và `Secret Project` là hai khóa khác nhau; `Secret Project Data` có thể đồng thời khớp `Secret Project`. Đặc trưng là hợp của từ khóa từ CSV nguồn và từ nội dung/đường dẫn bản xuất; audit giữ riêng hai nguồn quan sát.

Nhận dạng OOXML bằng cấu trúc ZIP, OLE bằng magic, không chọn parser chỉ theo đuôi. OOXML trích text và metadata trong `word/`, `ppt/`, `xl/`, `docProps/`, ghép các text run trong đoạn/cell. Với OLE, OST và dữ liệu nhị phân khác, trích chuỗi ASCII có thể in và ASCII trong UTF-16LE/UTF-16BE, tối thiểu 4 ký tự, trực tiếp bằng Python; đây là trích xuất một phần phù hợp bộ từ khóa ASCII của case, không thay thế parser Office/OST. Không đọc ảnh nhúng, không OCR, không mở/chạy macro và không giải nén file xuống thư mục chứng cứ.

Paper và hồ sơ bàn giao không định nghĩa công thức `Điểm_ẩn_giấu`. Prototype dùng quy tắc minh bạch sau để nhóm có thể kiểm tra và thay đổi trong `RUBRIC`:

| Dấu hiệu quan sát được | Điểm | Căn cứ |
|---|---:|---|
| Đuôi không phù hợp chữ ký/cấu trúc file | 3 | Ví dụ tên `.png`, nội dung `word/document.xml`; OLE dưới đuôi không phải Office |
| Đường dẫn chứa `$OrphanFiles/` hoặc `$CarvedFiles/` | 2 | Vị trí phục hồi theo hồ sơ nguồn |
| Tên artifact kết thúc `-slack` | 1 | Bản xuất vùng slack |

Điểm là tổng các dấu hiệu, không phải xác suất hay kết luận có chủ ý che giấu. Không cộng điểm vì entropy cao, dùng Google Drive hay đơn thuần trùng từ khóa. Với OLE chỉ xác nhận container, chưa phân biệt DOC/PPT/XLS nếu đuôi thuộc họ Office. Với đối tượng chưa xuất byte, không suy đoán sai đuôi: điểm chỉ dựa trên đường dẫn và trường `concealment_coverage` ghi rõ hạn chế này. Điểm 0 không chứng minh không có steganography; số từ khóa 0 ở parser hạn chế không chứng minh không liên quan.

Ví dụ: tài liệu gốc RM2 `proposal/landscape.png` là DOCX, nằm trong `$OrphanFiles`, nên điểm ẩn giấu là `3 + 2 = 5`. Việc có thêm bản `landscape.docx` để đọc không làm mất dấu hiệu sai đuôi của bản tên gốc.

## Mã hóa và định dạng bàn giao

Công thức triển khai:

```text
u_i được chọn độc lập trong {-1, 0, 1} bằng randomness hệ thống
c = [b + 2 × Σ(i=0..n−1) u_i × r^i]_d
[x]_d là đại diện có dấu trong [-d/2, d/2)
```

Khóa công khai hiện có thỏa `r^8 ≡ -1 (mod d)`, phù hợp lựa chọn kỹ thuật `f(x)=x^8+1` của module Algorithm 1. `dimension` được truyền công khai qua CLI, không lấy từ private key.

Algorithm 4 của paper trả plaintext modulo 2. Vì vậy, đưa trực tiếp điểm nguyên như 10 vào một ciphertext sẽ không có hợp đồng khôi phục đầy đủ số 10 theo phép giải mã đó. Mỗi thành phần `V_i` ở đây được biểu diễn bằng **8 bit không dấu, thứ tự bit thấp trước**; từng bit được mã hóa riêng bằng Algorithm 2, tổng cộng 16 ciphertext cho một vector. Cả hai đặc trưng đều có cùng chiều dài; nếu giá trị vượt 255, chương trình báo lỗi thay vì cắt cụt. Ví dụ 10 được biểu diễn `[0,1,0,1,0,0,0,0]` trước khi mã hóa. Đó là cách đóng gói số nguyên của prototype, không phải một bước được paper đặc tả sẵn.

```text
outputs/he_step_2_2b/
  audit/features.csv        bảng V_i dễ xem
  audit/features.json       vector, từ khóa, hash, alias, tham chiếu nguồn, mức bao phủ
  audit/provenance.json     dictionary, số hit từng CSV, danh sách file kiểm soát loại ra
  audit/run_summary.json    thống kê, mã phiên chạy, tham số, hash mã nguồn
  share/Cr_kwt_prime.json   Cr'_kwt, chỉ ID đối tượng và ciphertext
  share/public_key.json    khóa công khai được sử dụng
  OUTPUT_SHA256.json        SHA-256 của các file kết quả
```

`audit/` chứa đường dẫn, vector và từ khóa plaintext để kiểm chứng tại máy điều tra viên; chỉ thư mục `share/` dành cho bước nhận bản mã. Chương trình cố đặt quyền thư mục audit `0700` và file audit `0600`; filesystem mount có thể không thực thi quyền POSIX. Ciphertext được lưu thành chuỗi số nguyên thập phân có dấu để bên đọc JSON/JavaScript không làm tròn số lớn. `feature_order` là `[keyword_count, concealment_score]`; `records[].Cr_kwt_prime` là ma trận `[2][8]`. Liên kết với audit qua `artifact_id` và `run_id`. Noise không được xuất ra file.

Chương trình kiểm tra toàn bộ manifest trước và sau xử lý, rồi ghi checksum đầu ra. Hash các file mã nguồn và tham số giúp tái lập phương pháp; randomness mới làm ciphertext thay đổi giữa hai lần chạy.

## Giới hạn HE cần ghi trong báo cáo

Đây là bản triển khai **công thức Algorithm 2 phục vụ nghiên cứu**, chưa xác nhận tính đúng của chuỗi Algorithm 1 → 2 → 4 với private key hiện có, chưa kiểm định noise budget và chưa thực hiện giải mã hay K-means trên bản mã. Module Algorithm 1 hiện có tự ghi nhận một số giả định tái dựng paper; không được suy ra các test công thức ở bước này chứng minh toàn bộ hệ mật đúng.

Ở `n=8`, noise chỉ có `3^8 = 6.561` khả năng cho mỗi bit; người có public key có thể liệt kê ciphertext ứng viên. Vì vậy kết quả hiện tại không đủ bảo mật cho dữ liệu nhạy cảm thực tế. Cần backend HE đã được đánh giá và tham số đầy đủ khi triển khai thật.

Vector được mã hóa theo bit: module phân tích số học ở bước sau phải xử lý mạch bit có carry/comparison thích hợp và noise budget. Không cộng trực tiếp hai chuỗi ciphertext rồi diễn giải như phép cộng điểm nguyên, không chạy K-means thường trên các số ciphertext.

## Kiểm thử

```bash
python3 -m unittest -v test_ppdf_keygen.py test_ppdf_he.py
```

Các test mới kiểm tra ví dụ tính tay của công thức, miền modulo, bảo toàn biểu diễn số nguyên, từ chối sai chiều khóa/tràn bit, trích DOCX bị đổi đuôi và text bị tách run, gộp hit/alias, phát hiện evidence đổi hash và cấu trúc bản mã không kèm vector/đường dẫn plaintext. Đây là kiểm thử công thức và quy trình dữ liệu, không phải kiểm thử bảo mật hay giải mã đầu cuối.
