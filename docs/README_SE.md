# Tìm kiếm mù trên dữ liệu mã hoá (Searchable Encryption — Disjunctive Search)

Bộ công cụ đọc toàn bộ kho bàn giao `PC`, `RM1`, `RM2`, mã hoá chúng, lập chỉ mục mù, rồi chạy
phép tìm kiếm OR theo từ khoá trong `TuKhoa_PC.xml` và `TuKhoa_RM1_RM2.xml` **mà không giải mã
nội dung**. Máy phân tích chỉ thấy ciphertext và các tag HMAC; chuỗi từ khoá gốc không xuất hiện
ở phía máy đó.

> Tài liệu chi tiết về **cơ sở lý thuyết mật mã, giải thích từng file Python và câu lệnh demo**: xem [CO_SO_LY_THUYET_SE.md](CO_SO_LY_THUYET_SE.md).

## Mô hình

| Vai trò | Nắm giữ | Không nắm giữ |
|---|---|---|
| Data holder (người giao hồ sơ) | khoá master `K` 32 byte, toàn bộ file gốc | — |
| Máy phân tích (server) | `server/index.json`, `server/tags.bin`, `server/vault.bin` | `K`, plaintext, đường dẫn, tên file, từ khoá |
| Điều tra viên | danh sách từ khoá trong XML | ciphertext nếu chưa được cấp token |

Data holder xây chỉ mục và mã hoá tệp bằng `K`. Khi cần tìm, holder sinh trapdoor cho bộ từ khoá
từ XML và gửi **chỉ các giá trị kiểm tra** `v_w` cho server. Server quét chỉ mục, trả về handle của
tệp khớp; holder mới là người quy handle về đường dẫn thật và giải mã.

## Thuật toán

Theo cấu trúc mKEES (Goyal et al., *Multi-user Keyword Search over Encrypted Data*, NDSS 2012),
dùng PRF = HMAC-SHA256:

```
r_i    = PRF_K("mkees/v1/file/"  || doc_id)      # handle tài liệu, cũng là khoá dẫn xuất dữ liệu
t_w    = PRF_K("mkees/v1/term/"  || w)
v_w    = PRF_K("mkees/v1/verify/" || t_w)         # thành phần trapdoor
tag(i,w) = PRF_{v_w}(r_i)[0:16]                   # ghi vào tags.bin, cắt còn 128 bit
K_i    = HKDF-SHA256(K, info="mkees/v1/datakey/" || doc_id)
CT_i   = AES-256-GCM_{K_i}(nonce, metadata_i || file_i, AAD = r_i)
```

- **Trapdoor** cho bộ từ khóa `{w_1 … w_m}`: các cặp `(slot, v_{w_j})`. Không có `K` thì server
  không tính được `v_w` cho từ khoá tuỳ ý, nên không tự đặt câu hỏi và không đọc được nội dung.
- **Disjunctive (OR)**: trả tài liệu nếu `PRF_{v_w}(r_i)` khớp **ít nhất một** ô.
- **Conjunctive (AND)**: `--mode conjunctive`, yêu cầu khớp đủ mọi ô.
- Phía server kiểm tra sự có mặt của tag bằng **tìm nhị phân** trên vùng tag đã sắp xếp của từng
  tài liệu (`TagSequence` trong [se/store.py](se/store.py)), không dựng tập hợp hàng triệu phần tử;
  mỗi truy vấn chỉ tốn `số bản ghi × số ô` phép HMAC, không đụng tới khoá master.
- Nhãn ô mặc định trung tính (`…_k001`) để kết quả trả về không gắn được với từ khoá cụ thể;
  `--blind-slots` ngẫu nhiên hoá nhãn, chống cả suy luận theo vị trí ô.

## Khớp từ khoá đúng ngữ nghĩa Autopsy

XML khai báo `literal="true" whole="true"` (Exact Match, whole word). Bộ token hoá giữ cả ký tự
ngăn cách nên mỗi từ khoá trở thành một dãy token liền mạch:

| Từ khoá | Dãy token | Ý nghĩa |
|---|---|---|
| `secret_project` | `secret_project` | 1-gram, dấu `_` là ký tự từ |
| `Secret Project Data` | `Secret`, ` `, `Project`, ` `, `Data` | 5-gram |
| `iaman.informant@nist.gov` | 9 token, giữ nguyên `.` và `@` | 9-gram |

- Whole-word được bảo đảm vì token là dãy `\w+` tối đại: `secret_projectx` không khớp.
- Mặc định không phân biệt hoa/thường (đúng như hồ sơ đã ghi nhận `Secret Project` khớp
  `secret project`); dùng `--case-sensitive` để đảo.
- Độ sâu chỉ mục `L` lấy từ từ khoá dài nhất trong XML đang có (kho này `L=9`). Đây là tham số
  khởi tạo: từ khoá dài hơn `L` ở lần tìm sau sẽ bị bỏ sót.

## Truy xuất dữ liệu

`se/extractor.py` đọc từng file, nhận diện loại theo **magic byte** (đuôi có thể bị ngụy trang),
tách text, SHA-256 và khử trùng lặp:

| Loại phát hiện | Cách tách text |
|---|---|
| OOXML (`PK\x03\x04` + `[Content_Types].xml`) | đọc node `<t>/<v>` trong `word/`, `xl/`, `ppt/`, `docProps/` |
| OLE/CFB (`\xd0\xcf\x11\xe0`) | tự parse FAT/MiniFAT/DIFAT/directory ([se/olefile.py](se/olefile.py)), strings theo từng stream |
| Text (`.txt .csv .log .ini .md .json`) | giải mã utf-8 → cp1252 → latin-1 |
| PST/OST (`!BDN`), SQLite | strings ASCII + UTF-16LE |
| Ảnh/audio/video, nhị phân lạ | mặc định chỉ chỉ mục tên và đường dẫn (`--content-policy`) |

**Magic byte quyết định, đuôi file chỉ là gợi ý.** `extract_document()` thử zip → OLE → PST/SQLite
trước rồi mới đến nhánh "đuôi `.txt`". Lý do nằm ngay trong `RM2/$OrphanFiles`:
`diary_#2p.txt`, `diary_#3d.txt` là file OLE (PPT/DOC) mang tên `.txt`; nếu tin vào đuôi thì
toàn bộ nhị phân bị coi là văn bản, sinh hàng triệu n-gram nhiễu và làm chỉ mục vỡ.

Trần dung lượng (đều là cờ CLI, mặc định trong `se/config.py`): `--max-text-bytes` 32 MB cho văn bản
rút xuất của một tệp, `--max-terms-per-doc` 5 triệu n-gram phân biệt cho một bản ghi,
`--max-scan-bytes` 64 MB đọc đầu vào. Bản ghi chạm trần được đánh dấu `truncated` trong
`index.json` và báo trong bảng tham số — chỉ mục khi đó **có thể** sót từ khóa ở phần cuối tệp.

Chuỗi tìm kiếm của mỗi tài liệu = nội dung tách được + tất cả đường dẫn của nó (bản gốc trong
`$OrphanFiles` và bản đổi đuôi trong `$OrphanFiles_đổi đuôi` có SHA-256 trùng nhau nên gộp thành
một bản ghi, alias lưu cả hai). Sidecar `*-slack` bỏ qua mặc định.

Hai quyết định cần biết khi đối chiếu với Autopsy:
- Stream `Pictures` trong file OLE bị bỏ: đó là bitmap nhúng, thử nghiệm trên
  `[secret_project]_revised_points.ppt` cho 148.783 ký tự nhiễu và **0** lần khớp từ khoá.
- Kho ở đây là **bản export đã lọc**, không phải ảnh đĩa, nên không tìm được trong unallocated
  space; muốn quét nhị phân toàn bộ dùng `--content-policy all`.

## Chạy

```bash
pip install cryptography

# toan bo quy trinh: truy xuat -> ma hoa + lap chi muc -> token -> tim OR -> giai an -> doi chung
python se_disjunctive.py all

# chay thu nhanh
python se_disjunctive.py all --limit 25 --work-dir work_smoke

# chi chay mot lan tim kiem tren chi muc da xay
python se_disjunctive.py search --list TuKhoa_RoRi --mode disjunctive
python se_disjunctive.py verify

# test don vi va test hop nhat
python -m unittest discover -s tests
```

Cờ đáng chú ý: `--sources PC RM1`, `--xml TuKhoa_PC.xml`, `--mode conjunctive`, `--case-sensitive`,
`--blind-slots`, `--content-mode index-only`, `--content-policy documents|all|names`,
`--include-slack`, `--no-default-excludes`, `--exclude '*/emails.csv'`.

Mặc định loại các file tự tham chiếu (`KeywordHits/*.csv`, `hits_*.csv`, `BANG_BAN_GIAO_*.md`,
`KET_QUA_GOOGLE_DRIVE.md`) để kết quả không bị chính báo cáo của mình tiếp tay gây khớp giả.

## Sản phẩm

```
work/
  client/                 # chi data holder doc duoc
    master.key            # khoa 32 byte — tuyet doi khong di kem ho so
    corpus_manifest.json  # duong dan, alias, SHA-256, kieu, parser, so luong ki tu
    handle_map.json       # handle (ngau nhien voi server) -> doc_id
    extracted_text/*.gz   # ban text rut xuat
  server/                 # ban giao duoc cho may phan tich
    index.json            # params + danh sach handle, vung tag, vung vault
    tags.bin              # tag 16 byte, sap theo thu tu tu dien trong tung tai lieu
    vault.bin             # AES-256-GCM (metadata + noi dung file)
  queries/
    token_*.json          # gui len server: chi co v_w va nhan o
    expectation_*.json    # keep client: nhan o -> tu khoa that
  results/
    search_*.json         # server tra ve: handle + cac o khop
    released_*.csv        # duong dan that, SHA-256, tu khoa khop, ket qua kiem tra giai ma
    released/*            # ban giai ma dan xuat
    verify_by_keyword.csv, verify_by_doc.csv, verify.json
    bao_cao_tim_kiem_mu.md
```

## Đối chứng

`verify` so sánh **ba đường độc lập nhau** trên cùng tập tài liệu:

1. **Tìm kiếm mù**: server chỉ đọc `index.json` + `tags.bin` + token, so tag HMAC.
2. **Bản rõ**: regex trực tiếp trên văn bản rút xuất, dùng `phrase_to_regex()` với đúng cờ
   `literal`/`whole` của Autopsy — không đi qua máy n-gram + HMAC nào của chỉ mục.
3. **Byte thô**: tìm chuỗi từ khoá (kể cả dạng UTF-16LE) trực tiếp trong từng byte của tệp,
   bỏ qua hoàn toàn bước rút xuất.

Kỳ vọng precision = recall = 1.0 giữ giữa (1) và (2): mọi lệch liệt kê trong bảng *Bất đối khớp*.
Lệch giữa (2) và (3) cho thấy từ khoá vẫn nằm trong tệp nhưng không vào được bản rõ tìm kiếm —
báo cáo tách riêng hai loại: `gap_compressed_container` (text nằm trong container nén hoặc tệp bị
chính sách bỏ qua, điều này Autopsy cũng không tìm được) và `gap_other` (còn lại, nghĩa là
bước đọc file cần sửa). Bảng *Từ khóa chỉ còn trong byte thô* liệt kê từng trường hợp.

`verify_by_doc.csv` có thêm cột `parser`, `raw_bytes_match`, `raw_keywords` và trạng thái
`CHI_CON_TRONG_BYTE_THO` để truy vết.

## Độ lộ

Server biết: số lượng bản ghi, số tag mỗi bản ghi, handle, và ô nào khớp theo từng truy vấn
(table pattern + search pattern). Server không biết: từ khoá, nội dung, đường dẫn, tên file.
Muốn siết thêm thì dùng `--blind-slots`; muốn giảm table pattern thì phải thêm padding/oblivious
access, nằm ngoài phạm vi bài này.

## Giới hạn

- Khoá master nằm trong `work/client/master.key`; mất khoá là mất khả năng giải mã và mất cả
  quyền sinh trapdoor.
- Text của DOC/PPT/XLS cũ lấy theo hướng strings nên có thể lẫn rác và bỏ sót ký tự trong chuỗi
  bị phân mảnh; Autopsy đọc cả cấu trúc file nên số hit của hai bên không nhất thiết bằng nhau.
- Ảnh chụp màn hình (`email_google_drive.png`) cần OCR, không thuộc phạm vi.
- Chỉ mục theo n-gram tới `L`: mỗi lần thêm từ khoá dài hơn đều phải xây lại chỉ mục.
