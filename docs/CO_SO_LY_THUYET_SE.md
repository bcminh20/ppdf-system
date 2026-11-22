# Cơ sở lý thuyết, giải thích mã nguồn và hướng dẫn chạy

**Bộ công cụ:** Tìm kiếm mù (blind search) trên dữ liệu mã hoá — Searchable Encryption, phép tìm OR (disjunctive) và AND (conjunctive) theo danh sách từ khoá định dạng Autopsy, chạy trên kho bàn giao `PC`, `RM1`, `RM2`.

Tài liệu gồm ba phần: (A) cơ sở lý thuyết mật mã phía sau bộ công cụ, (B) giải thích từng file Python, (C) câu lệnh demo kèm output thật ghi lại trên máy ngày 2026-10-18.

---

# PHẦN A — CƠ SỞ LÝ THUYẾT

## A.1. Bài toán đặt ra

Trong điều tra số, người giao hồ sơ (data holder) muốn một máy phân tích **tìm được tài liệu chứa từ khoá** mà không đọc được **nội dung tài liệu**, đồng thời máy phân tích cũng không được biết **điều tra viên đang tìm từ khoá nào**.

Ba bài toán con phải giải quyết cùng lúc:

| Yêu cầu | Ý nghĩa pháp lý/kỹ thuật | Công cụ |
|---|---|---|
| Confidentiality of data | Server không đọc được bản rõ | AES-256-GCM với khoá dẫn xuất theo từng tài liệu |
| Confidentiality of query | Server không biết từ khoá trong trapdoor | PRF một chiều: `v_w = PRF_K(w)` |
| Searchability | Server vẫn trả về đúng tài liệu khớp | Chỉ mục mù (blind index) bằng tag HMAC |

Đây chính là mô hình **Searchable Symmetric Encryption (SSE)** / **Public Key Encryption with Keyword Search (PEKS)** và biến thể multi-user **mKEES** (Goyal, Cao, *Multi-user Keyword Search over Encrypted Data*, NDSS 2012). Mã nguồn đặt tên lớp lõi là `PEKE` theo hướng này.

## A.2. Các thuật toán của hệ

Một hệ SSE đối xứng là bộ bốn thuật toán xác suất:

```
(K, I) ← Build(1^λ, D)          sinh khoá + dựng chỉ mục trên tập tài liệu D
(T_w)  ← Trapdoor(K, w)         người giữ khoá sinh token cho từ khoá w
R      ← Search(I, T_w)         server quét chỉ mục, trả về danh sách định danh tài liệu
m      ← Decrypt(K, ct, id)     người giữ khoá giải mã tài liệu khớp
```

Đúng nghĩa **disjunctive (OR)**: mở rộng `Search(I, {T_{w_1}…T_{w_m}})` trả về `⋃_j Search(I, T_{w_j})` bằng **một lượt quét chỉ mục**, không phải `m` lượt. **Conjunctive (AND)** trả về giao của các tập.

Cài đặt trong repo map bốn thuật toán này vào pipeline:

| Thuật toán lý thuyết | Hàm trong mã nguồn |
|---|---|
| Build | `stage_build()` tại `se/pipeline.py:158` |
| Trapdoor | `stage_token()` tại `se/pipeline.py:239`, dùng `PEKE.trapdoor_value()` tại `se/peke.py:91` |
| Search | `stage_search()` tại `se/pipeline.py:267` + `search_record()` tại `se/peke.py:109` |
| Decrypt | `stage_release()` tại `se/pipeline.py:297` + `PEKE.decrypt_blob()` tại `se/peke.py:105` |

## A.3. Nguyên thuỷ mật mã được dùng

### A.3.1. HMAC-SHA256 trong vai trò PRF

`PRF_k(x) = HMAC-SHA256(k, x)` (`_prf()` tại `se/peke.py:49`). Tính chất cần dùng:

- **Giả ngẫu nhiên**: không phân biệt được output với chuỗi ngẫu nhiên nếu không có `k` → tag không lộ từ khoá.
- **Xác định (deterministic)**: cùng `k`, cùng `x` ⇒ cùng output. Đây là điều kiện **quyết định** để tìm kiếm được: chỉ mục và trapdoor phải "gặp nhau" mà không cần giải mã. Cái giá phải trả là lộ mẫu số lặp lại (xem A.6).
- **Một chiều**: từ `v_w` không suy ngược ra `w`, và không tính được `v_w'` cho từ khoá khác nếu không có `K`.

### A.3.2. HKDF-SHA256 để dẫn xuất khoá dữ liệu

`K_i = HKDF-SHA256(K, info = "mkees/v1/datakey/" || doc_id)` (`data_key()` tại `se/peke.py:97`). Mỗi tài liệu có một khoá AES riêng: mất một `K_i` không ảnh hưởng tài liệu khác, và một khối dữ liệu không thể bị giải mã bằng khoá của khối khác.

### A.3.3. AES-256-GCM

`CT_i = AESGCM(K_i).encrypt(nonce, metadata_i || file_i, AAD = "mkees/v1/blob/" || r_i)` (`encrypt_blob()` tại `se/peke.py:100`).

- **GCM = mã hoá + xác thực**: bất kỳ sửa đổi nào làm decrypt thất bại → bằng chứng toàn vẹn cho hồ sơ số.
- **nonce 12 byte ngẫu nhiên** (`secrets.token_bytes(12)`) cho mỗi bản ghi; không dùng lại nonce với cùng một khoá.
- **AAD = handle của tài liệu**: ràng buộc bản ghi vault với đúng vị trí chỉ mục. Test `test_encryption_round_trip` (`tests/test_se.py:87`) chứng minh: giải mã bằng handle của tài liệu khác **bắt buộc raise**.

### A.3.4. Domain separation — lý do có các hằng `mkees/v1/…`

```
DOMAIN_FILE    = "mkees/v1/file/"     # dẫn xuất handle tài liệu
DOMAIN_TERM    = "mkees/v1/term/"     # dẫn xuất t_w
DOMAIN_VERIFY  = "mkees/v1/verify/"   # dẫn xuất v_w
DOMAIN_DATAKEY = "mkees/v1/datakey/"  # dẫn xuất khoá AES
DOMAIN_BLOB    = "mkees/v1/blob/"     # prefix của AAD
```

Mỗi loại khoá/tag được PRF trên một "không gian" tiền tố riêng, nên không có va chạm có chủ đích giữa hai vai trò (thí dụ không thể lấy handle làm trapdoor). Đây là quy tắc chuẩn khi dùng chung một PRF cho nhiều mục đích.

### A.3.5. Công thức cài đặt

```
r_i      = PRF_K("mkees/v1/file/"    || doc_id)      # handle — định danh mù của tài liệu
t_w      = PRF_K("mkees/v1/term/"    || w)           # khoá trung gian của từ khoá
v_w      = PRF_K("mkees/v1/verify/"  || t_w)         # giá trị kiểm tra, chính là trapdoor
tag(i,w) = PRF_{v_w}(r_i)[0:16]                      # ghi vào tags.bin (cắt còn 128 bit)
K_i      = HKDF-SHA256(K, "mkees/v1/datakey/"||doc_id)
CT_i     = AES-256-GCM_{K_i}(nonce, metadata_i||file_i, AAD = "mkees/v1/blob/"||r_i)
```

Nhận xét quan trọng: **khoá của PRF sinh tag là `v_w`, không phải `K`**. Vì `v_w` là output của PRF dưới `K`, server nhận được `v_w` trong trapdoor chỉ có thể *kiểm tra* sự có mặt của từ khoá đó, không thể dùng nó để suy ra tag của từ khoá khác, càng không thể suy ra `K`.

## A.4. Trực quan hoá bằng số thật

Chạy với khoá demo `K = 0x11×32`:

```
'secret_project'       -> 1 token  -> gram = 'secret_project'
'Secret Project Data'  -> 5 token  -> gram = 'secret| |project| |data'   ('|' là \x1f)
'drive.google.com'     -> 5 token  -> gram = 'drive|.|google|.|com'

v_w('Secret Project')  = aa8946c0d7fcc989073361a61258daee...
v_w('secret project')  = aa8946c0d7fcc989073361a61258daee...   # casefold nen hai tu khoa cho cung gram

doc aaaa1111: handle = 0dcf09134c2239b0...  tag = 72b78ca3473293462459db3669e33495   # tag cua gram 'secret_project'
doc bbbb2222: handle = 11d6cf4f58236905...  tag = 1b5990c9cdbd5c7153a84598c25ff15a   # cung tu khao, tag khac het

Doi khoa master sang 0x22×32 (van gram 'secret_project'):  v_w = b85de07746f7b7a6475c5763226af25f...  # toan bo chi muc vo nghia
```

Ba tính chất của hệ hiện ra gọn trong ví dụ: (1) từ khoá ánh xạ **một-một và xác định** xuống `v_w`; (2) tag **phụ thuộc từng tài liệu** nên không so sánh tag cross-document được; (3) mọi thứ **đổi hoàn toàn khi đổi `K`**.

## A.5. Vì sao từ khoá nhiều từ vẫn khớp chính xác: bài toán n-gram

SSE cổ điển giả định từ khoá là **một token**. Hồ sơ điều tra ở đây có từ khoá là cả cụm: `Secret Project Data`, `iaman.informant@nist.gov`, và Autopsy khai báo `whole="true"` ( whole word). Cần một cách biểu diễn "cụm token" thành **một term** để đưa vào PRF.

Cách làm: token hoá văn bản và **giữ cả ký tự ngăn cách** (`tokenize()` tại `se/tokens.py:21`), rồi sinh mọi đoạn liên tiếp độ dài ≤ `L` (`grams_from_tokens()` tại `se/tokens.py:36`). Separator trong gram là `\x1f` (_unit separator_, không xuất hiện trong văn bản).

```
"the secret_project file"  → tokens: ['the', ' ', 'secret_project', ' ', 'file']
grams (L=4): 'the', 'the| ', 'the| |secret_project', '…', 'secret_project', 'secret_project| |file', …
```

| Tính chất | Kết quả |
|---|---|
| Cụm từ nhiều từ | `Secret Project Data` = gram 5 token, khớp đúng dãy token liên tiếp |
| Whole word | token là dãy `\w+` **tối đại**, nên `secret_projectx` tạo ra `secret_projectx`, không tạo `secret_project` → không khớp. Kiểm chứng: `test_whole_word_boundary` (`tests/test_se.py:42`) |
| Dấu `_`, `.`, `@` | `_` nằm trong `\w` nên `secret_project` và `do_u_wanna_build_a_snow_man` mỗi chuỗi là **1 token**; `.`, `@`, khoảng trắng tách thành token riêng |
| Chuỗi có dấu chấm | `drive.google.com` = 5 token `drive . google . com`, vẫn khớp nguyên chuỗi vì gram nối lại đúng dãy token liên tiếp |
| Hoa/thường | mặc định `casefold()` nên `Secret Project` ≡ `secret project` (đúng như hồ sơ Autopsy đã ghi nhận); `--case-sensitive` để đảo |

`L` (độ sâu chỉ mục) = số token của từ khoá dài nhất trong XML đang có (`query_depth()` tại `se/pipeline.py:154`). Với kho này, `TuKhoa_PC.xml` cho `L = 9` vì `iaman.informant.personal@gmail.com` = 9 token (`iaman` `.` `informant` `.` `personal` `@` `gmail` `.` `com`); `TuKhoa_RM1_RM2.xml` chỉ cần `L = 5`.

> **Giới hạn lý thuyết phải nhớ:** `L` là tham số **khởi tạo**, không phải runtime. Từ khoá có số token > `L` ở lần tìm sau sẽ sinh gram không tồn tại trong chỉ mục ⇒ bỏ sót. Phải chạy lại `build`.

## A.6. Mô hình bảo mật và độ lộ (leakage profile)

Không hệ SSE nào an toàn "không rò rỉ". Chuẩn đánh giá là **IND-CKA** (indistinguishability under chosen keyword attack, Boneh–Choi): adversary chọn từ khoá, nhận trapdoor, và chỉ được tiết lộ **hàm rò rỉ** Λ. Với thiết kế này:

**Server nhìn thấy:**

| Thành phần rò rỉ | Mô tả | Bằng chứng trong sản phẩm |
|---|---|---|
| **Table pattern** | Số bản ghi, số tag mỗi bản ghi — tức độ "rộng" chỉ mục của từng tài liệu | `index.json: records, tag_count` |
| **Search pattern (theo ô)** | Với mỗi truy vấn, ô slot nào khớp tài liệu nào | `results/search_*.json: hits[].slots` |
| **Volume** | Kích thước ciphertext mỗi tài liệu | `vault.bin` + `index.json: length` |
| **Repetition pattern** | Hai truy vấn dùng cùng từ khoá ⇒ cùng `v_w` ⇒ không phân biệt được | `queries/token_*.json` |

**Server không nhìn thấy:** từ khoá (chỉ có `v_w` 32 byte một chiều), nội dung bản rõ, đường dẫn, tên file, `doc_id`, SHA-256. Kiểm chứng bằng `test_server_artifacts_leak_no_keyword_text` (`tests/test_se.py:120`) và lệnh thực tế:

```
index.json + tags.bin chứa chuỗi từ khoá nào?  KHONG
vault.bin chứa 'secret_project'?               False
token_*.json chứa từ khoá?                     False
```

**Chống suy luận theo vị trí:** mặc định nhãn ô là `…_k001`, `…_k002` trung tính; `--blind-slots` thay nhãn bằng hex ngẫu nhiên (`se/pipeline.py:243`) để kết quả trả về không gắn được "ô 1 = từ khoá 1". Muốn giảm hẳn table/repetition pattern cần padding và oblivious RAM — nằm ngoài phạm vi bài.

## A.7. Vì sao thiết kế này "đúng" — ba đường đối chứng

Chứng minh một mình chỉ mục mã hoá cho kết quả đúng là không tầm thường, vì server không có bản rõ để so. Bộ công cụ dùng **ba oracle độc lập**:

```
(1) BLIND   : server đọc index.json + tags.bin + token, so tag HMAC. Không K, không bản rõ.
(2) PLAIN   : regex trực tiếp trên text rút xuất, qua phrase_to_regex() (se/tokens.py:63)
              với đúng cờ literal/whole của Autopsy. Không đụng n-gram/HMAC nào của chỉ mục.
(3) RAW     : tìm chuỗi từ khoá (ASCII + UTF-16LE) trong từng byte của tệp gốc,
              bỏ qua hoàn toàn bước rút xuất (raw_keyword_hits(), se/pipeline.py:350).
```

Kỳ vọng: `precision = recall = 1.0` giữa (1) và (2) — mọi lệch liệt kê vào bảng *Bất đối khớp*. Lệch giữa (2) và (3) **không** kết luận chỉ mục sai, mà kết luận bước đọc file bỏ sót; báo cáo tách thành `gap_compressed_container` (text nằm trong container nén / tệp bị chính sách bỏ qua — Autopsy cũng không thấy) và `gap_other` (cần sửa parser).

Kết quả lần chạy đầy đủ trên kho thật (50 tài liệu):

```
false_positive = 0   false_negative = 0   recall = 1.0   precision = 1.0
text_extraction_gap = 6 (gap_compressed_container = 6, gap_other = 0)
```

## A.8. Độ phức tạp — và vì sao `build` mất ~150 giây

Gọi `n` = số token của tài liệu, `L` = độ sâu, `T` = số gram **phân biệt**.

| Giai đoạn | Phức tạp | Thực đo (50 tài liệu) |
|---|---|---|
| `extract` | O(tổng byte) | 5.41 s / 200,622,270 B |
| `build` | Σ O(n·L) gram để sinh + O(T log T) để sắp tag + **3·T** phép HMAC | **152.76 s**, T = 10,135,420 tag, tags.bin 162,166,720 B |
| `search` | O(số bản ghi × số ô × log T_i) HMAC + nhị phân | 0.089 s (550 phép PRF) |
| `verify` | O(kích thước kho) cho oracle (3) + regex cho oracle (2) | ~vài chục giây |

Ba nguyên nhân khiến `build` chậm — đều là **chi phí thiết kế**, không phải lỗi:

1. **Số gram bùng nổ theo `L`**: mỗi vị trí sinh `L` gram, nên T ≈ n·L với văn bản dài. `L=9` gấp ~9 lần `L=1`.
2. **Mỗi gram tốn 3 lần HMAC**: `term_tag()` gọi `trapdoor_value()` → 2 PRF cho `t_w`, `v_w`, rồi 1 PRF nữa cho tag (`se/peke.py:94`). ≈ 30 triệu phép HMAC cho lần chạy đầy đủ.
3. **Set chuỗi Python**: `doc_grams()` (`se/tokens.py:46`) giữ toàn bộ gram phân biệt trong một `set[str]`, mỗi gram là chuỗi nối bằng `\x1f` → tiêu thụ RAM và hash nhiều.

Các hướng tăng tốc (chưa áp dụng, chỉ để tham khảo khi cần chạy full nhiều lần):
- **Memo hoá `v_w` theo gram**: `v_w` chỉ phụ thuộc gram chứ không phụ thuộc tài liệu ⇒ cache toàn cục cắt còn 1/3 số HMAC.
- **Song song hoá theo tài liệu**: mỗi tài liệu là một đơn vị độc lập (handle, tag, vault region riêng) ⇒ `ProcessPoolExecutor` gần like-linear.
- **Hạ `L`** nếu danh sách từ khoá hiện tại không cần gram dài (tham số hoá được, nhưng đổi `L` phải build lại).
- **`--limit` / `--max-terms-per-doc` / `--content-policy`** để phiên làm việc hằng ngày gọn.

## A.9. Mô hình phân quyền ba bên

| Vai trò | Nắm giữ | Không nắm giữ | Hành động |
|---|---|---|---|
| **Data holder** | `K` 32 byte (`work/client/master.key`), kho gốc, `corpus_manifest.json`, `handle_map.json` | — | `extract`, `build`, `token`, `release` |
| **Máy phân tích (server)** | `work/server/{index.json, tags.bin, vault.bin}` | `K`, bản rõ, đường dẫn, tên file, từ khoá | `search` |
| **Điều tra viên** | XML danh sách từ khoá | ciphertext nếu chưa được cấp token | chọn từ khoá, đọc `released_*.csv` |

Nguyên tắc: **trapdoor do holder sinh và holder là người duy nhất quy handle → đường dẫn thật.** Server trả về đúng `handle` (một giá trị PRF mù), holder tra `handle_map.json` rồi mới giải mã vault. Nếu để server tự tra từ khoá thì mô hình sụp đổ ngay.

---

# PHẦN B — GIẢI THÍCH TỪNG FILE

## B.0. Cây thư mục

```
SearchableEncryption/
├── se_disjunctive.py        # 18 dòng — điểm vào CLI
├── requirements.txt         # cryptography>=42
├── README_SE.md             # mô tả tóm tắt (tiếng Việt, đã có)
├── CO_SO_LY_THUYET_SE.md    # tài liệu này
├── se/                      # package lõi (10 file)
│   ├── __init__.py
│   ├── config.py            # tham số mặc định
│   ├── tokens.py            # token hoá + n-gram + regex đối chứng
│   ├── keywords.py          # đọc XML từ khoá kiểu Autopsy
│   ├── extractor.py         # nhận diện file theo magic byte, tách text, SHA-256, khử trùng lặp
│   ├── olefile.py           # parser OLE/CFB tối giản (FAT/MiniFAT/DIFAT/directory)
│   ├── peke.py              # LÕI MẬT MÃ: PRF, trapdoor, tag, AES-GCM, search_record
│   ├── store.py             # định dạng đĩa: index.json, tags.bin, vault.bin, TagSequence
│   ├── pipeline.py          # điều phối 6 stage + đối chứng + báo cáo
│   └── cli.py               # argparse → Config → gọi pipeline
├── tests/test_se.py         # 12 unit + integration test
├── _diag_grams.py / _diag_noise.py / _diag_streams.py / _diag_xlsx.py   # script khảo sát (không thuộc pipeline)
└── work/, work_demo/, work_check/  # sản phẩm chạy thật (client / server / queries / results)
```

Luồng dữ liệu:

```
XML từ khoá ─► keywords.py ─┐
                             ├─► pipeline.stage_token ─► queries/token_*.json ─┐
kho gốc ─► extractor.py ─► tokens.py ─► pipeline.stage_build ─► server/* ──────┤
                                  (peke.py + store.py)                          ├─► pipeline.stage_search
                                                                                 │   (chỉ đọc server/*)
                       handle_map.json ─► pipeline.stage_release ◄───────────────┘
                                                 └─► pipeline.stage_verify ─► results/*.csv, .md
```

## B.1. `se_disjunctive.py` — điểm vào

`se_disjunctive.py` (18 dòng) chỉ làm hai việc: chèn thư mục dự án vào `sys.path` để `import se` hoạt động mà không cần `pip install -e`, rồi gọi `se.cli.main()`. Tệp là *shell wrapper* — mọi logic nằm trong package.

```bash
python se_disjunctive.py all
python se_disjunctive.py search --list TuKhoa_RoRi --mode disjunctive
```

## B.2. `se/__init__.py`

Ba dòng: docstring + `__version__ = "1.0"`. Không xuất lại symbol nào, nên mọi import là tường minh (`from .peke import PEKE`).

## B.3. `se/config.py` — tham số chạy mặc định

Dataclass `Config` (dòng 26) gom **toàn bộ** knob của pipeline, để CLI chỉ việc ánh xạ cờ → field.

| Nhóm | Field đáng chú ý |
|---|---|
| Đường dẫn | `EVIDENCE_DIR = PROJECT_DIR.parent` (dòng 10) — thư mục cha chứa `PC/RM1/RM2/TuKhoa_*.xml`; `work_dir` |
| Phạm vi | `sources=("PC","RM1","RM2")`, `keyword_files`, `limit_docs` |
| Chế độ tìm | `mode` (`disjunctive`/`conjunctive`), `case_sensitive`, `blind_slots` |
| Đọc nội dung | `content_mode` (`full`/`index-only`), `content_policy` (`documents`/`all`/`names`), `skip_slack` |
| Trần an toàn | `max_text_bytes=32 MB`, `max_terms_per_doc=5 M`, `max_scan_bytes=64 MB` |
| Loại trừ | `DEFAULT_EXCLUDES` (dòng 15) — `*/KeywordHits/*`, `*/hits_*.csv`, `*/BANG_BAN_GIAO_*.md`… |

`DEFAULT_EXCLUDES` là quyết định **phương pháp luận**, không phải dọn dẹp: nếu đưa chính các báo cáo hit (`hits_*.csv`) vào chỉ mục, mọi từ khoá đều "khớp" trong file tổng hợp đó ⇒ tự tạo dương tính giả.

Ba method tiện ích: `corpus_roots()`, `resolved_keyword_files()` (mặc định glob `TuKhoa_*.xml`), `active_excludes()`.

## B.4. `se/tokens.py` — cầu nối giữa "ngôn ngữ Autopsy" và "một term cho PRF"

File ngắn nhất nhưng quyết định **độ đúng** của khớp từ khoá.

| Hàm | Dòng | Vai trò |
|---|---|---|
| `slugify()` | 13 | biến tên danh sách thành định danh an toàn cho tên file |
| `normalize()` | 17 | `casefold()` — chuẩn Unicode hơn `lower()` (xử lý `ß`, tiếng Việt) |
| `tokenize()` | 21 | regex `\w+ | \s+ | .` với `UNICODE|DOTALL`; khoảng trắng **gộp thành một token `' '`**, mỗi ký tự khác một token |
| `grams_from_tokens()` | 36 | sinh mọi đoạn liên tiếp độ dài 1..L, nối bằng `SEP='\x1f'` (streaming, không giữ tất cả trong RAM) |
| `doc_grams()` | 46 | tập gram phân biệt + trả cờ `truncated` khi chạm `cap` — chính là cột "Bản ghi bị giới hạn số term" trong báo cáo |
| `keyword_gram()` | 56 | từ khoá → (gram, list token); báo lỗi nếu từ khoá rỗng |
| `phrase_to_regex()` | 63 | **oracle độc lập** cho đối chứng: `re.escape` nếu `literal`, bọc `(?<!\w)…(?!\w)` nếu `whole` |
| `count_matches()` | 72 | đếm số lần khớp bản rõ |

Điểm thiết kế then chốt ở `tokenize()`: tách **cả ký tự ngăn cách** thay vì cắt câu. Nếu bỏ khoảng trắng thì `Secret Project Data` và `SecretProject Data` cho cùng bộ gram ⇒ mất tính whole-word và sinh dương tính giả. Giữ khoảng trắng làm token khiến "cụm từ" trở thành một chuỗi token liên tiếp duy nhất — đủ để PRF biểu diễn.

## B.5. `se/keywords.py` — đọc danh sách từ khoá định dạng Autopsy

XML Autopsy: `keyword_lists / keyword_list / keyword` với thuộc tính `literal`, `whole`.

- `Keyword` (dòng 19, frozen dataclass): `text`, `literal`, `whole`, `list_name`, và `gram` — gram được tính ngay lúc parse để tránh tính lại. `token_count` = số token của từ khoá.
- `build_keyword()` (dòng 31): gắn gram cho từ khoá theo `case_sensitive`.
- `KeywordList` (dòng 37): `max_token_count` → dùng quyết định độ sâu `L`; **`uid`** (dòng 49) = `slug(file XML)__slug(tên danh sách)`.
- `parse_keyword_xml()` (dòng 55): chấp nhận cả root là `keyword_list` lẫn nhiều `keyword_list` con; mặc định `literal`/`whole` là **True** khi thuộc tính vắng mặt.
- `load_keyword_lists()` (dòng 83): nối danh sách từ nhiều file XML.

Vì sao cần `uid`? Hai file XML (`TuKhoa_PC.xml`, `TuKhoa_RM1_RM2.xml`) **cùng mang tên danh sách `TuKhoa_RoRi`**. Nếu định danh theo tên sẽ ghi đè sản phẩm của nhau. Test `test_end_to_end_matches_plaintext` kiểm tra cả hai UID tách biệt (`TuKhoa_PC__TuKhoa_RoRi`, `TuKhoa_RM1_RM2__TuKhoa_RoRi`).

## B.6. `se/extractor.py` — bước forensics: đọc file không tin vào phần đuôi

File dài nhất về xử lý dữ liệu (323 dòng). **Luận điểm trung tâm: magic byte quyết định, đuôi file chỉ là gợi ý.**

### Phát hiện loại file
`sniff()` (dòng 61) đọc 16–256 byte đầu: `PK\x03\x04`→zip, `\xd0\xcf\x11\xe0`→OLE, `SQLite format 3\0`, `!BDN`→PST, `%PDF`, bảng `MEDIA_SIGNATURES` (dòng 54) cho ảnh/audio/video, header OneNote, XML, rồi `_looks_texty()` (dòng 83) — tiêu chí >85% ký tự in được **hoặc** decode UTF-8 hợp lệ (để đọc được tiếng Việt có dấu).

### Tách text theo loại
| Parser | Hàm | Cách |
|---|---|---|
| OOXML | `extract_ooxml()` 132 | kiểm tra `[Content_Types].xml`, đọc node `<t> <v> <instrText> <s> <content> <value> <code>` trong `word/ xl/ ppt/ docProps/` |
| ZIP thường | `extract_zip_generic()` 153 | liệt kê tên entry + đọc xml/txt/csv bên trong |
| OLE/CFB | `extract_ole()` 169 | mở bằng `CompoundFile`, `strings_scan` **từng stream** |
| PST/SQLite/PDF | dòng 206 | `strings_scan` (ASCII run ≥6, UTF-16LE run ≥4) |
| Text | dòng 208 | `decode_bytes()`: utf-8 → cp1252 → latin-1(replace) |
| Media/binary | dòng 210 | trả `""` + `skipped:<loại>` theo policy `documents` |

### Hai quyết định kỹ thuật đáng giải thích trong báo cáo

**(a) `extract_document()` thử container trước, thử đuôi text sau** (dòng 190). Lý do nằm ngay trong `RM2/$OrphanFiles`: `diary_#2p.txt`, `diary_#3d.txt` **là file OLE (PPT/DOC) mang tên `.txt`**. Nếu tin đuôi, cả khối nhị phân bị coi là văn bản → hàng trăm nghìn n-gram rác, phình chỉ mục và có nguy cơ vỡ. Test `test_container_beats_fake_text_extension` (`tests/test_se.py:174`).

**(b) Bỏ stream `Pictures` trong OLE** — `BINARY_OLE_STREAMS` (dòng 166) khi `content_policy="documents"`. Stream đó là bitmap nhúng; đo trên `[secret_project]_revised_points.ppt` cho **148.783 ký tự nhiễu và 0 lần khớp từ khoá**. Chính là nội dung `_diag_noise.py` đo đạc.

### Khử trùng lặp và gộp alias
`walk_corpus()` (dòng 233): duyệt `os.walk` (thứ tự ổn định), băm SHA-256 streaming (`hash_and_head()`, dòng 215), **một bản ghi cho nhiều đường dẫn**: hai phiên bản cùng nội dung trong `$OrphanFiles` và `$OrphanFiles_đổi đuôi` có SHA-256 trùng ⇒ gộp, `aliases` giữ cả hai. Đây là lý do `search` chỉ trả 50 handle dù kho có nhiều file hơn.

Chuỗi tìm kiếm của mỗi tài liệu = `doc.text + "\n" + "\n".join(doc.aliases)` (`searchable_text()` tại `se/pipeline.py:82`) ⇒ **tên file và đường dẫn cũng được chỉ mục mù**, khớp cả trường hợp từ khoá chỉ xuất hiện trong tên (như `happy_holiday.jpg`).

Bỏ qua sidecar `*-slack` mặc định, bỏ symlink, bỏ file không đọc được (ghi `read_error` thay vì crash).

## B.7. `se/olefile.py` — parser CFB tự viết (135 dòng)

Dùng cho DOC/PPT/XLS cũ và OST. Vì sao tự viết: giữ dependency đúng một `cryptography`, và chỉ cần đúng một chức năng (lấy stream + data), không cần API đầy đủ của `olefile`.

`CompoundFile.__init__` (dòng 26) đọc header: `sector_size = 1 << u16@30`, `mini_size = 1 << u16@32`, first_dir@48, mini_cutoff@56, first_minifat@60, first_difat@68, num_difat@72.

| Hàm | Dòng | Nội dung |
|---|---|---|
| `_sector()` | 45 | sector i = `data[(i+1)*ss : …]` (sector 0 bắt đầu sau header 512 B) |
| `_read_fat()` | 49 | 109 DIFAT entry trong header + chuỗi sector DIFAT mở rộng |
| `_chain_indices()` | 74 | lần theo liên kết FAT, **chống loop bằng `seen` và `MAX_CHAIN=1e6`** — quan trọng khi gặp file hỏng/chủ ý bất thường |
| `_read_directory()` | 88 | 128 B/entry: tên UTF-16 (len@64), obj_type@66, start@116, size@120 |
| `streams()` | 102 | type==2 (stream); size < mini_cutoff ⇒ đọc từ **mini stream theo MiniFAT**, ngược lại theo FAT thường |
| `_read_minifat()` / `_mini_chain()` | 118/127 | tương tự FAT nhưng trên minisector |

## B.8. `se/peke.py` — LÕI MẬT MÃ (125 dòng)

Toàn bộ công thức A.3.5 nằm ở đây, và **chỉ ở đây** — nguyên tắc: một chỗ duy nhất định nghĩa scheme, các file khác không được tự tính HMAC.

| Thành phần | Dòng | Ghi chú |
|---|---|---|
| `KEY_BYTES=32`, `TAG_BYTES=16` | 21–22 | tag cắt còn 128 bit |
| 5 hằng domain | 23–27 | xem A.3.4 |
| `generate_key()` / `load_or_create_key()` | 30/34 | idempotent, **kiểm tra độ dài 32 byte** khi đọc key cũ (chống key hỏng âm thầm) |
| `_prf()` | 49 | HMAC-SHA256 |
| `file_handle(doc_id)` | 83 | `r_i` — handle mù |
| `term_values(gram)` | 86 | `(t_w, v_w)` hai tầng PRF |
| `trapdoor_value(gram)` | 91 | chỉ trả `v_w` — thứ được gửi ra ngoài |
| `term_tag(handle, gram)` | 94 | `PRF_{v_w}(r_i)[:16]` |
| `data_key(doc_id)` | 97 | HKDF ⇒ khoá AES riêng từng tài liệu |
| `encrypt_blob/decrypt_blob` | 100/105 | AES-GCM, nonce 12 B, AAD có prefix domain |
| `search_record(handle, tags, trapdoor)` | 109 | **chạy phía server, không cần `K`** — với mỗi ô: `PRF_{v_w}(r_i)[:16] ∈ tags?` |
| `record_is_hit(matched, trapdoor)` | 122 | `conjunctive` ⇒ `len(matched)==len(slots)`; ngược lại `>0` (OR) |

Hai dataclass: `IndexRecord` (54) và `Trapdoor` (66) — `Trapdoor.slots` là tuple `(nhãn ô, v_w)`, **không chứa chuỗi từ khoá**.

Điểm lý thuyết đáng chú ý: `search_record` **tính lại tag phía server** rồi kiểm tra thành viên, thay vì so sánh hai list đã biết trước. Nhờ đó server không cần biết từ khoá, cũng không cần thứ tự tag, và phép kiểm tra thành viên dùng nhị phân (B.9).

## B.9. `se/store.py` — định dạng đĩa của chỉ mục


| Thành phần | Dòng | Ý nghĩa |
|---|---|---|
| `ServerRecord` | 15 | handle hex, `tag_offset`, `tag_count`, `offset`, `length`, `nonce`, `truncated` — **hoàn toàn định hướng con trỏ, không có metadata con người đọc được** |
| `ServerIndex` | 28 | `params` + danh sách record |
| `save_json/load_json` | 33/39 | JSON UTF-8, `sort_keys` để hai lần chạy so sánh được |
| `BinaryWriter` | 43 | append blob liên tục, trả `(offset, length)` ⇒ `tags.bin` và `vault.bin` là hai **log nhị phân phẳng**, index chỉ giữ con trỏ |
| `read_region()` | 68 | pread theo (offset,length) — server chỉ đọc đúng vùng của một tài liệu |
| `TagSequence` | 74 | **mấu chốt hiệu năng**: coi vùng bytes trong `tags.bin` như một dãy tag độ dài cố định đã sắp xếp. Không sao chép, không dựng `set()`. |
| `TagSequence.__contains__` | 95 | `bisect_left` trên Sequence ảo ⇒ tìm kiếm O(log tag_count) mà không tốn RAM cho hàng triệu tag |
| `write_server_index/load_server_index` | 100/106 | schema `{"params":…, "records":[…]}` |
| `encode/decode_trapdoor` | 113/123 | `v_w` hex hoá trong JSON; **hàm giải mã không cần K**, nên `stage_search` chạy được ở máy không có khoá |

Lý do tồn tại `TagSequence`: mỗi tài liệu có thể tới hàng triệu tag. Dựng `set(bytes)` cho từng truy vấn = tốn RAM và thời gian gấp nhiều lần; dãy đã sắp + nhị phân giải quyết bằng O(log n) mà không cấp phát.

## B.10. `se/pipeline.py` — điều phối 6 stage (637 dòng)

**`WorkDirs`** (dòng 45) định nghĩa cấu trúc sản phẩm và **ranh giới client/server**: `client/` (master.key, corpus_manifest.json, handle_map.json, extracted_text/) đối lập `server/` (index.json, tags.bin, vault.bin). `paths_for(uid, mode)` (dòng 70) sinh bộ ba tên file `token_/expectation_/search_` theo hậu tố `OR`/`AND` — nhờ vậy kết quả của hai chế độ **không ghi đè nhau**.

| Stage | Dòng | Ai chạy | Làm gì |
|---|---|---|---|
| `stage_extract` | 113 | holder | `walk_corpus` → gzip text từng tài liệu vào `client/extracted_text/`, ghi `corpus_manifest.json` kèm meta (thời gian, tổng byte, số unreadable) |
| `stage_build` | 158 | holder | vòng chính: handle → gram → tag sorted → `tags.bin`; metadata JSON + nguyên bytes của file → AES-GCM → `vault.bin`; ghi `handle_map.json` và `index.json` |
| `stage_token` | 239 | holder | sinh `v_w` cho từng từ khoá, đặt nhãn ô (`--blind-slots` ⇒ hex ngẫu nhiên); ghi `token_*.json` (đi server) + `expectation_*.json` (ở lại client, ánh xạ ô→từ khoá thật) |
| `stage_search` | 267 | **server** | đọc `index.json` + token, với mỗi record `seek` tới vùng tag rồi `search_record`/`record_is_hit`; ghi `search_*.json`, tự báo `prf_calls` |
| `stage_release` | 297 | holder | handle → `handle_map` → doc_id → cắt nonce/ciphertext → `decrypt_blob` → tách header metadata (4 byte big-endian) + nội dung → ghi `results/released/…` và `released_*.csv`, kèm **`decrypt_hash_check` = MATCH/MISMATCH/EMPTY** |
| `stage_verify` | 374 | holder | ba oracle (A.7) → `verify_by_keyword.csv`, `verify_by_doc.csv`, `verify.json` |

Chi tiết cần nắm khi trình bày:

- **`searchable_text()` (82)**: chuỗi chỉ mục = text rút xuất + alias.
- **`_read_original()` (230)**: `content_mode="index-only"` trả `b""` ⇒ lập chỉ mục mà không sao lưu nội dung (vault rỗng metadata-only) — dùng khi chỉ cần chứng minh khả năng tìm.
- **`COMPRESSED_PARSERS` (36)**: bộ prefix (`ooxml:`, `zip:`, `strings:pdf`, `skipped:`) dùng phân loại `gap_compressed_container` — vì với các parser đó byte thô **không phải text liên tục**, nên việc từ khoá không xuất hiện liền mạch trong byte là điều bình thường, không phải lỗi.
- **`raw_keyword_hits()` (350)**: oracle thứ ba, chỉ chạy needle ASCII, thử cả bản `utf-16-le` của needle, và đọc lại file gốc để **không bị ảnh hưởng bởi cache rút xuất**.
- **`ground_truth()` (339)**: regex trực tiếp trên `searchable_text` — độc lập hoàn toàn với máy n-gram + HMAC.
- **`leakage_profile()` (489)**: thống kê phân bố tag (mean/max) và số tài liệu khớp theo từng ô, đúng nghĩa "đo hàm rò rỉ Λ".
- **`write_markdown_report()` (515)**: sinh `bao_cao_tim_kiem_mu.md` với các bảng tham số / kết quả / bất đối khớp / lộ thông tin / hạn chế.
- **`run_all()` (614)**: `load_lists → extract → build → (token, search, release) cho từng danh sách → verify → leakage → report`.
- **`write_csv()` (629)**: dùng `utf-8-sig` (BOM) để Excel mở đúng tiếng Việt.

## B.11. `se/cli.py` — argparse

`build_parser()` (dòng 35) định nghĩa 5 lệnh (`all`, `extract`, `build`, `search`, `verify`) và toàn bộ cờ đã liệt kê ở Phần C. `make_config()` (67) map cờ → `Config`; `select_lists()` (89) lọc danh sách từ khoá theo `--list`, so cả tên gốc lẫn `slugify()` và **báo lỗi liệt kê các danh sách khả dụng** khi không tìm thấy. `main()` (106) rẽ nhánh theo lệnh.

Đáng chú ý ở nhánh `search` (dòng 122): thứ tự `stage_token → stage_search → stage_release` mô phỏng **đúng giao thức ba bên** trong một tiến trình — `stage_token` là holder, `stage_search` là server, `stage_release` lại là holder. Muốn tách thật, chỉ cần copy `work/server/` sang máy khác và chỉ chạy `stage_search(work, token_path)`; `stage_search` không tham chiếu `master.key` hay `evidence_dir`.

`cli.py:1` ghi docstring "CLP dieu khien" — đánh máy thừa, không ảnh hưởng chức năng.

## B.12. `tests/test_se.py` — 12 test

| Nhóm | Dòng | Kiểm gì |
|---|---|---|
| `make_corpus` | 18 | dựng kho giả 4 file + XML trong temp dir, có bẫy `secret_projectx` (whole-word) |
| `TokenTests` | 37 | token giữ dấu chấm, khoảng trắng gộp; biên whole-word; gram chứa cụm từ |
| `SchemeTests` | 53 | **disjunctive khớp đúng ô**, conjunctive yêu cầu đủ mọi ô, **sai khoá ⇒ 0 hit**, round-trip AES-GCM và ràng buộc AAD |
| `PipelineTests` | 95 | end-to-end `run_all` ⇒ `false_positive = false_negative = 0`, đúng số tài liệu khớp; **artifacts phía server không chứa chuỗi từ khoá** |
| `TagLookupTests` | 148 | `TagSequence` nhị phân cho kết quả như thành viên list thật |
| `ExtractorRoutingTests` | 173 | container thắng đuôi `.txt` giả; media được bỏ nhưng tên vẫn nằm trong alias |

`test_wrong_key_does_not_match` và `test_server_artifacts_leak_no_keyword_text` là hai test **chứng minh tính chất bảo mật**, không chỉ correctness — nên đưa vào phần thuyết minh bảo mật.

## B.13. `_diag_*.py` — script khảo sát, không thuộc pipeline

Bốn script này là **bằng chứng thực nghiệm** cho các quyết định ở B.6; đường dẫn thư mục hard-code, chạy standalone bằng `python _diag_grams.py`.

| File | Câu trả lời nó cung cấp |
|---|---|
| `_diag_grams.py` (19 dòng) | Đếm số gram của từng tài liệu, xếp giảm dần, in `TOTAL gram` và số tài liệu >500k gram ⇒ căn cứ đặt `--max-terms-per-doc` và giải thích thời gian build |
| `_diag_noise.py` (58 dòng) | So 4 cấu hình `strings` (min ASCII/UTF-16 run, buộc ≥2 chữ cái, buộc có nguyên âm) trên 7 file nghi vấn: file nào cho nhiều gram mà **hit=0** ⇒ chứng minh lọc nhiễu |
| `_diag_streams.py` (24 dòng) | Liệt kê stream trong OLE, số token và vị trí có chuỗi `ecret` ⇒ chứng minh stream `Pictures` là nguồn nhiễu |
| `_diag_xlsx.py` (20 dòng) | Với 1 file có đuôi giả: `extract_ooxml` cho parser gì, từ khoá nằm ở offset nào, kích thước raw vs text của từng entry zip ⇒ chứng minh route theo magic byte |

## B.14. `requirements.txt`

Một dòng: `cryptography>=42`. Toàn bộ HMAC/HKDF/AESGCM/`secrets` đều từ stdlib + gói này; parser OLE, OOXML, tokenisation tự viết ⇒ **không dependency nào khác**, phù hợp môi trường máy phân tích cách ly.

---

# PHẦN C — CÂU LỆNH DEMO VÀ CÁCH CHẠY

Môi trường đã kiểm chứng: Python 3.14.7, `cryptography` 50.0.1, Windows x64. Mọi lệnh dưới đây chạy từ thư mục dự án.

## C.1. Chuẩn bị

```bash
cd "D:\HUST\Nam 4\Digital Forensics\Project\KetQua\KetQua\SearchableEncryption"
python --version
pip install cryptography          # hoặc: pip install -r requirements.txt
python -c "import cryptography; print(cryptography.__version__)"
```

Cấu trúc bắt buộc (định nghĩa trong `se/config.py:10`):

```
..\                    <- EVIDENCE_DIR, thư mục CHA của SearchableEncryption
 ├── PC/  RM1/  RM2/   <- các nguồn, chọn bằng --sources
 └── TuKhoa_PC.xml, TuKhoa_RM1_RM2.xml   <- tự động glob TuKhoa_*.xml
```

## C.2. Sanity check — unit test (0.35 s, 12 test)

```bash
python -m unittest discover -s tests -v
```

Output thật (trích):

```
test_wrong_key_does_not_match (test_se.SchemeTests) ... ok
test_sorted_region_membership (test_se.TagLookupTests) ... ok
test_whole_word_boundary (test_se.TokenTests) ... ok
----------------------------------------------------------------------
Ran 12 tests in 0.352s

OK
[extract] 4 tai lieu doc lap, 179 byte, 0.03s
[index] 4 ban ghi, 311 tag (4,976 byte), do sau L=5, 0.0s
[search] khop 3/4 tai lieu theo phep OR, 0.0142s
[verify] false_positive=0 false_negative=0 tren 3 tai lieu khop
```

Hai dòng cuối là các test end-to-end tự chạy `run_all()` trên kho giả trong temp dir (không đụng dữ liệu thật). **Chạy bộ test này là cách nhanh nhất để thấy toàn bộ vòng đời hệ hoạt động.**

## C.3. Demo 2 phút — chạy toàn bộ quy trình trên 20 tệp

```bash
python se_disjunctive.py all --limit 20 --work-dir work_demo
```

Output thật (tổng 22.4 s):

```
[extract] 20 tai lieu doc lap, 119,263,635 byte, 1.2s
[index] 20 ban ghi, 1,539,981 tag (24,639,696 byte), do sau L=9, 15.04s
[token] 11 tu khoa cua TuKhoa_RoRi -> token_TuKhoa_PC__TuKhoa_RoRi_OR.json
[search] khop 9/20 tai lieu theo phep OR, 0.0379s
[release] giai ma 9 tai lieu khop -> released_TuKhoa_PC__TuKhoa_RoRi_OR.csv
[token] 3 tu khoa cua TuKhoa_RoRi -> token_TuKhoa_RM1_RM2__TuKhoa_RoRi_OR.json
[search] khop 6/20 tai lieu theo phep OR, 0.009s
[release] giai ma 6 tai lieu khop -> released_TuKhoa_RM1_RM2__TuKhoa_RoRi_OR.csv
[verify] false_positive=0 false_negative=0 tren 17 tai lieu khop
[report] work_demo\results\bao_cao_tim_kiem_mu.md
```

Cách đọc: `--limit 20` đếm **số tệp đã quét** chứ không phải số bản ghi; 20 tệp cho ra 20 tài liệu độc lập ở lượt chạy này, nhưng chỉ mục có 1.54 M tag nên mất 15 s (xem A.8).

## C.4. Chạy đầy đủ cả kho (50 tài liệu)

```bash
python se_disjunctive.py all
```

Số liệu lần chạy đã lưu trong `work/`:

```
[extract]  50 tài liệu, 200,622,270 B   5.41 s
[index]    50 bản ghi, 10,135,420 tag (tags.bin 162,166,720 B)   152.76 s   L=9, 1 bản ghi bị trần term
[search]   TuKhoa_PC:      22/50 khớp, 550 phép PRF, 0.089 s
[search]   TuKhoa_RM1_RM2: 19/50 khớp, 150 phép PRF, 0.100 s
[release]  22 + 19 tài liệu giải mã, vault.bin 200,642,969 B
[verify]   false_positive=0  false_negative=0  recall=1.0  precision=1.0
           text_extraction_gap=6 (gap_compressed_container=6, gap_other=0)
```

> `build` là giai đoạn đắt nhất (~2.5 phút) và **chỉ chạy một lần cho một bộ từ khoá / một `L`**. Các lần tìm sau chỉ cần `search` → `verify`: tổng chưa tới 1 s cho phần tìm.

## C.5. Chạy từng stage — mô phỏng đúng vai trò

```bash
# (0) Data holder: truy xuất + mã hoá + lập chỉ mục
python se_disjunctive.py extract
python se_disjunctive.py build

# (1) Data holder: sinh trapdoor cho một danh sách từ khoá
python se_disjunctive.py search --list TuKhoa_RoRi

# (2) Máy phân tích: copy work/server + queries/token_*.json sang máy khác, chạy stage_search
# (3) Data holder: quy handle -> đường dẫn, giải mã
# (4) Đối chứng + báo cáo
python se_disjunctive.py verify
```

`search` gộp cả ba bước holder/server/holder trong một tiến trình để demo; tách thật thì chỉ cần `stage_search()` là không có khoá master (B.11).

## C.6. Demo OR vs AND trên cùng một chỉ mục

Chỉ mục **không phụ thuộc chế độ tìm** — đổi mode chỉ đổi cách `record_is_hit` chấm điểm, nên có thể chạy AND ngay trên `index.json` đã build bằng OR:

```bash
python se_disjunctive.py search --work-dir work_demo --mode disjunctive   # OR
python se_disjunctive.py search --work-dir work_demo --mode conjunctive   # AND
```

Output thật — sự khác biệt rất trực quan:

```
[search] khop 9/20 tai lieu theo phep OR      (TuKhoa_PC, 11 từ khoá)
[search] khop 0/20 tai lieu theo phep AND     (TuKhoa_PC — không tệp nào chứa đủ 11 từ khoá)
[search] khop 6/20 tai lieu theo phep OR      (TuKhoa_RM1_RM2, 3 từ khoá)
[search] khop 5/20 tai lieu theo phep AND     (TuKhoa_RM1_RM2 — 5 tệp chứa cả 3)
```

Hai lượt viết ra file khác nhau (`..._OR.json` / `..._AND.json`) nhờ hậu tố mode trong `WorkDirs.paths_for()`.

## C.7. Demo chứng minh "server không thấy gì"

```bash
python - <<'PY'
from pathlib import Path
W = Path("work_demo")   # doi thanh "work" neu chay full
kws = ["secret_project", "Secret Project", "iaman.informant@nist.gov",
       "happy_holiday.jpg", "drive.google.com"]
blob = (W/"server/index.json").read_text(encoding="utf-8") + (W/"server/tags.bin").read_bytes().hex()
print("index.json + tags.bin chua tu keyword?", [k for k in kws if k.lower() in blob.lower()] or "KHONG")
print("vault.bin chua 'secret_project'?", b"secret_project" in (W/"server/vault.bin").read_bytes())
t = (W/"queries/token_TuKhoa_PC__TuKhoa_RoRi_OR.json").read_text(encoding="utf-8")
print("token_*.json chua tu keyword?", any(k.lower() in t.lower() for k in kws))
PY
```

Kết quả thật: `KHONG` / `False` / `False`.

## C.8. Demo lý thuyết A.3.5 bằng 10 dòng Python

```bash
python - <<'PY'
import sys; sys.path.insert(0, '.')
from se.peke import PEKE
from se.tokens import keyword_gram, tokenize, grams_from_tokens

A = PEKE(b"\x11"*32); B = PEKE(b"\x22"*32)
g = keyword_gram("Secret Project")[0]
print("gram        :", g.replace("\x1f", "|"))
print("v_w (K=0x11):", A.trapdoor_value(g).hex()[:32])
print("v_w (K=0x22):", B.trapdoor_value(g).hex()[:32])
for d in ("aaaa1111", "bbbb2222"):
    h = A.file_handle(d)
    print(f"doc {d}: handle={h.hex()[:16]} tag={A.term_tag(h, g).hex()}")
print("grams cua 'the secret_project file' (L=4):")
print([x.replace("\x1f","|") for x in list(grams_from_tokens(tokenize("the secret_project file"), 4))][:9])
PY
```

Output thật:

```
gram        : secret| |project
v_w (K=0x11): aa8946c0d7fcc989073361a61258daee
v_w (K=0x22): c3af779c4825044a624b2156dd47d993
doc aaaa1111: handle=0dcf09134c2239b0 tag=260e8137156bfe050586ed0b729056bb
doc bbbb2222: handle=11d6cf4f58236905 tag=9bb877553ae1a9a5b4eba900edcdf297
grams cua 'the secret_project file' (L=4):
['the', 'the| ', 'the| |secret_project', 'the| |secret_project| ', ' ', ' |secret_project',
 ' |secret_project| ', ' |secret_project| |file', 'secret_project']
```

## C.9. Demo đọc sản phẩm

```bash
# Tham số + kích thước chỉ mục
python -c "import json;d=json.load(open('work/server/index.json',encoding='utf-8'));print(json.dumps(d['params'],indent=1,ensure_ascii=False));print('records',len(d['records']))"

# Trapdoor gửi lên server: chỉ có ô nhãn + v_w
start work_demo\queries\token_TuKhoa_PC__TuKhoa_RoRi_OR.json   # Windows
python -m json.tool work_demo/queries/token_TuKhoa_PC__TuKhoa_RoRi_OR.json

# Map riêng của holder: ô -> từ khoá thật (KHONG bao giờ gửi đi)
python -m json.tool work_demo/queries/expectation_TuKhoa_PC__TuKhoa_RoRi_OR.json

# Kết quả server trả về: handle + các ô khớp
python -m json.tool work_demo/results/search_TuKhoa_PC__TuKhoa_RoRi_OR.json

# Bảng giải an: duong dan that + kiem tra SHA-256 sau giai ma
python -c "import csv;[print(r['file_path'],'|',r['matched_keywords'],'|',r['decrypt_hash_check']) for r in csv.DictReader(open('work_demo/results/released_TuKhoa_PC__TuKhoa_RoRi_OR.csv',encoding='utf-8-sig'))]"

# Đối chứng từng từ khoá / từng tài liệu
column -s, -t < work/results/verify_by_keyword.csv | less -S   # Git Bash
start work\results\bao_cao_tim_kiem_mu.md
```

Trong `released_*.csv`, cột `decrypt_hash_check` phải là `MATCH` — đó là bằng chứng AES-GCM giải mã ra **đúng tệp gốc** (SHA-256 so với manifest), không chỉ "giải mã không lỗi".

## C.10. Tham số CLI đầy đủ

```bash
python se_disjunctive.py --help
```

| Cờ | Mặc định | Tác dụng / khi nào dùng |
|---|---|---|
| `command` | `all` | `all` \| `extract` \| `build` \| `search` \| `verify` |
| `--evidence-dir PATH` | thư mục cha | trỏ tới kho chứng cứ khác |
| `--work-dir PATH` | `work` | cách ly sản phẩm từng phiên; demo dùng `work_demo` |
| `--sources PC RM1` | `PC RM1 RM2` | thu hẹp phạm vi |
| `--xml FILE` | glob `TuKhoa_*.xml` | chỉ dùng một/bộ XML định trước (lặp lại được) |
| `--list NAME` | tất cả | một danh sách từ khoá; tên khớp cả sau `slugify` |
| `--mode` | `disjunctive` | `conjunctive` để tìm AND |
| `--case-sensitive` | tắt | so khớp phân biệt hoa/thường |
| `--blind-slots` | tắt | nhãn ô thành hex ngẫu nhiên, chống suy luận theo vị trí |
| `--content-mode` | `full` | `index-only` = lập chỉ mục mà không lưu ciphertext nội dung |
| `--content-policy` | `documents` | `all` = strings cả ảnh/audio/video; `names` = chỉ tên và đường dẫn |
| `--include-slack` | tắt | gồm sidecar `*-slack` |
| `--no-default-excludes` | tắt | **cẩn thận**: sẽ index chính các `hits_*.csv`, sinh khớp giả |
| `--exclude PATTERN` | — | loại thêm, lặp lại được |
| `--limit N` | — | chạy thử nhanh |
| `--max-text-bytes` | 32 000 000 | trần text rút xuất / một tệp |
| `--max-terms-per-doc` | 5 000 000 | trần số gram / bản ghi; chạm trần ⇒ `truncated`, có thể sót từ khoá cuối tệp |
| `--master-key PATH` | `work/client/master.key` | dùng key đã có thay vì tạo mới |
| `--report-label NAME` | `bao_cao_tim_kiem_mu` | tên file báo cáo MD |

## C.11. Chạy script khảo sát

```bash
python _diag_grams.py      # tài liệu nào sinh nhiều gram nhất, tổng gram, số doc >500k
python _diag_noise.py      # 4 chiến lược strings: gram vs hit
python _diag_streams.py    # liệt kê stream OLE và vị trí chuỗi cần tìm
python _diag_xlsx.py       # file đuôi giả: parser thực tế + offset từ khoá
```

Các file này hard-code đường dẫn `D:\HUST\...\KetQua` — chỉ chạy được trên máy đã đặt kho đúng chỗ đó.

## C.12. Lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `Khong doc duoc danh sach tu khoa nao` | không có `TuKhoa_*.xml` trong `--evidence-dir` | kiểm tra `EVIDENCE_DIR = PROJECT_DIR.parent` (`se/config.py:10`) hoặc truyền `--xml` |
| `Khong co danh sach tu khoa '...'` | sai tên danh sách | CLI in ra các tên khả dụng; `TuKhoa_PC.xml` và `TuKhoa_RM1_RM2.xml` **cùng có** `TuKhoa_RoRi`, phân biệt bằng UID |
| `Khoa master sai do dai` | `master.key` bị hỏng/bị cắt | xoá `work/client/master.key` để tạo key mới ⇒ **phải build lại toàn bộ**, vì mọi tag phụ thuộc K |
| `Khong the giai ma` / `MISMATCH` | dùng key khác với key đã build, hoặc `index.json`/`tags.bin`/`vault.bin` không cùng một lượt build | giữ nguyên bộ ba, hoặc build lại |
| Từ khoá nhiều từ không khớp | số token của từ khoá > `L` lúc build | thêm XML chứa từ khoá dài hơn (hoặc đặt `Config.max_query_tokens`, field này chưa có cờ CLI — xem `se/config.py:41`) rồi chạy lại `build` |
| `build` rất chậm / tràn RAM | `L` lớn, tệp nhị phân bị strings hoá | `--limit`, `--content-policy documents`, hạ `--max-terms-per-doc`; đối chiếu `_diag_grams.py` |
| Có hit trong `released` mà Autopsy không có (và ngược lại) | repo đọc bản **export đã lọc**, Autopsy đọc cả unallocated space và cấu trúc file | xem `verify_by_doc.csv`, cột `parser`, `raw_bytes_match`, trạng thái `CHI_CON_TRONG_BYTE_THO` |

## C.13. Checklist khi trình bày / nộp bài

1. `python -m unittest discover -s tests -v` → 12/12 OK.
2. `python se_disjunctive.py all --limit 20 --work-dir work_demo` → 0 FP, 0 FN.
3. Mở `work/server/index.json` và `work/queries/token_*.json`: **chỉ thấy hex**, không thấy từ khoá → chứng minh confidentiality of query.
4. Mở `work/results/released_*.csv`: cột `decrypt_hash_check` = `MATCH` → chứng minh giải mã đúng tệp.
5. Mở `work/results/bao_cao_tim_kiem_mu.md`: bảng *Bất đối khớp* (kỳ vọng: trống hoặc chỉ còn dòng byte thô) và bảng *Lộ thông tin*.
6. Demo AND/OR: hai con số khác nhau trên cùng một chỉ mục → chứng minh chế độ tìm là phía trapdoor, không phải phía chỉ mục.
