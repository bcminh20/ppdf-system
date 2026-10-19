# PPDF cho điều tra rò rỉ dữ liệu nội bộ trên disk image

Tài liệu này chuyển mô hình **Privacy-Preserving Digital Forensics (PPDF)** trong paper *Cryptographic Techniques for Data Privacy in Digital Forensics* của Taiwo Blessing Ogunseyi và Oluwasola Mary Adedayo (IEEE Access, 2023, DOI: `10.1109/ACCESS.2023.3343360`) thành một kế hoạch có thể triển khai cho bài Computer & Disk Forensics/NCL.

Sơ đồ tổng quát của phiên bản điều chỉnh nằm ở [ppdf_flow.svg](ppdf_flow.svg).

## 1. Mục tiêu của nhóm

Nhóm mô phỏng một cuộc điều tra **nhân viên nội bộ làm rò rỉ tài liệu mật**. Đầu vào là một bản sao pháp chứng của ổ đĩa máy trạm; đầu ra là báo cáo cho biết:

- dữ liệu nào trên disk image có liên hệ với vụ việc;
- dữ liệu nào thực sự phù hợp để kiểm định giả thuyết rò rỉ;
- chuỗi thời gian và dấu vết thao tác của nhân viên;
- dữ liệu đã được bảo vệ thế nào để điều tra viên không phải mở toàn bộ dữ liệu cá nhân không liên quan;
- bằng chứng có đủ để ủng hộ hoặc bác bỏ giả thuyết hay chưa.

Mục tiêu không phải là mã hóa toàn bộ disk image rồi tuyên bố đã bảo vệ quyền riêng tư. Cách đó vừa tốn tài nguyên vừa làm mất khả năng phân tích. PPDF thu hẹp dữ liệu qua hai lần chọn từ khóa, chỉ mã hóa và phân tích sâu phần có liên hệ với vụ việc, đồng thời giữ bản gốc bất biến.

## 2. Paper nói gì về PPDF?

Paper bắt đầu từ mâu thuẫn cơ bản của điều tra số: điều tra viên cần thu thập đủ dữ liệu để không bỏ sót bằng chứng, nhưng thiết bị thường chứa rất nhiều thông tin cá nhân, thông tin của người thứ ba, người dùng phụ và nhà cung cấp dịch vụ. Vì thế, việc truy cập tất cả dữ liệu có thể xâm phạm quyền riêng tư của cả người vô tội.

Các tác giả phân loại kỹ thuật bảo vệ dữ liệu thành:

1. **Policy-based**: quy định phạm vi, quyền truy cập, mục đích sử dụng và thời hạn lưu trữ.
2. **Non-cryptographic**: ví dụ blockchain cho tính toàn vẹn và chain of custody.
3. **Cryptographic**: homomorphic encryption (HE), commutative encryption, searchable encryption (SE), secret sharing và identity-based encryption (IBE).

Ba tiêu chí được dùng để đánh giá giải pháp là:

- có cần bên thứ ba đáng tin hay có thể chịu được service provider không đáng tin;
- có cho phép nhiều điều tra viên cùng truy cập dữ liệu vụ án không;
- có hỗ trợ tìm kiếm nhiều từ khóa hay không.

PPDF là mô hình khái niệm, không phải một sản phẩm hoàn chỉnh. Điểm cốt lõi của nó là đưa mã hóa và kiểm soát quyền truy cập vào quy trình điều tra, thay vì chỉ mã hóa ở cuối.

## 3. Flow gốc của PPDF

Paper gom quy trình pháp chứng sáu bước truyền thống — identification, preservation, acquisition, examination, analysis, presentation — thành bốn stage bảo vệ riêng tư.

### Stage 1 — Preparation / Key Generation

Điều tra viên xác định loại sự cố, phạm vi, giả thuyết cần kiểm định, dữ liệu cần có, công cụ, nhân sự và warrant/approval. Đồng thời tạo cặp khóa bất đối xứng `(Prikey, Pubkey)`.

- Nếu user hợp tác, user có thể tạo cặp khóa; public key được chia sẻ với điều tra viên hoặc service provider.
- Nếu user không hợp tác/không có mặt, điều tra viên tạo cặp khóa.
- Private key phải được giữ trong kho kiểm soát; paper đề xuất cần quyền của điều tra viên cấp cao trước khi lấy private key để giải mã.
- Public key có thể chia sẻ cho service provider trong trường hợp dữ liệu nằm trên cloud. Với disk image cục bộ, service provider có thể được mô phỏng bằng module/indexer nội bộ.

Stage này chưa cần thao tác mật mã trên evidence, nhưng phải thiết kế readiness, chain of custody và policy ngay từ đầu.

### Stage 2 — Preservation / Encryption

Điều tra viên tạo forensic image (hoặc thu thập live data nếu thiết bị không thể tắt), ghi nhận hash và đóng băng bản gốc. Vì chưa thể biết ngay dữ liệu nào là bằng chứng, image vẫn có thể chứa cả dữ liệu liên quan và không liên quan.

PPDF dùng **từ khóa thứ nhất** (`Fkywd`) để tìm rộng theo phép **disjunctive/OR**. Ví dụ:

```text
leak OR confidential OR export OR USB OR Project-X OR archive
```

Kết quả là **case-related data**: có thể liên hệ với vụ án nhưng chưa chắc là bằng chứng phù hợp. Chỉ tập kết quả này được mã hóa bằng public key hoặc searchable encryption. Cách này giảm kích thước ciphertext và tránh đưa dữ liệu không liên quan vào các bước sau.

Trong paper, nếu dữ liệu nằm ở cloud, các từ khóa đầu tiên cũng có thể được mã hóa rồi gửi cho service provider; service provider tìm trên dữ liệu mã hóa và trả về ciphertext. Với disk image cục bộ, việc tìm rộng được thực hiện trong môi trường điều tra được kiểm soát, sau đó ciphertext được tạo trước khi chia sẻ cho analyst khác.

### Stage 3 — Extraction / Computation

Điều tra viên tạo **từ khóa thứ hai** (`Crvkw`) có tính đặc thù cao và tìm trên tập case-related đã mã hóa theo phép **conjunctive/AND**. Ví dụ:

```text
Project-X AND export AND 2026-10-14
```

Kết quả là **case-pertinent data**: phần thực sự cần để kiểm định giả thuyết. Có thể lặp lại việc chọn từ khóa khi giả thuyết được thu hẹp.

Paper cho phép thực hiện một số phép tính trên dữ liệu mã hóa, chẳng hạn phân loại hoặc K-means, bằng HE. Trong prototype disk image, có thể bắt đầu bằng searchable encryption + phân tích metadata đã được mã hóa/đã giảm phạm vi; nếu cần chứng minh HE, bổ sung một demo trên vector metadata nhỏ thay vì cố mã hóa toàn bộ filesystem.

### Stage 4 — Presentation / Decryption

Kết quả phân tích được kiểm tra, sau đó điều tra viên có thẩm quyền dùng private key để giải mã phần kết quả cần trình bày. Báo cáo phải nối được:

```text
artifact → observation → finding → mức độ ủng hộ/bác bỏ giả thuyết
```

Phần không liên quan không được mở chỉ vì nó nằm trong disk image. Mọi lần lấy private key, giải mã hoặc mở rộng phạm vi phải có lý do, người phê duyệt và audit log.

## 4. Kịch bản NCL được đề xuất

### 4.1 Bối cảnh

Doanh nghiệp **HUST-Research** phát hiện một gói mã nguồn nội bộ của dự án `Project-X` xuất hiện trong kho bên ngoài. Nhân viên `alice` là người có quyền đọc thư mục dự án. Giả thuyết điều tra là Alice đã gom tài liệu, nén chúng, sao chép qua USB hoặc thư mục đồng bộ cloud rồi xóa dấu vết trước khi rời công ty.

NCL cung cấp một disk image của workstation Alice. Nhóm không cần khẳng định Alice phạm tội chỉ từ một artifact; nhiệm vụ là tái dựng sự kiện, đánh giá độ mạnh của bằng chứng và bảo vệ dữ liệu riêng tư không liên quan.

### 4.2 Giả thuyết cần kiểm định

- **H1 — Ủng hộ rò rỉ:** Alice đã truy cập dữ liệu `Project-X`, tạo bản sao/ archive, rồi ghi ra thiết bị rời hoặc thư mục đồng bộ trong khoảng thời gian điều tra.
- **H2 — Kịch bản thay thế:** artifact chỉ là hoạt động phát triển hoặc backup hợp lệ, không có dấu hiệu xuất dữ liệu.
- **H3 — Không đủ kết luận:** có dấu vết liên quan nhưng thiếu liên kết giữa user, thời gian, nội dung và đích đến.

### 4.3 Nguồn artifact cần ưu tiên

| Nhóm | Ví dụ artifact | Mục đích |
|---|---|---|
| File system | MFT/USN Journal, MACB, recycle bin, deleted files | thời gian tạo/sửa/xóa, khôi phục tên file |
| User activity | Recent files, Jump Lists, LNK, ShellBags | file nào đã được mở và từ đường dẫn nào |
| USB | USBSTOR, MountedDevices, setupapi, volume serial | thiết bị rời, thời điểm kết nối, serial |
| Archive | `.zip`, `.7z`, `.rar`, staging directory, temp files | gom dữ liệu trước khi chuyển đi |
| Cloud/browser | browser history, downloads, sync client logs | upload, download, webmail, cloud sync |
| Communication | email/chat export nếu có trong image | trao đổi về tài liệu hoặc đích nhận |
| OS/security | Windows event logs, PowerShell, Prefetch, Defender | tiến trình, script, đăng nhập, xóa dấu vết |
| Privacy boundary | ảnh cá nhân, tài liệu y tế, tài chính, tài khoản khác | phải loại khỏi phạm vi nếu không có justification |

Danh sách này là nguồn để xây dictionary; không có nghĩa là phải mở toàn bộ nội dung của mọi artifact.

## 5. Mapping PPDF vào disk image cục bộ

| PPDF | Triển khai trong bài | Đầu ra kiểm chứng |
|---|---|---|
| User | nhân viên Alice/chủ dữ liệu; có thể mô phỏng user không hợp tác | quyết định ai giữ khóa, phạm vi privacy |
| Investigator | nhóm NCL/forensic examiner | case ID, scope, warrant, hypothesis |
| Service Provider | module index/search hoặc analyst thứ hai; không cần cloud thật | chỉ nhận ciphertext + metadata được phép |
| Public key | khóa dùng để mã hóa case-related/case-pertinent set | public key fingerprint |
| Private key | lưu riêng, encrypted at rest, lấy qua approval | access log, thời điểm giải mã |
| Case-related | kết quả OR rộng của từ khóa 1 | manifest và ciphertext lớp 1 |
| Case-pertinent | kết quả AND hẹp của từ khóa 2 | ciphertext/feature set lớp 2 |
| Presentation | báo cáo timeline, bảng artifact, hash, finding | report tái lập được |

Với image cục bộ, không nhất thiết phải dựng cloud. Điều quan trọng là chứng minh ranh giới quyền: module tạo index/điều tra viên phụ có thể tìm và phân tích phần được phép mà không có private key của toàn bộ user data.

## 6. Kiến trúc prototype nên làm

```text
forensic_image.E01/raw (read-only)
        │
        ├── acquisition_manifest.json
        │     ├── image hash (SHA-256)
        │     ├── tool/version
        │     ├── examiner/time/host
        │     └── chain-of-custody events
        │
        ├── parser + keyword index
        │       └── Stage 2 OR search → case_related_manifest
        │
        ├── key manager
        │       ├── public key → encrypt/search module
        │       └── private key → restricted vault + approval log
        │
        ├── ciphertext store
        │       └── Stage 3 AND search → case_pertinent_set
        │
        ├── encrypted feature analysis
        │       └── timeline/correlation/clustering
        │
        └── approved decryptor
                └── Stage 4 report + appendix + hashes
```

### Hai mức triển khai

**Mức A — prototype dễ trình diễn.** Dùng AES-GCM để mã hóa nội dung file đã lọc, khóa nội dung được bọc bằng RSA-OAEP hoặc một public-key scheme; dùng inverted index/keyword token cho tìm kiếm trong tập đã lọc. Mức này chứng minh được flow, chain of custody, key custody và privacy boundary.

**Mức B — bám sát paper hơn.** Dùng searchable public-key encryption cho truy vấn trên ciphertext và một thư viện HE cho phép tính trên vector metadata nhỏ. Chỉ áp dụng HE cho feature set như timestamp bucket, kích thước archive, volume USB; không cố mã hóa toàn bộ file system bằng FHE vì chi phí sẽ làm prototype khó chạy và khó giải thích.

Không nên gọi Mức A là “fully homomorphic PPDF”. Báo cáo phải nêu chính xác primitive nào đã dùng và primitive nào chỉ được mô phỏng.

## 7. Quy trình thực nghiệm chi tiết

### Bước 0 — Chuẩn bị case

1. Tạo `case_id`, mô tả incident, người phê duyệt, phạm vi thời gian và phạm vi user.
2. Ghi rõ H1/H2/H3 trước khi xem dữ liệu.
3. Tạo key pair; lưu private key ngoài thư mục làm việc, mã hóa at rest.
4. Chốt dictionary từ khóa và lý do từng nhóm từ khóa.

Ví dụ dictionary ban đầu:

```yaml
first_keywords_or:
  - project-x
  - confidential
  - internal-only
  - export
  - exfil
  - usb
  - archive
  - upload
  - sync
  - 2026-10-14
second_keywords_and:
  - project-x
  - export
  - usb
```

Từ khóa thứ nhất phải rộng để recall cao; từ khóa thứ hai phải hẹp để precision cao. Với từ khóa thời gian, cần ghi rõ timezone và cách xử lý clock skew.

### Bước 1 — Acquire và preserve

1. Dùng công cụ pháp chứng để tạo image hoặc nhận image do NCL cung cấp.
2. Tính SHA-256/SHA-512 của image và ghi vào manifest.
3. Mount image read-only; không chạy thao tác trực tiếp trên bản gốc.
4. Tạo working copy; ghi hash trước và sau mỗi bước biến đổi.
5. Ghi tool, version, command, hostname, examiner, timestamp UTC và timezone.

Manifest tối thiểu:

```json
{
  "case_id": "NCL-PPDF-001",
  "source": "alice_workstation.E01",
  "sha256": "<hash>",
  "acquired_at_utc": "<timestamp>",
  "mounted_read_only": true,
  "examiner": "<team-member>",
  "tool_versions": ["<tool> <version>"],
  "parent_hash": null
}
```

### Bước 2 — Stage 2: OR search và mã hóa

1. Parse tên file, đường dẫn, metadata, text trích xuất và artifact có thể đọc được.
2. Chạy OR search; lưu cả query, parser version và danh sách match.
3. Gắn mỗi match với `artifact_id`, path, offset (nếu có), timestamp và source.
4. Loại các hit rõ ràng ngoài phạm vi; phải ghi lý do loại.
5. Đóng gói case-related set thành manifest bất biến.
6. Mã hóa nội dung bằng public key/envelope encryption.
7. Xóa plaintext tạm theo policy an toàn; giữ hash của plaintext để tái lập mà không cần phát hành nội dung.

Ví dụ record:

```json
{
  "artifact_id": "a-0042",
  "source_path": "C:/Users/alice/AppData/Local/Temp/px_export.7z",
  "matched_first_keywords": ["project-x", "export", "archive"],
  "sha256_plaintext": "<hash>",
  "ciphertext_uri": "ciphertext/a-0042.bin",
  "privacy_class": "L3",
  "status": "case-related"
}
```

### Bước 3 — Stage 3: AND search và phân tích

1. Chỉ analyst có quyền mới được gửi từ khóa thứ hai.
2. Tìm `Project-X AND export AND USB` trên case-related set.
3. Tạo timeline từ metadata đã lọc: archive creation, USB insertion, file access, deletion, upload/sync.
4. Correlate theo user, volume serial, path, timestamp và hash.
5. Nếu đủ feature, chạy clustering trên encrypted/feature data; giải thích rõ kết quả cluster không tự động chứng minh hành vi.
6. Nếu chưa đủ, lặp lại từ khóa thứ hai với scope nhỏ hơn hoặc xin mở rộng có phê duyệt.

Điều tra viên chỉ xem dữ liệu sâu ở các record đã đạt ngưỡng case-pertinent. Dữ liệu như ảnh cá nhân hoặc tài liệu tài chính không liên quan vẫn nằm ngoài scope.

### Bước 4 — Giải mã có kiểm soát và báo cáo

1. Viết yêu cầu giải mã nêu artifact IDs, mục đích và người phê duyệt.
2. Key manager ghi access log rồi mới cấp private-key operation.
3. Giải mã đúng subset; không giải mã cả ciphertext store.
4. Kiểm tra hash, timestamp, provenance và khả năng tái lập.
5. Viết findings theo H1/H2/H3, kèm confidence và alternative explanation.
6. Đính kèm danh sách dữ liệu không xem/không phát hành do privacy boundary.

## 8. Pseudocode của flow

```text
PPDF(case, image):
    scope, warrant, hypotheses = define_case(case)
    (pub, priv) = generate_key_pair()
    store_private_key_in_vault(priv, approval_required=True)

    original_hash = hash(image)
    working_copy = mount_read_only_and_copy(image)
    assert hash(image) == original_hash

    related = OR_search(working_copy, first_keywords)
    related = apply_scope_and_privacy_policy(related, scope)
    related_ct = encrypt_each(related, pub)
    save_manifest(related_ct, original_hash, chain_of_custody)

    repeat:
        pertinent_ct = AND_search(related_ct, second_keywords)
        features_ct = extract_allowed_features(pertinent_ct)
        findings_ct = analyze(features_ct)       # correlation / optional HE / clustering
        if hypothesis_is_sufficient(findings_ct):
            break
        second_keywords = refine_with_approval(second_keywords)

    approved_subset = request_decryption_scope(findings_ct)
    findings = decrypt(approved_subset, priv)
    report(findings, hashes, queries, approvals, limitations)
```

## 9. Đánh giá privacy và tính pháp chứng

### Privacy

- **Data minimization:** chỉ mã hóa case-related và phân tích case-pertinent.
- **Purpose limitation:** mọi query phải gắn với H1/H2/H3.
- **Access control:** public key có thể chia sẻ; private key không chia sẻ tự do.
- **Third-party privacy:** dữ liệu người dùng khác trên workstation không bị mở mặc định.
- **Auditability:** log query, decryption, approval và export.
- **Retention:** đặt thời hạn xóa working copy/plaintext tạm; giữ manifest và hash theo policy.

### Tính toàn vẹn và khả năng tái lập

- hash image trước/sau acquire;
- hash từng artifact và ciphertext;
- version của parser, keyword dictionary, key ID và công cụ;
- UTC timestamp kèm timezone gốc;
- chain-of-custody event append-only;
- báo cáo ghi rõ thao tác nào chạy trên bản gốc, bản sao hay ciphertext.

PPDF bảo vệ tính riêng tư; nó không tự động chứng minh tính toàn vẹn. Vì vậy cần kết hợp hash, read-only acquisition, signed manifest hoặc một audit store bất biến.

## 10. Kết quả nhóm nên nộp

1. `PPDF_Disk_Forensics_Plan.md` — scope, flow, mapping và giới hạn.
2. Sơ đồ `ppdf_flow.svg`.
3. `acquisition_manifest.json` và chain-of-custody log.
4. Keyword dictionary phiên bản hóa, có lý do chọn từng nhóm.
5. Case-related manifest + ciphertext sample.
6. Case-pertinent timeline và bảng correlation.
7. Key-management/access log đã ẩn bí mật.
8. Báo cáo cuối: H1/H2/H3, artifact IDs, hashes, confidence, alternative explanation và privacy decisions.
9. README chạy lại prototype từ image/fixture, nêu rõ tool versions và primitive mã hóa.

## 11. Cách trình bày demo

Một demo 8–10 phút có thể đi theo nhịp sau:

1. Nêu incident, phạm vi và H1/H2/H3.
2. Cho xem hash image và chain of custody.
3. Chạy từ khóa 1 dạng OR; cho thấy nhiều hit nhưng chưa mở nội dung riêng tư.
4. Mã hóa case-related set; cho xem manifest/ciphertext.
5. Chạy từ khóa 2 dạng AND; cho thấy dataset giảm còn các artifact của `Project-X`/USB/export.
6. Hiển thị timeline và correlation trên tập đã lọc.
7. Xin approval, giải mã một subset, đối chiếu hash.
8. Kết luận mức độ ủng hộ H1/H2/H3 và chỉ ra dữ liệu cố ý không xem.

## 12. Các giới hạn phải nói rõ

- Paper là mô hình khái niệm; không cung cấp một tool hoàn chỉnh cho mọi filesystem.
- HE có chi phí tính toán và ciphertext lớn; không phù hợp để mã hóa toàn bộ disk image trong prototype nhỏ.
- Searchable encryption có thể làm lộ một số metadata/pattern tùy scheme; cần nêu leakage profile của thư viện dùng.
- Initial OR search trên disk image cục bộ diễn ra trong môi trường điều tra có quyền; nếu muốn bảo vệ điều tra viên khỏi dữ liệu riêng tư ngay cả ở bước này, cần thêm blind/secure indexing hoặc tách vai trò operator.
- Keyword search không tìm thấy mọi bằng chứng: file không có text, mã hóa, steganography, tên đổi hoặc clock sai có thể bị bỏ sót.
- K-means/clustering chỉ là hỗ trợ phân tích, không phải kết luận pháp lý.
- Private-key custody, approval và retention là vấn đề vận hành; không thể giải quyết chỉ bằng thuật toán.

## 13. Kết luận làm việc

Flow phù hợp nhất cho nhóm là:

```text
scope + key
  → image/hash/read-only
  → OR search rộng (case-related)
  → encrypt + freeze
  → AND search hẹp (case-pertinent)
  → encrypted metadata analysis
  → approved decryption
  → reproducible report
```

Đây chính là tinh thần PPDF: điều tra vẫn đủ để kiểm định vụ rò rỉ, nhưng quyền truy cập vào dữ liệu riêng tư tăng dần theo mức cần thiết và có thể kiểm toán.

## Tài liệu nguồn

- Ogunseyi, T. B., & Adedayo, O. M. (2023). *Cryptographic Techniques for Data Privacy in Digital Forensics*. IEEE Access, 11, 142392–142408. DOI: `10.1109/ACCESS.2023.3343360`.
- File paper trong thư mục bài: [Cryptographic Techniques for Data Privacy in Digital_Forensics.pdf](Cryptographic%20Techniques%20for%20Data%20Privacy%20in%20Digital_Forensics.pdf).
