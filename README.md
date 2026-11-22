# PPDF Hybrid System (HE + SSE)
## Privacy-Preserving Digital Forensics Framework

Hệ thống điều tra pháp chứng số bảo toàn quyền riêng tư kết hợp **Searchable Symmetric Encryption (SSE)** và **Homomorphic Encryption (HE)** theo bài báo khoa học:
> T. B. Ogunseyi & O. M. Adedayo, *"Cryptographic Techniques for Data Privacy in Digital Forensics"*, **IEEE Access**, vol. 11, pp. 142392–142408, 2023. DOI: [10.1109/ACCESS.2023.3343360](https://doi.org/10.1109/ACCESS.2023.3343360).

---

## 1. Sơ đồ Luồng Dữ liệu (4 Giai đoạn)

```
[DỮ LIỆU GỐC TRÍCH XUẤT TỪ AUTOPSY: U_D] (PC, RM1, RM2)
   │ (Bao gồm: emails.csv, Secret Project Data, $OrphanFiles_đổi đuôi, barn.gif, cave.png...)
   ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ GIAI ĐOẠN 1 & 2: KHỞI TẠO KHÓA, LỌC SƠ BỘ & MÃ HÓA KÉP                    │
│                                                                           │
│  [Bước 2.1] Lọc từ khóa vòng 1 (Disjunctive Search - OR): F_kywd          │
│     • Điều kiện: Chứa "secret" HOẶC "pricing" HOẶC "proposal"             │
│     ├─► File KHÔNG khớp (barn.gif, cave.png, eggs.gif)                    │
│     │     ──► [LOẠI BỎ NGAY] -> Bảo vệ quyền riêng tư 100%                │
│     │                                                                     │
│     └─► File KHỚP (Cr_kw): Tập ứng viên (F1, F2, F3)                      │
│           │                                                               │
│           ├─────────────────────────────┬─────────────────────────────────┤
│           ▼ (Nhánh Văn bản - SSE)       ▼ (Nhánh Số học - HE)             │
│  [Bước 2.2a] Tạo Index & Mã hóa File   [Bước 2.2b] Trích xuất & Mã hóa HE │
│   • Băm từ khóa bằng HMAC(K_SSE, w)     • Chấm điểm đặc trưng mỗi file:   │
│     để tạo Encrypted Inverted Index.      V_i = [Số_từ_khóa, Điểm_ẩn_giấu]│
│   • Mã hóa nội dung F1, F2, F3          • Mã hóa V_i bằng Pub_key (d, r)  │
│     bằng AES-GCM (K_AES).                 (Algorithm 2) -> Bản mã Cr'_kw  │
└───────────┼─────────────────────────────┼─────────────────────────────────┘
            │                             │
            ▼                             ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ GIAI ĐOẠN 3: TRUY VẤN TỪ KHÓA (SSE) & PHÂN CỤM ĐỒNG HÌNH (HE)             │
│ (Toàn bộ quá trình diễn ra trên dữ liệu đã mã hóa - Ciphertext)           │
│                                                                           │
│  [Bước 3.1] Lọc tinh bằng SSE (Conjunctive Search - AND): S_kywd          │
│     • Điều tra viên tìm: "secret" VÀ "pricing"                            │
│     • Tạo Trapdoor: T1 = HMAC("secret"), T2 = HMAC("pricing")             │
│     • Tra bảng Encrypted Index ──► Tìm ra tập giao: F1 và F3 (Crv'_kw)    │
│     • (File F2 bị loại vì chỉ chứa 1 từ khóa)                             │
│                                                                           │
│  [Bước 3.2] Phân cụm K-Means trên bản mã HE (Algorithm 3):                │
│     • Chỉ lấy vector mã hóa HE của F1 và F3 đưa vào K-Means (q = 2 cụm)   │
│     • Tính khoảng cách trên bản mã ──► Chia thành:                        │
│         + Cụm C'_1 (Mức độ nghi vấn CAO - Dấu vết cố tình che giấu)       │
│         + Cụm C'_2 (Mức độ nghi vấn THẤP - File liên quan thông thường)   │
└─────────────────────────────────────────┼─────────────────────────────────┘
                                          │
                                          ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ GIAI ĐOẠN 4: GIẢI MÃ CÓ CHỌN LỌC & TRÌNH BÀY BẰNG CHỨNG                   │
│                                                                           │
│  [Bước 4.1] Giải mã kết quả phân cụm bằng Pri_key (Algorithm 4):          │
│     • Mở khóa C'_1, C'_2 ──► Biết được F3 thuộc Cụm 1 (Nguy hiểm nhất)    │
│                                                                           │
│  [Bước 4.2] Giải mã nội dung file bằng chứng (K_AES):                     │
│     • Chỉ giải mã nội dung file F3 ($OrphanFiles_đổi đuôi) để trình bày!  │
│     • Các file khác giữ nguyên dạng mã hóa AES trong vault.bin.           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Các lệnh thực thi từng giai đoạn

```bash
# 1. Kiểm thử toàn bộ 25 unit & integration tests
.\run.ps1 test

# 2. Giai đoạn 1: Sinh khóa HE (Pubkey, Prikey) và SSE Master Key
.\run.ps1 keygen --overwrite

# 3. Giai đoạn 2: Lọc OR rộng (SSE) + Lập chỉ mục & Mã hóa đặc trưng V_i (HE Alg 2)
.\run.ps1 stage2 --evidence-dir "..\KetQua"

# 4. Giai đoạn 3: Lọc AND hẹp (SSE 3.1) + Phân cụm K-Means trên bản mã (HE Alg 3)
.\run.ps1 stage3 --evidence-dir "..\KetQua" --mode conjunctive

# 5. Giai đoạn 4: Giải mã phân cụm (HE Alg 4) + Giải mã chọn lọc file nghi can (AES)
.\run.ps1 stage4 --evidence-dir "..\KetQua"

# Hoặc: Chạy liên hoàn toàn bộ quy trình từ đầu đến cuối
.\run.ps1 full --evidence-dir "..\KetQua" --overwrite
```
