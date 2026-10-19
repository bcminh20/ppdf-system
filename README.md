# PPDF Algorithm 1 — Asymmetric Key Generation

Module Python này triển khai phần **Khởi tạo khóa (Algorithm 1)** trong mô hình Privacy-Preserving Digital Forensics (PPDF). Trong bài của nhóm, module này là **Stage 1 — Preparation / Key Generation**: tạo cặp khóa để bảo vệ dữ liệu pháp chứng ở các bước lọc, mã hóa và phân tích sau đó.

## NCL description

Trong kịch bản NCL của nhóm, điều tra viên nhận được disk image của máy nhân viên bị nghi làm rò rỉ dữ liệu nội bộ. Module này không phân tích disk image và không tự tìm file. Nó chỉ tạo khóa trước khi các block khác bắt đầu trích xuất và mã hóa dữ liệu liên quan đến vụ án.

Flow sử dụng module:

```text
case scope / hypothesis
        ↓
module này: generate_keypair()
        ↓
PublicKey  → dùng cho block mã hóa/search
PrivateKey → giữ local trong .env, chỉ dùng ở block giải mã được cấp quyền
```

Ví dụ trong bài: block tìm kiếm đã lọc ra các artifact liên quan tới `Project-X`, USB và thao tác export. Block đó dùng public key để mã hóa dữ liệu. Private key được giữ lại ở máy điều tra viên để block cuối giải mã kết quả cần trình bày.

Module **không** làm các việc sau:

- mount hoặc parse disk image;
- tìm keyword trong filesystem;
- mã hóa file evidence;
- giải mã dữ liệu;
- xây dựng hệ thống phân quyền nhiều người dùng.

## Cài đặt

Yêu cầu Python 3.10 trở lên và SymPy.

```bash
python -m pip install -r requirements.txt
```

Nếu máy dùng lệnh `python3` thay cho `python`:

```bash
python3 -m pip install -r requirements.txt
```

Không cần cài hoặc kích hoạt conda environment để chạy module.

## Chạy bằng command line

Chạy cấu hình mặc định theo paper:

```bash
python ppdf_keygen.py
```

Giá trị mặc định:

```text
dimension = 8
coefficient_bits = 128
max_attempts = 100
```

Kết quả được ghi vào thư mục hiện tại:

- `public_key.json`: public key `Pub_key = (d, r)`;
- `.env`: private key `Pri_key = (w_i)`.

Private key không được in ra terminal. File `.env` đã nằm trong `.gitignore` và không được commit lên Git.

Sinh khóa với tham số khác:

```bash
python ppdf_keygen.py \
  --dimension 16 \
  --coefficient-bits 128 \
  --max-attempts 100
```

Nếu `.env` đã có private key, chương trình dừng để tránh ghi đè nhầm. Chỉ ghi đè khi thật sự muốn tạo key pair mới:

```bash
python ppdf_keygen.py --overwrite
```

`--seed` chỉ dùng cho test hoặc demo tái lập, không dùng khi tạo khóa thật:

```bash
python ppdf_keygen.py \
  --dimension 4 \
  --coefficient-bits 8 \
  --seed 12345 \
  --public-key /tmp/public_key.json \
  --env-file /tmp/ppdf.env
```

## API của module

Block khác có thể import các thành phần từ `ppdf_keygen.py`:

```python
from ppdf_keygen import (
    generate_keypair,
    save_public_key,
    save_private_key_to_env,
    load_public_key,
    load_private_key_from_env,
)
```

### Kiểu dữ liệu trả về

#### `PublicKey`

Đại diện cho public key:

```python
PublicKey(
    d: int,
    r: int,
)
```

Các thuộc tính:

- `d`: modulus tạo từ resultant của `v(x)` và `f(x)`;
- `r`: giá trị được tính từ `w0`, `w1` theo Algorithm 1.

Các phương thức:

```python
public_key.as_dict() -> dict[str, int]
```

Kết quả:

```python
{"d": 123456789, "r": 987654321}
```

#### `PrivateKey`

Đại diện cho private key:

```python
PrivateKey(
    w: tuple[int, ...],
)
```

`w` là dãy các giá trị `w_i` được tạo từ các hệ số của `w(x)`.

Phương thức:

```python
private_key.as_list() -> list[int]
```

#### `KeyPair`

Đối tượng kết quả đầy đủ của `generate_keypair()`:

```python
KeyPair(
    public_key: PublicKey,
    private_key: PrivateKey,
    dimension: int,
    coefficient_bits: int,
    attempts: int,
)
```

- `public_key`: khóa công khai;
- `private_key`: khóa bí mật;
- `dimension`: số hệ số của đa thức;
- `coefficient_bits`: số bit của hệ số ban đầu;
- `attempts`: số lần thử trước khi tạo được khóa hợp lệ.

### API chính cho block khác

#### `generate_keypair()`

Đây là **hàm duy nhất cần gọi nếu block chỉ cần tạo khóa**.

```python
generate_keypair(
    dimension: int = 8,
    coefficient_bits: int = 128,
    *,
    max_attempts: int = 100,
    seed: int | None = None,
) -> KeyPair
```

Đầu vào:

| Tham số | Kiểu | Bắt buộc | Ý nghĩa |
|---|---:|---:|---|
| `dimension` | `int` | Không | Số hệ số của đa thức. Giá trị tối thiểu là `2`, mặc định `8`. |
| `coefficient_bits` | `int` | Không | Số bit của mỗi hệ số ngẫu nhiên ban đầu. Mặc định `128` theo paper. |
| `max_attempts` | `int` | Không | Số lần thử tối đa nếu khóa không đạt điều kiện GCD. Mặc định `100`. |
| `seed` | `int \| None` | Không | Seed cho test tái lập. Để `None` khi chạy thật để dùng randomness hệ thống. |

Đầu ra:

```python
pair = generate_keypair()

pair.public_key   # PublicKey(d=..., r=...)
pair.private_key  # PrivateKey(w=(..., ..., ...))
```

Tương ứng với notation trong paper:

```text
pair.public_key  = Pub_key = (d, r)
pair.private_key = Pri_key = (w_i)
```

Các lỗi có thể gặp:

- `ValueError`: tham số nhỏ hơn giới hạn hoặc sai kiểu;
- `KeyGenerationError`: không tạo được khóa hợp lệ trong `max_attempts` lần.

Ví dụ block tạo khóa:

```python
from ppdf_keygen import generate_keypair

key_pair = generate_keypair()
public_key = key_pair.public_key
private_key = key_pair.private_key

# Block mã hóa/search dùng public_key.
# Block giải mã dùng private_key sau khi có quyền phù hợp.
```

#### `save_public_key()`

Lưu public key thành JSON để block khác hoặc investigator khác có thể đọc.

```python
save_public_key(
    public_key: PublicKey,
    path: str | pathlib.Path = "public_key.json",
) -> pathlib.Path
```

Đầu vào:

- `public_key`: đối tượng `PublicKey` từ `generate_keypair()`;
- `path`: đường dẫn file JSON, mặc định `public_key.json`.

Đầu ra:

- trả về `Path` của file đã ghi;
- file có dạng:

```json
{
  "d": 123456789,
  "r": 987654321
}
```

#### `save_private_key_to_env()`

Lưu private key trong file `.env` local.

```python
save_private_key_to_env(
    private_key: PrivateKey,
    path: str | pathlib.Path = ".env",
    *,
    dimension: int | None = None,
    coefficient_bits: int | None = None,
    overwrite: bool = False,
) -> pathlib.Path
```

Đầu vào:

- `private_key`: đối tượng `PrivateKey`;
- `path`: đường dẫn file env, mặc định `.env`;
- `dimension`: tham số dùng để tạo khóa, được ghi lại để tái lập;
- `coefficient_bits`: tham số dùng để tạo khóa, được ghi lại để tái lập;
- `overwrite`: mặc định `False`, không cho ghi đè private key cũ.

Đầu ra:

- trả về `Path` của file `.env`;
- ghi biến:

```env
PPDF_PRIVATE_KEY_W=[...]
PPDF_KEY_DIMENSION=8
PPDF_COEFFICIENT_BITS=128
```

Hàm ghi file theo cách atomic và cố đặt permission `0600` trên hệ thống POSIX.

#### `load_public_key()`

Đọc public key từ JSON để block mã hóa/search sử dụng.

```python
load_public_key(
    path: str | pathlib.Path = "public_key.json",
) -> PublicKey
```

Đầu vào là đường dẫn JSON. Đầu ra là `PublicKey`. Hàm kiểm tra `d > 1` và `0 <= r < d`.

#### `load_private_key_from_env()`

Đọc private key từ `.env` cho block giải mã.

```python
load_private_key_from_env(
    path: str | pathlib.Path = ".env",
) -> PrivateKey
```

Đầu vào là đường dẫn `.env`. Đầu ra là `PrivateKey`. Nếu biến `PPDF_PRIVATE_KEY_W` thiếu hoặc không phải JSON list các số nguyên, hàm báo lỗi.

### Các hàm toán học public trong module

Các hàm sau được để public để nhóm có thể kiểm tra từng bước của Algorithm 1. Block nghiệp vụ thông thường **không cần gọi trực tiếp**; chỉ gọi khi muốn debug, viết test hoặc trình bày từng bước trong demo.

#### `modulus_polynomial()`

```python
modulus_polynomial(dimension: int) -> sympy.Poly
```

Đầu vào là `dimension = n`. Đầu ra là đa thức mô-đun:

```text
f(x) = x^n + 1
```

Ví dụ `dimension=4` trả về `x**4 + 1`.

#### `random_vector()`

```python
random_vector(
    dimension: int,
    coefficient_bits: int,
    rng: _RandomSource | None = None,
) -> tuple[int, ...]
```

Sinh vector `v` có đúng `dimension` hệ số. Mỗi hệ số được sinh với `coefficient_bits` bit; hệ số cuối được điều chỉnh để tổng các hệ số là số lẻ, đúng điều kiện của Algorithm 1.

Đầu ra:

```python
(v0, v1, ..., v[n-1])
```

`rng` chỉ dành cho test nội bộ. Khi block gọi `generate_keypair()` mà không truyền seed, module dùng randomness hệ thống.

#### `vector_to_polynomial()`

```python
vector_to_polynomial(values: Sequence[int]) -> sympy.Poly
```

Chuyển vector hệ số theo thứ tự tăng dần thành đa thức. Ví dụ:

```python
vector_to_polynomial([2, 3, 5])
# 2 + 3*x + 5*x**2
```

Đầu vào không được là vector rỗng. Đầu ra là `sympy.Poly` trên miền số nguyên.

#### `resultant_and_w()`

```python
resultant_and_w(
    vector: Sequence[int],
    dimension: int,
) -> tuple[int, tuple[int, ...]]
```

Tính hai giá trị trung gian quan trọng:

- `d`: resultant của `v(x)` và `f(x)`;
- `w`: các hệ số của đa thức `w(x)` thỏa `w(x)v(x) = d (mod f(x))`.

Đầu vào là vector `v` có độ dài đúng bằng `dimension`. Đầu ra có dạng:

```python
(d, (w0, w1, ..., w[n-1]))
```

Nếu đa thức không khả nghịch hoặc resultant không tạo được khóa hợp lệ, hàm ném `KeyGenerationError` để `generate_keypair()` thử vector mới.

#### `KeyGenerationError`

Đây là exception riêng của module cho các lỗi toán học hoặc trường hợp không sinh được khóa hợp lệ trong số lần thử cho phép. Block có thể bắt exception này để báo lỗi job, nhưng không nên tự dùng private key chưa hoàn chỉnh.

#### `main()`

```python
main() -> int
```

Đây là entry point của command line. Nó đọc các tham số `--dimension`, `--coefficient-bits`, `--max-attempts`, `--seed`, `--public-key`, `--env-file`, sau đó gọi các API lưu khóa. Block Python khác không cần gọi `main()`; chỉ dùng lệnh `python ppdf_keygen.py ...`.

## Cách dùng trong một block

### Block chỉ cần tạo khóa

Chỉ gọi:

```python
from ppdf_keygen import generate_keypair

pair = generate_keypair()
```

Đầu vào cần thiết: không bắt buộc tham số nào nếu dùng mặc định.

Đầu ra:

```text
pair.public_key  → chuyển sang block mã hóa/search
pair.private_key → chuyển sang block lưu khóa hoặc giữ trong memory
```

Nếu muốn lưu ra file:

```python
from ppdf_keygen import (
    generate_keypair,
    save_public_key,
    save_private_key_to_env,
)

pair = generate_keypair()
save_public_key(pair.public_key, "public_key.json")
save_private_key_to_env(
    pair.private_key,
    ".env",
    dimension=pair.dimension,
    coefficient_bits=pair.coefficient_bits,
)
```

### Block mã hóa/search

Block mã hóa chỉ cần public key:

```python
from ppdf_keygen import load_public_key

public_key = load_public_key("public_key.json")
# dùng public_key.d và public_key.r trong block mã hóa/search
```

Block này không cần đọc `.env` và không được yêu cầu private key.

### Block giải mã

Block giải mã mới đọc private key:

```python
from ppdf_keygen import load_private_key_from_env

private_key = load_private_key_from_env(".env")
# dùng private_key.w trong block giải mã
```

Trong flow PPDF, việc gọi hàm này phải xảy ra sau khi có quyền giải mã. Module hiện chỉ lưu/đọc key local; việc kiểm tra quyền thuộc về block điều phối của nhóm.

## Algorithm 1 được triển khai như thế nào?

Với `n = dimension`, `t = coefficient_bits`:

1. Sinh vector ngẫu nhiên `v = (v0, ..., v(n-1))`, mỗi hệ số có `t` bit.
2. Điều chỉnh để `sum(v_i) ≡ 1 (mod 2)`.
3. Tạo đa thức `v(x)`.
4. Dùng đa thức mô-đun:

   ```text
   f(x) = x^n + 1
   ```

5. Tính resultant `d` của `v(x)` và `f(x)`.
6. Tính `w(x)` sao cho:

   ```text
   w(x) * v(x) = d (mod f(x))
   ```

7. Lấy `w0`, `w1`, kiểm tra điều kiện GCD.
8. Tính `r = w0 × inverse(w1, d) mod d`.
9. Tạo các private coefficient `w_i` theo biến đổi của Algorithm 1.
10. Nếu điều kiện khóa không đạt, lặp lại với vector ngẫu nhiên mới.

## Định dạng file khóa

Public key trong `public_key.json`:

```json
{
  "d": 123456789,
  "r": 987654321
}
```

Private key trong `.env`:

```env
PPDF_PRIVATE_KEY_W=[123,456,789]
PPDF_KEY_DIMENSION=8
PPDF_COEFFICIENT_BITS=128
```

Không commit `.env`, không gửi private key vào báo cáo hoặc chat nhóm. `public_key.json` không bị ignore vì public key có thể chia sẻ cho các block khác.

## Kiểm thử

Chạy toàn bộ test:

```bash
python -m unittest -v test_ppdf_keygen.py
```

Test bao gồm:

- sinh khóa với seed và kiểm tra tính tái lập;
- kiểm tra tham số không hợp lệ;
- kiểm tra retry contract;
- lưu/đọc public key;
- lưu/đọc private key từ `.env`;
- chống ghi đè private key khi chưa truyền `overwrite=True`;
- kiểm tra permission `0600` của `.env` trên POSIX.

## Giả định và giới hạn

Paper mô tả Algorithm 1 dựa trên scheme ở tài liệu tham chiếu [77] nhưng không đưa đầy đủ định nghĩa của đa thức mô-đun. Module này dùng giả định kỹ thuật `f(x) = x^n + 1`, dùng SymPy để tính resultant và nghịch đảo đa thức, sau đó kiểm tra quan hệ:

```text
w(x) * v(x) = d (mod f(x))
```

Đây là implementation nghiên cứu/prototype để nhóm kiểm tra flow và định dạng khóa, không phải cryptosystem production. Nếu triển khai thực tế cần thay backend bằng scheme được đặc tả đầy đủ, có đánh giá bảo mật và dùng hệ thống quản lý khóa chuyên dụng thay cho `.env`.
