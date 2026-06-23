Build window
cd "D:\24162075.All6labs\lab 3\rsatool_window"
Remove-Item -Recurse -Force build
mkdir build
cd build
cmake .. -G "MinGW Makefiles"
mingw32-make

Build Ubuntu
cd "/home/quangminh/24162075_AllLab/lab 3/rsatool_window"
cd build
rm -rf *
cmake ..
cmake --build .


# RSA & Hybrid Encryption Tool (Cross-Platform Benchmarking)

Một công cụ dòng lệnh (CLI Tool) hiệu năng cao được phát triển bằng C++ nhằm thực hiện các tác vụ mã hóa bất đối xứng RSA-OAEP và hệ thống mã hóa lai (Hybrid Encryption) kết hợp mã hóa đối xứng AES-GCM. Dự án bao gồm các kịch bản kiểm thử hiệu năng tự động (Benchmarking Script) chạy trên cả hai môi trường Windows và Ubuntu (Linux).

## Tính năng cốt lõi
* **RSA Key Generation:** Sinh cặp khóa RSA an toàn tiêu chuẩn NIST với kích thước 3072-bit và 4096-bit. Chủ động từ chối và chặn cấu hình khóa yếu (2048-bit).
* **RSA-OAEP Encryption/Decryption:** Mã hóa an toàn cho dữ liệu nhỏ dưới ngưỡng giới hạn cấu trúc hình học (318 bytes đối với khóa 3072-bit dùng SHA-256).
* **Hybrid Encryption (Envelope Mode):** Khắc phục rào cản dung lượng của RSA bằng cách sinh khóa phiên AES-256 ngẫu nhiên, mã hóa dữ liệu lớn thông qua **AES-256-GCM** và dùng RSA-OAEP để bao bọc khóa phiên.
* **Automated Benchmarking:** Script đo lường hiệu năng độc lập N 30 lần, tự động tính toán các chỉ số thống kê (Mean, Median, Std Dev, 95% CI) xuất ra file CSV.

---

## Các gói phụ thuộc (Dependencies)

Để biên dịch và chạy dự án này thành công, hệ thống của bạn bắt buộc phải cài đặt các thành phần phụ thuộc sau:

### 1. Trên hệ điều hành Ubuntu (Linux)
* **Trình biên dịch:** `g++` (hỗ trợ tiêu chuẩn C++17 trở lên).
* **Thư viện Mật mã học:** `OpenSSL 3.x` (bao gồm các file nhị phân và thư viện phát triển `libssl-dev`).

### 2. Trên hệ điều hành Windows
* **Môi trường & Trình biên dịch:** `MSYS2` với bộ công cụ `MinGW-w64` (`g++` hỗ trợ C++17).
* **Thư viện Mật mã học:** `OpenSSL 3.x` được cài đặt thông qua trình quản lý gói của MSYS2.
* **Môi trường chạy script:** `PowerShell 7+` hoặc Windows PowerShell tích hợp sẵn để thực thi script benchmark `.ps1`.

---

### Các lệnh thực thi mẫu (Example Execution Commands)

Dưới đây là kịch bản các lệnh chạy thực tế từ đầu đến cuối để bạn dễ dàng test toàn bộ tính năng của công cụ trên Terminal / PowerShell.

#### 1. Chuẩn bị file dữ liệu Test
Trước khi chạy, hãy tạo ra 2 file dữ liệu mẫu (1 file nhỏ dưới 318 bytes và 1 file lớn) để kiểm thử rào cản của RSA:
```bash
# Tạo file nhỏ (đạt chuẩn mã hóa RSA-OAEP 3072-bit thuần túy)
echo "Hello Minh, day la du lieu test duoi 318 bytes." > data_nho.txt

# Tạo file lớn (vượt ngưỡng RSA thuần túy, bắt buộc phải dùng Hybrid)
echo "Nội dung này giả lập một file dữ liệu rất lớn..." > data_lon.txt
# (Tùy chọn) Nhân bản nội dung hoặc dùng một file ảnh/zip bất kỳ để làm data_lon.txt
```
# Kịch bản 1:
# Bước A: Sinh cặp khóa 3072-bit
./rsatool keygen 3072 priv3072.pem pub3072.pem

# Bước B: Mã hóa file nhỏ bằng khóa công khai (Dùng mode rsa-enc)
./rsatool rsa-enc pub3072.pem data_nho.txt cipher_nho.bin

# Bước C: Giải mã file nhỏ bằng khóa bí mật (Dùng mode rsa-dec)
./rsatool rsa-dec priv3072.pem cipher_nho.bin restore_nho.txt

# Bước D: Kiểm tra nội dung sau khi giải mã xem có khớp file gốc không
cat restore_nho.txt

# Kịch bản 2:
# Cố tình nạp file lớn vào chế độ mã hóa RSA thuần túy
./rsatool rsa-enc pub3072.pem data_lon.txt cipher_loi.bin

# [KẾT QUẢ MONG ĐỢI]: 
# Chương trình chủ động chặn đứng và ném lỗi kiểm soát dung lượng:
# "Error: Plaintext too large for RSA key size!"

# Giả lập tình huống file cấu hình đầu vào bị rỗng hoặc sai định dạng cấu trúc dữ liệu:
./rsatool rsa-enc pub3072.pem empty_config.json cipher_loi.bin

# [KẾT QUẢ MONG ĐỢI]: 
# Hệ thống không thể phân tích và báo lỗi luồng đọc dữ liệu:
# "Error: Failed to load or parse JSON/Key configuration data!"




# Kịch bản 3:
# Bước A: Sinh cặp khóa 4096-bit (Để nâng cao độ an toàn phân phối khóa)
./rsatool keygen 4096 priv4096.pem pub4096.pem

# Bước B: Mã hóa lai file dữ liệu lớn (Dùng mode hybrid-enc)
./rsatool hybrid-enc pub4096.pem data_lon.txt cipher_lai.bin

# Bước C: Giải mã lai bằng khóa bí mật (Dùng mode hybrid-dec)
./rsatool hybrid-dec priv4096.pem cipher_lai.bin restore_lon.txt

# Bước D: So sánh hash của file gốc và file phục hồi để đảm bảo toàn vẹn dữ liệu
# Trên Ubuntu:
sha256sum data_lon.txt restore_lon.txt
# Trên Windows (PowerShell):
Get-FileHash data_lon.txt, restore_lon.txt

# Kịch bản 4:   
# Thử cố tình sinh khóa 2048-bit (Không đạt tiêu chuẩn Lab / NIST hiện tại)
./rsatool keygen 2048 priv2048.pem pub2048.pem

# [KẾT QUẢ MONG ĐỢI]: 
# "Error: Key size 2048-bit is insecure. Minimum required is 3072-bit."