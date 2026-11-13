# Nền tảng XDR và EDR

XDR là API và dashboard giám sát, tiếp nhận sự kiện, tạo cảnh báo và gom cảnh báo thành incident. EDR là agent chạy trên Windows, đọc sự kiện Sysmon rồi gửi theo lô về XDR.

> Đây là prototype phục vụ học tập/lab. API hiện dùng HTTP; không mở trực tiếp ra Internet. Khi triển khai ngoài mạng tin cậy, hãy dùng VPN hoặc reverse proxy có HTTPS, giới hạn nguồn truy cập và bảo vệ các khóa.

## Thành phần

- `backend/`: API FastAPI, xác thực, tiếp nhận sự kiện, phát hiện và lưu SQLite.
- `frontend/xdr-dashboard/`: dashboard được backend phục vụ tại `/dashboard/`.
- `rules/`: luật phát hiện và dữ liệu IOC mẫu.
- `EDR/` (thư mục dự án riêng): agent Windows đọc Sysmon và gửi sự kiện đến XDR.
- `tests/`: kiểm thử backend.

## Luồng triển khai

1. Chạy XDR trên Ubuntu Server.
2. Tạo tài khoản quản trị và một khóa agent dùng chung.
3. Cài Sysmon và chạy EDR trên máy Windows; cấu hình URL XDR và cùng khóa agent đó.
4. Đăng nhập dashboard để xem sự kiện, host, cảnh báo và incident.

Ví dụ bên dưới giả sử Ubuntu và Windows kết nối được với nhau qua LAN hoặc VPN. Thay `192.168.1.10` bằng địa chỉ IP có thể truy cập được của Ubuntu Server.

## 1. Chạy XDR trên Ubuntu Server bằng Docker Compose

### Yêu cầu

- Ubuntu Server 22.04/24.04, quyền `sudo`.
- Docker Engine và Docker Compose plugin (`docker compose`).
- TCP `8000` chỉ được phép truy cập từ máy EDR hoặc mạng tin cậy.

Cài Docker Engine theo hướng dẫn chính thức của Docker cho Ubuntu, sau đó kiểm tra:

```bash
docker --version
docker compose version
```

Chép hoặc clone thư mục `XDR` lên máy chủ, rồi chuyển vào thư mục gốc của dự án:

```bash
cd /opt/XDR
```

Tạo file `.env` tại thư mục này. Dùng mật khẩu quản trị dài ít nhất 12 ký tự và thay khóa mẫu bằng một chuỗi ngẫu nhiên:

```dotenv
XDR_BOOTSTRAP_ADMIN_USERNAME=admin
XDR_BOOTSTRAP_ADMIN_PASSWORD=THAY_BANG_MAT_KHAU_DAI_IT_NHAT_12_KY_TU
XDR_AGENT_KEY=THAY_BANG_KHOA_NGAU_NHIEN_DUNG_CHUNG_VOI_EDR
```

Có thể tạo khóa ngẫu nhiên bằng `openssl rand -hex 32`, rồi đặt cùng giá trị vào `XDR_AGENT_KEY` và `agent.agent_key` trong cấu hình EDR. Giữ file `.env` và khóa bí mật, không đưa chúng lên Git:

```bash
chmod 600 .env
```

Khởi chạy XDR:

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f api
```

Nhấn `Ctrl+C` để thoát màn hình log; container vẫn chạy nền. Dữ liệu SQLite được lưu trong Docker volume `xdr-data` và tồn tại sau khi container khởi động lại.

Kiểm tra trên Ubuntu:

```bash
curl http://127.0.0.1:8000/health
```

Kết quả mong đợi:

```json
{"status":"ok"}
```

Nếu Ubuntu bật UFW, chỉ mở cổng từ IP máy Windows (thay IP ví dụ bằng IP thực tế):

```bash
sudo ufw allow from 192.168.1.20 to any port 8000 proto tcp
sudo ufw status
```

Nếu máy chủ nằm trên cloud, hãy giới hạn inbound TCP `8000` trong firewall/security group của nhà cung cấp tương tự. Không tạo rule cho phép mọi IP truy cập cổng này.

Để dừng hoặc khởi động lại:

```bash
docker compose down
docker compose up -d
```

Không dùng `docker compose down -v` nếu muốn giữ dữ liệu trong volume.

### Tạo tài khoản quản trị lần đầu

Ở lần khởi chạy đầu tiên, XDR tạo tài khoản quản trị từ `XDR_BOOTSTRAP_ADMIN_USERNAME` và `XDR_BOOTSTRAP_ADMIN_PASSWORD`. Tên tài khoản dài 3–64 ký tự, chỉ gồm chữ, số, `_`, `-`; mật khẩu tối thiểu 12 ký tự. Sau khi tạo tài khoản, có thể bỏ hai biến bootstrap khỏi `.env`; chúng không thay đổi tài khoản đã có. Không xóa volume dữ liệu nếu không chủ ý tạo lại hệ thống.

## 2. Chạy XDR trực tiếp bằng Python (không dùng Docker)

Trên Ubuntu, cần Python 3.10 trở lên và `python3-venv` (Ubuntu Server 22.04/24.04 đáp ứng yêu cầu này). Chép mã nguồn vào máy chủ, rồi chạy tại thư mục gốc dự án:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd /opt/XDR
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Đặt các biến môi trường trước lần khởi chạy đầu tiên. Dùng cùng một giá trị khóa với `agent.agent_key` trong cấu hình EDR:

```bash
export XDR_BOOTSTRAP_ADMIN_USERNAME=admin
export XDR_BOOTSTRAP_ADMIN_PASSWORD='THAY_BANG_MAT_KHAU_DAI_IT_NHAT_12_KY_TU'
export XDR_AGENT_KEY='THAY_BANG_KHOA_NGAU_NHIEN_DUNG_CHUNG_VOI_EDR'
```

Khởi động backend:

```bash
cd /opt/XDR/backend
../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Tiến trình chạy ở foreground; giữ phiên terminal/SSH này mở. Nhấn `Ctrl+C` để dừng. Mặc định SQLite được tạo tại `backend/data/xdr.sqlite3` khi chạy lệnh từ thư mục `backend`. Để chạy lâu dài qua các lần đăng xuất/khởi động lại, nên cấu hình service `systemd` và lưu các biến bí mật trong file chỉ quản trị viên đọc được; không đặt bí mật trực tiếp trong mã nguồn.

## 3. Cài và chạy EDR trên Windows

### Cài Sysmon

EDR đọc kênh `Microsoft-Windows-Sysmon/Operational`, vì vậy Windows cần cài và bật Sysmon. Mở PowerShell bằng quyền Administrator. Có thể tải Sysmon từ Microsoft Sysinternals và cài với cấu hình Sysmon phù hợp chính sách của bạn. Ví dụ dùng cấu hình mẫu để thử nghiệm:

```powershell
New-Item -ItemType Directory -Force C:\Sysmon | Out-Null
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon\Sysmon.zip
Expand-Archive C:\Sysmon\Sysmon.zip -DestinationPath C:\Sysmon -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

Kiểm tra Event Viewer → **Applications and Services Logs** → **Microsoft** → **Windows** → **Sysmon** → **Operational** có sự kiện mới. Cấu hình Sysmon mẫu là của bên thứ ba; hãy xem xét trước khi dùng trong môi trường thật.

### Cài thư viện và cấu hình agent

Đảm bảo thư mục dự án EDR trên Windows có `edr_agent.py`, `sysmon_collector.py`, `sender.py`, `config.yaml` và `requirements.txt`. Mở PowerShell tại thư mục `EDR`:

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Mở `config.yaml` và cập nhật các trường sau:

```yaml
agent:
  agent_id: ""
  agent_key: "THAY_BANG_DUNG_GIA_TRI_XDR_AGENT_KEY"

sender:
  url: "http://192.168.1.10:8000/api/events/batch"
```

- `agent_key` phải khớp chính xác với `XDR_AGENT_KEY` trên Ubuntu.
- Thay `192.168.1.10` bằng IP Ubuntu Server; không dùng `127.0.0.1` nếu EDR và XDR ở hai máy khác nhau.
- Để `agent_id` trống, agent sẽ dùng hostname Windows.
- Không sử dụng khóa mẫu `A19-EDR-DEMO-KEY` trong môi trường thật.

### Khởi chạy và kiểm tra

Trong PowerShell tại thư mục EDR, kích hoạt virtual environment nếu cần rồi chạy:

```powershell
.\.venv\Scripts\Activate.ps1
python edr_agent.py --config config.yaml
```

Agent chạy liên tục, đọc Sysmon và gửi batch theo cấu hình. Có thể tạo sự kiện kiểm tra bằng cách chạy lệnh mới như `whoami`. Dừng agent bằng `Ctrl+C`; agent sẽ thử gửi nốt batch đang chờ.

Trên Windows, kiểm tra XDR có thể truy cập được:

```powershell
Invoke-RestMethod http://192.168.1.10:8000/health
```

Dashboard: `http://192.168.1.10:8000/dashboard/`. Đăng nhập bằng tài khoản quản trị đã tạo ở bước đầu.

Sau khi đăng nhập, API dùng bearer session token; dashboard tự xử lý đăng nhập. Agent EDR dùng riêng `X-Agent-Id` và `X-Agent-Key`, không dùng tài khoản dashboard.

## 4. Sự kiện, cảnh báo và API

- EDR gửi batch tới `POST /api/events/batch`. XDR chuẩn hóa và lưu sự kiện; Sysmon record đã nhận trước đó được nhận diện là trùng.
- Event khớp `rules/detection_rules.json` (rule) hoặc `rules/ioc.json` (IP, domain, hash SHA256/MD5) mới tạo cảnh báo ngay. Sự kiện thông thường vẫn được lưu dù không khớp. Rule hỗ trợ điều kiện trên field Sysmon, ví dụ `"data.CommandLine": {"contains_any": ["-enc"]}`; các toán tử: `equals`, `contains_any`, `endswith_any`, `startswith_any` (không phân biệt hoa thường).
- AI chấm điểm hành vi theo từng host trong cửa sổ 5 phút (xem mục 4.1).
- Dashboard hiển thị sự kiện, host, cảnh báo và incident tại `/dashboard/`.
- Tài liệu API tương tác: `/docs`; kiểm tra trạng thái dịch vụ: `/health`.
- API xem dữ liệu chính: `GET /api/events`, `GET /api/alerts`, `GET /api/incidents`, `GET /api/hosts`.

Các vai trò dashboard:

| Vai trò | Quyền |
|---|---|
| `admin` | Xem dữ liệu, quản lý tài khoản/vai trò, cảnh báo, incident và tạo yêu cầu response. |
| `analyst` | Xem sự kiện; xem và cập nhật cảnh báo/incident. |
| `viewer` | Chỉ đọc sự kiện, cảnh báo, incident và host. |

Wazuh và Suricata cũng có endpoint tiếp nhận riêng tại `/api/collectors/wazuh/events` và `/api/collectors/suricata/events`. Khóa của mỗi collector được cấu hình độc lập bằng `XDR_WAZUH_INGEST_KEY` và `XDR_SURICATA_INGEST_KEY`.

> Endpoint response chỉ tạo yêu cầu chờ admin khác phê duyệt; hệ thống hiện chưa thực thi lệnh cô lập host, dừng process hoặc chặn IP trên endpoint/firewall.

## 4.1. Phát hiện bất thường bằng AI

Mã nguồn: `backend/ai/`. Luồng xử lý:

```
EDR (Sysmon) ─▶ events (SQLite) ─▶ gom theo host + 5 phút ─▶ 21 feature hành vi
                                                             │
                     Isolation Forest (bất thường tổ hợp) ───┤
                     Novelty so với baseline p99 (hành vi mới)┘─▶ ai_score 0..1
                                                             │
          ai_windows ◀─ lưu kết quả       alert "ai-anomaly" ◀─ nếu bất thường
          alert rule trong cùng cửa sổ ◀─ cập nhật ai_score + risk_score
```

- **Feature** (`ai/features.py`): số process, shell, LOLBin, command line đáng ngờ, process chạy từ thư mục người dùng ghi được, Office sinh process con; số kết nối, số IP/cổng đích, kết nối ra ngoài; số truy vấn DNS, domain khác nhau, entropy domain; file thực thi được tạo, registry Run key, truy cập LSASS; số lần đăng nhập thất bại (Wazuh). Cùng một hàm được dùng cho train, chấm điểm thời gian thực và đánh giá.
- **Model** (`ai/detector.py`): Isolation Forest train trên dữ liệu sạch, cộng thêm điểm novelty `Σ log2((x+1)/(p99+1))` cho các feature vượt p99 của baseline (Isolation Forest không phản ứng được với feature luôn bằng 0 lúc train, ví dụ truy cập LSASS). Ngưỡng của cả hai thành phần được hiệu chỉnh theo `--target-fpr` (mặc định 1% cửa sổ baseline).
- **Giải thích**: mỗi kết quả kèm `top_features` (feature vượt baseline nhiều nhất) và gợi ý kỹ thuật MITRE ATT&CK.
- **Chạy nền**: server tự chấm các cửa sổ đã đóng mỗi `XDR_AI_INTERVAL_SECONDS` giây (mặc định 60). Khi chưa có model, AI tự tắt và hệ thống vẫn chạy bình thường.

### Train và đánh giá model

1. Cài Sysmon, chạy EDR agent trên các máy Windows và dùng máy bình thường trong vài ngày để thu baseline sạch (tối thiểu 50 cửa sổ 5 phút; nên có nhiều hơn).
2. Train (trong Docker: `docker compose exec api python -m ai.train ...`; chạy trực tiếp: tại thư mục `backend`):

   ```bash
   python -m ai.train --since 2026-11-01 --until 2026-11-06
   ```

   Cửa sổ có chứa cảnh báo rule sẽ bị loại khỏi baseline (dùng `--keep-alerted` để giữ). Model được lưu tại `XDR_AI_MODEL_PATH` (mặc định `data/ai_model.joblib`, nằm trong volume `xdr-data`). Server tự nạp lại model mới mà không cần khởi động lại.
3. Đánh giá trên dữ liệu **không dùng để train** (dữ liệu sạch của những ngày sau, cùng dữ liệu tấn công như OTRF Security-Datasets hoặc Atomic Red Team chạy trong lab):

   ```bash
   python -m ai.evaluate --benign-db data/xdr.sqlite3 --since 2026-11-06 --until 2026-11-08 \
       --attack /path/to/otrf/*.zip --report data/ai_evaluation.json
   ```

   Kết quả gồm precision, recall, F1, FPR, ROC-AUC, PR-AUC và số cửa sổ tấn công do từng thành phần (Isolation Forest hoặc novelty) phát hiện. File OTRF, file Get-WinEvent export và `spool.jsonl` của EDR đều đọc được; event được lọc giống như EDR agent (Sysmon 1, 3, 10 chỉ với lsass, 11, 13, 22).

API: `GET /api/ai/status`, `GET /api/ai/windows?anomalies_only=true`, `POST /api/ai/analyze` (chấm ngay, quyền admin/analyst).

Dashboard: mục **AI phát hiện** hiển thị trạng thái model, biểu đồ AI score theo cửa sổ, bảng cửa sổ kèm lý do (bấm vào một dòng để so sánh từng feature với baseline p99) và các alert đã được AI chấm điểm.

### Demo nhanh (dữ liệu tổng hợp)

Để xem trang AI khi chưa có máy Windows chạy EDR, tạo database và model **riêng cho demo** (không đụng tới dữ liệu thật). Không dùng kết quả demo làm số liệu đánh giá:

```bash
cd backend
python -m ai.demo
```

Lệnh in ra câu lệnh khởi động server trỏ vào `data/demo.sqlite3` và `data/demo_model.joblib` (đăng nhập `admin` / `demo-password-123`).

Biến môi trường: `XDR_AI_ENABLED` (mặc định `1`), `XDR_AI_MODEL_PATH`, `XDR_AI_INTERVAL_SECONDS` (60), `XDR_AI_LOOKBACK_MINUTES` (120), `XDR_AI_GRACE_SECONDS` (120: thời gian chờ event đến muộn trước khi chấm một cửa sổ). Event đến muộn hơn khi cửa sổ đã được chấm sẽ không được chấm lại.

## 5. Xử lý sự cố thường gặp

| Triệu chứng | Kiểm tra |
|---|---|
| Không mở được dashboard/API từ Windows | Kiểm tra IP Ubuntu, kết nối LAN/VPN, trạng thái container/service và firewall TCP `8000`. |
| Agent báo HTTP `401` | `agent.agent_key` trong `config.yaml` không khớp `XDR_AGENT_KEY` trên XDR. |
| Agent báo HTTP `503` | XDR chưa được cấu hình `XDR_AGENT_KEY` hoặc cần khởi động lại sau khi đặt biến. |
| Không thấy event | Xác nhận Sysmon đang chạy và có event mới trong kênh Operational; xem log agent và kiểm tra URL. |
| XDR dừng khi SSH ngắt | Chạy XDR bằng Docker Compose hoặc cấu hình native backend thành service `systemd`. |
| Mất kết nối tạm thời | EDR thử gửi lại; batch không gửi được được lưu trong `spool.jsonl` để thử gửi lại sau. |

## 6. Kiểm thử backend

Từ thư mục gốc dự án XDR:

```bash
python -m pip install -r requirements.txt
python -m pytest -q tests
```
