# ORION — Panduan Instalasi dan Pengujian Keamanan API

ORION adalah proyek lab untuk memahami cara kerja dua kelemahan API: **Excessive Data Exposure** (data yang dikirim API terlalu banyak) dan **Broken Object Level Authorization / BOLA** (pengguna dapat membaca objek milik pengguna lain). Target API memakai data sintetis; attacker-agent menggunakan model AI lokal melalui Ollama untuk menjalankan skenario pengujian.

> Jalankan pengujian hanya pada lab ini atau sistem yang memang Anda berwenang menguji. Docker Compose menerbitkan port API `3000` dan Ollama `11434` ke host. Jangan arahkan agent ke layanan pihak ketiga atau jaringan yang tidak Anda kendalikan.

## 1. Gambaran alur

1. User uji masuk melalui `/api/auth/login` dan memperoleh JWT.
2. Agent mencari user target lewat `/api/users/search?phone=...` dengan JWT user uji.
3. Dalam mode rentan, hasil pencarian menyertakan ID internal target.
4. Agent mencoba memakai ID tersebut pada `/api/locations/<id>/latest`, tetap dengan JWT user uji.
5. Jika API mengirim lokasi target (HTTP 200 dengan `latitude` dan `longitude`), akses lintas-user berhasil. Itu menunjukkan BOLA.
6. Hasil run disimpan sebagai JSON di folder `evidence/`.

`SECURITY_MODE` mengubah perilaku API tanpa mengubah route:

| Nilai | Pencarian user | Lokasi user lain |
|---|---|---|
| `vulnerable` | Mengembalikan objek user termasuk `id` | Tidak memeriksa kepemilikan objek |
| `secure` | Hanya mengembalikan `name` dan `avatar_url` | Menolak dengan HTTP 403 sebelum query database |

Mode default adalah `vulnerable`, untuk demonstrasi sebelum mitigasi.

## 2. Prasyarat

- Windows dengan PowerShell dan Docker Desktop yang sedang berjalan.
- Docker Compose v2 (`docker compose version`).
- Ruang disk yang cukup untuk image Docker dan model Ollama. Model `qwen2.5-coder:7b` memerlukan ruang dan memori lebih besar dibanding model kecil.
- Koneksi internet saat mengunduh image Docker dan model. Setelah model diunduh, pengujian dapat dilakukan tanpa mengunduh ulang.

Perintah di bawah memakai PowerShell. Jalankan dari folder proyek:

```powershell
cd 'C:\Inilah my Kuliah sob\Semester 5\KI\project'
```

## 3. Siapkan file konfigurasi

Salin contoh konfigurasi jika file lokal belum ada. File `.env` menyimpan konfigurasi pribadi dan tidak seharusnya dimasukkan ke Git.

```powershell
if (-not (Test-Path 'target-api/.env')) {
    Copy-Item 'target-api/.env.example' 'target-api/.env'
}
if (-not (Test-Path 'attacker-agent/.env')) {
    Copy-Item 'attacker-agent/.env.example' 'attacker-agent/.env'
}
```

Periksa `target-api/.env`. Untuk pengujian awal, pastikan nilainya seperti berikut:

```dotenv
PORT=3000
JWT_SECRET=devsecret_ganti_ini_untuk_lab_anda
DB_PATH=./data/lab.sqlite3
SECURITY_MODE=vulnerable
```

`JWT_SECRET` contoh hanya untuk lab lokal. Jangan gunakan nilai contoh untuk aplikasi sungguhan.

Periksa `attacker-agent/.env`. Untuk menguji kerentanan, atur:

```dotenv
TARGET_API_BASE_URL=http://target-api:3000
OLLAMA_BASE_URL=http://ollama:11434
MODEL_NAME=qwen2.5-coder:7b
MAX_STEPS=15
AGENT_MODE=assessment
OWN_JWT_TOKEN=
TARGET_PHONE=081200000002
```

Token dibiarkan kosong dahulu; token akan diisi setelah login. `TARGET_PHONE` adalah nomor user target sintetis dari seeder. Akun penguji yang digunakan adalah `081200000001`.

## 4. Jalankan API dan Ollama

Build image dan jalankan kedua service pendukung:

```powershell
docker compose up -d --build target-api ollama
docker compose ps
docker compose logs target-api
```

Tunggu sampai log API menyatakan server berjalan. Pastikan health check merespons:

```powershell
Invoke-RestMethod http://localhost:3000/health
```

Respons yang diharapkan:

```json
{"status":"ok","service":"target-api"}
```

Unduh model yang sesuai dengan `MODEL_NAME` di `attacker-agent/.env`:

```powershell
docker compose exec ollama ollama pull qwen2.5-coder:7b
docker compose exec ollama ollama list
```

Jika Anda mengganti `MODEL_NAME`, gunakan nama model yang sama pada perintah `ollama pull`.

## 5. Isi database sintetis

Jalankan seeder satu kali untuk membuat tiga akun dan satu lokasi dummy per akun:

```powershell
docker compose exec target-api npm run seed
```

Data akun lab:

| Peran | Nomor telepon | Password |
|---|---|---|
| User penguji | `081200000001` | `password123` |
| User target | `081200000002` | `password123` |
| User tambahan | `081200000003` | `password123` |

Database disimpan pada Docker volume sehingga tetap ada setelah container dihentikan. Seeder saat ini menambahkan lokasi baru setiap kali dijalankan; jangan jalankan berulang-ulang kecuali memang ingin menambah titik lokasi.

## 6. Login dan siapkan JWT

Di PowerShell, minta token untuk akun penguji:

```powershell
$login = Invoke-RestMethod `
    -Method Post `
    -Uri 'http://localhost:3000/api/auth/login' `
    -ContentType 'application/json' `
    -Body '{"phone":"081200000001","password":"password123"}'

$login.token
```

Salin nilai token yang ditampilkan ke `OWN_JWT_TOKEN` pada `attacker-agent/.env`:

```dotenv
OWN_JWT_TOKEN=salin_token_jwt_di_sini
```

Jangan menambahkan kata `Bearer` pada nilai di file `.env`; agent yang akan menambahkannya ke header request. Token berlaku **2 jam**. Jika mendapat HTTP 401 `Token tidak valid`, login lagi dan perbarui token.

## 7. Jalankan assessment dengan agent

Pastikan `AGENT_MODE=assessment`, `OWN_JWT_TOKEN` terisi, dan `TARGET_PHONE=081200000002`. Buat ulang container agar Docker membaca nilai `.env` terbaru, lalu lihat log:

```powershell
docker compose up -d --force-recreate attacker-agent
docker compose logs -f attacker-agent
```

Agent dapat berhenti sendiri setelah selesai. Hentikan tampilan log dengan `Ctrl+C`; itu hanya menghentikan proses mengikuti log.

Untuk menjalankan ulang assessment setelah container selesai, gunakan:

```powershell
docker compose run --rm --no-deps attacker-agent
```

Perintah tersebut membaca konfigurasi `.env` saat ini dan menjalankan satu proses agent. Jika token diperbarui, perintah ini tidak memerlukan pembuatan ulang container service.

## 8. Periksa hasil secara langsung

Hasil agent perlu dibaca bersama respons API. Model dapat menghasilkan ringkasan yang keliru, sehingga respons HTTP dan field pada body adalah bukti utamanya.

Contoh pemeriksaan manual di PowerShell. Ganti placeholder dengan token JWT yang masih berlaku:

```powershell
$token = 'salin_token_jwt_di_sini'
$headers = @{ Authorization = "Bearer $token" }

# Cari user target. Pada mode vulnerable, respons memuat id.
Invoke-RestMethod `
    -Method Get `
    -Uri 'http://localhost:3000/api/users/search?phone=081200000002' `
    -Headers $headers

# Coba baca lokasi user target (ID hasil pencarian biasanya 2 pada database baru).
# Mode vulnerable diharapkan memberi lokasi (HTTP 200).
# Mode secure diharapkan menolak akses lintas-user (HTTP 403).
Invoke-WebRequest `
    -Method Get `
    -Uri 'http://localhost:3000/api/locations/2/latest' `
    -Headers $headers
```

Di Windows PowerShell 5.1, `Invoke-WebRequest` dapat menampilkan error untuk status 403, tetapi respons 403 itu sendiri adalah hasil yang diharapkan pada mode secure. Jika database pernah diisi berkali-kali, ID user tetap berasal dari respons pencarian; jangan menganggap ID tertentu tanpa memeriksa database/respons.

## 9. Bandingkan mode rentan dan aman

### Pengujian rentan

Pastikan `target-api/.env` berisi:

```dotenv
SECURITY_MODE=vulnerable
```

Terapkan konfigurasi dengan membuat ulang API:

```powershell
docker compose up -d --force-recreate target-api
```

Login ulang bila token lama kedaluwarsa, lalu jalankan assessment. Hasil yang mendukung kerentanan adalah:

- pencarian mengembalikan `id` target;
- request lokasi target memakai JWT user penguji mendapat HTTP 200;
- body lokasi berisi `latitude` dan `longitude`.

### Pengujian setelah mitigasi

Ubah `SECURITY_MODE` pada `target-api/.env` menjadi:

```dotenv
SECURITY_MODE=secure
```

Buat ulang API agar konfigurasi baru dimuat, lalu periksa log:

```powershell
docker compose up -d --force-recreate target-api
docker compose logs target-api
```

Jalankan lagi pemeriksaan manual atau assessment dengan JWT yang masih berlaku. Hasil yang diharapkan:

- pencarian hanya mengembalikan `name` dan `avatar_url`, tanpa `id`;
- akses lokasi user lain ditolak dengan HTTP 403.

Endpoint lokasi milik sendiri tetap seharusnya dapat diakses. Perbandingan vulnerable dan secure menunjukkan pengaruh mitigasi.

## 10. Membaca evidence dan status akhir

File hasil tersimpan di `evidence/`, misalnya `run-assessment-<timestamp>.json`. Buka file terbaru:

```powershell
Get-ChildItem evidence\run-assessment-*.json |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
```

Field penting di JSON:

- `transcript`: instruksi, aksi model, dan respons API.
- `scratchpad`: temuan yang dicatat agent.
- `final_result.actual_outcome`: hasil teknis berdasarkan respons API.
- `final_result.objective_achieved`: apakah respons lokasi 200 memuat koordinat.
- `final_result.warning_narrative_mismatch`: apakah ringkasan model mengklaim berhasil tanpa bukti teknis.

`BOLA_TERTOLAK_ATAU_GAGAL` **tidak otomatis berarti API aman**. Periksa transkrip: jika responsnya 401, token tidak valid dan pengujian belum sampai ke pemeriksaan otorisasi objek. Jika respons 403 pada mode secure, itu menunjukkan akses lintas-user ditolak. Jika agent menghasilkan beberapa aksi sekaligus atau ID yang tidak muncul pada hasil pencarian, utamakan respons API dan pemeriksaan manual.

## 11. Masalah umum

| Gejala | Penyebab umum | Langkah pemeriksaan |
|---|---|---|
| `AGENT_MODE=assessment membutuhkan variabel berikut terisi` | Salah satu konfigurasi assessment kosong | Periksa nama variabel yang disebut pada error di `attacker-agent/.env` |
| HTTP 401 `Token tidak valid` | JWT kedaluwarsa atau dibuat dengan secret berbeda | Login lagi; pastikan `JWT_SECRET` API tidak berubah sejak token diterbitkan |
| HTTP 404 `User tidak ditemukan` | Database belum di-seed atau nomor target keliru | Jalankan seeder satu kali dan gunakan `081200000002` |
| Tidak dapat terhubung ke Ollama | Service belum siap atau model belum diunduh | Periksa `docker compose ps`, `docker compose logs ollama`, dan `ollama list` |
| Output model berbeda dari respons API | Model lokal salah membaca hasil atau mengarang langkah | Gunakan status HTTP/body sebagai bukti; periksa file evidence |
| Perubahan `.env` tidak terlihat di container yang sudah berjalan | Environment Compose dimuat ketika container dibuat | Gunakan `docker compose up -d --force-recreate <service>` |

## 12. Menghentikan lab

Hentikan service tanpa menghapus data atau model:

```powershell
docker compose down
```

Volume database dan model tetap tersimpan. `docker compose down -v` akan menghapus volume, termasuk database lab dan model Ollama; gunakan hanya jika memang ingin menghapus semua data tersebut.

## Etika dan batas penggunaan

Nama, nomor telepon, password, serta koordinat seeder adalah data fiktif untuk pembelajaran. Pengujian ini ditujukan hanya untuk lab lokal yang Anda kendalikan. Jangan memasukkan token atau data pribadi sungguhan ke evidence atau repository publik.
