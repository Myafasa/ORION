# ORION — Offensive Reasoning & Intelligent Object-abuse Node

Final Project Keamanan Informasi — pengujian keamanan API otomatis menggunakan
agen AI lokal (LLM via Ollama) yang menalar lewat pola ReAct untuk merangkai
celah **Excessive Data Exposure (OWASP API3)** menjadi **Broken Object Level
Authorization / BOLA (OWASP API1)**, lalu memverifikasi efektivitas mitigasinya.

> Seluruh pengujian berjalan di lab sandbox terisolasi (Docker network
> internal), dengan data 100% sintetis. Tidak ada sistem pihak ketiga yang
> disentuh. Lihat bagian Etika di bawah.


## Struktur Folder

```
.
├── docker-compose.yml       # Orkestrasi 3 service: target-api, ollama, attacker-agent
├── target-api/              # Sisi TARGET: Node.js + Express + SQLite
│   ├── src/
│   │   ├── app.js              # Entry point server, logging SECURITY_MODE aktif
│   │   ├── config/db.js        # Inisialisasi & schema SQLite
│   │   ├── middleware/auth.js  # Verifikasi JWT
│   │   ├── routes/auth.js      # Register & login
│   │   ├── routes/users.js     # /me (aman) & /search (mode ganda vulnerable/secure)
│   │   ├── routes/locations.js # /me/latest (aman) & /:userId/latest (mode ganda)
│   │   └── seed/seed.js        # 3 user dummy + titik lokasi dummy (Tasikmalaya)
│   ├── package.json
│   ├── Dockerfile
│   └── .env.example
├── attacker-agent/          # Sisi ATTACKER: Python + Ollama
│   ├── agent.py               # Loop ReAct: parsing robust, antrean multi-aksi,
│   │                          # deteksi loop, validasi finish, verifikasi ground-truth
│   ├── tools.py                # send_request, note_finding (scratchpad)
│   ├── prompts/system_prompt.txt  # Aturan format & daftar tool untuk LLM
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
└── evidence/                 # Transkrip lengkap tiap run (bukti Luaran Khusus Topik 2)
    └── run-<mode>-<timestamp>.json
```

## Mode Keamanan Target API (`SECURITY_MODE`)

Satu env var di `target-api/.env` mengontrol apakah target-api dalam kondisi
rentan atau sudah dimitigasi — dipakai untuk evaluasi "before vs after" tanpa
mengubah kode:

| `SECURITY_MODE` | Perilaku `/api/users/search` | Perilaku `/api/locations/:userId/latest` |
|---|---|---|
| `vulnerable` (default) | Mengembalikan field `id` (Excessive Data Exposure) | Tidak ada cek kepemilikan (BOLA) |
| `secure` | Hanya `{ name, avatar_url }` | Menolak 403 jika `req.user.id !== userId` |

Ganti nilainya di `.env`, lalu `docker compose up -d --build target-api` agar
berlaku.

## Mode Agen (`AGENT_MODE`)

Env var di `attacker-agent/.env`:

| `AGENT_MODE` | Tugas Agen |
|---|---|
| `neutral` | Hanya cek `/health` — uji konektivitas pipeline |
| `assessment` | Jalankan skenario pengujian Excessive Data Exposure + BOLA terhadap `TARGET_PHONE`, pakai `OWN_JWT_TOKEN` |

**PENTING:** `OWN_JWT_TOKEN` kedaluwarsa dalam 2 jam (`expiresIn: "2h"` di
`auth.js`) — login ulang untuk dapat token segar sebelum tiap sesi pengujian.

## Cara Menjalankan

1. Salin file environment (sekali saja, hanya kalau `.env` belum ada):
   ```
   cp target-api/.env.example target-api/.env
   cp attacker-agent/.env.example attacker-agent/.env
   ```
2. Build & jalankan semua service:
   ```
   docker compose up -d --build
   ```
3. Tarik model LLM ke dalam container ollama (sekali saja; `lab-network`
   harus `internal: false` dulu saat ini — lihat bagian di bawah):
   ```
   docker exec -it ollama ollama pull qwen2.5-coder:7b
   ```
4. Isi data dummy:
   ```
   docker compose exec target-api npm run seed
   ```
5. Login untuk dapat token:
   ```
   curl -X POST http://localhost:3000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"phone":"081200000001","password":"password123"}'
   ```
6. Isi `OWN_JWT_TOKEN` di `attacker-agent/.env` dengan token dari langkah 5,
   set `AGENT_MODE=assessment`, lalu:
   ```
   docker compose restart attacker-agent
   docker compose logs -f attacker-agent
   ```
7. Cek hasilnya di `evidence/run-assessment-*.json`.

## Setup Awal vs Mode Isolasi Penuh (Jaringan)

Project punya dua "mode" jaringan, diatur lewat `internal: true/false` pada
`lab-network` di `docker-compose.yml`:

| Mode | `internal` | Kapan dipakai |
|---|---|---|
| **Setup** | `false` (saat ini) | Saat `ollama pull` & instalasi awal — butuh akses internet |
| **Isolasi Penuh** | `true` | Saat pengujian/eksploitasi sungguhan — prinsip isolasi lab |

Ganti nilainya, lalu **wajib** `docker compose down && docker compose up -d`
(restart saja tidak cukup, network perlu dibuat ulang).

## Data Dummy (Sintetis, Bukan Data Nyata)

| Nama | Nomor Telepon | ID |
|---|---|---|
| Andi Pratama (akun pengujian) | `081200000001` | 1 |
| Budi Santoso (target simulasi) | `081200000002` | 2 |
| Citra Wulandari | `081200000003` | 3 |

Password semua akun: `password123`. Koordinat lokasi adalah titik acak di
sekitar Kota Tasikmalaya, 100% fiktif.

## Catatan Keamanan Sebelum Push ke GitHub

- File `.env` (bukan `.env.example`) **tidak ikut ter-commit** (lihat
  `.gitignore`) — berisi `JWT_SECRET` dan (di `attacker-agent/.env`)
  `OWN_JWT_TOKEN` yang sebaiknya tidak dipublikasikan meski hanya untuk lab.
- File di `evidence/*.json` **sengaja tetap ter-commit** (ini bukti wajib
  Luaran Khusus Topik 2), tapi beberapa di antaranya memuat token JWT yang
  tercatat dalam transkrip. Token-token itu ditandatangani dengan
  `JWT_SECRET` dev (`devsecret_ganti_ini_untuk_lab_anda`) dan sudah
  kedaluwarsa, jadi risikonya rendah — tapi kalau mau lebih rapi, redaksi
  manual string `Bearer ...` di file evidence sebelum push.

## Etika

Sesuai ketentuan mata kuliah: seluruh kode, payload, dan teknik yang
dihasilkan proyek ini hanya untuk keperluan pengujian lab ini sendiri, tidak
disebarluaskan untuk tujuan lain, dan tidak pernah diarahkan ke sistem pihak
ketiga.