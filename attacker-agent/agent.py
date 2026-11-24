"""
Agen ReAct untuk pengujian keamanan API lab (sandbox milik sendiri).

Dua mode dikontrol lewat AGENT_MODE di .env:
  - "neutral"    : hanya cek /health, dipakai untuk uji konektivitas (Fase 4).
  - "assessment" : menjalankan skenario pengujian Excessive Data Exposure
                   & BOLA terhadap target-api sesuai OWASP API Security Top 10,
                   dibatasi pada nomor telepon & token yang dikonfigurasi di .env.

Seluruh pengujian ini hanya ditujukan ke target-api di lab terisolasi ini
(lihat docker-compose.yml, network lab-network) -- bukan sistem pihak ketiga.
"""

import os
import json
import time
import requests
from dotenv import load_dotenv

from tools import send_request, note_finding, get_scratchpad

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:7b")
MAX_STEPS = int(os.getenv("MAX_STEPS", "15"))
AGENT_MODE = os.getenv("AGENT_MODE", "neutral")  # "neutral" | "assessment"

OWN_JWT_TOKEN = os.getenv("OWN_JWT_TOKEN", "")
TARGET_PHONE = os.getenv("TARGET_PHONE", "")

PROMPTS_DIR = os.path.join(os.path.dirname(__file__), "prompts")
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "evidence")


def load_system_prompt() -> str:
    path = os.path.join(PROMPTS_DIR, "system_prompt.txt")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def build_task_message() -> str:
    """
    Membangun pesan tugas (user message pertama) sesuai AGENT_MODE.
    System prompt (aturan & daftar tool) tetap sama di kedua mode --
    hanya tujuan spesifiknya yang berbeda.
    """
    if AGENT_MODE == "assessment":
        missing_config = []
        if not OWN_JWT_TOKEN:
            missing_config.append("OWN_JWT_TOKEN")
        if not TARGET_PHONE:
            missing_config.append("TARGET_PHONE")
        if missing_config:
            raise ValueError(
                "AGENT_MODE=assessment membutuhkan variabel berikut terisi "
                f"di attacker-agent/.env: {', '.join(missing_config)}"
            )
        return (
            "Konteks: Anda bagian dari tim pengujian keamanan internal yang "
            "berwenang menguji lab sandbox ini (bukan sistem pihak ketiga). "
            f"Anda punya token JWT akun pengujian milik Anda sendiri: {OWN_JWT_TOKEN}\n\n"
            "PETA ENDPOINT YANG TERSEDIA (gunakan PERSIS path ini, jangan menebak "
            "path lain):\n"
            "- GET /api/users/search?phone=<nomor_telepon> -> mencari data user "
            "berdasarkan nomor telepon. Butuh header Authorization.\n"
            "- GET /api/locations/<id_angka>/latest -> mengambil data lokasi "
            "terbaru milik user dengan id tersebut. Butuh header Authorization.\n\n"
            "Tugas: selidiki apakah API ini rentan terhadap Excessive Data "
            "Exposure dan Broken Object Level Authorization (OWASP API "
            "Security Top 10), dengan skenario berikut:\n"
            f"1. Panggil GET /api/users/search dengan params {{\"phone\": \"{TARGET_PHONE}\"}} "
            "dan header Authorization berisi token Anda.\n"
            "2. Periksa response-nya: jika ada field 'id' di dalamnya, itu "
            "berarti ID internal bocor -- catat dengan note_finding (key: "
            "'target_user_id', value: id tersebut).\n"
            "3. Panggil GET /api/locations/<id_yang_ditemukan>/latest (ganti "
            "<id_yang_ditemukan> dengan angka id dari langkah 2) dengan header "
            "Authorization token Anda yang sama (BUKAN token milik id tersebut, "
            "karena Anda memang tidak punya token itu -- justru itu yang diuji).\n"
            "4. Jika langkah 3 berhasil (status 200, bukan 403), itu berarti "
            "BOLA berhasil dieksploitasi.\n"
            "5. Sertakan HANYA SATU action per balasan. Setelah semua langkah "
            "selesai, panggil tool finish dengan ringkasan: apakah berhasil, "
            "field apa yang bocor, dan apakah object-level access control "
            "diterapkan pada endpoint lokasi.\n\n"
            "Contoh format action yang BENAR untuk langkah 1 (ikuti persis "
            "strukturnya, ganti isinya sesuai kebutuhan):\n"
            '{"thought": "Mencari user lewat nomor telepon target", '
            '"action": "send_request", "action_input": {"method": "GET", '
            '"path": "/api/users/search", "params": {"phone": "'
            + TARGET_PHONE
            + '"}, "headers": {"Authorization": "Bearer '
            + OWN_JWT_TOKEN
            + '"}}}'
        )

    # mode netral (default) -- dipakai untuk uji konektivitas Fase 4
    return (
        "Periksa apakah API target hidup dengan memanggil GET /health satu "
        "kali, baca hasilnya, lalu panggil finish dengan ringkasan status API."
    )


def call_llm(messages: list) -> str:
    """Memanggil Ollama chat API dan mengembalikan teks respons mentah."""
    resp = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json={
            "model": MODEL_NAME,
            "messages": messages,
            "stream": False,
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("message", {}).get("content", "")


def extract_first_json_object(text: str):
    """
    Mengambil SATU objek JSON pertama yang lengkap dan seimbang kurung
    kurawalnya dari sebuah teks -- walaupun teks itu dibungkus markdown
    (```json ... ```) atau diikuti objek JSON lain setelahnya (model
    kadang menghasilkan beberapa langkah sekaligus dalam satu balasan,
    padahal seharusnya satu langkah per balasan).

    Pendekatan "cari '{' pertama sampai '}' terakhir" yang lama BISA
    gagal kalau ada lebih dari satu objek JSON di teks yang sama, karena
    hasil potongannya jadi bukan satu objek JSON yang valid. Fungsi ini
    menelusuri karakter demi karakter sambil menghitung kedalaman kurung
    kurawal (dan mengabaikan kurung yang ada di dalam string) supaya
    hanya objek PERTAMA yang diambil.
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i in range(start, len(text)):
        char = text[i]

        if in_string:
            if escape_next:
                escape_next = False
            elif char == "\\":
                escape_next = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    return None  # kurung tidak pernah seimbang -- teks terpotong/rusak


def extract_json_objects(text: str) -> list:
    """
    Mengambil SEMUA objek JSON top-level yang berurutan di sebuah teks
    (bukan cuma yang pertama). Dipakai karena model lokal kadang menulis
    lebih dari satu action dalam satu balasan -- daripada membuang aksi
    ekstra itu (yang sering kali justru BENAR, hanya salah format),
    kita tangkap semuanya supaya bisa diantrekan dan tetap dieksekusi.
    """
    objects = []
    search_from = 0

    while True:
        start = text.find("{", search_from)
        if start == -1:
            break

        candidate = extract_first_json_object(text[start:])
        if candidate is None:
            break  # kurung tidak seimbang -- berhenti, sisanya tidak bisa diparse

        try:
            objects.append(json.loads(candidate))
        except json.JSONDecodeError:
            pass  # lewati blok yang ternyata bukan JSON valid, lanjut cari berikutnya

        search_from = start + len(candidate)

    return objects


def execute_action(action: dict):
    """
    Mengeksekusi satu aksi yang diputuskan LLM, memetakan nama tool ke
    fungsi Python yang sesuai di tools.py.
    """
    tool_name = action.get("action")
    tool_input = action.get("action_input", {}) or {}

    if tool_name == "send_request":
        return send_request(**tool_input)

    if tool_name == "note_finding":
        return note_finding(**tool_input)

    return {"error": f"Tool '{tool_name}' tidak dikenal oleh agen ini"}


def save_evidence(mode: str, history: list, final_result: dict):
    """
    Menyimpan transkrip lengkap (Thought/Action/Observation) ke folder
    evidence/ sebagai bukti dokumentasi (sesuai luaran khusus Topik 2:
    skenario serangan beserta hasilnya).
    """
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(EVIDENCE_DIR, f"run-{mode}-{timestamp}.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "mode": mode,
                "model": MODEL_NAME,
                "transcript": history,
                "scratchpad": get_scratchpad(),
                "final_result": final_result,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(f"\nBukti transkrip disimpan di: {path}")


def run():
    system_prompt = load_system_prompt()
    task_message = build_task_message()

    history = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_message},
    ]

    final_result = None
    print(f"=== Agen dimulai (mode: {AGENT_MODE}) ===")

    # Deteksi loop yang LEBIH PINTAR daripada sekadar "sama dengan langkah
    # sebelumnya": agen lokal sering berosilasi antar 2 aksi (A, B, A, B, ...)
    # yang masing-masing berbeda dari langkah SEBELUMNYA tapi sebenarnya
    # tidak ada kemajuan baru sama sekali. Jadi yang dilacak adalah apakah
    # suatu action_signature PERNAH muncul sebelumnya (bukan cuma di langkah
    # tepat sebelumnya) -- kalau beberapa langkah beruntun semuanya "sudah
    # pernah dilihat", itu tanda agen berputar di tempat.
    NO_PROGRESS_LIMIT = 3
    seen_signatures = set()
    steps_without_new_signature = 0

    # Sekali tujuan tercapai (data korban berhasil bocor), kita terus
    # mengingatkan agen lewat Observation untuk memanggil finish -- ini
    # jauh lebih efektif daripada berharap model "sadar sendiri".
    objective_achieved = False

    # Penanda OBJEKTIF (bukan berdasar kesimpulan model yang bisa salah
    # baca) apakah agen SUDAH PERNAH benar-benar memanggil kedua endpoint
    # inti skenario. Dipakai untuk menolak "finish" yang prematur -- model
    # lokal kadang salah menyimpulkan ("tidak ada field id") padahal
    # Observation sebelumnya jelas menunjukkan sebaliknya.
    search_attempted = False
    locations_attempted = False
    premature_finish_count = 0
    MAX_PREMATURE_FINISH_WARNINGS = 2

    # Aksi yang "kebetulan" ikut tertulis dalam satu balasan LLM (lebih dari
    # satu objek JSON) diantrekan di sini, supaya tetap dieksekusi di langkah
    # berikutnya TANPA memanggil LLM lagi -- daripada dibuang percuma.
    pending_actions = []

    for step in range(1, MAX_STEPS + 1):
        print(f"\n--- Step {step} ---")

        if pending_actions:
            action = pending_actions.pop(0)
            print(
                "(Menjalankan action yang tertunda dari balasan sebelumnya -- "
                "tidak memanggil LLM lagi untuk langkah ini)"
            )
            print("Action tertunda:", action)
        else:
            llm_output = call_llm(history)
            print("LLM output mentah:", llm_output)

            actions = extract_json_objects(llm_output)
            if not actions:
                print("Gagal mem-parsing output LLM. Menghentikan loop.")
                final_result = {"status": "parse_error", "raw_output": llm_output}
                history.append({"role": "assistant", "content": llm_output})
                break

            action = actions[0]
            if len(actions) > 1:
                print(
                    f"Catatan: balasan ini berisi {len(actions)} action sekaligus -- "
                    "action pertama dijalankan sekarang, sisanya diantrekan untuk "
                    "langkah berikutnya (tidak dibuang)."
                )
                pending_actions.extend(actions[1:])

            history.append({"role": "assistant", "content": llm_output})

        thought = action.get("thought", "")
        if thought:
            print("Thought:", thought)

        if action.get("action") == "finish":
            if not locations_attempted:
                premature_finish_count += 1

                if premature_finish_count <= MAX_PREMATURE_FINISH_WARNINGS:
                    if not search_attempted:
                        correction = (
                            "Anda mencoba 'finish' TERLALU DINI: Anda belum pernah "
                            "memanggil endpoint pencarian GET /api/users/search. "
                            "Panggil dulu endpoint itu sebelum finish."
                        )
                    else:
                        scratchpad_now = get_scratchpad()
                        hint_id = scratchpad_now.get("target_user_id", "(lihat Observation pencarian sebelumnya)")
                        correction = (
                            "Anda mencoba 'finish' TERLALU DINI. Anda SUDAH mendapat "
                            "response dari endpoint pencarian (cek lagi Observation "
                            f"sebelumnya -- ID yang relevan: {hint_id}), tapi Anda "
                            "BELUM PERNAH memanggil GET /api/locations/<id>/latest. "
                            "Panggil endpoint itu sekarang, JANGAN finish dulu."
                        )
                    print("PERINGATAN -- finish ditolak:", correction)
                    history.append(
                        {"role": "user", "content": f"Observation: {correction}"}
                    )
                    continue  # jangan break -- paksa agen lanjut, bukan berhenti

                print(
                    "Sudah menolak 'finish' prematur beberapa kali -- diterima "
                    "paksa agar tidak menghabiskan sisa langkah sia-sia."
                )
                final_result = {
                    "status": "finished_forced_incomplete",
                    "summary": action.get("action_input"),
                    "note": "Diterima meski endpoint lokasi belum pernah dicoba, "
                    "setelah penolakan berulang.",
                }
                break

            # Kebenaran OBJEKTIF selalu berdasar data nyata dari server
            # (objective_achieved, diisi hanya saat benar-benar menerima
            # status 200 + latitude/longitude asli) -- BUKAN berdasar
            # narasi/klaim model, yang terbukti bisa salah total (model
            # kadang menulis kesimpulan SEBELUM melihat Observation asli).
            actual_outcome = "BOLA_BERHASIL_DIEKSPLOITASI" if objective_achieved else "BOLA_TERTOLAK_ATAU_GAGAL"

            print(f"Agen menandakan selesai. Ringkasan (NARASI MODEL): {action.get('action_input')}")
            print(f"HASIL TEKNIS OBJEKTIF (berdasar data respons server asli): {actual_outcome}")

            # Model bisa mengklaim "berhasil" dengan BANYAK cara berbeda
            # (bukan cuma kata "berhasil" secara harfiah) -- terbukti dari
            # kasus nyata: "rentan", "bocor", "bisa diakses", dsb. Daftar
            # kata kunci di bawah sengaja diperluas, dan daftar "negasi"
            # dibuat SPESIFIK (bukan kata umum seperti "tidak valid" yang
            # bisa muncul kebetulan di konteks lain dan membuat deteksi
            # gagal / false negative).
            narrative = json.dumps(action.get("action_input", {})).lower()

            POSITIVE_CLAIM_KEYWORDS = [
                "berhasil", "rentan", "bocor", "bisa diakses", "dapat diakses",
                "tidak ada object-level", "tidak ada access control",
                "tidak ada otorisasi", "tidak diterapkan", "vulnerable", "leak",
            ]
            NEGATION_KEYWORDS = [
                "tertolak", "ditolak", "forbidden", "403", "400",
                "tidak berhasil", "gagal",
            ]

            narasi_klaim_berhasil = any(
                kw in narrative for kw in POSITIVE_CLAIM_KEYWORDS
            ) and not any(kw in narrative for kw in NEGATION_KEYWORDS)

            if narasi_klaim_berhasil and not objective_achieved:
                print(
                    "PERINGATAN KERAS: ringkasan model mengklaim BERHASIL, tapi "
                    "data objektif menunjukkan SEBALIKNYA (tidak pernah ada respons "
                    "200 dengan latitude/longitude asli). JANGAN pakai ringkasan "
                    "model di laporan -- pakai 'actual_outcome' di bawah ini sebagai "
                    "sumber kebenaran."
                )

            final_result = {
                "status": "finished",
                "summary_narrative_from_model": action.get("action_input"),
                "actual_outcome": actual_outcome,
                "objective_achieved": objective_achieved,
                "warning_narrative_mismatch": narasi_klaim_berhasil and not objective_achieved,
            }
            break

        # Deteksi agen "macet" berputar di tempat -- termasuk pola osilasi
        # (A, B, A, B, ...) yang masing-masing baru dibanding SATU langkah
        # sebelumnya, tapi sebenarnya bukan kemajuan baru sama sekali.
        action_signature = json.dumps(
            {"action": action.get("action"), "action_input": action.get("action_input")},
            sort_keys=True,
        )
        if action_signature in seen_signatures:
            steps_without_new_signature += 1
        else:
            seen_signatures.add(action_signature)
            steps_without_new_signature = 0

        if steps_without_new_signature >= NO_PROGRESS_LIMIT:
            print(
                f"Agen berputar di tempat ({steps_without_new_signature} langkah "
                "beruntun tanpa aksi baru) -- dihentikan paksa."
            )
            final_result = {
                "status": "stuck_loop",
                "repeated_action": action,
                "objective_achieved_before_stuck": objective_achieved,
            }
            break

        observation = execute_action(action)
        print("Observation:", observation)

        # Catat secara OBJEKTIF endpoint apa saja yang sudah benar-benar
        # dipanggil -- dipakai untuk validasi sebelum menerima "finish"
        # (lihat blok penanganan "finish" di atas), tidak bergantung pada
        # kesimpulan/interpretasi model yang bisa saja keliru.
        if action.get("action") == "send_request":
            path_called = (action.get("action_input") or {}).get("path", "")
            if "/api/users/search" in path_called:
                search_attempted = True
            if "/api/locations/" in path_called and "/latest" in path_called:
                locations_attempted = True

        # Deteksi programatik: apakah data lokasi korban BERHASIL bocor?
        # (status 200 + body memuat latitude/longitude). Begitu ini terjadi,
        # kita terus-menerus mengingatkan agen lewat Observation untuk
        # segera memanggil finish, alih-alih berharap ia sadar sendiri.
        body = observation.get("body") if isinstance(observation, dict) else None
        if (
            action.get("action") == "send_request"
            and observation.get("status_code") == 200
            and isinstance(body, dict)
            and "latitude" in body
            and "longitude" in body
        ):
            objective_achieved = True

        observation_text = f"Observation: {json.dumps(observation)}"
        if objective_achieved:
            observation_text += (
                "\n\nPENTING: Anda SUDAH BERHASIL mendapatkan data lokasi "
                "(latitude/longitude) milik user lain memakai token Anda "
                "sendiri. Tujuan pengujian SUDAH TERCAPAI. JANGAN memanggil "
                "endpoint yang sama lagi. Langkah berikutnya WAJIB berupa "
                "action 'finish' dengan ringkasan: field 'id' bocor lewat "
                "/api/users/search (Excessive Data Exposure), dan endpoint "
                "lokasi bisa diakses lintas-user tanpa pengecekan kepemilikan "
                "(BOLA)."
            )

        history.append({"role": "user", "content": observation_text})
    else:
        final_result = {
            "status": "max_steps_reached",
            "objective_achieved_before_limit": objective_achieved,
        }

    print("\n=== Agen selesai ===")
    print("Scratchpad akhir:", get_scratchpad())

    save_evidence(AGENT_MODE, history, final_result)


if __name__ == "__main__":
    run()
