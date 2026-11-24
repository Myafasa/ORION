"""
Kumpulan "tool" generik yang nantinya ditawarkan ke LLM lewat function calling
atau lewat instruksi dalam system prompt (format ReAct).

File ini HANYA berisi wrapper HTTP generik. Tool ini bisa dipakai untuk
request APA SAJA -- endpoint, method, dan tujuannya sepenuhnya ditentukan
oleh parameter yang diberikan pemanggil (nanti: oleh keputusan LLM di
agent.py), bukan oleh file ini.
"""

import os
import requests

TARGET_API_BASE_URL = os.getenv("TARGET_API_BASE_URL", "http://target-api:3000")


def send_request(method: str, path: str, headers: dict = None, json_body: dict = None, params: dict = None):
    """
    Mengirim HTTP request ke target-api dan mengembalikan ringkasan response.

    Parameters
    ----------
    method : str        -> "GET", "POST", dst.
    path   : str         -> path relatif, mis. "/health" atau "/api/users/search"
    headers: dict | None -> header tambahan (mis. Authorization)
    json_body: dict|None -> body JSON untuk POST/PUT
    params : dict | None -> query string parameters

    Returns
    -------
    dict berisi status_code dan body (sudah di-parse jika JSON).
    """
    url = f"{TARGET_API_BASE_URL}{path}"
    resp = requests.request(
        method=method.upper(),
        url=url,
        headers=headers or {},
        json=json_body,
        params=params,
        timeout=10,
    )

    try:
        body = resp.json()
    except ValueError:
        body = resp.text

    return {"status_code": resp.status_code, "body": body}


# Scratchpad sederhana (in-memory) agar agen bisa "mencatat" temuan
# penting antar langkah, mis. user_id yang ditemukan di satu endpoint
# untuk dipakai di endpoint lain pada langkah berikutnya.
_scratchpad = {}


def note_finding(key: str, value):
    """
    Mencatat satu temuan ke scratchpad, supaya tidak hilang/terlewat
    saat loop ReAct berlanjut ke langkah berikutnya.
    """
    _scratchpad[key] = value
    return {"status": "saved", "key": key, "value": value}


def get_scratchpad() -> dict:
    """Mengembalikan salinan seluruh temuan yang sudah dicatat sejauh ini."""
    return dict(_scratchpad)
