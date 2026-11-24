const express = require("express");
const { verifyToken } = require("../middleware/auth");
const { getDb } = require("../config/db");

const router = express.Router();

/**
 * GET /api/locations/me/latest
 *
 * BASELINE AMAN (pembanding "before" untuk nanti).
 *
 * Sama seperti /api/users/me: objek yang diambil ditentukan dari
 * req.user.id (hasil verifikasi JWT), bukan dari parameter URL yang
 * bisa diubah bebas oleh client. Pola inilah yang nanti dibandingkan
 * dengan versi rentan di endpoint /:userId/latest di bawah.
 */
router.get("/me/latest", verifyToken, (req, res) => {
  const db = getDb();
  const location = db
    .prepare(
      `SELECT latitude, longitude, recorded_at
       FROM locations
       WHERE user_id = ?
       ORDER BY recorded_at DESC
       LIMIT 1`
    )
    .get(req.user.id);

  if (!location) {
    return res.status(404).json({ error: "Belum ada data lokasi untuk user ini" });
  }

  return res.json(location);
});

/**
 * GET /api/locations/:userId/latest
 *
 * ================================================================
 * MODE GANDA via env SECURITY_MODE (vulnerable | secure)
 * ================================================================
 * - "vulnerable" (default): STATUS: VULNERABLE BY DESIGN -- Broken
 *   Object Level Authorization (OWASP API1: BOLA). verifyToken HANYA
 *   memastikan token valid (signature benar, belum kedaluwarsa) --
 *   TIDAK ada pengecekan lapis kedua "apakah req.user.id memang
 *   berhak atas data milik :userId yang diminta?". User mana pun bisa
 *   mengganti :userId di URL dengan ID siapa saja dan tetap dapat
 *   datanya -- inilah inti BOLA.
 *
 * - "secure": MITIGASI -- Object-Level Access Control. req.user.id
 *   (dari token, tidak bisa dipalsukan client) WAJIB sama dengan
 *   :userId yang diminta; kalau tidak, ditolak 403 SEBELUM query
 *   database dijalankan.
 *
 * Toggle lewat target-api/.env: SECURITY_MODE=secure, lalu restart
 * container target-api.
 */
router.get("/:userId/latest", verifyToken, (req, res) => {
  const userId = Number(req.params.userId);

  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: "userId tidak valid" });
  }

  const isSecureMode = process.env.SECURITY_MODE === "secure";

  if (isSecureMode && req.user.id !== userId) {
    // MITIGASI: object-level access control -- ditolak SEBELUM query DB.
    return res.status(403).json({
      error: "Forbidden: Anda tidak berhak mengakses data lokasi user lain",
    });
  }

  const db = getDb();

  // Mode vulnerable: tidak ada pengecekan req.user.id vs userId -- ini celahnya.
  const location = db
    .prepare(
      `SELECT latitude, longitude, recorded_at
       FROM locations
       WHERE user_id = ?
       ORDER BY recorded_at DESC
       LIMIT 1`
    )
    .get(userId);

  if (!location) {
    return res.status(404).json({ error: "Belum ada data lokasi untuk user ini" });
  }

  return res.json(location);
});

module.exports = router;