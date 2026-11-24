const jwt = require("jsonwebtoken");

/**
 * Middleware verifikasi JWT.
 *
 * Saat ini middleware HANYA memastikan token valid (signature & belum
 * kedaluwarsa) dan menempelkan payload-nya ke req.user.
 *
 * TODO (Fase implementasi mitigasi):
 *   Middleware generik seperti ini TIDAK cukup untuk mencegah BOLA.
 *   Pengecekan "apakah req.user berhak atas objek yang diminta" harus
 *   dilakukan terpisah, per-endpoint, di dalam masing-masing route
 *   handler (lihat komentar TODO di routes/locations.js).
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Token tidak ditemukan" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // mis. { id, phone }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token tidak valid" });
  }
}

module.exports = { verifyToken };
