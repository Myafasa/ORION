const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { getDb } = require("../config/db");

const router = express.Router();

/**
 * POST /api/auth/register
 * body: { name, phone, password }
 */
router.post("/register", (req, res) => {
  const { name, phone, password } = req.body || {};
  if (!name || !phone || !password) {
    return res.status(400).json({ error: "name, phone, dan password wajib diisi" });
  }

  const db = getDb();
  const existing = db.prepare("SELECT id FROM users WHERE phone = ?").get(phone);
  if (existing) {
    return res.status(409).json({ error: "Nomor telepon sudah terdaftar" });
  }

  const password_hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare("INSERT INTO users (name, phone, password_hash) VALUES (?, ?, ?)")
    .run(name, phone, password_hash);

  return res.status(201).json({ id: info.lastInsertRowid, name, phone });
});

/**
 * POST /api/auth/login
 * body: { phone, password }
 * response: { token }  -> dipakai sebagai Bearer token di endpoint lain
 */
router.post("/login", (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) {
    return res.status(400).json({ error: "phone dan password wajib diisi" });
  }

  const db = getDb();
  const user = db.prepare("SELECT * FROM users WHERE phone = ?").get(phone);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Nomor telepon atau password salah" });
  }

  const token = jwt.sign(
    { id: user.id, phone: user.phone },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );

  return res.json({ token });
});

module.exports = router;
