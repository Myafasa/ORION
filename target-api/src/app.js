require("dotenv").config();
const express = require("express");

const { initDb } = require("./config/db");
const authRouter = require("./routes/auth");
const usersRouter = require("./routes/users");
const locationsRouter = require("./routes/locations");

const app = express();
app.use(express.json());

// Inisialisasi koneksi & schema database saat server start
initDb();

// Health check sederhana, berguna untuk verifikasi container hidup
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "target-api" });
});

app.use("/api/auth", authRouter);
app.use("/api/users", usersRouter);
app.use("/api/locations", locationsRouter);

const PORT = process.env.PORT || 3000;
const SECURITY_MODE = process.env.SECURITY_MODE || "vulnerable";
app.listen(PORT, () => {
  console.log(`target-api berjalan di port ${PORT} | SECURITY_MODE=${SECURITY_MODE}`);
});