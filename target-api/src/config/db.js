const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const DB_PATH = process.env.DB_PATH || "./data/lab.sqlite3";

let db;

function initDb() {
  // Pastikan folder data ada
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");

  // Schema dasar. Field-field di sini disengaja mencakup data internal
  // (mis. last_location_id) yang NANTI akan menjadi relevan untuk
  // pembahasan "Excessive Data Exposure" -- tapi query/endpoint-nya
  // belum ditentukan di tahap skeleton ini.
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_url TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS locations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      latitude REAL NOT NULL,
      longitude REAL NOT NULL,
      recorded_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  console.log(`Database siap di: ${DB_PATH}`);
  return db;
}

function getDb() {
  if (!db) {
    throw new Error("Database belum diinisialisasi. Panggil initDb() dulu.");
  }
  return db;
}

module.exports = { initDb, getDb };
