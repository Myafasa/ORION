require("dotenv").config();
const bcrypt = require("bcryptjs");
const { initDb } = require("../config/db");

/**
 * Seeder data dummy (100% fiktif/sintetis) untuk kebutuhan pengujian.
 * Nomor telepon, koordinat, dan nama di bawah ini BUKAN data orang
 * sungguhan -- koordinat hanya acak di sekitar area Kota Tasikmalaya.
 */
const dummyUsers = [
  { name: "Andi Pratama", phone: "081200000001", password: "password123", avatar_url: null },
  { name: "Budi Santoso", phone: "081200000002", password: "password123", avatar_url: null },
  { name: "Citra Wulandari", phone: "081200000003", password: "password123", avatar_url: null },
];

// Satu titik lokasi dummy per user, dikaitkan lewat nomor telepon
const dummyLocations = [
  { phoneOfOwner: "081200000001", latitude: -7.3274, longitude: 108.2207 },
  { phoneOfOwner: "081200000002", latitude: -7.3509, longitude: 108.2109 },
  { phoneOfOwner: "081200000003", latitude: -7.3381, longitude: 108.2345 },
];

function seed() {
  const db = initDb();

  const insertUser = db.prepare(
    `INSERT OR IGNORE INTO users (name, phone, password_hash, avatar_url)
     VALUES (?, ?, ?, ?)`
  );
  const findUserByPhone = db.prepare("SELECT id FROM users WHERE phone = ?");
  const insertLocation = db.prepare(
    `INSERT INTO locations (user_id, latitude, longitude)
     VALUES (?, ?, ?)`
  );

  for (const u of dummyUsers) {
    const hash = bcrypt.hashSync(u.password, 10);
    insertUser.run(u.name, u.phone, hash, u.avatar_url || null);
  }
  console.log(`Seed users selesai. ${dummyUsers.length} user dummy diproses.`);

  for (const loc of dummyLocations) {
    const owner = findUserByPhone.get(loc.phoneOfOwner);
    if (owner) {
      insertLocation.run(owner.id, loc.latitude, loc.longitude);
    }
  }
  console.log(`Seed locations selesai. ${dummyLocations.length} titik lokasi dummy diproses.`);
}

seed();
