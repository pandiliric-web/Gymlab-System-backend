const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

// Load backend env vars. Prefer .env.local then fallback to .env.
const envLocalPath = path.join(__dirname, '..', '.env.local');
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envLocalPath)) {
  dotenv.config({ path: envLocalPath, override: true });
} else {
  dotenv.config({ path: envPath, override: true });
}

const MONGODB_URI = process.env.MONGODB_URI || '';
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'clutchlab';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || 'admin@clutchlab.com').trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || 'admin12345');

function now() {
  return new Date();
}

async function main() {
  if (!MONGODB_URI) {
    throw new Error('MONGODB_URI is missing. Create backend/.env.local (or set env var) then rerun.');
  }

  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(MONGODB_DB_NAME);

  // Requested minimal indexing: only userId index.
  await db.collection('payments').createIndex({ userId: 1 });

  const users = db.collection('users');
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  const nowTs = now();

  const adminByEmail = await users.findOne({ email: ADMIN_EMAIL });
  const anyAdmin = adminByEmail ? null : await users.findOne({ role: 'admin' });

  if (adminByEmail) {
    await users.updateOne(
      { _id: adminByEmail._id },
      { $set: { email: ADMIN_EMAIL, passwordHash, role: 'admin', fullName: 'Administrator', updatedAt: nowTs } }
    );
  } else if (anyAdmin) {
    // Rewrite the existing admin record to match current env.
    await users.updateOne(
      { _id: anyAdmin._id },
      { $set: { email: ADMIN_EMAIL, passwordHash, role: 'admin', fullName: 'Administrator', updatedAt: nowTs } }
    );
  } else {
    await users.insertOne({
      email: ADMIN_EMAIL,
      passwordHash,
      role: 'admin',
      fullName: 'Administrator',
      createdAt: nowTs,
      updatedAt: nowTs,
    });
  }

  // eslint-disable-next-line no-console
  console.log(`[setupMongo] ensured admin user: ${ADMIN_EMAIL}`);

  const settings = db.collection('settings');
  await settings.updateOne(
    { _id: 'pricing' },
    {
      $setOnInsert: {
        _id: 'pricing',
        standard: { base: 49, pro: 119, elite: 119 },
        tiers: {
          member: { monthly: 49, daily: 119 },
          nonMember: { monthly: 49, daily: 119 },
        },
        sessionDefaults: {
          member: { monthly: 10, daily: 1 },
          nonMember: { monthly: 10, daily: 1 },
        },
        updatedAt: now(),
      },
    },
    { upsert: true }
  );

  await client.close();
  // eslint-disable-next-line no-console
  console.log('[setupMongo] done');
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('[setupMongo] failed:', e?.message || e);
  process.exit(1);
});

