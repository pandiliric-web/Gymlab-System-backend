const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Load backend env vars. Base .env first, then .env.local overrides for local dev.
const envLocalPath = path.join(__dirname, '.env.local');
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) dotenv.config({ path: envPath, override: false });
if (fs.existsSync(envLocalPath)) dotenv.config({ path: envLocalPath, override: true });

const app = express();

const PORT = Number(process.env.PORT || 5000);
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
const MONGODB_URI = process.env.MONGODB_URI || '';
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'clutchlab';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || 'admin@clutchlab.com').trim().toLowerCase();

const allowedOrigins = CORS_ORIGIN.split(',').map((v) => v.trim()).filter(Boolean);

function isLocalOrLanOrigin(origin) {
  try {
    const { hostname } = new URL(origin);
    if (!hostname) return false;
    if (hostname === 'localhost' || hostname === '127.0.0.1') return true;
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(hostname);
  } catch {
    return false;
  }
}

const allowAnyOrigin = allowedOrigins.includes('*');
const normalizedAllowedOrigins = new Set(allowedOrigins.map((v) => v.toLowerCase()));

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      const normalizedOrigin = String(origin).toLowerCase();
      if (allowAnyOrigin || normalizedAllowedOrigins.has(normalizedOrigin) || isLocalOrLanOrigin(origin)) {
        return callback(null, true);
      }
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
  })
);
app.use(express.json());

let mongoClient = null;
let db = null;

async function connectMongo() {
  if (!MONGODB_URI) throw new Error('MONGODB_URI is missing.');
  mongoClient = new MongoClient(MONGODB_URI);
  await mongoClient.connect();
  db = mongoClient.db(MONGODB_DB_NAME);

  // Requested minimal indexing: only userId index.
  await db.collection('payments').createIndex({ userId: 1 });
  await db.collection('users').createIndex({ customerId: 1 }, { unique: true, sparse: true });
}

function now() {
  return new Date();
}

function normalizeMemberIdValue(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Same ID with/without a leading zero (e.g. month 02 vs 2) for lookup. */
function customerIdLookupVariants(normalizedId) {
  const n = String(normalizedId || '').trim();
  if (!n) return [];
  const set = new Set([n]);
  // If the stored ID includes a leading 0 (e.g. 03...) but the user typed without it (e.g. 3...),
  // accept both shapes. Expected format is MMDDYYYY + first3 (11 chars). Missing leading month zero => 10 chars.
  if (n.length > 1 && n[0] === '0') set.add(n.slice(1));
  if (n.length === 10 && /^[0-9]/.test(n)) set.add(`0${n}`);
  return Array.from(set);
}

async function findMemberUserByCustomerIdInput(usersCollection, rawInput) {
  const primary = normalizeMemberIdValue(rawInput);
  if (!primary) return null;
  const variants = customerIdLookupVariants(primary);
  const emails = variants.map((v) => `${v}@member.clutchlab.local`);
  return usersCollection.findOne({
    $or: [{ customerId: { $in: variants } }, { email: { $in: emails } }],
  });
}

function buildCustomerIdFromProfile(fullName, birthday) {
  const name = String(fullName || '').trim().toLowerCase();
  const first = (name.split(/\s+/).find(Boolean) || '').replace(/[^a-z]/g, '');
  const first3 = (first.slice(0, 3) || '').padEnd(3, 'x');

  const b = String(birthday || '').trim(); // expected: YYYY-MM-DD
  const m = b.slice(5, 7);
  const d = b.slice(8, 10);
  const y = b.slice(0, 4);
  const mm = /^\d{2}$/.test(m) ? m : '00';
  const dd = /^\d{2}$/.test(d) ? d : '00';
  const yyyy = /^\d{4}$/.test(y) ? y : '0000';

  return normalizeMemberIdValue(`${mm}${dd}${yyyy}${first3}`);
}

function generateCustomerId() {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return normalizeMemberIdValue(`c${`${ts}${rand}`.slice(-10)}`);
}

async function allocateUniqueCustomerId(base, usersCollection) {
  const clean = normalizeMemberIdValue(base);
  if (!clean) return null;
  const exists = await usersCollection.findOne({ customerId: clean });
  if (!exists) return clean;

  // Handle duplicates: append 2 digits (01..99)
  for (let i = 1; i <= 99; i += 1) {
    const suffix = String(i).padStart(2, '0');
    const candidate = `${clean}${suffix}`;
    // eslint-disable-next-line no-await-in-loop
    const taken = await usersCollection.findOne({ customerId: candidate });
    if (!taken) return candidate;
  }
  // Worst case fallback
  return `${clean}${Date.now().toString(36).slice(-3)}`;
}

function sanitizeReferencePart(v) {
  return String(v || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .slice(0, 24);
}

function generateReferenceNumber({ userId, plan }) {
  const userPart = sanitizeReferencePart(userId);
  const planPart = sanitizeReferencePart(plan);
  const ts = Date.now().toString(36);
  return `${userPart}_${planPart}_${ts}`.replace(/-+/g, '-').slice(0, 64);
}

function issueToken(user) {
  return jwt.sign(
    {
      uid: String(user._id),
      email: user.email || null,
      role: user.role || 'member',
      customerId: user.customerId || null,
    },
    JWT_SECRET,
    { expiresIn: '14d' }
  );
}

function authRequired(req, res, next) {
  try {
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    req.auth = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function adminRequired(req, res, next) {
  if (req.auth?.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  return next();
}

async function ensureDefaultAdmin() {
  const users = db.collection('users');
  const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin12345', 10);
  const nowTs = now();

  const adminByEmail = await users.findOne({ email: ADMIN_EMAIL });
  const anyAdmin = adminByEmail ? null : await users.findOne({ role: 'admin' });

  if (adminByEmail) {
    await users.updateOne(
      { _id: adminByEmail._id },
      { $set: { email: ADMIN_EMAIL, passwordHash: hash, role: 'admin', fullName: 'Administrator', updatedAt: nowTs } }
    );
    return;
  }

  if (anyAdmin) {
    // If there is an old admin record (from earlier env values), rewrite it to match current env.
    await users.updateOne(
      { _id: anyAdmin._id },
      { $set: { email: ADMIN_EMAIL, passwordHash: hash, role: 'admin', fullName: 'Administrator', updatedAt: nowTs } }
    );
    return;
  }

  await users.insertOne({
    email: ADMIN_EMAIL,
    passwordHash: hash,
    role: 'admin',
    fullName: 'Administrator',
    createdAt: nowTs,
    updatedAt: nowTs,
  });
}

const DEFAULT_SESSION_TIER = { monthly: 10, daily: 1 };

function normalizeSessionDefaults(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const flatM = Math.max(1, Math.floor(Number(r.monthly)) || DEFAULT_SESSION_TIER.monthly);
  const flatD = Math.max(1, Math.floor(Number(r.daily)) || DEFAULT_SESSION_TIER.daily);
  const mem = r.member || {};
  const non = r.nonMember || {};
  return {
    member: {
      monthly: Math.max(1, Math.floor(Number(mem.monthly)) || flatM),
      daily: Math.max(1, Math.floor(Number(mem.daily)) || flatD),
    },
    nonMember: {
      monthly: Math.max(1, Math.floor(Number(non.monthly)) || flatM),
      daily: Math.max(1, Math.floor(Number(non.daily)) || flatD),
    },
  };
}

const DEFAULT_PRICING_DOC = {
  _id: 'pricing',
  standard: { base: 49, pro: 119, elite: 119 },
  tiers: {
    member: { monthly: 49, membership: 49, daily: 119 },
    nonMember: { monthly: 49, membership: 49, daily: 119 },
  },
  sessionDefaults: {
    member: { ...DEFAULT_SESSION_TIER },
    nonMember: { ...DEFAULT_SESSION_TIER },
  },
};

async function getPricingSettings() {
  const settings = await db.collection('settings').findOne({ _id: 'pricing' });
  if (!settings) {
    return { ...DEFAULT_PRICING_DOC, updatedAt: now() };
  }
  return {
    ...DEFAULT_PRICING_DOC,
    ...settings,
    standard: { ...DEFAULT_PRICING_DOC.standard, ...(settings.standard || {}) },
    tiers: {
      member: { ...DEFAULT_PRICING_DOC.tiers.member, ...(settings.tiers?.member || {}) },
      nonMember: { ...DEFAULT_PRICING_DOC.tiers.nonMember, ...(settings.tiers?.nonMember || {}) },
    },
    sessionDefaults: normalizeSessionDefaults(settings.sessionDefaults || {}),
    updatedAt: settings.updatedAt || now(),
  };
}

function mapUser(u) {
  const sr = u.sessionsRemaining;
  return {
    id: String(u._id),
    email: u.email || null,
    role: u.role || 'member',
    customerId: u.customerId || null,
    memberId: u.customerId || null,
    fullName: u.fullName || null,
    phone: u.phone || null,
    gender: u.gender || null,
    birthday: u.birthday || null,
    hasAccess: Boolean(u.hasAccess),
    access: u.access || {},
    isWalkInClient: Boolean(u.isWalkInClient),
    lastMemberCategory: u.lastMemberCategory || null,
    lastPlanType: u.lastPlanType || null,
    sessionsRemaining: typeof sr === 'number' && Number.isFinite(sr) ? sr : null,
    createdAt: u.createdAt || null,
    updatedAt: u.updatedAt || null,
  };
}

function mapPayment(p) {
  return {
    id: p._id,
    userId: p.userId || null,
    customerId: p.customerId || null,
    courseId: p.courseId || null,
    plan: p.plan || null,
    title: p.title || null,
    amount: p.amount || 0,
    planType: p.planType || null,
    memberCategory: p.memberCategory || null,
    paymentMethod: p.paymentMethod || null,
    startDate: p.startDate || null,
    endDate: p.endDate || null,
    sessions: typeof p.sessions === 'number' && Number.isFinite(p.sessions) ? p.sessions : null,
    status: p.status || 'pending',
    provider: p.provider || {},
    submittedAt: p.submittedAt || null,
    createdAt: p.createdAt || null,
    updatedAt: p.updatedAt || null,
    paidAt: p.paidAt || null,
    walkInDiscountApplied: Boolean(p.walkInDiscountApplied),
    walkInRegularAmount:
      typeof p.walkInRegularAmount === 'number' && Number.isFinite(p.walkInRegularAmount)
        ? p.walkInRegularAmount
        : null,
    walkInDiscountedAmount:
      typeof p.walkInDiscountedAmount === 'number' && Number.isFinite(p.walkInDiscountedAmount)
        ? p.walkInDiscountedAmount
        : null,
  };
}

app.post('/api/auth/signup', async (req, res) => {
  try {
    const fullName = String(req.body?.fullName || '').trim();
    const phone = String(req.body?.phone || '').trim();
    const gender = String(req.body?.gender || '').trim() || 'prefer_not_say';
    const birthday = String(req.body?.birthday || '').trim() || null;
    const waiverAccepted = Boolean(req.body?.waiverAccepted);
    if (!waiverAccepted) return res.status(400).json({ error: 'Waiver must be accepted.' });

    const users = db.collection('users');
    const requested = normalizeMemberIdValue(req.body?.customerId || '');
    const baseCustomerId = requested || buildCustomerIdFromProfile(fullName, birthday) || generateCustomerId();
    const customerId = await allocateUniqueCustomerId(baseCustomerId, users);
    if (!customerId) return res.status(400).json({ error: 'Could not generate customer ID.' });

    const email = `${customerId}@member.clutchlab.local`;
    const exists = await users.findOne({ $or: [{ customerId }, { email }] });
    if (exists) return res.status(409).json({ error: 'Customer ID already exists.' });

    const passwordHash = await bcrypt.hash(customerId, 10);
    const doc = {
      email,
      customerId,
      passwordHash,
      role: 'member',
      fullName: fullName || null,
      phone: phone || null,
      gender,
      birthday,
      waiverAccepted,
      hasAccess: false,
      access: {},
      lastMemberCategory: 'non-member',
      lastPlanType: null,
      createdAt: now(),
      updatedAt: now(),
    };
    const inserted = await users.insertOne(doc);
    const user = { ...doc, _id: inserted.insertedId };
    const token = issueToken(user);
    return res.json({ ok: true, token, user: mapUser(user) });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'Signup failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const identifier = String(req.body?.identifier || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!identifier) return res.status(400).json({ error: 'Missing login identifier.' });

    const users = db.collection('users');
    let user = null;
    if (identifier.includes('@')) {
      user = await users.findOne({ email: identifier });
      if (!user) return res.status(401).json({ error: 'No account found for that email.' });
      const ok = await bcrypt.compare(password, user.passwordHash || '');
      if (!ok) return res.status(401).json({ error: 'Incorrect password.' });
    } else {
      user = await findMemberUserByCustomerIdInput(users, identifier);
      if (!user) return res.status(401).json({ error: 'No account found for that customer ID.' });
      // Members login by Customer ID only (no separate password).
      // As long as the customerId exists, we accept the login.
    }

    user.updatedAt = now();
    await users.updateOne({ _id: user._id }, { $set: { updatedAt: user.updatedAt } });
    const token = issueToken(user);
    return res.json({ ok: true, token, user: mapUser(user) });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'Login failed.' });
  }
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  const user = await db.collection('users').findOne({ _id: new ObjectId(req.auth.uid) });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  return res.json({ ok: true, user: mapUser(user) });
});

app.get('/api/users', authRequired, adminRequired, async (_req, res) => {
  const users = await db.collection('users').find({}).toArray();
  return res.json({ users: users.map(mapUser) });
});

app.get('/api/payments', authRequired, async (req, res) => {
  const query = {};
  const userId = String(req.query.userId || '').trim();
  const status = String(req.query.status || '').trim();
  if (userId) query.userId = userId;
  if (status) query.status = status;
  if (req.auth.role !== 'admin') query.userId = req.auth.uid;
  const payments = await db.collection('payments').find(query).toArray();
  return res.json({ payments: payments.map(mapPayment) });
});

app.get('/api/payments/:id', authRequired, async (req, res) => {
  const payment = await db.collection('payments').findOne({ _id: req.params.id });
  if (!payment) return res.status(404).json({ error: 'Payment not found.' });
  if (req.auth.role !== 'admin' && payment.userId !== req.auth.uid) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  return res.json({ payment: mapPayment(payment) });
});

app.post('/api/payments/request', authRequired, async (req, res) => {
  const courseId = String(req.body?.courseId || '').trim() || 'base';
  const formData = req.body?.formData || {};
  const pricing = await getPricingSettings();
  const standard = pricing.standard || {};
  const tiers = pricing.tiers || {};
  const plan = String(courseId || '').toLowerCase();
  const isWalkInPlan = plan === 'daily' || plan === 'walkin' || plan === 'walk-in';
  const requestedCategory = String(formData?.memberCategory || '').trim().toLowerCase();
  let memberCategory = requestedCategory;
  if (plan === 'monthly') {
    const lockedCategory = await resolveLockedMemberCategory({
      userId: req.auth.uid,
      customerIdInput: formData?.customerId,
    });
    if (lockedCategory === 'member' || lockedCategory === 'non-member') {
      memberCategory = lockedCategory;
    }
  }
  let tierKey = memberCategory === 'non-member' ? 'nonMember' : 'member';
  let walkInQuote = null;
  if (isWalkInPlan) {
    walkInQuote = await resolveWalkInQuoteForUser({
      userId: req.auth.uid,
      pricing,
      customerIdInput: formData?.customerId,
    });
    tierKey = walkInQuote.tierKey;
  }
  const tier = tiers?.[tierKey] || {};
  const amountMap = {
    daily: Number(standard.elite || 119),
    weekly: Number(standard.pro || standard.elite || 119),
    monthly: Number(standard.base || 49),
    membership: Number(tier?.membership || tier?.monthly || standard.base || 49),
    base: Number(standard.base || 49),
    pro: Number(standard.pro || standard.elite || 119),
    elite: Number(standard.elite || 119),
  };
  const tierPrice = Number(tier?.[plan]);
  const baseFromTier = isWalkInPlan
    ? Number(walkInQuote?.amount || 0)
    : Number((Number.isFinite(tierPrice) && tierPrice > 0 ? tierPrice : amountMap[plan]) || 80);
  const sdNorm = normalizeSessionDefaults(pricing.sessionDefaults || {});
  const tierSessions = tierKey === 'nonMember' ? sdNorm.nonMember : sdNorm.member;

  const isAdmin = String(req.auth?.role || '').trim().toLowerCase() === 'admin';

  function defaultSessionsForPlan() {
    if (plan === 'monthly') return tierSessions.monthly;
    if (plan === 'membership') return tierSessions.monthly;
    if (plan === 'daily') return tierSessions.daily;
    if (plan === 'weekly' || plan === 'pro') return tierSessions.daily;
    return 1;
  }

  let sessions = Math.floor(Number(formData.sessions));
  if (!isAdmin || !Number.isFinite(sessions) || sessions < 1) {
    sessions = defaultSessionsForPlan();
  }

  const formAmt = Number(formData.amount);
  let resolvedAmount = baseFromTier;
  if (isAdmin && Number.isFinite(formAmt) && formAmt > 0) {
    resolvedAmount = formAmt;
  }

  const walkInMemberCategory = walkInQuote?.eligibleForReturningDiscount
    ? 'Returning Member (Walk-in Discount)'
    : 'Walk-in Client';

  const paymentId = generateReferenceNumber({ userId: req.auth.uid, plan: courseId });
  await db.collection('payments').insertOne({
    _id: paymentId,
    userId: req.auth.uid,
    customerId: String(formData.customerId || '').trim() || req.auth.customerId || null,
    courseId,
    plan,
    title: `${courseId} membership`,
    amount: resolvedAmount,
    planType: formData.planType || null,
    memberCategory: isWalkInPlan ? walkInMemberCategory : memberCategory || null,
    paymentMethod: formData.paymentMethod || 'Cash',
    startDate: formData.startDate || null,
    endDate: formData.endDate || null,
    sessions,
    status: 'pending',
    walkInDiscountApplied: Boolean(walkInQuote?.eligibleForReturningDiscount),
    walkInRegularAmount: walkInQuote?.regularAmount || null,
    walkInDiscountedAmount: walkInQuote?.discountedAmount || null,
    provider: { gateway: 'manual' },
    submittedAt: now(),
    createdAt: now(),
    updatedAt: now(),
  });
  return res.json({
    paymentId,
    status: 'pending',
    amount: resolvedAmount,
    memberCategoryLocked: plan === 'monthly' ? memberCategory : null,
    walkInEligibleForReturningDiscount: Boolean(walkInQuote?.eligibleForReturningDiscount),
    walkInRegularAmount: walkInQuote?.regularAmount || null,
    walkInDiscountedAmount: walkInQuote?.discountedAmount || null,
  });
});

app.post('/api/payments/member-category-quote', authRequired, async (req, res) => {
  try {
    const lockedCategory = await resolveLockedMemberCategory({
      userId: req.auth.uid,
      customerIdInput: req.body?.customerId,
    });
    return res.json({
      memberCategory: lockedCategory || null,
      lock: Boolean(lockedCategory),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'Failed to resolve member category.' });
  }
});

app.post('/api/payments/walkin-quote', authRequired, async (req, res) => {
  try {
    const pricing = await getPricingSettings();
    const quote = await resolveWalkInQuoteForUser({
      userId: req.auth.uid,
      pricing,
      customerIdInput: req.body?.customerId,
    });
    return res.json({
      amount: quote.amount,
      regularAmount: quote.regularAmount,
      discountedAmount: quote.discountedAmount,
      eligibleForReturningDiscount: quote.eligibleForReturningDiscount,
      tierKey: quote.tierKey,
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'Failed to quote walk-in price.' });
  }
});

app.post('/api/payments/:id/mark-paid', authRequired, adminRequired, async (req, res) => {
  const paymentId = String(req.params.id || '').trim();
  const payment = await db.collection('payments').findOne({ _id: paymentId });
  if (!payment) return res.status(404).json({ error: 'Payment not found.' });
  await db.collection('payments').updateOne(
    { _id: paymentId },
    { $set: { status: 'paid', paidAt: now(), updatedAt: now(), provider: { ...(payment.provider || {}), manualConfirmed: true } } }
  );
  if (payment.userId) {
    const sessionCount = Number(payment.sessions);
    const addSessions = Number.isFinite(sessionCount) && sessionCount > 0 ? sessionCount : 0;
    const userIdObj = ObjectId.isValid(payment.userId) ? new ObjectId(payment.userId) : null;
    if (userIdObj) {
      const current = await db.collection('users').findOne({ _id: userIdObj });
      const existing = Number(current?.sessionsRemaining);
      const existingSafe = Number.isFinite(existing) && existing >= 0 ? existing : 0;
      const sessionsRemaining = existingSafe + addSessions;
      await db.collection('users')
        .updateOne(
          { _id: userIdObj },
          {
            $set: {
              hasAccess: true,
              [`access.${payment.courseId || 'plan'}`]: true,
              sessionsRemaining,
              lastPlanType: payment.planType || null,
              ...(function buildCategoryUpdate() {
                const planKey = inferPaymentPlanKey(payment);
                // Only paid monthly/membership can change membership tier.
                if (planKey === 'monthly') {
                  return {
                    lastMemberCategory: isNonMemberCategory(payment.memberCategory) ? 'non-member' : 'member',
                  };
                }
                return {};
              })(),
              membershipEndDate: payment.endDate || null,
              updatedAt: now(),
            },
          }
        )
        .catch(() => {});
    }
  }
  return res.json({ ok: true });
});

function parsePaymentEndMs(endDate) {
  if (!endDate) return null;
  const ms = Date.parse(String(endDate).trim());
  return Number.isFinite(ms) ? ms : null;
}

function normalizePlanKey(value) {
  const v = String(value || '')
    .trim()
    .toLowerCase();
  if (!v) return null;
  if (v === 'base') return 'monthly';
  if (v === 'pro') return 'weekly';
  if (v === 'elite') return 'daily';
  if (v === 'walk-in') return 'walkin';
  if (v === 'walkin') return 'walkin';
  if (v.includes('walk-in') || v.includes('walk in')) return 'walkin';
  if (v.includes('daily')) return 'daily';
  if (v.includes('weekly')) return 'weekly';
  if (v.includes('monthly') || v.includes('membership')) return 'monthly';
  return null;
}

function inferPaymentPlanKey(payment) {
  return (
    normalizePlanKey(payment?.courseId) ||
    normalizePlanKey(payment?.plan) ||
    normalizePlanKey(payment?.planType) ||
    null
  );
}

function resolveMembershipEndMs(payment) {
  const explicitEnd = parsePaymentEndMs(payment?.endDate);
  if (Number.isFinite(explicitEnd)) return explicitEnd;

  const planKey = inferPaymentPlanKey(payment);
  if (planKey !== 'monthly') return null;

  const paidMs =
    parsePaymentEndMs(payment?.paidAt) ||
    parsePaymentEndMs(payment?.updatedAt) ||
    parsePaymentEndMs(payment?.createdAt) ||
    parsePaymentEndMs(payment?.submittedAt);
  if (!Number.isFinite(paidMs)) return null;

  return paidMs + 30 * 24 * 60 * 60 * 1000;
}

function normalizeMemberCategoryValue(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function isNonMemberCategory(value) {
  const v = normalizeMemberCategoryValue(value);
  if (!v) return false;
  return (
    v === 'non-member' ||
    v === 'non member' ||
    v === 'walk-in client' ||
    v === 'walk in client' ||
    v.includes('non-member') ||
    v.includes('walk-in client') ||
    v.includes('walk in client')
  );
}

function hasMemberPricingEligibility(payments) {
  return (payments || []).some((p) => {
    if (String(p?.status || '').toLowerCase() !== 'paid') return false;
    const memberCategory = normalizeMemberCategoryValue(p?.memberCategory);

    // If category is available, use it directly.
    if (memberCategory) return !isNonMemberCategory(memberCategory);

    // Legacy fallback: paid monthly plans are treated as member records.
    return inferPaymentPlanKey(p) === 'monthly';
  });
}

function categoryFromPaymentHistory(payments) {
  const paid = (payments || [])
    .filter((p) => String(p?.status || '').toLowerCase() === 'paid')
    .sort((a, b) => {
      const am = Date.parse(String(a?.paidAt || a?.updatedAt || a?.createdAt || 0));
      const bm = Date.parse(String(b?.paidAt || b?.updatedAt || b?.createdAt || 0));
      return (Number.isFinite(bm) ? bm : 0) - (Number.isFinite(am) ? am : 0);
    });
  if (!paid.length) return null;

  for (const p of paid) {
    const mc = normalizeMemberCategoryValue(p?.memberCategory);
    if (!mc) continue;
    return isNonMemberCategory(mc) ? 'non-member' : 'member';
  }

  return hasMemberPricingEligibility(paid) ? 'member' : null;
}

async function resolveLockedMemberCategory({ userId, customerIdInput }) {
  const usersCollection = db.collection('users');
  const paymentsCollection = db.collection('payments');

  const candidateUids = new Set();
  const candidateCustomerIds = new Set();
  const uid = String(userId || '').trim();

  const rawCustomerId = String(customerIdInput || '').trim();
  if (!rawCustomerId && uid) candidateUids.add(uid);
  if (rawCustomerId) candidateCustomerIds.add(rawCustomerId);
  const normalizedInputId = normalizeMemberIdValue(rawCustomerId);
  for (const v of customerIdLookupVariants(normalizedInputId)) {
    candidateCustomerIds.add(v);
    candidateCustomerIds.add(v.toUpperCase());
  }

  if (rawCustomerId) {
    const userByCustomer = await findMemberUserByCustomerIdInput(usersCollection, rawCustomerId);
    const matchedUid = String(userByCustomer?._id || '').trim();
    if (matchedUid) candidateUids.add(matchedUid);
    const matchedCustomerId = String(userByCustomer?.customerId || '').trim();
    if (matchedCustomerId) {
      candidateCustomerIds.add(matchedCustomerId);
      const normalizedMatchedId = normalizeMemberIdValue(matchedCustomerId);
      for (const v of customerIdLookupVariants(normalizedMatchedId)) {
        candidateCustomerIds.add(v);
        candidateCustomerIds.add(v.toUpperCase());
      }
    }
  }

  for (const candidateUid of candidateUids) {
    const paidHistory = await paymentsCollection
      .find({ userId: candidateUid, status: 'paid' })
      .sort({ paidAt: -1, updatedAt: -1, createdAt: -1 })
      .limit(120)
      .toArray();
    const resolved = categoryFromPaymentHistory(paidHistory);
    if (resolved) return resolved;
  }

  if (candidateCustomerIds.size) {
    const paidByCustomerId = await paymentsCollection
      .find({
        status: 'paid',
        customerId: { $in: Array.from(candidateCustomerIds) },
      })
      .sort({ paidAt: -1, updatedAt: -1, createdAt: -1 })
      .limit(120)
      .toArray();
    const resolved = categoryFromPaymentHistory(paidByCustomerId);
    if (resolved) return resolved;
  }

  return null;
}

async function resolveWalkInQuoteForUser({ userId, pricing, customerIdInput }) {
  const tiers = pricing?.tiers || {};
  const standard = pricing?.standard || {};

  const nonMemberDaily = Number(tiers?.nonMember?.daily);
  const memberDaily = Number(tiers?.member?.daily);
  const standardDaily = Number(standard?.elite);

  const regularAmount =
    (Number.isFinite(nonMemberDaily) && nonMemberDaily > 0 ? nonMemberDaily : null) ||
    (Number.isFinite(standardDaily) && standardDaily > 0 ? standardDaily : null) ||
    100;
  const configuredDiscounted = Number.isFinite(memberDaily) && memberDaily > 0 ? memberDaily : null;
  const discountedAmount =
    configuredDiscounted && configuredDiscounted < regularAmount
      ? configuredDiscounted
      : Math.max(1, regularAmount - 20);

  const lockedCategory = await resolveLockedMemberCategory({
    userId,
    customerIdInput,
  });
  const eligibleForReturningDiscount = lockedCategory === 'member';

  return {
    amount: eligibleForReturningDiscount ? discountedAmount : regularAmount,
    regularAmount,
    discountedAmount,
    eligibleForReturningDiscount,
    tierKey: eligibleForReturningDiscount ? 'member' : 'nonMember',
  };
}

/** Public: member enters Customer ID; each call deducts 1 session if balance > 0, returns plan stats. */
app.post('/api/members/check-balance', async (req, res) => {
  try {
    const raw = String(req.body?.customerId || '').trim();
    if (!raw) return res.status(400).json({ error: 'Customer ID is required.' });

    const users = db.collection('users');
    const user = await findMemberUserByCustomerIdInput(users, raw);
    if (!user) return res.status(404).json({ error: 'No account found for that Customer ID.' });
    if (String(user.role || '').toLowerCase() === 'admin') {
      return res.status(400).json({ error: 'This action is for members only.' });
    }

    const uid = String(user._id);
    const payments = db.collection('payments');

    let remaining = Number(user.sessionsRemaining);
    if (!Number.isFinite(remaining)) {
      const latestPaid = await payments
        .find({ userId: uid, status: 'paid' })
        .sort({ paidAt: -1 })
        .limit(1)
        .toArray();
      const p = latestPaid[0];
      const n = Number(p?.sessions);
      remaining = Number.isFinite(n) && n >= 0 ? n : 0;
      await users.updateOne({ _id: user._id }, { $set: { sessionsRemaining: remaining, updatedAt: now() } });
    }

    const paidAgg = await payments
      .aggregate([{ $match: { userId: uid, status: 'paid' } }, { $group: { _id: null, total: { $sum: '$amount' } } }])
      .toArray();
    const totalPaid = typeof paidAgg[0]?.total === 'number' ? paidAgg[0].total : 0;

    const latestPaid = await payments
      .find({ userId: uid, status: 'paid' })
      .sort({ paidAt: -1 })
      .limit(1)
      .toArray();
    const lp = latestPaid[0] || null;

    const plan = lp?.planType || user.lastPlanType || '—';
    const memberCategory = lp?.memberCategory || user.lastMemberCategory || '—';

    let monthlyDaysLeft = 0;
    const endMs = parsePaymentEndMs(lp?.endDate || user.membershipEndDate);
    if (endMs) {
      monthlyDaysLeft = Math.max(0, Math.ceil((endMs - Date.now()) / (24 * 60 * 60 * 1000)));
    }

    if (remaining <= 0) {
      return res.json({
        ok: true,
        deducted: false,
        sessionsRemaining: 0,
        plan,
        memberCategory,
        monthlyDaysLeft,
        totalPaid,
        message: 'No sessions remaining. Please renew your plan.',
      });
    }

    const newRemaining = remaining - 1;
    await users.updateOne({ _id: user._id }, { $set: { sessionsRemaining: newRemaining, updatedAt: now() } });

    return res.json({
      ok: true,
      deducted: true,
      sessionsRemaining: newRemaining,
      previousSessions: remaining,
      plan,
      memberCategory,
      monthlyDaysLeft,
      totalPaid,
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'Check balance failed.' });
  }
});

app.get('/api/settings/pricing', authRequired, async (_req, res) => {
  const pricing = await getPricingSettings();
  return res.json({ pricing });
});

app.put('/api/settings/pricing', authRequired, adminRequired, async (req, res) => {
  const payload = req.body || {};
  const memberTier = payload?.tiers?.member || {};
  const nonMemberTier = payload?.tiers?.nonMember || {};
  const sessionDefaults = normalizeSessionDefaults(payload?.sessionDefaults || {});
  const memberDaily = Number(memberTier.daily || payload?.standard?.elite || 119);
  const memberMonthly = Number(memberTier.monthly || payload?.standard?.base || 49);
  const memberMembership = Number(memberTier.membership || memberMonthly);
  const nonMemberDaily = Number(nonMemberTier.daily || payload?.standard?.elite || 119);
  const nonMemberMonthly = Number(nonMemberTier.monthly || payload?.standard?.base || 49);
  const nonMemberMembership = Number(nonMemberTier.membership || nonMemberMonthly);
  const doc = {
    _id: 'pricing',
    standard: {
      base: memberMonthly,
      pro: Number(memberTier.daily || payload?.standard?.pro || memberDaily),
      elite: Number(memberTier.daily || payload?.standard?.elite || 119),
    },
    tiers: {
      member: {
        monthly: memberMonthly,
        membership: memberMembership,
        daily: memberDaily,
      },
      nonMember: {
        monthly: nonMemberMonthly,
        membership: nonMemberMembership,
        daily: nonMemberDaily,
      },
    },
    sessionDefaults,
    updatedAt: now(),
  };
  await db.collection('settings').updateOne({ _id: 'pricing' }, { $set: doc }, { upsert: true });
  return res.json({ ok: true, pricing: doc });
});

app.post('/api/admin/walkin', authRequired, adminRequired, async (req, res) => {
  const fullName = String(req.body?.fullName || '').trim();
  if (!fullName) return res.status(400).json({ error: 'Client name is required.' });
  const customerId = normalizeMemberIdValue(req.body?.customerId) || `walkin${Date.now().toString(36)}`;
  const amount = Number(req.body?.amount || 80);
  const pricingWalkin = await getPricingSettings();
  const sdW = normalizeSessionDefaults(pricingWalkin?.sessionDefaults || {});
  const walkinSessions = Math.max(1, Math.floor(Number(sdW.member.walkin)) || 1);
  const userDoc = await db.collection('users').findOneAndUpdate(
    { customerId },
    {
      $set: {
        fullName,
        phone: String(req.body?.phone || '').trim() || null,
        customerId,
        role: 'member',
        isWalkInClient: true,
        hasAccess: true,
        lastMemberCategory: 'non-member',
        lastPlanType: 'Walk-in',
        updatedAt: now(),
      },
      $setOnInsert: { createdAt: now() },
    },
    { upsert: true, returnDocument: 'after' }
  );
  const userId = String(userDoc.value?._id || userDoc.lastErrorObject?.upserted);
  const paymentId = generateReferenceNumber({ userId, plan: 'walkin' });
  await db.collection('payments').insertOne({
    _id: paymentId,
    userId,
    customerId,
    courseId: 'walkin',
    plan: 'walkin',
    planType: 'Walk-in',
    memberCategory: 'Walk-in Client',
    paymentMethod: 'Cash',
    amount,
    sessions: walkinSessions,
    status: 'paid',
    source: 'admin_customization',
    paidAt: now(),
    createdAt: now(),
    updatedAt: now(),
  });
  await db.collection('users').updateOne(
    { _id: new ObjectId(userId) },
    { $set: { sessionsRemaining: walkinSessions, hasAccess: true, updatedAt: now() } }
  ).catch(() => {});
  return res.json({ ok: true, customerId, userId, paymentId, amount });
});

app.post('/api/admin/members', authRequired, adminRequired, async (req, res) => {
  const fullName = String(req.body?.fullName || '').trim() || null;
  const phone = String(req.body?.phone || '').trim() || null;
  const gender = String(req.body?.gender || '').trim() || null;
  const birthday = String(req.body?.birthday || '').trim() || null;
  const users = db.collection('users');
  const requested = normalizeMemberIdValue(req.body?.customerId || '');
  const baseCustomerId = requested || buildCustomerIdFromProfile(fullName, birthday) || generateCustomerId();
  const customerId = await allocateUniqueCustomerId(baseCustomerId, users);
  if (!customerId) return res.status(400).json({ error: 'Could not generate customer ID.' });
  const email = `${customerId}@member.clutchlab.local`;
  const exists = await users.findOne({ $or: [{ customerId }, { email }] });
  if (exists) return res.status(409).json({ error: 'Member already exists.' });
  const passwordHash = await bcrypt.hash(customerId, 10);
  const inserted = await users.insertOne({
    email,
    role: 'member',
    customerId,
    fullName,
    phone,
    gender,
    birthday,
    passwordHash,
    hasAccess: false,
    access: {},
    lastMemberCategory: 'non-member',
    lastPlanType: null,
    createdAt: now(),
    updatedAt: now(),
  });
  return res.json({ ok: true, uid: String(inserted.insertedId), customerId, email });
});

app.delete('/api/admin/members', authRequired, adminRequired, async (req, res) => {
  const customerId = normalizeMemberIdValue(req.body?.customerId || '');
  const requestedUid = String(req.body?.uid || '').trim();
  let user = null;
  if (requestedUid && ObjectId.isValid(requestedUid)) {
    user = await db.collection('users').findOne({ _id: new ObjectId(requestedUid) });
  }
  if (!user && customerId) {
    user = await db.collection('users').findOne({ customerId });
  }
  if (!user) return res.status(404).json({ error: 'Member record not found.' });
  if (String(user.role || '').trim().toLowerCase() === 'admin') {
    return res.status(400).json({ error: 'Admin accounts cannot be deleted from the dashboard.' });
  }
  const uid = String(user._id);
  const paymentDelete = await db.collection('payments').deleteMany({ userId: uid });
  await db.collection('users').deleteOne({ _id: user._id });
  return res.json({ ok: true, uid, customerId: user.customerId || null, deletedPayments: paymentDelete.deletedCount || 0, authDeleted: true });
});

app.get('/health', (_req, res) => res.send('ok'));

connectMongo()
  .then(ensureDefaultAdmin)
  .then(() => {
    app.listen(PORT, () => {
      // eslint-disable-next-line no-console
      console.log(`[backend] listening on port ${PORT}`);
    });
  })
  .catch((e) => {
    // eslint-disable-next-line no-console
    console.error('[backend] startup failed:', e?.message || e);
    process.exit(1);
  });
