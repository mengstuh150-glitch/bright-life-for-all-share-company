        const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// --- PRODUCTION SECURITY MIDDLEWARES ---
app.use(helmet());
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiter for authentication routes to prevent brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: { error: 'እጅግ በጣም ብዙ ሙከራዎች ተደርገዋል፤ እባክዎ ከ15 ደቂቃ በኋላ እንደገና ይሞክሩ።' }
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/admin/login', authLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'bright_life_secret_key_2026_secure';
const db = new Database('bright_life.db');

// Enable WAL mode for high concurrency
db.pragma('journal_mode = WAL');

// --- DATABASE TABLES CREATION ---
db.exec(`
  CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    pin_code TEXT DEFAULT '1234',
    referral_code TEXT UNIQUE NOT NULL,
    referred_by TEXT,
    status TEXT DEFAULT 'Pending',
    otp_code TEXT,
    is_phone_verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER UNIQUE NOT NULL,
    balance REAL DEFAULT 0.0,
    FOREIGN KEY (member_id) REFERENCES members(id)
  );

  CREATE TABLE IF NOT EXISTS referral_payouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    beneficiary_id INTEGER NOT NULL,
    source_member_id INTEGER NOT NULL,
    tier INTEGER NOT NULL,
    amount REAL NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (beneficiary_id) REFERENCES members(id),
    FOREIGN KEY (source_member_id) REFERENCES members(id)
  );

  CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS admin_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL,
    pin_code TEXT DEFAULT '1234'
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    stock INTEGER DEFAULT 100
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Initialize Default Admin
const adminRow = db.prepare('SELECT * FROM admin_settings WHERE id = 1').get();
if (!adminRow) {
  const defaultPassHash = bcrypt.hashSync('BrightLifeAdmin@2026!', 10);
  db.prepare('INSERT INTO admin_settings (id, password_hash, pin_code) VALUES (1, ?, ?)').run(defaultPassHash, '1234');
}

// Initialize Default Products
const prodCount = db.prepare('SELECT COUNT(*) as cnt FROM products').get().cnt;
if (prodCount === 0) {
  const insertProd = db.prepare('INSERT INTO products (name, price, description) VALUES (?, ?, ?)');
  insertProd.run('የማህበሩ አክሲዮን የምስክር ወረቀት (የተቀረጸ)', 500, 'ኦፊሴላዊ የታተመ የአክሲዮን ሰርተፍኬት');
  insertProd.run('የብሩህ ህይወት ማስታወሻ ደብተር እና እስክሪፕቶ', 250, 'ለስብሰባ የሚሆን ጥራት ያለው ደብተር');
  insertProd.run('የቆዳ ዶክመንት ያዥ (Folder)', 800, 'ውልና ማስረጃዎችን ለመያዝ የሚረዳ ሌዘር ፎልደር');
}

function generateReferralCode(name) {
  const prefix = name.substring(0, 3).toUpperCase().replace(/[^A-Z]/g, 'BL');
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  return `${prefix}-${randomNum}`;
}

function sendSMS(phone, message) {
  console.log(`[SMS MOCK TO ${phone}]: ${message}`);
  return true;
}

// Admin Token Verification Middleware
function verifyAdminToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'ዕውቅና የለውም (Token አልተገኘም)' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || !user.isAdmin) return res.status(403).json({ error: 'ይህንን ማከናወን ፈቃድ የሎትም!' });
    req.admin = user;
    next();
  });
}

// Input Validation Error Handler Middleware
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
}

// --- API ENDPOINTS ---

app.post('/api/register', [
  body('full_name').trim().notEmpty().withMessage('ስም መሞላት አለበት'),
  body('phone').trim().notEmpty().withMessage('ስልክ ቁጥር መሞላት አለበት'),
  body('password').isLength({ min: 6 }).withMessage('የይለፍ ቃል ቢያንስ 6 ሆሄያት መሆን አለበት')
], handleValidationErrors, async (req, res, next) => {
  const { full_name, phone, password, referred_by } = req.body;

  try {
    const existing = db.prepare('SELECT * FROM members WHERE phone = ?').get(phone);
    if (existing) return res.status(400).json({ error: 'ይህ የስልክ ቁጥር አስቀድሞ ተመዝግቧል።' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const myReferralCode = generateReferralCode(full_name);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const registerTransaction = db.transaction(() => {
      const insert = db.prepare(`
        INSERT INTO members (full_name, phone, password, referral_code, referred_by, otp_code)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      const result = insert.run(full_name, phone, hashedPassword, myReferralCode, referred_by || null, otp);
      db.prepare('INSERT INTO wallets (member_id, balance) VALUES (?, 0.0)').run(result.lastInsertRowid);
      return result.lastInsertRowid;
    });

    const newMemberId = registerTransaction();
    sendSMS(phone, `የብሩህ ህይወት ማህበር የማረጋገጫ ኮድዎ: ${otp}`);

    res.status(201).json({ message: 'ምዝገባው ተሳክቷል!', member_id: newMemberId, referral_code: myReferralCode });
  } catch (err) {
    next(err);
  }
});

app.post('/api/login', [
  body('phone').trim().notEmpty().withMessage('ስልክ ቁጥር ያስገቡ'),
  body('password').notEmpty().withMessage('የይለፍ ቃል ያስገቡ')
], handleValidationErrors, async (req, res, next) => {
  const { phone, password } = req.body;
  const member = db.prepare('SELECT * FROM members WHERE phone = ?').get(phone);

  if (!member || !(await bcrypt.compare(password, member.password))) {
    return res.status(401).json({ error: 'የተሳሳተ የስልክ ቁጥር ወይም የይለፍ ቃል::' });
  }

  const token = jwt.sign({ id: member.id, phone: member.phone, isAdmin: false }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, member: { id: member.id, full_name: member.full_name, referral_code: member.referral_code, status: member.status } });
});

app.post('/api/admin/login', [
  body('password').notEmpty().withMessage('የአድሚን የይለፍ ቃል ያስገቡ')
], handleValidationErrors, async (req, res, next) => {
  const { password } = req.body;
  const admin = db.prepare('SELECT * FROM admin_settings WHERE id = 1').get();
  
  if (admin && (await bcrypt.compare(password, admin.password_hash))) {
    const token = jwt.sign({ isAdmin: true }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token, message: 'የአድሚን መግቢያ ተሳክቷል!' });
  } else {
    res.status(401).json({ error: 'የተሳሳተ የአድሚን የይለፍ ቃል!' });
  }
});

// Admin Verify Member with Payouts & Transaction Logging
app.post('/api/admin/verify-member', verifyAdminToken, [
  body('member_id').isInt().withMessage('ትክክለኛ የአባል መለያ (ID) ያስገቡ')
], handleValidationErrors, (req, res) => {
  const { member_id } = req.body;
  
  try {
    const verifyTransaction = db.transaction(() => {
      const member = db.prepare('SELECT * FROM members WHERE id = ?').get(member_id);
      if (!member) throw new Error('አባል አልተገኘም።');
      if (member.status === 'Verified') throw new Error('አስቀድሞ ተረጋግጧል።');

      db.prepare("UPDATE members SET status = 'Verified' WHERE id = ?").run(member_id);

      const payouts = [500, 300, 100];
      let currentReferrerCode = member.referred_by;

      for (let tier = 1; tier <= 3; tier++) {
        if (!currentReferrerCode) break;
        const referrer = db.prepare('SELECT * FROM members WHERE referral_code = ?').get(currentReferrerCode);
        if (!referrer) break;

        const payoutAmount = payouts[tier - 1];
        db.prepare('UPDATE wallets SET balance = balance + ? WHERE member_id = ?').run(payoutAmount, referrer.id);
        
        db.prepare(`
          INSERT INTO referral_payouts (beneficiary_id, source_member_id, tier, amount)
          VALUES (?, ?, ?, ?)
        `).run(referrer.id, member.id, tier, payoutAmount);

        // Log transaction
        db.prepare(`
          INSERT INTO transactions (sender_id, receiver_id, type, amount, description)
          VALUES (?, ?, ?, ?, ?)
        `).run(member.id, referrer.id, 'REFERRAL_COMMISSION', payoutAmount, `Tier ${tier} commission from ${member.full_name}`);

        currentReferrerCode = referrer.referred_by;
      }
    });

    verifyTransaction();
    res.json({ message: 'አባሉ ተረጋግጧል፤ የሪፈራል ክፍያውም ተፈጽሟል።' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/member/dashboard/:id', (req, res) => {
  const memberId = req.params.id;
  const member = db.prepare('SELECT id, full_name, phone, referral_code, status, created_at FROM members WHERE id = ?').get(memberId);
  if (!member) return res.status(404).json({ error: 'አባል አልተገኘም።' });

  const wallet = db.prepare('SELECT balance FROM wallets WHERE member_id = ?').get(memberId);
  const directInvites = db.prepare('SELECT COUNT(*) as count FROM members WHERE referred_by = ?').get(member.referral_code);
  const payouts = db.prepare('SELECT rp.*, m.full_name as source_name FROM referral_payouts rp JOIN members m ON rp.source_member_id = m.id WHERE rp.beneficiary_id = ?').all(memberId);
  const products = db.prepare('SELECT * FROM products').all();

  res.json({ member, wallet_balance: wallet ? wallet.balance : 0, direct_invites: directInvites.count, payouts, products });
});

// New Endpoint for Member Transaction History
app.get('/api/member/transactions/:id', (req, res) => {
  const memberId = req.params.id;
  const transactions = db.prepare(`
    SELECT * FROM transactions 
    WHERE sender_id = ? OR receiver_id = ? 
    ORDER BY created_at DESC
  `).all(memberId, memberId);

  res.json({ transactions });
});

app.post('/api/wallet/transfer', [
  body('sender_id').notEmpty(),
  body('recipient_phone').trim().notEmpty(),
  body('amount').isNumeric().withMessage('ትክክለኛ መጠን ያስገቡ')
], handleValidationErrors, (req, res) => {
  const { sender_id, recipient_phone, amount } = req.body;
  const transferAmount = parseFloat(amount);

  if (transferAmount <= 0) {
    return res.status(400).json({ error: 'እባክዎን ከዜሮ በላይ የሆነ መጠን ያስገቡ።' });
  }

  try {
    const transferTx = db.transaction(() => {
      const senderWallet = db.prepare('SELECT * FROM wallets WHERE member_id = ?').get(sender_id);
      if (!senderWallet || senderWallet.balance < transferAmount) throw new Error('በቂ ገንዘብ የለም።');

      const recipient = db.prepare('SELECT * FROM members WHERE phone = ?').get(recipient_phone);
      if (!recipient) throw new Error('ተቀባዩ አልተገኘም።');
      if (senderWallet.member_id === recipient.id) throw new Error('ለራስዎ ገንዘብ ማስተላለፍ አይችሉም።');

      db.prepare('UPDATE wallets SET balance = balance - ? WHERE member_id = ?').run(transferAmount, sender_id);
      db.prepare('UPDATE wallets SET balance = balance + ? WHERE member_id = ?').run(transferAmount, recipient.id);

      // Log transaction
      db.prepare(`
        INSERT INTO transactions (sender_id, receiver_id, type, amount, description)
        VALUES (?, ?, ?, ?, ?)
      `).run(sender_id, recipient.id, 'TRANSFER', transferAmount, `Transfer to phone ${recipient_phone}`);
    });

    transferTx();
    res.json({ message: 'ገንዘብ ማስተላለፉ ተሳክቷል!' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/wallet/withdraw', (req, res) => {
  const { member_id, amount } = req.body;
  const withdrawAmount = parseFloat(amount);

  if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
    return res.status(400).json({ error: 'እባክዎን ትክክለኛ መጠን ያስገቡ።' });
  }

  try {
    const withdrawTx = db.transaction(() => {
      const wallet = db.prepare('SELECT * FROM wallets WHERE member_id = ?').get(member_id);
      if (!wallet || wallet.balance < withdrawAmount) throw new Error('በቂ ቀሪ ሂሳብ የለም።');

      db.prepare('UPDATE wallets SET balance = balance - ? WHERE member_id = ?').run(withdrawAmount, member_id);

      // Log transaction
      db.prepare(`
        INSERT INTO transactions (sender_id, receiver_id, type, amount, description)
        VALUES (?, ?, ?, ?, ?)
      `).run(member_id, null, 'WITHDRAWAL', withdrawAmount, 'Withdrawal request');
    });

    withdrawTx();
    res.json({ message: 'የወጪ ማዘዣ ጥያቄዎ ተቀባይነት አግኝቷል!' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/store/buy', (req, res) => {
  const { member_id, product_id } = req.body;
  
  try {
    const buyTx = db.transaction(() => {
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
      if (!product) throw new Error('ምርቱ አልተገኘም።');

      const wallet = db.prepare('SELECT * FROM wallets WHERE member_id = ?').get(member_id);
      if (!wallet || wallet.balance < product.price) throw new Error('በቂ ገንዘብ የለም።');

      db.prepare('UPDATE wallets SET balance = balance - ? WHERE member_id = ?').run(product.price, member_id);

      // Log transaction
      db.prepare(`
        INSERT INTO transactions (sender_id, receiver_id, type, amount, description)
        VALUES (?, ?, ?, ?, ?)
      `).run(member_id, null, 'PURCHASE', product.price, `Bought product: ${product.name}`);
    });

    buyTx();
    res.json({ message: `እቃውን በተሳካ ሁኔታ ገዝተዋል!` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/admin/analytics', verifyAdminToken, (req, res) => {
  const totalMembers = db.prepare('SELECT COUNT(*) as count FROM members').get().count;
  const verifiedMembers = db.prepare("SELECT COUNT(*) as count FROM members WHERE status = 'Verified'").get().count;
  const totalPayouts = db.prepare('SELECT SUM(amount) as total FROM referral_payouts').get().total || 0;
  const memberStats = db.prepare(`
    SELECT m.*, (SELECT COUNT(*) FROM members WHERE referred_by = m.referral_code) AS total_invited, COALESCE(w.balance, 0) AS total_commission
    FROM members m LEFT JOIN wallets w ON m.id = w.member_id ORDER BY total_invited DESC
  `).all();

  res.json({ total_members: totalMembers, verified_members: verifiedMembers, total_payouts: totalPayouts, total_registration_collected: verifiedMembers * 1400, member_stats: memberStats });
});

// Render Port Configuration
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Production server is running securely on port ${PORT}`);
});
