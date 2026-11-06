const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'bright_life_secret_key_2026';
const db = new Database('bright_life.db');

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

// Initialize Default Admin (Fixed SQL Syntax Error here)
const adminRow = db.prepare('SELECT * FROM admin_settings WHERE id = 1').get();
if (!adminRow) {
  const defaultPassHash = bcrypt.hashSync('12345678', 10);
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

// --- API ENDPOINTS ---

app.post('/api/register', async (req, res) => {
  const { full_name, phone, password, referred_by } = req.body;
  if (!full_name || !phone || !password) {
    return res.status(400).json({ error: 'እባክዎን ሁሉንም አስፈላጊ መረጃዎች ያስገቡ።' });
  }

  try {
    const existing = db.prepare('SELECT * FROM members WHERE phone = ?').get(phone);
    if (existing) return res.status(400).json({ error: 'ይህ የስልክ ቁጥር አስቀድሞ ተመዝግቧል።' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const myReferralCode = generateReferralCode(full_name);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const insert = db.prepare(`
      INSERT INTO members (full_name, phone, password, referral_code, referred_by, otp_code)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = insert.run(full_name, phone, hashedPassword, myReferralCode, referred_by || null, otp);

    db.prepare('INSERT INTO wallets (member_id, balance) VALUES (?, 0.0)').run(result.lastInsertRowid);
    sendSMS(phone, `የብሩህ ህይወት ማህበር የማረጋገጫ ኮድዎ: ${otp}`);

    res.status(201).json({ message: 'ምዝገባው ተሳክቷል!', member_id: result.lastInsertRowid, referral_code: myReferralCode });
  } catch (err) {
    res.status(500).json({ error: 'የሲስተም ስህተት: ' + err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  const member = db.prepare('SELECT * FROM members WHERE phone = ?').get(phone);

  if (!member || !(await bcrypt.compare(password, member.password))) {
    return res.status(401).json({ error: 'የተሳሳተ የስልክ ቁጥር ወይም የይለፍ ቃል::' });
  }

  const token = jwt.sign({ id: member.id, phone: member.phone }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, member: { id: member.id, full_name: member.full_name, referral_code: member.referral_code, status: member.status } });
});

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  const admin = db.prepare('SELECT * FROM admin_settings WHERE id = 1').get();
  
  if (await bcrypt.compare(password, admin.password_hash)) {
    res.json({ success: true, message: 'የአድሚን መግቢያ ተሳክቷል!' });
  } else {
    res.status(401).json({ error: 'የተሳሳተ የአድሚን የይለፍ ቃል!' });
  }
});

app.post('/api/admin/verify-member', (req, res) => {
  const { member_id } = req.body;
  const member = db.prepare('SELECT * FROM members WHERE id = ?').get(member_id);
  if (!member) return res.status(404).json({ error: 'አባል አልተገኘም።' });
  if (member.status === 'Verified') return res.status(400).json({ error: 'አስቀድሞ ተረጋግጧል።' });

  // Use transaction to ensure data integrity for payouts
  const verifyAndUpdate = db.transaction((mId) => {
    db.prepare("UPDATE members SET status = 'Verified' WHERE id = ?").run(mId);

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
      
      currentReferrerCode = referrer.referred_by;
    }
  });

  try {
    verifyAndUpdate(member_id);
    res.json({ message: 'አባሉ ተረጋግጧል፤ የሪፈራል ክፍያውም ተፈጽሟል።' });
  } catch (err) {
    res.status(500).json({ error: 'ማረጋገጥ ላይ ስህተት አጋጥሟል: ' + err.message });
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

app.post('/api/wallet/transfer', (req, res) => {
  const { sender_id, recipient_phone, amount } = req.body;
  const transferAmount = parseFloat(amount);

  if (isNaN(transferAmount) || transferAmount <= 0) {
    return res.status(400).json({ error: 'ትክክለኛ ያልሆነ የገንዘብ መጠን።' });
  }

  const transferAction = db.transaction(() => {
    const senderWallet = db.prepare('SELECT * FROM wallets WHERE member_id = ?').get(sender_id);
    if (!senderWallet || senderWallet.balance < transferAmount) {
      throw new Error('በቂ ገንዘብ የለም።');
    }

    const recipient = db.prepare('SELECT * FROM members WHERE phone = ?').get(recipient_phone);
    if (!recipient) {
      throw new Error('ተቀባዩ አልተገኘም።');
    }

    if (senderWallet.member_id === recipient.id) {
      throw new Error('ለራስዎ ገንዘብ ማስተላለፍ አይችሉም።');
    }

    db.prepare('UPDATE wallets SET balance = balance - ? WHERE member_id = ?').run(transferAmount, sender_id);
    db.prepare('UPDATE wallets SET balance = balance + ? WHERE member_id = ?').run(transferAmount, recipient.id);
    
    db.prepare(`
      INSERT INTO transactions (sender_id, receiver_id, type, amount, description)
      VALUES (?, ?, 'TRANSFER', ?, 'Wallet to Wallet Transfer')
    `).run(sender_id, recipient.id, transferAmount);
  });

  try {
    transferAction();
    res.json({ message: 'ገንዘብ ማስተላለፉ ተሳክቷል!' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/wallet/withdraw', (req, res) => {
  const { member_id, amount } = req.body;
  const withdrawAmount = parseFloat(amount);

  const wallet = db.prepare('SELECT * FROM wallets WHERE member_id = ?').get(member_id);
  if (!wallet || wallet.balance < withdrawAmount) return res.status(400).json({ error: 'በቂ ቀሪ ሂሳብ የለም።' });

  db.prepare('UPDATE wallets SET balance = balance - ? WHERE member_id = ?').run(withdrawAmount, member_id);
  res.json({ message: 'የወጪ ማዘዣ ጥያቄዎ ተቀባይነት አግኝቷል!' });
});

app.post('/api/store/buy', (req, res) => {
  const { member_id, product_id } = req.body;
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
  if (!product) return res.status(404).json({ error: 'እቃው አልተገኘም።' });

  const wallet = db.prepare('SELECT * FROM wallets WHERE member_id = ?').get(member_id);
  if (!wallet || wallet.balance < product.price) return res.status(400).json({ error: 'በቂ ገንዘብ የለም።' });

  db.prepare('UPDATE wallets SET balance = balance - ? WHERE member_id = ?').run(product.price, member_id);
  res.json({ message: `"${product.name}" እቃውን በተሳካ ሁኔታ ገዝተዋል!` });
});

app.get('/api/admin/analytics', (req, res) => {
  const totalMembers = db.prepare('SELECT COUNT(*) as count FROM members').get().count;
  const verifiedMembers = db.prepare("SELECT COUNT(*) as count FROM members WHERE status = 'Verified'").get().count;
  const totalPayouts = db.prepare('SELECT SUM(amount) as total FROM referral_payouts').get().total || 0;
  const memberStats = db.prepare(`
    SELECT m.*, (SELECT COUNT(*) FROM members WHERE referred_by = m.referral_code) AS total_invited, COALESCE(w.balance, 0) AS total_commission
    FROM members m LEFT JOIN wallets w ON m.id = w.member_id ORDER BY total_invited DESC
  `).all();

  res.json({ total_members: totalMembers, verified_members: verifiedMembers, total_payouts: totalPayouts, total_registration_collected: verifiedMembers * 1400, member_stats: memberStats });
});

app.listen(5000, () => console.log('Server running on port 5000'));
