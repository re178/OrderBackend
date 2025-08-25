require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// === PostgreSQL (Render now, ElephantSQL later) ===
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render Internal/External or ElephantSQL
  ssl: { rejectUnauthorized: false }
});

// Ensure table exists (non-blocking). If DB is down, CSV continues to work.
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        fullname TEXT,
        email TEXT,
        category TEXT,
        requirements TEXT,
        file TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ orders table ready');
  } catch (e) {
    console.log('⚠️ DB init skipped (using CSV fallback):', e.message);
  }
})();

// ---- CSV <-> DB sync helpers ----
const ORDERS_CSV = path.join(__dirname, 'orders.csv');

// Parse CSV lines -> array of objects (tolerates optional id at the end)
function parseCsvOrders() {
  if (!fs.existsSync(ORDERS_CSV)) return [];
  const lines = fs.readFileSync(ORDERS_CSV, 'utf8').split('\n').filter(l => l.trim() !== '');
  return lines.map((line, i) => {
    const parts = line.split(/","|^"|"$/g).filter(p => p);
    // parts: [fullname, email, category, requirements, file, date, (optional) id]
    const obj = {
      index: i,
      fullname: parts[0],
      email: parts[1],
      category: parts[2],
      requirements: parts[3],
      file: parts[4],
      date: parts[5]
    };
    if (parts[6]) obj.id = parts[6]; // DB id if present
    return obj;
  });
}

// Write array of order objects back to CSV (keeps optional id if present)
function writeCsvOrders(rows) {
  const lines = rows.map(r => {
    const base = [
      r.fullname ?? '',
      r.email ?? '',
      r.category ?? '',
      r.requirements ?? '',
      r.file ?? '',
      r.date ?? ''
    ].map(v => `"${(v + '').replace(/"/g, '""')}"`).join(',');
    // append id if present
    return r.id ? `${base},"${r.id}"` : base;
  });
  fs.writeFileSync(ORDERS_CSV, lines.join('\n') + (lines.length ? '\n' : ''));
}

// If CSV missing/empty, rebuild it from DB so admin keeps working
async function ensureCsvFromDb() {
  try {
    const exists = fs.existsSync(ORDERS_CSV);
    const isEmpty = !exists || fs.readFileSync(ORDERS_CSV, 'utf8').trim() === '';
    if (!isEmpty) return;

    const r = await pool.query('SELECT id, fullname, email, category, requirements, file, created_at FROM orders ORDER BY created_at DESC');
    const rows = r.rows.map(row => ({
      fullname: row.fullname || '',
      email: row.email || '',
      category: row.category || '',
      requirements: row.requirements || '',
      file: row.file || '',
      date: (row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at) || '',
      id: String(row.id)
    }));
    writeCsvOrders(rows);
    console.log('🔁 CSV rebuilt from DB');
  } catch (e) {
    console.log('⚠️ Could not rebuild CSV from DB:', e.message);
  }
}

// Run heal-on-start (non-blocking)
ensureCsvFromDb();

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const useragent = require('express-useragent');
app.use(useragent.express());

// === Static files ===
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/admin', express.static(path.join(__dirname, 'public')));

// === Multer for optional file uploads ===
const upload = multer({ dest: 'uploads/' });

// === Nodemailer ===
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// === JWT helpers ===
function makeToken() {
  return jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '2h' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error('not admin');
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// === Admin login ===
app.post('/admin/api/login', (req, res) => {
  const { password } = req.body;
  const adminHash = process.env.ADMIN_HASH || '';
  const adminPlain = process.env.ADMIN_PASSWORD || '';

  let ok = false;
  if (adminHash) ok = bcrypt.compareSync(password, adminHash);
  else if (adminPlain) ok = password === adminPlain;

  if (!ok) return res.status(401).json({ message: 'Invalid password' });

  const token = makeToken();
  return res.json({ token });
});

// === Visitor Tracking ===
const visitorFile = path.join(__dirname, 'visitors.json');

// helper to get IP properly
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
}

// daily auto-reset (24 hours)
setInterval(() => {
  fs.writeFileSync(visitorFile, JSON.stringify([], null, 2));
  console.log('♻️ Visitor logs cleared (daily reset)');
}, 24 * 60 * 60 * 1000);

app.post('/log-visit', (req, res) => {
  let visitors = [];
  if (fs.existsSync(visitorFile)) {
    visitors = JSON.parse(fs.readFileSync(visitorFile));
  }

  visitors.push({
    time: new Date().toLocaleString(),     // local format
    page: req.body.page || req.originalUrl || 'unknown',
    ip: getClientIp(req),
    browser: req.useragent.browser,
    os: req.useragent.os,
    platform: req.useragent.platform,
    source: req.useragent.source
  });

  fs.writeFileSync(visitorFile, JSON.stringify(visitors, null, 2));
  res.sendStatus(200);
});

app.get('/admin/api/get-visits', authMiddleware, (req, res) => {
  let visitors = [];
  if (fs.existsSync(visitorFile)) {
    visitors = JSON.parse(fs.readFileSync(visitorFile));
  }
  res.json(visitors);
});


// === Lock/Unlock Orders ===
const lockFile = path.join(__dirname, 'orders_locked.json');
function isOrdersLocked() {
  if (!fs.existsSync(lockFile)) return false;
  const status = JSON.parse(fs.readFileSync(lockFile));
  return status.locked;
}

app.post('/admin/api/lock-orders', authMiddleware, (req, res) => {
  fs.writeFileSync(lockFile, JSON.stringify({ locked: true }));
  res.send({ locked: true });
});

app.post('/admin/api/unlock-orders', authMiddleware, (req, res) => {
  fs.writeFileSync(lockFile, JSON.stringify({ locked: false }));
  res.send({ locked: false });
});

// === Client order submission ===
app.post('/submit-order', upload.single('fileupload'), async (req, res) => {
  if (isOrdersLocked()) return res.status(403).send('Orders are currently locked');

  const { fullname, email, category, requirements } = req.body;
  const file = req.file ? req.file.filename : '';
  const date = new Date().toISOString();
  const line = `"${fullname}","${email}","${category}","${requirements}","${file}","${date}"\n`;

  if (!fs.existsSync('orders.csv')) fs.writeFileSync('orders.csv', '');
  fs.appendFileSync('orders.csv', line);
  // Mirror to DB; then stamp DB id into the same CSV line (so later actions map 1:1)
  try {
    const ins = await pool.query(
      `INSERT INTO orders (fullname, email, category, requirements, file, created_at)
       VALUES ($1, $2, $3, $4, $5, to_timestamp($6, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
       RETURNING id`,
      [fullname, email, category, requirements, file, date]
    );
    const newId = String(ins.rows[0].id);

    // Append the id into the last CSV row we just wrote (adds 7th field)
    try {
      const rows = parseCsvOrders();
      if (rows.length) {
        const last = rows[rows.length - 1];
        // If last row matches this order and has no id, add it
        const same =
          last.fullname === fullname &&
          last.email === email &&
          last.category === category &&
          last.requirements === requirements &&
          (last.file || '') === (file || '') &&
          last.date === date &&
          !last.id;
        if (same) {
          last.id = newId;
          writeCsvOrders(rows);
        }
      }
    } catch (e2) {
      console.log('⚠️ Could not stamp DB id into CSV:', e2.message);
    }
  } catch (e) {
    console.log('⚠️ DB insert failed, CSV still holds the order:', e.message);
  }

  // Admin notification
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL_USER,
        subject: 'New Order Received',
        html: `<h3>New Order</h3>
               <p><b>Name:</b> ${fullname}</p>
               <p><b>Email:</b> ${email}</p>
               <p><b>Category:</b> ${category}</p>
               <p><b>Requirements:</b> ${requirements}</p>
               <p><b>File:</b> ${file || 'No file'}</p>
               <p><b>Date:</b> ${new Date(date).toLocaleString()}</p>`
      });
    } catch (err) { console.log('Admin email error:', err.message); }

    // Client auto-reply
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Order is Received',
        html: `<h3>Hi ${fullname},</h3>
               <p>Thank you for your order. We have received it.</p>
               <ul>
                 <li>Category: ${category}</li>
                 <li>Requirements: ${requirements}</li>
                 <li>Date: ${new Date(date).toLocaleString()}</li>
               </ul>
               <p>Best regards,<br>Admin</p>`
      });
    } catch (err) { console.log('Client email error:', err.message); }
  }

  res.send('Thank you! Your order has been received.');
});

// === Admin APIs ===
app.get('/admin/api/orders-data', authMiddleware, async (req, res) => {
  await ensureCsvFromDb(); // if CSV was lost, repopulate from DB
  const orders = parseCsvOrders();
  return res.json(orders);
});

app.delete('/admin/api/order/:index', authMiddleware, async (req, res) => {
  const idx = parseInt(req.params.index, 10);

  // Read CSV first (source of truth for admin ops)
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No orders');
  const rows = parseCsvOrders();
  if (idx < 0 || idx >= rows.length) return res.status(400).send('Invalid index');

  const victim = rows[idx];

  // Try DB delete (by id if present; else best-effort match by tuple)
  try {
    if (victim.id) {
      await pool.query('DELETE FROM orders WHERE id = $1', [victim.id]);
    } else {
      await pool.query(
        `DELETE FROM orders
         WHERE id IN (
           SELECT id FROM orders
           WHERE fullname = $1 AND email = $2 AND category = $3 AND requirements = $4 AND COALESCE(file,'') = $5
           ORDER BY created_at DESC
           LIMIT 1
         )`,
        [victim.fullname, victim.email, victim.category, victim.requirements, victim.file || '']
      );
    }
  } catch (e) {
    console.log('⚠️ DB delete failed, proceeding with CSV delete:', e.message);
  }

  // CSV delete (existing behavior)
  rows.splice(idx, 1);
  writeCsvOrders(rows);
  res.send('Order deleted');
});
  // Mirror delete in DB first
  // Inside an async function, e.g., in your DELETE route:
app.delete('/admin/api/order/:index', authMiddleware, async (req, res) => {
  const idx = parseInt(req.params.index, 10);

  await ensureCsvFromDb();
  const rowsRJ = parseCsvOrders();
  if (idx < 0 || idx >= rowsRJ.length) return res.status(400).send('Invalid index');

  // ...rest of your delete logic
});


  const victimRJ = rowsRJ[idx];
  try {
    if (victimRJ.id) {
      await pool.query('DELETE FROM orders WHERE id = $1', [victimRJ.id]);
    } else {
      await pool.query(
        `DELETE FROM orders
         WHERE id IN (
           SELECT id FROM orders
           WHERE fullname = $1 AND email = $2 AND category = $3 AND requirements = $4 AND COALESCE(file,'') = $5
           ORDER BY created_at DESC
           LIMIT 1
         )`,
        [victimRJ.fullname, victimRJ.email, victimRJ.category, victimRJ.requirements, victimRJ.file || '']
      );
    }
  } catch (e) {
    console.log('⚠️ DB reject-delete failed, continuing with CSV + email:', e.message);
  }

// Reject order
app.post('/admin/api/reject-order/:index', authMiddleware, async (req, res) => {
  const idx = parseInt(req.params.index, 10);
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No orders');
  const lines = fs.readFileSync('orders.csv', 'utf8')
    .split('\n').filter(l => l.trim() !== '');
  if (idx < 0 || idx >= lines.length) return res.status(400).send('Invalid index');

  const parts = lines[idx].split(/","|^"|"$/g).filter(p => p);
  const email = parts[1]; 
  const fullname = parts[0];

  lines.splice(idx, 1);
  fs.writeFileSync('orders.csv', lines.join('\n') + (lines.length ? '\n' : ''));

  // Notify client
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Order Was Rejected',
        html: `<h3>Hi ${fullname},</h3>
               <p>Unfortunately, your order has been rejected by the admin.</p>
               <p>If you have questions, please contact support.</p>`
      });
    } catch(err){ console.log('Client reject email error:', err.message); }
  }

  res.send('Order rejected and client notified');
});

// Send emails
app.post('/admin/api/email-client', authMiddleware, async (req, res) => {
  const { email, subject, message } = req.body;
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return res.status(500).send('Email not configured');
  }
  try {
    await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject, html: message });
    res.send('Email sent successfully');
  } catch (err) {
    res.status(500).send('Error sending email: ' + err.message);
  }
});

app.post('/admin/api/email-all', authMiddleware, async (req, res) => {
  const { subject, message } = req.body;
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No clients');
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return res.status(500).send('Email not configured');
  }
  const data = fs.readFileSync('orders.csv', 'utf8').split('\n').filter(l => l.trim() !== '');
  const emails = data.map(line => line.split(/","|^"|"$/g).filter(p => p)[1]);

  try {
    for (const e of emails) {
      await transporter.sendMail({ from: process.env.EMAIL_USER, to: e, subject, html: message });
    }
    res.send('Emails sent to all clients');
  } catch (err) {
    res.status(500).send('Error sending emails: ' + err.message);
  }
});

// PDF Generation
app.get('/admin/api/orders/pdf', authMiddleware, (req, res) => {
  if (!fs.existsSync('orders.csv')) return res.status(404).send('No orders');
  const data = fs.readFileSync('orders.csv', 'utf8')
    .split('\n').filter(l => l.trim() !== '');

  const doc = new PDFDocument({ margin:30, size:'A4' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=orders.pdf');
  doc.pipe(res);

  doc.fontSize(20).fillColor('#007BFF').text('GigiCraft Hub Orders', { align:'center' });
  doc.moveDown(0.5);
  doc.fontSize(12).fillColor('black').text(`Admin Email: ${process.env.EMAIL_USER || 'N/A'}`, { align:'center' });
  doc.moveDown(1);

  data.forEach((line,i)=>{
    const parts = line.split(/","|^"|"$/g).filter(p=>p);
    doc.fontSize(12).fillColor('black').text(
      `${i+1}. Name: ${parts[0]}, Email: ${parts[1]}, Category: ${parts[2]}, Requirements: ${parts[3]}, File: ${parts[4] || 'No file'}, Date: ${new Date(parts[5]).toLocaleString()}`
    );
    doc.moveDown(0.5);
  });

  doc.end();
});
// PDF Generation (Visitors)
app.get('/admin/api/visits/pdf', authMiddleware, (req, res) => {
  if (!fs.existsSync(visitorFile)) return res.status(404).send('No visits logged');
  const visitors = JSON.parse(fs.readFileSync(visitorFile, 'utf8'));

  const doc = new PDFDocument({ margin:30, size:'A4' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=visitors.pdf');
  doc.pipe(res);

  // Title + Subtitle
  doc.fontSize(22).fillColor('#007BFF').text('Visitor Tracking Report', { align:'center' });
  doc.moveDown(0.3);
  doc.fontSize(14).fillColor('black').text('Website Visitors — Analytics Log', { align:'center' });
  doc.moveDown(0.5);
  doc.fontSize(10).fillColor('gray').text(`Generated: ${new Date().toLocaleString()}`, { align:'center' });
  doc.moveDown(1);

  // Table header
  const headers = ['Time','Page','IP Address','Browser','OS','Platform','Source'];
  const colWidths = [100, 90, 90, 70, 70, 70, 150];
  let x = doc.x, y = doc.y;
  doc.rect(x, y, 550, 20).fill('#007BFF');
  doc.fillColor('white').fontSize(10);
  headers.forEach((h, i) => {
    doc.text(h, x + colWidths.slice(0,i).reduce((a,b)=>a+b,0) + 2, y+5, { width: colWidths[i]-4 });
  });
  doc.fillColor('black');
  y += 20;

  // Table rows
  visitors.forEach(v => {
    headers.forEach((h,i)=>{
      const key = h.toLowerCase().replace(/ /g,'');
      let val = v[ key ] || v[ h.toLowerCase() ] || '';
      doc.text(val.toString(), x + colWidths.slice(0,i).reduce((a,b)=>a+b,0) + 2, y+3, { width: colWidths[i]-4 });
    });
    y += 20;
    if (y > 750) { doc.addPage(); y = 50; }
  });

  // Rubber-stamp placeholder
  doc.rect(400, 750, 150, 40).stroke();
  doc.text('Stamp/Signature', 420, 765);

  // Footer
  doc.fontSize(9).fillColor('gray').text('Confidential — For Admin Use Only', 30, 800, { align:'center' });

  doc.end();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`Backend running on port ${PORT}`));



